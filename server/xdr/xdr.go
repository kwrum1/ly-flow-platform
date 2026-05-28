package xdr

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/lyflow/ly-flow-platform/server/unified"
	"github.com/lyflow/ly-flow-platform/server/xdr/decoder"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
	"github.com/lyflow/ly-flow-platform/server/xdr/rules"
)

type XDRProcessor struct {
	engine    *rules.RuleEngine
	loader    *rules.RuleLoader
	redis     *redis.Client
	redisAddr string
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup

	stats     *models.XDREventStats
	statsMu   sync.RWMutex

}

func NewXDRProcessor(redisAddr string, rulesDir string) (*XDRProcessor, error) {
	xp := &XDRProcessor{
		redisAddr: redisAddr,
		engine:    rules.NewRuleEngine(),
		loader:    rules.NewRuleLoader(rulesDir),
		stats:     &models.XDREventStats{},
	}

	xp.ctx, xp.cancel = context.WithCancel(context.Background())

	if err := xp.initRedis(); err != nil {
		log.Printf("[XDR] Redis 连接失败: %v，不启用模拟数据", err)
	}

	decoder.InitDecoders()

	if err := xp.LoadRules(); err != nil {
		log.Printf("[XDR] 加载规则失败: %v", err)
	}

	return xp, nil
}

func (xp *XDRProcessor) initRedis() error {
	xp.redis = redis.NewClient(&redis.Options{
		Addr: xp.redisAddr,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := xp.redis.Ping(ctx).Err(); err != nil {
		return err
	}

	for _, stream := range []string{"events:xdr", "alerts:xdr"} {
		if err := xp.redis.XGroupCreateMkStream(ctx, stream, "xdr-processor", "0").Err(); err != nil {
			if err.Error() != "BUSYGROUP Consumer Group name already exists" {
				log.Printf("[XDR] 创建消费者组失败 (%s): %v", stream, err)
			}
		}
	}

	return nil
}

func (xp *XDRProcessor) LoadRules() error {
	allRules, err := xp.loader.LoadRules()
	if err != nil {
		return err
	}

	for i := range allRules {
		if allRules[i].Enabled {
			xp.engine.LoadRules(allRules)
			break
		}
	}

	xp.engine.LoadRules(allRules)
	return nil
}

func (xp *XDRProcessor) Start() {
	log.Println("[XDR] XDR Processor 启动中...")

	xp.wg.Add(1)
	go xp.consumeLogs()

	log.Println("[XDR] XDR Processor 已启动")
}

func (xp *XDRProcessor) Stop() {
	log.Println("[XDR] XDR Processor 停止中...")
	xp.cancel()
	xp.wg.Wait()
	if xp.redis != nil {
		xp.redis.Close()
	}
	log.Println("[XDR] XDR Processor 已停止")
}

func (xp *XDRProcessor) consumeLogs() {
	defer xp.wg.Done()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-xp.ctx.Done():
			return
		case <-ticker.C:
			xp.consumeUnifiedEvents()
		}
	}
}

func (xp *XDRProcessor) consumeUnifiedEvents() {
	ctx := xp.ctx

	streams, err := xp.redis.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group:    "xdr-processor",
		Consumer: "xdr-consumer",
		Streams:  []string{"events:xdr", "alerts:xdr", ">", ">"},
		Count:    100,
		Block:    time.Second,
	}).Result()

	if err != nil || len(streams) == 0 {
		return
	}

	for _, stream := range streams {
		for _, msg := range stream.Messages {
			log := xp.convertMessageToNormalizedLog(stream.Stream, msg)
			if log == nil {
				continue
			}
			xp.processLog(log)
		}

		xp.redis.XAck(ctx, stream.Stream, "xdr-processor", msgIDsToStrings(stream.Messages)...)
	}
}

func (xp *XDRProcessor) convertMessageToNormalizedLog(stream string, msg redis.XMessage) *models.NormalizedLog {
	data, ok := msg.Values["data"]
	if !ok {
		return nil
	}

	var payload []byte
	switch v := data.(type) {
	case string:
		payload = []byte(v)
	case []byte:
		payload = v
	default:
		return nil
	}

	var event unified.UnifiedEvent
	if err := json.Unmarshal(payload, &event); err == nil {
		if event.EventType != "" || event.ID != "" || event.Source != "" {
			return xp.unifiedEventToNormalizedLog(stream, msg.ID, &event)
		}
	}

	var logInput models.XDRLogInput
	if err := json.Unmarshal(payload, &logInput); err != nil {
		return nil
	}

	log, err := logInput.ToNormalizedLog()
	if err != nil {
		return nil
	}
	if log.Metadata == nil {
		log.Metadata = make(map[string]interface{})
	}
	log.Metadata["stream"] = stream
	log.Metadata["message_id"] = msg.ID
	return log
}

func (xp *XDRProcessor) unifiedEventToNormalizedLog(stream, msgID string, event *unified.UnifiedEvent) *models.NormalizedLog {
	timestamp := event.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now()
	}

	source := event.Source
	if source == "" {
		source = string(event.SourceModule)
	}
	if source == "" {
		source = string(event.Module)
	}
	if source == "" {
		source = stream
	}

	raw := event.RawData
	if raw == "" {
		raw = event.Message
	}

	log := &models.NormalizedLog{
		Timestamp: timestamp,
		AgentID:   event.AgentID,
		Hostname:  event.Hostname,
		Source:    source,
		Program:   event.Service,
		Level:     string(event.Severity),
		Message:   event.Message,
		SrcIP:     event.SrcIP,
		DstIP:     event.DstIP,
		SrcPort:   event.SrcPort,
		DstPort:   event.DstPort,
		User:      event.User,
		Service:   event.Service,
		Raw:       raw,
		Metadata: map[string]interface{}{
			"stream":         stream,
			"message_id":     msgID,
			"unified_id":     event.ID,
			"unified_type":   event.EventType,
			"schema_version": event.SchemaVersion,
		},
	}

	if log.Message == "" {
		log.Message = event.EventType
	}
	if log.Level == "" {
		log.Level = models.SeverityLow
	}
	if log.AgentID == "" && event.EntityIDs != nil {
		log.AgentID = event.EntityIDs.AgentID
	}

	return log
}

func (xp *XDRProcessor) processLog(log *models.NormalizedLog) {
	matches := xp.engine.Match(log)

	for _, result := range matches {
		xp.generateAlert(result)
	}

	xp.updateStats(log, matches)
}

func (xp *XDRProcessor) generateAlert(result *models.MatchResult) {
	event := &models.XDREventInput{
		EventType:       result.Rule.GetEventType(),
		Severity:        result.Rule.GetSeverity(),
		AgentID:         result.Log.AgentID,
		Hostname:        result.Log.Hostname,
		Message:         fmt.Sprintf("%s - %s", result.Rule.Name, result.Log.Message),
		SrcIP:           result.Log.SrcIP,
		DstIP:           result.Log.DstIP,
		SrcPort:         result.Log.SrcPort,
		DstPort:         result.Log.DstPort,
		User:            result.Log.User,
		Service:         result.Log.Service,
		RawLog:          result.Log.Raw,
		RuleID:          result.Rule.ID,
		RuleName:        result.Rule.Name,
		MitreTactic:     result.Rule.GetMitreTactic(),
		MitreTechnique:  result.Rule.GetMitreTechnique(),
		Tags:            result.Rule.GetTags(),
		LogSource:       result.Log.Source,
		Frequency:       result.Rule.Frequency,
	}

	xp.publishAlert(event.ToXDREvent())
}

func (xp *XDRProcessor) publishAlert(event *models.XDREvent) {
	data, _ := json.Marshal(event)

	if xp.redis != nil {
		ctx := context.Background()
		xp.redis.XAdd(ctx, &redis.XAddArgs{
			Stream: "alerts:xdr",
			MaxLen: 10000,
			Approx: true,
			Values: map[string]interface{}{
				"event_type": event.EventType,
				"severity":   event.Severity,
				"message":    event.Message,
				"data":       string(data),
				"timestamp":  event.CreatedAt.Format(time.RFC3339),
			},
		})

		xp.redis.LPush(ctx, "alerts:list", string(data))
		xp.redis.LTrim(ctx, "alerts:list", 0, 999)
	}

	log.Printf("[XDR] 告警: [%s] %s (%d) - %s", event.Severity, event.RuleName, event.RuleID, event.SrcIP)
}

func (xp *XDRProcessor) updateStats(log *models.NormalizedLog, matches []*models.MatchResult) {
	xp.statsMu.Lock()
	defer xp.statsMu.Unlock()

	xp.stats.TotalEvents++

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	if log.Timestamp.After(today) {
		xp.stats.EventsToday++
	}

	if len(matches) > 0 {
		xp.stats.TotalAlerts++
		if log.Timestamp.After(today) {
			xp.stats.AlertsToday++
		}

		severity := matches[0].Rule.GetSeverity()
		switch severity {
		case models.SeverityCritical:
			xp.stats.CriticalAlerts++
		case models.SeverityHigh:
			xp.stats.HighAlerts++
		case models.SeverityMedium:
			xp.stats.MediumAlerts++
		case models.SeverityLow:
			xp.stats.LowAlerts++
		}
	}

	if xp.stats.TopSources == nil {
		xp.stats.TopSources = make(map[string]int64)
	}
	xp.stats.TopSources[log.Source]++
}

func (xp *XDRProcessor) GetStats() *models.XDREventStats {
	xp.statsMu.RLock()
	defer xp.statsMu.RUnlock()

	stats := &models.XDREventStats{
		TotalEvents:     xp.stats.TotalEvents,
		TotalAlerts:     xp.stats.TotalAlerts,
		CriticalAlerts:  xp.stats.CriticalAlerts,
		HighAlerts:      xp.stats.HighAlerts,
		MediumAlerts:    xp.stats.MediumAlerts,
		LowAlerts:       xp.stats.LowAlerts,
		EventsToday:     xp.stats.EventsToday,
		AlertsToday:     xp.stats.AlertsToday,
		TopSources:      xp.stats.TopSources,
	}

	stats.Sources = make([]string, 0, len(stats.TopSources))
	for source := range stats.TopSources {
		stats.Sources = append(stats.Sources, source)
	}
	return stats
}

func msgIDsToStrings(messages []redis.XMessage) []string {
	ids := make([]string, len(messages))
	for i, m := range messages {
		ids[i] = m.ID
	}
	return ids
}
