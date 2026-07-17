package xdr

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/lyflow/ly-flow-platform/server/internal/redisconfig"
	"github.com/lyflow/ly-flow-platform/server/unified"
	"github.com/lyflow/ly-flow-platform/server/xdr/decoder"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
	"github.com/lyflow/ly-flow-platform/server/xdr/rules"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
)

type XDRProcessor struct {
	engine    *rules.RuleEngine
	loader    *rules.RuleLoader
	redis     *redis.Client
	redisAddr string
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	reliable  *transport.RedisConsumer

	stats   *models.XDREventStats
	statsMu sync.RWMutex
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
	spool, err := transport.RuntimeSpoolFromEnv("server-xdr-consumer")
	if err != nil {
		return nil, fmt.Errorf("configure encrypted transport spool: %w", err)
	}
	xp.reliable = transport.NewRedisConsumer(transport.ConsumerConfig{
		Client: xp.redis, Group: "xdr-processor", Consumer: "xdr-consumer", Spool: spool,
		Retry: transport.RetryPolicy{MaxAttempts: 4, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second, Jitter: 0.2},
	})

	decoder.InitDecoders()

	if err := xp.LoadRules(); err != nil {
		log.Printf("[XDR] 加载规则失败: %v", err)
	}

	return xp, nil
}

func (xp *XDRProcessor) initRedis() error {
	xp.redis = redis.NewClient(redisconfig.Options(xp.redisAddr, 0))

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
	if err := transport.RegisterProducer(ctx, xp.redis, "server-xdr"); err != nil {
		return err
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
	if err := transport.RegisterProducer(ctx, xp.redis, "server-xdr"); err != nil {
		log.Printf("[XDR] reliable producer lease renewal failed: %v", err)
		return
	}
	for _, stream := range []string{"events:xdr", "alerts:xdr"} {
		if err := xp.reliable.Reclaim(ctx, stream, xp.processDelivery); err != nil {
			log.Printf("[XDR] pending reclaim failed stream=%s err=%v", stream, err)
			return
		}
	}

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
		if err := xp.reliable.Handle(ctx, stream.Stream, stream.Messages, xp.processDelivery); err != nil {
			log.Printf("[XDR] durable handoff failed stream=%s err=%v", stream.Stream, err)
		}
	}
}

func (xp *XDRProcessor) processDelivery(ctx context.Context, delivery transport.Delivery) (transport.DurableOutcome, error) {
	uid := transport.DeterministicUID("xdr_events_v2", delivery.Stream, delivery.MessageID)
	processed, err := xp.redis.HExists(ctx, "transport_reliability:xdr_events_v2", uid).Result()
	if err != nil {
		return transport.DurableOutcome{}, fmt.Errorf("load XDR receipt: %w", err)
	}
	if processed {
		return transport.DurableOutcome{UID: uid, Sink: "xdr_events_v2"}, nil
	}
	logEntry := xp.convertMessageToNormalizedLog(delivery.Stream, redis.XMessage{ID: delivery.MessageID, Values: delivery.Values})
	if logEntry == nil {
		return transport.DurableOutcome{}, transport.Permanent(transport.ReasonInvalidPayload, fmt.Errorf("unsupported XDR payload"))
	}
	if err := xp.processLog(ctx, logEntry); err != nil {
		return transport.DurableOutcome{}, err
	}
	if err := xp.redis.HSet(ctx, "transport_reliability:xdr_events_v2", uid, delivery.MessageID).Err(); err != nil {
		return transport.DurableOutcome{}, fmt.Errorf("persist XDR receipt: %w", err)
	}
	return transport.DurableOutcome{UID: uid, Sink: "xdr_events_v2"}, nil
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

func (xp *XDRProcessor) processLog(ctx context.Context, log *models.NormalizedLog) error {
	matches := xp.engine.Match(log)

	for _, result := range matches {
		if err := xp.generateAlert(ctx, result); err != nil {
			return err
		}
	}

	xp.updateStats(log, matches)
	return nil
}

func (xp *XDRProcessor) generateAlert(ctx context.Context, result *models.MatchResult) error {
	event := &models.XDREventInput{
		EventType:      result.Rule.GetEventType(),
		Severity:       result.Rule.GetSeverity(),
		AgentID:        result.Log.AgentID,
		Hostname:       result.Log.Hostname,
		Message:        fmt.Sprintf("%s - %s", result.Rule.Name, result.Log.Message),
		SrcIP:          result.Log.SrcIP,
		DstIP:          result.Log.DstIP,
		SrcPort:        result.Log.SrcPort,
		DstPort:        result.Log.DstPort,
		User:           result.Log.User,
		Service:        result.Log.Service,
		RawLog:         result.Log.Raw,
		RuleID:         result.Rule.ID,
		RuleName:       result.Rule.Name,
		MitreTactic:    result.Rule.GetMitreTactic(),
		MitreTechnique: result.Rule.GetMitreTechnique(),
		Tags:           result.Rule.GetTags(),
		LogSource:      result.Log.Source,
		Frequency:      result.Rule.Frequency,
	}

	nativeID := fmt.Sprint(result.Log.Metadata["message_id"])
	uid := transport.DeterministicUID("xdr_alerts", fmt.Sprint(result.Log.Metadata["stream"]), nativeID+":"+fmt.Sprint(result.Rule.ID))
	return xp.publishAlert(ctx, event.ToXDREvent(), uid)
}

func (xp *XDRProcessor) publishAlert(ctx context.Context, event *models.XDREvent, uid string) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode XDR alert: %w", err)
	}

	if xp.redis != nil {
		if err := xp.redis.Eval(ctx, xdrAlertScript, []string{"transport_reliability:xdr_alerts", "alerts:xdr", "alerts:list"},
			uid, event.EventType, event.Severity, event.Message, string(data), event.CreatedAt.Format(time.RFC3339),
		).Err(); err != nil {
			return fmt.Errorf("publish idempotent XDR alert: %w", err)
		}
	}

	log.Printf("[XDR] 告警: [%s] %s (%d) - %s", event.Severity, event.RuleName, event.RuleID, event.SrcIP)
	return nil
}

const xdrAlertScript = `
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then return redis.call('HGET', KEYS[1], ARGV[1]) end
local id = redis.call('XADD', KEYS[2], '*', 'event_uid', ARGV[1], 'event_type', ARGV[2], 'severity', ARGV[3], 'message', ARGV[4], 'data', ARGV[5], 'timestamp', ARGV[6])
redis.call('HSET', KEYS[1], ARGV[1], id)
redis.call('LPUSH', KEYS[3], ARGV[5])
redis.call('LTRIM', KEYS[3], 0, 999)
return id
`

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
		TotalEvents:    xp.stats.TotalEvents,
		TotalAlerts:    xp.stats.TotalAlerts,
		CriticalAlerts: xp.stats.CriticalAlerts,
		HighAlerts:     xp.stats.HighAlerts,
		MediumAlerts:   xp.stats.MediumAlerts,
		LowAlerts:      xp.stats.LowAlerts,
		EventsToday:    xp.stats.EventsToday,
		AlertsToday:    xp.stats.AlertsToday,
		TopSources:     xp.stats.TopSources,
	}

	stats.Sources = make([]string, 0, len(stats.TopSources))
	for source := range stats.TopSources {
		stats.Sources = append(stats.Sources, source)
	}
	return stats
}
