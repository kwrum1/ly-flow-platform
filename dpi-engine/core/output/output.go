package output

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	"ly-flow-platform/dpi-engine/model"
)

const (
	batchSize   = 100
	flushPeriod = 1 * time.Second
)

// Alert represents a DPI alert
type Alert struct {
	ID        uint64 `json:"id"`
	Timestamp string `json:"timestamp"`
	Type      string `json:"type"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   uint16 `json:"src_port"`
	DstPort   uint16 `json:"dst_port"`
	Protocol  string `json:"protocol"`
	Signature string `json:"signature"`
	Category  string `json:"category"`
	Severity  uint8  `json:"severity"`
	Score     int    `json:"score"`
	Status    string `json:"status"`
	SensorID  string `json:"sensor_id"`
	Domain    string `json:"domain,omitempty"`
	Data      string `json:"data,omitempty"`
}

// Output handles alert output to Redis Stream
type Output struct {
	client         *redis.Client
	stream         string
	semanticStream string
	sessionStream  string
	ctx            context.Context
	mu             sync.Mutex
	queue          []*Alert
	wg             sync.WaitGroup
	running        atomic.Bool
	stats          struct {
		Sent   uint64
		Errors uint64
	}
}

// New creates a new output handler
func New(client *redis.Client, stream string) *Output {
	return NewWithStreams(client, stream, "flows:semantic", "sessions:semantic")
}

func NewWithStreams(client *redis.Client, alertStream, semanticStream, sessionStream string) *Output {
	return &Output{
		client:         client,
		stream:         alertStream,
		semanticStream: semanticStream,
		sessionStream:  sessionStream,
		ctx:            context.Background(),
		queue:          make([]*Alert, 0, batchSize),
	}
}

// Start begins the output worker
func (o *Output) Start() {
	if !o.running.CompareAndSwap(false, true) {
		return
	}

	o.wg.Add(1)
	go o.worker()
	log.Printf("[output] Started, stream: %s", o.stream)
}

// Stop gracefully stops the output worker
func (o *Output) Stop() {
	if !o.running.CompareAndSwap(true, false) {
		return
	}

	o.flush()

	o.wg.Wait()
	log.Println("[output] Stopped")
}

func (o *Output) worker() {
	defer o.wg.Done()

	ticker := time.NewTicker(flushPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-o.ctx.Done():
			o.flush()
			return
		case <-ticker.C:
			o.flush()
		}
	}
}

func (o *Output) flush() {
	o.mu.Lock()
	if len(o.queue) == 0 {
		o.mu.Unlock()
		return
	}

	alerts := o.queue
	o.queue = make([]*Alert, 0, batchSize)
	o.mu.Unlock()

	failed := make([]*Alert, 0)
	for _, alert := range alerts {
		if err := o.sendJSONToStream(o.stream, "dpi_alert", alert); err != nil {
			failed = append(failed, alert)
		}
	}
	if len(failed) > 0 {
		o.mu.Lock()
		o.queue = append(failed, o.queue...)
		o.mu.Unlock()
		log.Printf("[output] durable handoff paused for %d alerts", len(failed))
	}
}

// SendAlert queues an alert for output (accepts model.Alert)
func (o *Output) SendAlert(alert *model.Alert) {
	o.mu.Lock()
	defer o.mu.Unlock()

	outAlert := &Alert{
		ID:        uint64(alert.Timestamp.UnixNano()),
		Timestamp: alert.Timestamp.Format(time.RFC3339),
		Type:      alert.Type,
		SrcIP:     alert.SrcIP,
		DstIP:     alert.DstIP,
		SrcPort:   alert.SrcPort,
		DstPort:   alert.DstPort,
		Protocol:  alert.Protocol,
		Signature: alert.Signature,
		Category:  alert.Category,
		Severity:  alert.Severity,
		Score:     alert.Score,
		Status:    alert.Status,
		SensorID:  alert.SensorID,
		Domain:    alert.Domain,
	}

	o.queue = append(o.queue, outAlert)
	if len(o.queue) >= batchSize {
		go o.flush()
	}
}

// Send queues an alert for output
func (o *Output) Send(alert *Alert) {
	o.mu.Lock()
	o.queue = append(o.queue, alert)
	shouldFlush := len(o.queue) >= batchSize
	o.mu.Unlock()

	if shouldFlush {
		o.flush()
	}
}

// SendDirect sends an alert immediately (bypass queue)
func (o *Output) SendDirect(alert *Alert) error {
	return o.sendJSONToStream(o.stream, "dpi_alert", alert)
}

func (o *Output) SendSemanticFlow(flow *model.SemanticFlow) error {
	if flow == nil {
		return nil
	}
	return o.sendJSONToStream(o.semanticStream, "semantic_flow", flow)
}

func (o *Output) SendSemanticSession(session *model.SemanticSession) error {
	if session == nil {
		return nil
	}
	return o.sendJSONToStream(o.sessionStream, "semantic_session", session)
}

func (o *Output) sendJSONToStream(stream, payloadType string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		atomic.AddUint64(&o.stats.Errors, 1)
		return err
	}

	sum := sha256.Sum256(append([]byte(stream+"\x00"+payloadType+"\x00"), data...))
	uid := "dpi-" + hex.EncodeToString(sum[:16])
	err = o.client.Eval(o.ctx, idempotentOutputScript, []string{"transport_reliability:dpi_outputs", stream}, uid, payloadType, string(data)).Err()
	if err == nil {
		atomic.AddUint64(&o.stats.Sent, 1)
	} else {
		atomic.AddUint64(&o.stats.Errors, 1)
	}
	return err
}

const idempotentOutputScript = `
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then return redis.call('HGET', KEYS[1], ARGV[1]) end
local id = redis.call('XADD', KEYS[2], '*', 'event_uid', ARGV[1], 'type', ARGV[2], 'data', ARGV[3])
redis.call('HSET', KEYS[1], ARGV[1], id)
return id
`

// Stats returns output statistics
func (o *Output) Stats() (sent, errors uint64) {
	return atomic.LoadUint64(&o.stats.Sent),
		atomic.LoadUint64(&o.stats.Errors)
}
