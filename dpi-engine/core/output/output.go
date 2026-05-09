package output

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	batchSize   = 100
	flushPeriod = 1 * time.Second
)

// Alert represents a DPI alert
type Alert struct {
	ID        uint64    `json:"id"`
	Timestamp string    `json:"timestamp"`
	Type      string    `json:"type"`
	SrcIP     string    `json:"src_ip"`
	DstIP     string    `json:"dst_ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Protocol  string    `json:"protocol"`
	Signature string    `json:"signature"`
	Category  string    `json:"category"`
	Severity  uint8     `json:"severity"`
	Score     int       `json:"score"`
	Status    string    `json:"status"`
	SensorID  string    `json:"sensor_id"`
	Domain    string    `json:"domain,omitempty"`
}

// Output handles alert output to Redis Stream
type Output struct {
	client    *redis.Client
	stream    string
	ctx       context.Context
	mu        sync.Mutex
	queue     []*Alert
	wg        sync.WaitGroup
	running   atomic.Bool
	stats     struct{ Sent uint64; Errors uint64 }
}

// New creates a new output handler
func New(client *redis.Client, stream string) *Output {
	return &Output{
		client: client,
		stream: stream,
		ctx:    context.Background(),
		queue:  make([]*Alert, 0, batchSize),
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

	pipe := o.client.Pipeline()
	for _, alert := range alerts {
		data, _ := json.Marshal(alert)
		pipe.XAdd(o.ctx, &redis.XAddArgs{
			Stream: o.stream,
			MaxLen: 10000,
			Approx: true,
			Values: map[string]interface{}{
				"type": "dpi_alert",
				"data": string(data),
			},
		})
	}

	_, err := pipe.Exec(o.ctx)
	if err != nil {
		atomic.AddUint64(&o.stats.Errors, uint64(len(alerts)))
		log.Printf("[output] Batch error: %v", err)
		return
	}

	atomic.AddUint64(&o.stats.Sent, uint64(len(alerts)))
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
	data, err := json.Marshal(alert)
	if err != nil {
		atomic.AddUint64(&o.stats.Errors, 1)
		return err
	}

	err = o.client.XAdd(o.ctx, &redis.XAddArgs{
		Stream: o.stream,
		MaxLen: 10000,
		Approx: true,
		Values: map[string]interface{}{
			"type": "dpi_alert",
			"data": string(data),
		},
	}).Err()

	if err == nil {
		atomic.AddUint64(&o.stats.Sent, 1)
	} else {
		atomic.AddUint64(&o.stats.Errors, 1)
	}
	return err
}

// Stats returns output statistics
func (o *Output) Stats() (sent, errors uint64) {
	return atomic.LoadUint64(&o.stats.Sent),
		atomic.LoadUint64(&o.stats.Errors)
}