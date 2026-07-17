package ops

import (
	"fmt"
	"time"

	transport "github.com/lyflow/ly-flow-platform/transportreliability"
)

type DeadLetterRecord struct {
	Stream    string                     `json:"stream"`
	MessageID string                     `json:"message_id"`
	Reason    transport.DeadLetterReason `json:"reason"`
	Payload   string                     `json:"payload"`
	CreatedAt time.Time                  `json:"created_at"`
}

func DeadLetterStream(source string) string {
	if source == "" {
		return "deadletter:unknown"
	}
	return fmt.Sprintf("deadletter:%s", source)
}

func NewDeadLetterRecord(stream, messageID, reason, payload string) (DeadLetterRecord, error) {
	if stream == "" {
		return DeadLetterRecord{}, fmt.Errorf("stream and reason are required")
	}
	parsed, err := transport.ParseDeadLetterReason(reason)
	if err != nil {
		return DeadLetterRecord{}, err
	}
	return DeadLetterRecord{Stream: stream, MessageID: messageID, Reason: parsed, Payload: payload, CreatedAt: time.Now().UTC()}, nil
}

type HealthSnapshot struct {
	StreamLag         map[string]int64   `json:"stream_lag"`
	ConsumerErrors    map[string]int64   `json:"consumer_errors"`
	AnalyzerRate      map[string]float64 `json:"analyzer_rate"`
	ClickHouseBacklog int64              `json:"clickhouse_backlog"`
	PolicyDrift       int64              `json:"policy_drift"`
	DeadLetters       map[string]int64   `json:"dead_letters"`
}

func (h HealthSnapshot) Healthy() bool {
	return h.ClickHouseBacklog == 0 && h.PolicyDrift == 0 && sumInt64(h.ConsumerErrors) == 0
}

func sumInt64(values map[string]int64) int64 {
	var total int64
	for _, value := range values {
		total += value
	}
	return total
}
