package transportreliability

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type DeadLetterReason string

const (
	ReasonInvalidPayload  DeadLetterReason = "invalid_payload"
	ReasonHandlerRejected DeadLetterReason = "handler_rejected"
	ReasonRetryExhausted  DeadLetterReason = "retry_exhausted"
)

var ErrInvalidDeadLetterReason = errors.New("invalid dead-letter reason")

type permanentError struct {
	reason DeadLetterReason
	cause  error
}

func ParseDeadLetterReason(value string) (DeadLetterReason, error) {
	switch DeadLetterReason(value) {
	case ReasonInvalidPayload:
		return ReasonInvalidPayload, nil
	case ReasonHandlerRejected:
		return ReasonHandlerRejected, nil
	case ReasonRetryExhausted:
		return ReasonRetryExhausted, nil
	default:
		return "", fmt.Errorf("%q: %w", value, ErrInvalidDeadLetterReason)
	}
}

func (failure *permanentError) Error() string {
	return string(failure.reason) + ": " + failure.cause.Error()
}

func (failure *permanentError) Unwrap() error {
	return failure.cause
}

func Permanent(reason DeadLetterReason, cause error) error {
	parsed, err := ParseDeadLetterReason(string(reason))
	if err != nil {
		return err
	}
	if cause == nil {
		cause = errors.New("permanent delivery failure")
	}
	return &permanentError{reason: parsed, cause: cause}
}

func (consumer *RedisConsumer) deadLetter(ctx context.Context, delivery Delivery, reason DeadLetterReason, cause error) error {
	parsed, err := ParseDeadLetterReason(string(reason))
	if err != nil {
		return err
	}
	payload, err := json.Marshal(delivery.Values)
	if err != nil {
		return fmt.Errorf("encode dead letter payload: %w", err)
	}
	values := map[string]interface{}{
		"source_stream": delivery.Stream, "source_message_id": delivery.MessageID,
		"reason": string(parsed), "detail": cause.Error(), "payload": string(payload),
		"created_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	uid := DeterministicUID("deadletter", delivery.Stream, delivery.MessageID)
	if err := consumer.client.Eval(ctx, deadLetterScript, []string{"transport_reliability:deadletter_index", "deadletter:" + delivery.Stream},
		uid, values["source_stream"], values["source_message_id"], values["reason"], values["detail"], values["payload"], values["created_at"],
	).Err(); err != nil {
		return fmt.Errorf("persist dead letter: %w", err)
	}
	return nil
}

const deadLetterScript = `
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then return redis.call('HGET', KEYS[1], ARGV[1]) end
local id = redis.call('XADD', KEYS[2], '*', 'deadletter_uid', ARGV[1], 'source_stream', ARGV[2], 'source_message_id', ARGV[3], 'reason', ARGV[4], 'detail', ARGV[5], 'payload', ARGV[6], 'created_at', ARGV[7])
redis.call('HSET', KEYS[1], ARGV[1], id)
return id
`
