package ops

import "testing"

func TestDeadLetterRecordRequiresReason(t *testing.T) {
	if _, err := NewDeadLetterRecord("alerts:runtime", "1-0", "", "{}"); err == nil {
		t.Fatal("expected validation error")
	}
	record, err := NewDeadLetterRecord("alerts:runtime", "1-0", "invalid_json", "{")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if record.Stream != "alerts:runtime" || DeadLetterStream(record.Stream) != "deadletter:alerts:runtime" {
		t.Fatalf("unexpected record: %#v", record)
	}
}

func TestHealthSnapshotHealthy(t *testing.T) {
	if !((HealthSnapshot{ConsumerErrors: map[string]int64{}, ClickHouseBacklog: 0, PolicyDrift: 0}).Healthy()) {
		t.Fatal("expected healthy snapshot")
	}
	if (HealthSnapshot{ConsumerErrors: map[string]int64{"xdr": 1}}).Healthy() {
		t.Fatal("expected unhealthy snapshot")
	}
}
