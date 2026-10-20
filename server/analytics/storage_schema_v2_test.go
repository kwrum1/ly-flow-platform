package analytics

import (
	"strings"
	"testing"
)

func TestV2ClickHouseSchema(t *testing.T) {
	if !strings.Contains(clickHouseEventsV2DDL, "lyflow_events_v2") {
		t.Fatal("events v2 table missing")
	}
	if !strings.Contains(clickHouseEventsV2DDL, "PARTITION BY toDate(event_at)") {
		t.Fatal("events v2 partition key missing")
	}
	if !strings.Contains(clickHouseEventsV2DDL, "TTL toDateTime(event_at) + INTERVAL 30 DAY") {
		t.Fatal("events v2 TTL missing")
	}
	if !strings.Contains(clickHouseEvents1mDDL, "lyflow_events_1m") {
		t.Fatal("1m aggregate view missing")
	}
	if !strings.Contains(clickHouseEvents1hDDL, "lyflow_events_1h") {
		t.Fatal("1h aggregate view missing")
	}
}

func TestV2PostgresEvidenceSchema(t *testing.T) {
	if !strings.Contains(postgresEvidenceDDL, "lyflow_evidence") {
		t.Fatal("evidence table missing")
	}
	if !strings.Contains(postgresEvidenceDDL, "expires_at") {
		t.Fatal("evidence expiry missing")
	}
	if !strings.Contains(postgresIncidentEvidenceDDL, "lyflow_incident_evidence") {
		t.Fatal("incident evidence table missing")
	}
	if !strings.Contains(postgresIncidentEvidenceDDL, "ON DELETE CASCADE") {
		t.Fatal("incident evidence cleanup missing")
	}
}

func TestV2MigrationVersionsAreUnique(t *testing.T) {
	postgresSeen := map[uint64]bool{}
	for _, item := range postgresStorageMigrations {
		if postgresSeen[item.version] {
			t.Fatalf("duplicate postgres migration version %d", item.version)
		}
		postgresSeen[item.version] = true
	}
	for _, version := range []uint64{6, 7, 8, 9} {
		if !postgresSeen[version] {
			t.Fatalf("postgres migration version %d missing", version)
		}
	}

	clickHouseSeen := map[uint64]bool{}
	for _, item := range clickHouseStorageMigrations {
		if clickHouseSeen[item.version] {
			t.Fatalf("duplicate clickhouse migration version %d", item.version)
		}
		clickHouseSeen[item.version] = true
	}
	for _, version := range []uint64{4, 5, 6} {
		if !clickHouseSeen[version] {
			t.Fatalf("clickhouse migration version %d missing", version)
		}
	}
}
