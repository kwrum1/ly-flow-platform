package loganalyzer

import (
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

func TestAnalyzeLogDetectsSSHFailure(t *testing.T) {
	event, ok := AnalyzeLog(models.NormalizedLog{Timestamp: time.Unix(1, 0), AgentID: "agent-1", Hostname: "host-1", Source: "auth.log", Program: "sshd", Message: "Failed password for invalid user admin from 10.0.0.1"})
	if !ok {
		t.Fatal("expected ssh failure event")
	}
	if event.EventType != "auth.login_failed" || event.EntityIDs.AgentID != "agent-1" || event.RawReference.Stream != "logs:raw" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestAnalyzeLogIgnoresUnmatchedLine(t *testing.T) {
	if _, ok := AnalyzeLog(models.NormalizedLog{Program: "cron", Message: "normal job completed"}); ok {
		t.Fatal("did not expect event for unmatched log")
	}
}
