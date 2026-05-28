package webhook

import (
	"strings"
	"testing"
)

func TestFormatWeComIncidentMarkdown(t *testing.T) {
	msg := FormatWeComIncidentMarkdown(IncidentNotification{ID: "inc-1", Title: "multi-stage", Severity: "critical", Status: "open", Asset: "host-1", Action: "temporary_block", DetailURL: "http://ly/incidents/inc-1"})
	if msg.MsgType != "markdown" || msg.Markdown == nil {
		t.Fatalf("expected markdown message: %#v", msg)
	}
	if !strings.Contains(msg.Markdown.Content, "inc-1") || !strings.Contains(msg.Markdown.Content, "temporary_block") {
		t.Fatalf("message missing incident fields: %s", msg.Markdown.Content)
	}
}
