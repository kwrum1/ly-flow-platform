package main

import "testing"

func TestRASPBridgePayloadNormalizesHookFields(t *testing.T) {
	payload := map[string]interface{}{
		"db_query":        "select * from users union select password",
		"process_command": "id",
		"filename":        "/etc/passwd",
		"request_url":     "http://169.254.169.254/latest/meta-data",
	}
	normalizeRASPBridgePayload(payload)
	for _, key := range []string{"query", "command", "cmdline", "path", "url", "payload", "message"} {
		if payload[key] == "" || payload[key] == nil {
			t.Fatalf("%s not normalized: %#v", key, payload)
		}
	}
}
