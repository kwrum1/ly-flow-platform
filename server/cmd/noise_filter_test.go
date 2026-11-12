package main

import "testing"

// The same benign root-cron session is reported by old agents as a generic
// component alert. It must be filtered in both shapes, while sudo/su and
// non-cron privilege-use signals stay visible.
func TestXDRIsAuthPrivilegeNoiseCoversLegacyComponentAlert(t *testing.T) {
	cases := []struct {
		name  string
		event map[string]interface{}
		want  bool
	}{
		{
			name: "legacy component alert root cron",
			event: map[string]interface{}{
				"event_type": "component.alert",
				"message":    "authentication signal detected: privilege-use",
				"severity":   "medium",
				"metadata": map[string]interface{}{
					"log_line": "2026-11-12T08:17:01+08:00 ubuntu CRON[2186911]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
				},
			},
			want: true,
		},
		{
			name: "legacy component alert cron nested in raw_event",
			event: map[string]interface{}{
				"event_type": "component.alert",
				"message":    "authentication signal detected: privilege-use",
				"severity":   "low",
				"raw_event": map[string]interface{}{
					"metadata": map[string]interface{}{
						"log_line": "CRON[42]: pam_unix(cron:session): session closed for user root",
					},
				},
			},
			want: true,
		},
		{
			name: "component alert sudo stays",
			event: map[string]interface{}{
				"event_type": "component.alert",
				"message":    "authentication signal detected: privilege-use",
				"severity":   "medium",
				"metadata": map[string]interface{}{
					"log_line": "sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
				},
			},
			want: false,
		},
		{
			name: "component alert unrelated message",
			event: map[string]interface{}{
				"event_type": "component.alert",
				"message":    "authentication signal detected: failed-auth",
				"severity":   "medium",
				"metadata": map[string]interface{}{
					"log_line": "pam_unix(cron:session): session opened for user root",
				},
			},
			want: false,
		},
		{
			name: "explicit runtime privilege event",
			event: map[string]interface{}{
				"event_type": "runtime.auth.privilege",
				"message":    "authentication signal detected: privilege-use",
				"severity":   "medium",
			},
			want: true,
		},
		{
			name: "high severity is not hidden",
			event: map[string]interface{}{
				"event_type": "component.alert",
				"message":    "authentication signal detected: privilege-use",
				"severity":   "high",
				"metadata": map[string]interface{}{
					"log_line": "CRON[42]: pam_unix(cron:session): session opened for user root",
				},
			},
			want: false,
		},
	}

	for _, testCase := range cases {
		if got := xdrEventIsAuthPrivilegeNoise(testCase.event); got != testCase.want {
			t.Fatalf("%s: got %v, want %v", testCase.name, got, testCase.want)
		}
	}
}
