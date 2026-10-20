package main

import "testing"

func TestParseAuditdExec(t *testing.T) {
	line := `type=SYSCALL msg=audit(1792499000.123:456): arch=c000003e syscall=59 success=yes exit=0 comm="curl" exe="/usr/bin/curl" pid=4242`
	event, ok := parseAuditdExec(line)
	if !ok {
		t.Fatal("expected auditd exec line to parse")
	}
	if event.Command != "curl" || event.Exe != "/usr/bin/curl" || event.PID != 4242 {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestParseAuditdExecIgnoresNonExec(t *testing.T) {
	if _, ok := parseAuditdExec(`type=USER_LOGIN msg=audit(1792499000.123:1): pid=1 uid=0`); ok {
		t.Fatal("non-exec audit record must be ignored")
	}
}
