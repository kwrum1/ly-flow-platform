package loganalyzer

import (
	"regexp"
	"strings"

	"github.com/lyflow/ly-flow-platform/server/unified"
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type Decoder struct {
	Name    string
	Program string
	Pattern *regexp.Regexp
	Type    string
	Level   unified.Severity
}

var BuiltinDecoders = []Decoder{
	{Name: "sshd_failed_login", Program: "sshd", Pattern: regexp.MustCompile(`(?i)(failed password|invalid user|authentication failure)`), Type: "auth.login_failed", Level: unified.SeverityHigh},
	{Name: "sshd_login_success", Program: "sshd", Pattern: regexp.MustCompile(`(?i)(accepted password|accepted publickey)`), Type: "auth.login_success", Level: unified.SeverityLow},
	{Name: "sudo_privilege", Program: "sudo", Pattern: regexp.MustCompile(`(?i)(COMMAND=|session opened|authentication failure)`), Type: "privilege.sudo", Level: unified.SeverityMedium},
	{Name: "nginx_admin_access", Program: "nginx", Pattern: regexp.MustCompile(`(?i)(/admin|/manager|/actuator|/wp-admin)`), Type: "web.admin_access", Level: unified.SeverityMedium},
}

func AnalyzeLog(log models.NormalizedLog) (unified.UnifiedEvent, bool) {
	program := strings.ToLower(log.Program)
	message := log.Raw
	if message == "" {
		message = log.Message
	}
	for _, decoder := range BuiltinDecoders {
		if decoder.Program != "" && !strings.Contains(program, decoder.Program) {
			continue
		}
		if !decoder.Pattern.MatchString(message) {
			continue
		}
		return unified.UnifiedEvent{
			ID:           log.Source + ":" + decoder.Name,
			Module:       unified.ModuleXDR,
			SourceModule: unified.ModuleRuntime,
			EventType:    decoder.Type,
			Source:       log.Source,
			Severity:     decoder.Level,
			Timestamp:    log.Timestamp,
			EntityIDs:    &unified.EntityIDs{AgentID: log.AgentID, HostID: log.Hostname, UserID: log.User},
			User:         log.User,
			BehaviorContext: &unified.BehaviorContext{Scenario: "log_analysis", Action: decoder.Type, Labels: []string{decoder.Name, log.Program}, Details: map[string]interface{}{"log_source": log.Source, "program": log.Program}},
			RawReference: &unified.RawReference{Stream: "logs:raw", MessageID: log.Source},
			Status:       unified.StatusNew,
		}, true
	}
	return unified.UnifiedEvent{}, false
}
