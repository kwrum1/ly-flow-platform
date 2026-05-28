package decoder

import (
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

var decoders = make(map[string]Decoder)

type Decoder interface {
	Name() string
	Decode(line string) (*models.NormalizedLog, error)
}

func Register(name string, d Decoder) {
	decoders[name] = d
}

func GetDecoder(name string) Decoder {
	return decoders[name]
}

func InitDecoders() {
	Register("sshd", NewSSHDecoder())
	Register("nginx", NewNginxDecoder())
	Register("nginx_error", NewNginxErrorDecoder())
	Register("mysql", NewMySQLDecoder())
	Register("mysql_slow", NewMySQLSlowLogDecoder())
	Register("systemd", NewSystemdDecoder())
	Register("pam", NewPAMDecoder())
	Register("auditd", NewAuditdDecoder())
}

func Decode(source, line string) (*models.NormalizedLog, error) {
	d := GetDecoder(source)
	if d == nil {
		d = GetDecoder("systemd")
	}
	if d == nil {
		log := models.NewNormalizedLog()
		log.Source = source
		log.Message = line
		log.Raw = line
		return log, nil
	}
	return d.Decode(line)
}

func DetectSource(line string) string {
	if contains(line, "sshd") {
		return "sshd"
	}
	if contains(line, "nginx") || contains(line, "GET ") || contains(line, "POST ") {
		return "nginx"
	}
	if contains(line, "mysqld") || contains(line, "MySQL") || contains(line, "mariadb") {
		return "mysql"
	}
	if contains(line, "systemd") || contains(line, "journald") {
		return "systemd"
	}
	if contains(line, "pam_") || contains(line, "PAM:") {
		return "pam"
	}
	if contains(line, "type=") && contains(line, "audit") {
		return "auditd"
	}
	return "systemd"
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
