package security

import "strings"

var secretKeys = []string{"agent_key", "jwt_secret", "password", "token", "secret", "authorization"}

func RedactMap(input map[string]interface{}) map[string]interface{} {
	output := map[string]interface{}{}
	for key, value := range input {
		if isSecretKey(key) {
			output[key] = "***REDACTED***"
			continue
		}
		if nested, ok := value.(map[string]interface{}); ok {
			output[key] = RedactMap(nested)
			continue
		}
		output[key] = value
	}
	return output
}

func isSecretKey(key string) bool {
	lower := strings.ToLower(key)
	for _, token := range secretKeys {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

type AuditEntry struct {
	Actor    string `json:"actor"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
	Result   string `json:"result"`
}

func ValidateAudit(entry AuditEntry) bool {
	return entry.Actor != "" && entry.Action != "" && entry.Resource != "" && entry.Result != ""
}
