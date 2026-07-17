package security

import "strings"

var secretKeys = []string{"agent_key", "private_key", "signing_key", "jwt_secret", "password", "token", "secret", "authorization"}

func RedactMap(input map[string]interface{}) map[string]interface{} {
	output := map[string]interface{}{}
	for key, value := range input {
		if isSecretKey(key) {
			output[key] = "***REDACTED***"
			continue
		}
		output[key] = redactValue(value)
	}
	return output
}

func redactValue(value interface{}) interface{} {
	switch nested := value.(type) {
	case map[string]interface{}:
		return RedactMap(nested)
	case []interface{}:
		redacted := make([]interface{}, len(nested))
		for index, item := range nested {
			redacted[index] = redactValue(item)
		}
		return redacted
	default:
		return value
	}
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
