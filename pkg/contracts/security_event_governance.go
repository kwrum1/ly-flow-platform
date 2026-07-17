package contracts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var ErrGovernanceDenied = errors.New("governance authorization denied")

type GovernanceRole string

const (
	RoleViewer        GovernanceRole = "viewer"
	RoleAnalyst       GovernanceRole = "analyst"
	RoleSecurityAdmin GovernanceRole = "security_admin"
	RolePrivacyAdmin  GovernanceRole = "privacy_admin"
)

type GovernanceAction string

const (
	GovernanceRead   GovernanceAction = "read"
	GovernanceExport GovernanceAction = "export"
	GovernanceDelete GovernanceAction = "delete"
)

var governedSecretKeys = []string{"agent_key", "authorization", "credential", "jwt", "password", "private_key", "secret", "signing_key", "token"}

func RedactJSON(input json.RawMessage) (json.RawMessage, []string, error) {
	if len(input) == 0 {
		return json.RawMessage(`{}`), []string{}, nil
	}
	var value json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(input))
	if err := decoder.Decode(&value); err != nil {
		return nil, nil, fmt.Errorf("decode governed payload: %w", err)
	}
	redacted, fields, err := redactRaw(value, "")
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(fields)
	return redacted, fields, nil
}

func AuthorizeGovernance(event CanonicalSecurityEvent, role GovernanceRole, action GovernanceAction) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("authorize governed event: %w", err)
	}
	switch action {
	case GovernanceRead:
		if role == RoleAnalyst || role == RoleSecurityAdmin || role == RolePrivacyAdmin {
			return nil
		}
	case GovernanceExport:
		if role == RoleSecurityAdmin || role == RolePrivacyAdmin {
			return nil
		}
	case GovernanceDelete:
		if role == RolePrivacyAdmin {
			return nil
		}
	}
	return fmt.Errorf("role %s cannot %s event %s: %w", role, action, event.EventUID, ErrGovernanceDenied)
}

func redactRaw(input json.RawMessage, path string) (json.RawMessage, []string, error) {
	trimmed := bytes.TrimSpace(input)
	if len(trimmed) == 0 {
		return json.RawMessage("null"), nil, nil
	}
	switch trimmed[0] {
	case '{':
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return nil, nil, fmt.Errorf("decode governed object: %w", err)
		}
		fields := make([]string, 0)
		for key, value := range object {
			fieldPath := key
			if path != "" {
				fieldPath = path + "." + key
			}
			if isGovernedSecretKey(key) {
				object[key] = json.RawMessage(`"` + RedactedValue + `"`)
				fields = append(fields, fieldPath)
				continue
			}
			updated, nested, err := redactRaw(value, fieldPath)
			if err != nil {
				return nil, nil, err
			}
			object[key] = updated
			fields = append(fields, nested...)
		}
		encoded, err := json.Marshal(object)
		return encoded, fields, err
	case '[':
		var array []json.RawMessage
		if err := json.Unmarshal(trimmed, &array); err != nil {
			return nil, nil, fmt.Errorf("decode governed array: %w", err)
		}
		fields := make([]string, 0)
		for index, value := range array {
			updated, nested, err := redactRaw(value, fmt.Sprintf("%s[%d]", path, index))
			if err != nil {
				return nil, nil, err
			}
			array[index] = updated
			fields = append(fields, nested...)
		}
		encoded, err := json.Marshal(array)
		return encoded, fields, err
	default:
		return append(json.RawMessage(nil), trimmed...), nil, nil
	}
}

func isGovernedSecretKey(key string) bool {
	lower := strings.ToLower(key)
	for _, secret := range governedSecretKeys {
		if strings.Contains(lower, secret) {
			return true
		}
	}
	return false
}
