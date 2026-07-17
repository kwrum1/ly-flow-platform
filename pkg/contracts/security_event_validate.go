package contracts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

func validateCanonicalMetadata(event CanonicalSecurityEvent) error {
	if event.Provenance.NativeSchema == "" || event.Provenance.NativeEventID == "" || event.Provenance.Adapter == "" {
		return errors.New("security event: provenance metadata required")
	}
	digest, err := hex.DecodeString(event.Provenance.PayloadSHA256)
	if err != nil || len(digest) != 32 {
		return errors.New("security event: provenance digest invalid")
	}
	if event.Attack.Version != AttackMappingVersion {
		return errors.New("security event: ATT&CK version invalid")
	}
	if err := validateAttackTacticID(event.Attack.TacticID); err != nil {
		return err
	}
	if err := validateAttackTechniqueID(event.Attack.TechniqueID); err != nil {
		return err
	}
	if len(event.QualityFlags) == 0 {
		return ErrInvalidEnum
	}
	seen := make(map[QualityFlag]struct{}, len(event.QualityFlags))
	for _, flag := range event.QualityFlags {
		if !isKnownQualityFlag(flag) {
			return ErrInvalidEnum
		}
		if _, exists := seen[flag]; exists {
			return errors.New("security event: duplicate quality flag")
		}
		seen[flag] = struct{}{}
	}
	return nil
}

func isKnownQualityFlag(flag QualityFlag) bool {
	switch flag {
	case QualityNormalized, QualityPrincipalBound, QualityLegacyAdapted:
		return true
	default:
		return false
	}
}

func validateCanonicalPayloadGovernance(payload json.RawMessage, declared []string) error {
	if len(payload) == 0 || !json.Valid(payload) {
		return ErrInvalidField
	}
	redacted, paths, err := RedactJSON(payload)
	if err != nil {
		return errors.Join(ErrInvalidField, err)
	}
	if !bytes.Equal(compactJSON(payload), compactJSON(redacted)) {
		return errors.Join(ErrInvalidField, errors.New("security event: governed secret is not redacted"))
	}
	expected := append([]string(nil), declared...)
	sort.Strings(expected)
	if !equalStrings(paths, expected) {
		return errors.New("security event: redaction metadata does not match payload")
	}
	return nil
}

func compactJSON(value []byte) []byte {
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, value); err != nil {
		return nil
	}
	return buffer.Bytes()
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
