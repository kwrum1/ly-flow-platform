package trustroot

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type revocationState struct {
	Revoked map[RootRole][]string `json:"revoked"`
}

func (l Layout) Revoke(role RootRole, rootFingerprint string) error {
	state, err := l.loadRevocations()
	if err != nil {
		return err
	}
	for _, existing := range state.Revoked[role] {
		if existing == rootFingerprint {
			return nil
		}
	}
	state.Revoked[role] = append(state.Revoked[role], rootFingerprint)
	contents, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("marshal root revocations: %w", err)
	}
	if err := atomicWrite(filepath.Join(l.TrustDir, "revocations.json"), contents, 0o644); err != nil {
		return fmt.Errorf("write root revocations: %w", err)
	}
	return nil
}

func (l Layout) Verify(role RootRole, payload, signature []byte) error {
	return l.VerifyAttributed(role, payload, signature, "")
}

func (l Layout) VerifyAttributed(role RootRole, payload, signature []byte, signerFingerprint string) error {
	state, err := l.loadRevocations()
	if err != nil {
		return err
	}
	foundRevoked := false
	for _, path := range []string{l.RootPath(role), l.previousRootPath(role)} {
		contents, readErr := os.ReadFile(path)
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			return fmt.Errorf("read %s root: %w", role, readErr)
		}
		publicKey, parseErr := ParsePublicRoot(contents)
		if parseErr != nil {
			return parseErr
		}
		if !ed25519.Verify(publicKey, payload, signature) {
			continue
		}
		candidateFingerprint := fingerprint(publicKey)
		if signerFingerprint != "" && signerFingerprint != candidateFingerprint {
			continue
		}
		if isRevoked(state, role, candidateFingerprint) {
			foundRevoked = true
			continue
		}
		return nil
	}
	if foundRevoked {
		return ErrRootRevoked
	}
	return ErrSignature
}

func (l Layout) loadRevocations() (revocationState, error) {
	state := revocationState{Revoked: make(map[RootRole][]string)}
	contents, err := os.ReadFile(filepath.Join(l.TrustDir, "revocations.json"))
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, fmt.Errorf("read root revocations: %w", err)
	}
	if err := json.Unmarshal(contents, &state); err != nil {
		return state, fmt.Errorf("parse root revocations: %w", err)
	}
	if state.Revoked == nil {
		state.Revoked = make(map[RootRole][]string)
	}
	return state, nil
}

func isRevoked(state revocationState, role RootRole, candidate string) bool {
	for _, revoked := range state.Revoked[role] {
		if revoked == candidate {
			return true
		}
	}
	return false
}
