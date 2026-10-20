package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const signedDigestSchemaVersion = "lyflow.signed_digest.v1"

var (
	errAgentBinaryIntegrity = errors.New("agent binary integrity verification failed")
	errAgentConfigIntegrity = errors.New("agent configuration integrity verification failed")
)

type signedDigestPayload struct {
	SchemaVersion     string `json:"schema_version"`
	Artifact          string `json:"artifact"`
	Digest            string `json:"digest"`
	SignerFingerprint string `json:"signer_fingerprint"`
}

func (payload signedDigestPayload) bytes() []byte {
	encoded, _ := json.Marshal(payload)
	return encoded
}

type signedDigestEnvelope struct {
	Payload   signedDigestPayload `json:"payload"`
	Signature string              `json:"signature"`
}

func (a *Agent) verifyAgentStartupIntegrity(ctx context.Context, executablePath string) error {
	a.cfgMu.RLock()
	required := a.cfg.RequireAgentIntegrity
	digestPath := a.cfg.AgentBinaryDigestPath
	rootPath := a.cfg.AgentBinaryRootPath
	configPath := a.cfg.AgentConfigPath
	configSignaturePath := a.cfg.AgentConfigSignaturePath
	configRootPath := a.cfg.AgentConfigRootPath
	configRequired := a.cfg.RequireConfigIntegrity
	a.cfgMu.RUnlock()
	if !required && !configRequired && strings.TrimSpace(digestPath) == "" && strings.TrimSpace(configSignaturePath) == "" {
		return nil
	}
	if required {
		if strings.TrimSpace(executablePath) == "" {
			executablePath = os.Getenv("AGENT_BINARY_PATH")
		}
		if strings.TrimSpace(executablePath) == "" {
			resolved, err := os.Executable()
			if err != nil {
				return a.failClosedIntegrity("binary_integrity_failed", fmt.Errorf("resolve current executable: %w", err))
			}
			executablePath = resolved
		}
		if err := verifySignedArtifactIntegrity(ctx, executablePath, digestPath, rootPath, errAgentBinaryIntegrity); err != nil {
			return a.failClosedIntegrity("binary_integrity_failed", err)
		}
	}
	if configRequired {
		if strings.TrimSpace(configPath) == "" {
			configPath = resolveConfigPath(os.Args[1:])
		}
		if err := verifySignedConfigIntegrity(ctx, configPath, configSignaturePath, firstNonEmpty(configRootPath, rootPath)); err != nil {
			return a.failClosedIntegrity("signed_config_integrity_failed", err)
		}
	}
	return nil
}

func (a *Agent) failClosedIntegrity(reason string, cause error) error {
	healthErr := a.propagateControlHealth(a.runtimeHealth.Degrade(reason, true))
	return fmt.Errorf("%s: %w", reason, errors.Join(cause, healthErr))
}

func (a *Agent) disablePrevention() {
	a.cfgMu.Lock()
	a.cfg.RASPEnabled = false
	a.cfg.RASPMode = "off"
	a.cfg.RASPBlockOnHit = false
	a.cfgMu.Unlock()
	a.setRuntimePreventionEnabled(false)
}

func (a *Agent) propagateControlHealth(snapshot runtimeControlHealthSnapshot) error {
	if !snapshot.PreventionEnabled {
		a.disablePrevention()
	}
	return a.publishControlHealth(snapshot)
}

func (a *Agent) handleControlHealth(snapshot runtimeControlHealthSnapshot) {
	if err := a.propagateControlHealth(snapshot); err != nil {
		fmt.Printf("[runtime] control health publish failed: %v\n", err)
	}
}

func verifySignedConfigIntegrity(ctx context.Context, configPath, signaturePath, rootPath string) error {
	return verifySignedArtifactIntegrity(ctx, configPath, signaturePath, rootPath, errAgentConfigIntegrity)
}

func verifySignedArtifactIntegrity(ctx context.Context, artifactPath, signaturePath, rootPath string, failure error) error {
	if strings.TrimSpace(artifactPath) == "" || strings.TrimSpace(signaturePath) == "" || strings.TrimSpace(rootPath) == "" {
		return fmt.Errorf("integrity paths are required: %w", failure)
	}
	envelope, err := readSignedDigestEnvelope(signaturePath)
	if err != nil {
		return fmt.Errorf("read signed digest: %w: %v", failure, err)
	}
	if envelope.Payload.SchemaVersion != signedDigestSchemaVersion || envelope.Payload.Artifact == "" || envelope.Payload.Digest == "" || envelope.Payload.SignerFingerprint == "" {
		return fmt.Errorf("signed digest payload invalid: %w", failure)
	}
	if filepath.Base(filepath.Clean(envelope.Payload.Artifact)) != filepath.Base(filepath.Clean(artifactPath)) {
		return fmt.Errorf("signed digest artifact mismatch: %w", failure)
	}
	expected, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(envelope.Payload.Digest)))
	if err != nil || len(expected) != 32 {
		return fmt.Errorf("signed digest encoding invalid: %w", failure)
	}
	publicKey, err := loadPolicyRoot(rootPath)
	if err != nil {
		return fmt.Errorf("load integrity root: %w: %v", failure, err)
	}
	if envelope.Payload.SignerFingerprint != policyRootFingerprint(publicKey) {
		return fmt.Errorf("integrity signer fingerprint mismatch: %w", failure)
	}
	signature, err := hex.DecodeString(strings.TrimSpace(envelope.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, envelope.Payload.bytes(), signature) {
		return fmt.Errorf("integrity signature invalid: %w", failure)
	}
	actual, err := streamSHA256(ctx, artifactPath)
	if err != nil {
		return fmt.Errorf("hash integrity artifact: %w: %v", failure, err)
	}
	if !equalBytes(actual, expected) {
		return fmt.Errorf("integrity digest mismatch: %w", failure)
	}
	return nil
}

func readSignedDigestEnvelope(path string) (signedDigestEnvelope, error) {
	file, err := os.Open(path)
	if err != nil {
		return signedDigestEnvelope{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	var envelope signedDigestEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return signedDigestEnvelope{}, err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return signedDigestEnvelope{}, errors.New("signed digest contains trailing data")
		}
		return signedDigestEnvelope{}, err
	}
	return envelope, nil
}

func streamSHA256(ctx context.Context, path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		read, readErr := file.Read(buffer)
		if read > 0 {
			_, _ = hash.Write(buffer[:read])
		}
		if errors.Is(readErr, io.EOF) {
			return hash.Sum(nil), nil
		}
		if readErr != nil {
			return nil, readErr
		}
	}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare(left, right) == 1
}
