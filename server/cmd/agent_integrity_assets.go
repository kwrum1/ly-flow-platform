package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

// serveAgentBinaryDigest returns a signed digest envelope for the installed
// Linux agent. The signing key is the platform policy signer, whose public
// root is already served to agents at /api/v1/agent/rasp/policy-root.
func serveAgentBinaryDigest(w http.ResponseWriter, targetArch string) {
	targetArch = strings.ToLower(strings.TrimSpace(targetArch))
	if targetArch == "" {
		targetArch = "amd64"
	}
	if targetArch != "amd64" && targetArch != "arm64" {
		http.Error(w, "unsupported agent arch", http.StatusBadRequest)
		return
	}

	layout := trustroot.Layout{
		TrustDir: getEnv("POLICY_TRUST_DIR", "/var/lib/lyflow/policy/trust"),
		KeyDir:   getEnv("POLICY_KEY_DIR", "/var/lib/lyflow/policy/keys"),
	}
	signer, err := layout.LoadSigner(trustroot.PolicySigner)
	if err != nil {
		http.Error(w, "agent integrity signer unavailable", http.StatusServiceUnavailable)
		return
	}

	var binaryPath string
	for _, candidate := range agentBinaryCandidates("linux", targetArch) {
		if info, statErr := os.Stat(candidate); statErr == nil && info.Mode().IsRegular() {
			binaryPath = candidate
			break
		}
	}
	if binaryPath == "" {
		http.Error(w, "agent binary not found", http.StatusNotFound)
		return
	}
	contents, err := os.ReadFile(binaryPath)
	if err != nil {
		http.Error(w, "agent binary unreadable", http.StatusInternalServerError)
		return
	}
	digest := sha256.Sum256(contents)
	payload := struct {
		SchemaVersion     string `json:"schema_version"`
		Artifact          string `json:"artifact"`
		Digest            string `json:"digest"`
		SignerFingerprint string `json:"signer_fingerprint"`
	}{
		SchemaVersion:     "lyflow.signed_digest.v1",
		Artifact:          "ly-agent",
		Digest:            hex.EncodeToString(digest[:]),
		SignerFingerprint: signer.Fingerprint(),
	}
	encodedPayload, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "agent digest encoding failed", http.StatusInternalServerError)
		return
	}
	envelope := struct {
		Payload   interface{} `json:"payload"`
		Signature string      `json:"signature"`
	}{
		Payload:   payload,
		Signature: hex.EncodeToString(signer.Sign(encodedPayload)),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(envelope)
}
