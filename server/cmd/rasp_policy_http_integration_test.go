package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
	"github.com/lyflow/ly-flow-platform/server/agentpolicy"
	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

func TestAgentConfigHTTP_assigns_signed_policy_and_persists_ack(t *testing.T) {
	// Given
	dsn := os.Getenv("LYFLOW_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("LYFLOW_TEST_POSTGRES_DSN is required for real policy HTTP QA")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `DROP TABLE IF EXISTS rasp_policy_audit,rasp_policy_assignments,rasp_policy_versions,agents CASCADE`); err != nil {
		t.Fatalf("reset tables: %v", err)
	}
	if _, err := pool.Exec(ctx, `CREATE TABLE agents (uuid TEXT PRIMARY KEY,agent_key TEXT,traffic_enabled BOOLEAN,hids_enabled BOOLEAN,rasp_enabled BOOLEAN); INSERT INTO agents VALUES ('agent-http','agent-key',false,false,true)`); err != nil {
		t.Fatalf("create agent fixture: %v", err)
	}
	store := agentpolicy.NewPostgresStore(pool)
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("ensure policy schema: %v", err)
	}
	base := t.TempDir()
	layout := trustroot.Layout{TrustDir: filepath.Join(base, "trust"), KeyDir: filepath.Join(base, "keys")}
	if err := layout.Bootstrap(rand.Reader); err != nil {
		t.Fatalf("bootstrap roots: %v", err)
	}
	signer, err := layout.LoadSigner(trustroot.PolicySigner)
	if err != nil {
		t.Fatalf("load signer: %v", err)
	}
	manager := agentpolicy.NewManager(agentpolicy.ManagerConfig{Store: store, Signer: signer, Verifier: layout, Now: time.Now})
	if _, err := manager.EnsureDefault(ctx, "platform-owner", "audit://http/default"); err != nil {
		t.Fatalf("ensure default: %v", err)
	}
	handler := agentConfigHandler(&Config{DBPool: pool, RASPPolicy: manager})

	// When
	capabilities := map[string]interface{}{"rasp_probe_manager": map[string]interface{}{"languages": []string{"python"}}}
	first := postAgentConfig(t, handler, map[string]interface{}{"agent_id": "agent-http", "agent_key": "agent-key", "capabilities": capabilities})
	payload, err := shared.CanonicalBytes(first.Policy, first.SignerFingerprint)
	if err != nil {
		t.Fatalf("canonicalize assigned policy: %v", err)
	}
	signature, err := hex.DecodeString(first.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if err := layout.Verify(trustroot.PolicyRoot, payload, signature); err != nil {
		t.Fatalf("verify live assignment: %v", err)
	}
	postAgentConfig(t, handler, map[string]interface{}{
		"agent_id": "agent-http", "agent_key": "agent-key",
		"ack_policy_version": first.Policy.Version, "ack_policy_signature": first.Signature, "capabilities": capabilities,
	})

	// Then
	assignment, err := store.Assignment(ctx, "agent-http")
	if err != nil {
		t.Fatalf("load assignment: %v", err)
	}
	if assignment.ACKVersion != first.Policy.Version || assignment.ACKSignature != first.Signature {
		t.Fatalf("persisted ack = version %d signature %q", assignment.ACKVersion, assignment.ACKSignature)
	}
}

func postAgentConfig(t *testing.T, handler http.Handler, request map[string]interface{}) shared.SignedPolicy {
	t.Helper()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/agent/config", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Data struct {
			Policy shared.SignedPolicy `json:"rasp_policy"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return response.Data.Policy
}
