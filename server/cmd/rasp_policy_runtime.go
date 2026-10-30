package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	shared "github.com/lyflow/ly-flow-platform/rasppolicy"
	"github.com/lyflow/ly-flow-platform/server/agentpolicy"
	"github.com/lyflow/ly-flow-platform/server/trustroot"
)

var errLegacyRASPConflict = errors.New("legacy RASP environment conflicts with monitor-first policy")

func validateLegacyRASPEnvironment() error {
	if raw, exists := os.LookupEnv("RASP_BLOCK_BY_DEFAULT"); exists {
		value, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil || value {
			return fmt.Errorf("RASP_BLOCK_BY_DEFAULT=%q: %w", raw, errLegacyRASPConflict)
		}
	}
	if raw, exists := os.LookupEnv("RASP_BLOCK_ON_HIT"); exists {
		value, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil || value {
			return fmt.Errorf("RASP_BLOCK_ON_HIT=%q: %w", raw, errLegacyRASPConflict)
		}
	}
	if raw, exists := os.LookupEnv("RASP_MODE"); exists && !strings.EqualFold(strings.TrimSpace(raw), "monitor") {
		return fmt.Errorf("RASP_MODE=%q: %w", raw, errLegacyRASPConflict)
	}
	return nil
}

func newRASPPolicyRuntime(ctx context.Context, pool *pgxpool.Pool) (*agentpolicy.Manager, error) {
	layout := trustroot.Layout{
		TrustDir: getEnv("POLICY_TRUST_DIR", "/etc/lyflow/trust"),
		KeyDir:   getEnv("POLICY_KEY_DIR", "/var/lib/lyflow/keys"),
	}
	if err := layout.EnsureOnlineRoots(rand.Reader); err != nil {
		return nil, fmt.Errorf("initialize policy trust root: %w", err)
	}
	signer, err := layout.LoadSigner(trustroot.PolicySigner)
	if err != nil {
		return nil, fmt.Errorf("load policy signer: %w", err)
	}
	store := agentpolicy.NewPostgresStore(pool)
	if err := store.EnsureSchema(ctx); err != nil {
		return nil, err
	}
	manager := agentpolicy.NewManager(agentpolicy.ManagerConfig{
		Store: store, Signer: signer, Verifier: layout, Now: time.Now,
		AllowProductionBlock: toBool(getEnv("LYFLOW_RASP_ALLOW_BLOCK", "false")),
	})
	if _, err := manager.EnsureDefault(ctx, getEnv("RASP_POLICY_OWNER", "lyflow-platform"), "audit://rasp-policy/default"); err != nil {
		return nil, fmt.Errorf("ensure default RASP policy: %w", err)
	}
	return manager, nil
}

func raspPolicyConfig(policy agentpolicy.Policy, enforceBlock bool) map[string]interface{} {
	languages := make(map[string]bool, len(policy.Selectors.Languages))
	for _, language := range policy.Selectors.Languages {
		languages[string(language)] = true
	}
	if len(languages) == 0 {
		languages["python"] = true
		languages["java"] = false
	}
	return map[string]interface{}{
		"enabled": policy.Mode != agentpolicy.ModeOff, "mode": policy.Mode,
		"languages": languages, "block_on_hit": enforceBlock, "version": policy.Version,
		"expires_at": policy.ExpiresAt, "fail_behavior": policy.FailBehavior,
		"max_events_per_second": policy.Limits.MaxEventsPerSecond,
	}
}

func raspRuntimeLanguages(capabilities map[string]interface{}) []shared.Language {
	probeManager, ok := capabilities["rasp_probe_manager"].(map[string]interface{})
	if !ok {
		return nil
	}
	rawLanguages, ok := probeManager["languages"]
	if !ok {
		return nil
	}
	values := make([]string, 0)
	switch typed := rawLanguages.(type) {
	case []string:
		values = append(values, typed...)
	case []interface{}:
		for _, value := range typed {
			if language, languageOK := value.(string); languageOK {
				values = append(values, language)
			}
		}
	}
	languages := make([]shared.Language, 0, len(values))
	for _, value := range values {
		switch shared.Language(strings.ToLower(strings.TrimSpace(value))) {
		case shared.LanguagePython:
			languages = append(languages, shared.LanguagePython)
		case shared.LanguageJava:
			languages = append(languages, shared.LanguageJava)
		case shared.LanguagePHP:
			languages = append(languages, shared.LanguagePHP)
		case shared.LanguageNodeJS:
			languages = append(languages, shared.LanguageNodeJS)
		case shared.LanguageDotnet:
			languages = append(languages, shared.LanguageDotnet)
		case shared.LanguageGo:
			languages = append(languages, shared.LanguageGo)
		}
	}
	return languages
}

func raspAssignmentTarget(agentID string, capabilities map[string]interface{}) agentpolicy.AssignmentTarget {
	return agentpolicy.AssignmentTarget{
		AgentID:      agentID,
		Capabilities: agentpolicy.RuntimeCapabilities{Languages: raspRuntimeLanguages(capabilities)},
	}
}
