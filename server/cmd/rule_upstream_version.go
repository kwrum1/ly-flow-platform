package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

type upstreamRuleVersionEntry struct {
	version   string
	expiresAt time.Time
}

var upstreamRuleVersionCache sync.Map

func upstreamRuleVersion(ctx context.Context, sourceID string) string {
	repositories := map[string]string{
		"yara-signature-base":           "https://api.github.com/repos/Neo23x0/signature-base/commits?path=yara&per_page=1",
		"falco-supported-subset":        "https://api.github.com/repos/falcosecurity/rules/commits?path=rules&per_page=1",
		"elastic-linux-detection-rules": "https://api.github.com/repos/elastic/detection-rules/commits?path=rules/linux&per_page=1",
	}
	endpoint := repositories[sourceID]
	if endpoint == "" {
		return ""
	}
	if cached, ok := upstreamRuleVersionCache.Load(sourceID); ok {
		entry := cached.(upstreamRuleVersionEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.version
		}
	}
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("User-Agent", "lyflow-rule-version-check/1")
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return ""
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ""
	}
	var commits []struct {
		SHA string `json:"sha"`
	}
	if json.NewDecoder(response.Body).Decode(&commits) != nil || len(commits) == 0 {
		return ""
	}
	sha := strings.TrimSpace(commits[0].SHA)
	if len(sha) > 12 {
		sha = sha[:12]
	}
	if sha == "" {
		return ""
	}
	version := "upstream-" + sha
	upstreamRuleVersionCache.Store(sourceID, upstreamRuleVersionEntry{version: version, expiresAt: time.Now().Add(10 * time.Minute)})
	return version
}
