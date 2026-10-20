package rulecompiler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleRules = `
# simple convertible rules
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB SQL union select"; flow:to_server,established; http_uri; content:"union select"; nocase; sid:9001001; rev:1; classtype:web-application-attack;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB PHP eval body"; flow:to_server,established; http_client_body; content:"eval("; sid:9001002; rev:1; classtype:web-application-attack;)
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE suspicious xyz SNI"; tls_sni; content:".xyz"; sid:9001003; rev:1; classtype:trojan-activity;)
alert dns $HOME_NET any -> any 53 (msg:"ET TROJAN DNS profile test"; dns_query; content:"profile.test"; sid:9001004; rev:1; classtype:trojan-activity;)
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET WEB pcre union"; flow:to_server,established; http_uri; pcre:"/union\s+select/i"; sid:9001005; rev:1; classtype:web-application-attack;)
alert tcp any any -> any any (msg:"complex flowbits"; content:"cmd.exe"; flowbits:set,foo; sid:9001006; rev:1;)
alert http any any -> any any (msg:"multiple contents"; content:"GET"; content:"POST"; sid:9001007; rev:1;)
`

func TestConvertSimpleRules(t *testing.T) {
	result := Convert([]SourceFile{{Name: "sample.rules", Content: []byte(sampleRules)}})
	if result.Converted != 5 {
		t.Fatalf("converted = %d, want 5; skipped=%+v", result.Converted, result.Skipped)
	}
	if len(result.Skipped) != 2 {
		t.Fatalf("skipped = %d, want 2: %+v", len(result.Skipped), result.Skipped)
	}
	if result.Skipped[0].SID != 9001006 || result.Skipped[1].SID != 9001007 {
		t.Fatalf("skipped SIDs = %+v", result.Skipped)
	}
	httpRule := result.Bundle.Threat.Rules["9001001"]
	if httpRule.Protocol != "tcp" || httpRule.IsHTTP != 1 || httpRule.Part != "head" || httpRule.Regex != "(?i)union select" {
		t.Fatalf("http rule = %+v", httpRule)
	}
	if httpRule.Type != "WEB" {
		t.Fatalf("http type = %q", httpRule.Type)
	}
	bodyRule := result.Bundle.Threat.Rules["9001002"]
	if bodyRule.IsHTTP != 1 || bodyRule.Part != "body" || bodyRule.Regex != `eval\(` {
		t.Fatalf("body rule = %+v", bodyRule)
	}
	sniRule := result.Bundle.Threat.Rules["9001003"]
	if sniRule.Protocol != "tcp" || sniRule.Regex != `\.xyz` {
		t.Fatalf("sni rule = %+v", sniRule)
	}
	dnsRule := result.Bundle.Threat.Rules["9001004"]
	if dnsRule.Protocol != "udp" || dnsRule.Regex != `\x07profile\x04test` {
		t.Fatalf("dns rule = %+v", dnsRule)
	}
	pcreRule := result.Bundle.Threat.Rules["9001005"]
	if pcreRule.Regex != `(?i)union\s+select` {
		t.Fatalf("pcre rule = %+v", pcreRule)
	}
}

func TestDuplicateSIDIsSkipped(t *testing.T) {
	source := `
alert http any any -> any any (msg:"one"; http_uri; content:"one"; sid:9010001;)
alert http any any -> any any (msg:"two"; http_uri; content:"two"; sid:9010001;)
`
	result := Convert([]SourceFile{{Name: "dupes.rules", Content: []byte(source)}})
	if result.Converted != 1 {
		t.Fatalf("converted = %d, want 1", result.Converted)
	}
	if len(result.Skipped) != 1 || !strings.Contains(result.Skipped[0].Reason, "duplicate") {
		t.Fatalf("skipped = %+v", result.Skipped)
	}
}

func TestValidateBundleRejectsBadRegex(t *testing.T) {
	bundle := Bundle{Threat: ThreatClass{Rules: map[string]Rule{
		"1": {Type: "WEB", Name: "bad", Regex: "("},
	}}}
	if err := ValidateBundle(bundle); err == nil {
		t.Fatal("expected invalid regex error")
	}
}

func TestWriteBundleIsAtomicAndManifested(t *testing.T) {
	dir := t.TempDir()
	result := Convert([]SourceFile{{Name: "sample.rules", Content: []byte(sampleRules)}})
	result.SourceHash = HashSources([]SourceFile{{Name: "sample.rules", Content: []byte(sampleRules)}})
	output := filepath.Join(dir, "fp-patterns", "threat.json")
	manifest := filepath.Join(dir, "fp-patterns", "manifest.json")
	digest, err := WriteBundle(output, manifest, result)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	payload, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if !strings.Contains(string(payload), `"9001001"`) {
		t.Fatalf("output missing rule: %s", payload)
	}
	manifestPayload, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(manifestPayload), digest) {
		t.Fatalf("manifest missing digest %s: %s", digest, manifestPayload)
	}
	entries, err := os.ReadDir(filepath.Dir(output))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("temporary file left behind: %s", entry.Name())
		}
	}
}

func TestWatcherRefreshesAndKeepsOldRulesOnError(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.rules")
	output := filepath.Join(dir, "threat.json")
	manifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(source, []byte(sampleRules), 0o644); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	compiler := &Compiler{
		Sources:      []string{source},
		OutputPath:   output,
		ManifestPath: manifest,
		Reload: func(context.Context) error {
			reloads++
			return nil
		},
	}
	first, err := compiler.Sync(context.Background())
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if first.Converted != 5 || reloads != 1 {
		t.Fatalf("first result converted=%d reloads=%d", first.Converted, reloads)
	}
	same, changed, err := compiler.SyncIfChanged(context.Background(), first.SourceHash)
	if err != nil || changed {
		t.Fatalf("unchanged sync changed=%v err=%v", changed, err)
	}
	if same.Converted != 0 {
		t.Fatalf("unchanged result = %+v", same)
	}
	// A new rule with no supported match is a compile failure and must not
	// overwrite the previously valid output.
	if err := os.WriteFile(source, []byte("not a suricata rule\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, changed, err = compiler.SyncIfChanged(context.Background(), first.SourceHash)
	if err == nil || !changed {
		t.Fatalf("invalid sync changed=%v err=%v", changed, err)
	}
	payload, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"9001001"`) {
		t.Fatalf("old rules were overwritten: %s", payload)
	}
	if reloads != 1 {
		t.Fatalf("reload should not run on failed compile, got %d", reloads)
	}
}
