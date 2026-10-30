package rules

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

// T4-01: every enabled rule with a match expression must ship positive,
// negative and (optionally) boundary samples. The corpus is the contract that
// stops a broadened regex or a dropped exclusion from reaching production
// without a failing test.

type ruleSampleLog struct {
	Message string `yaml:"message"`
	Raw     string `yaml:"raw"`
	Source  string `yaml:"source"`
	Program string `yaml:"program"`
	User    string `yaml:"user"`
}

type ruleBoundarySample struct {
	Text string `yaml:"text"`
	Want bool   `yaml:"want"`
	Note string `yaml:"note"`
}

type ruleSampleCase struct {
	RuleID   int                  `yaml:"rule_id"`
	Positive []ruleSampleLog      `yaml:"positive"`
	Negative []ruleSampleLog      `yaml:"negative"`
	Boundary []ruleBoundarySample `yaml:"boundary"`
}

type ruleSampleCorpus struct {
	Samples []ruleSampleCase `yaml:"samples"`
}

func loadRuleCorpus(t *testing.T) []*models.Rule {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "rules", "xdr")
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no rule files under %s: %v", dir, err)
	}
	var all []*models.Rule
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var set models.RuleSet
		if err := yaml.Unmarshal(body, &set); err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for i := range set.Rules {
			rule := set.Rules[i]
			all = append(all, &rule)
		}
	}
	return all
}

func loadSampleCorpus(t *testing.T) []ruleSampleCase {
	t.Helper()
	path := filepath.Join("..", "..", "..", "rules", "testdata", "xdr_rule_samples.yaml")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read samples: %v", err)
	}
	var corpus ruleSampleCorpus
	if err := yaml.Unmarshal(body, &corpus); err != nil {
		t.Fatalf("parse samples: %v", err)
	}
	return corpus.Samples
}

func sampleToLog(sample ruleSampleLog, rule *models.Rule) *models.NormalizedLog {
	log := models.NewNormalizedLog()
	log.Message = sample.Message
	log.Raw = sample.Raw
	log.Program = sample.Program
	log.Source = sample.Source
	log.User = sample.User
	// Fill routing fields from the rule so samples only express the message.
	if log.Source == "" {
		log.Source = rule.Source
	}
	if log.Program == "" {
		log.Program = rule.Program
	}
	if log.User == "" {
		log.User = rule.User
	}
	return log
}

func TestRuleSamplesMatchAndReject(t *testing.T) {
	rules := loadRuleCorpus(t)
	corpus := loadSampleCorpus(t)

	byID := map[int]*models.Rule{}
	for _, rule := range rules {
		byID[rule.ID] = rule
	}

	seen := map[int]bool{}
	for _, sampleCase := range corpus {
		rule, ok := byID[sampleCase.RuleID]
		if !ok {
			t.Fatalf("sample references unknown rule %d", sampleCase.RuleID)
		}
		seen[sampleCase.RuleID] = true
		if len(sampleCase.Positive) == 0 || len(sampleCase.Negative) == 0 {
			t.Fatalf("rule %d needs at least one positive and one negative sample", rule.ID)
		}
		for _, sample := range sampleCase.Positive {
			matched, _ := rule.Evaluate(sampleToLog(sample, rule))
			if !matched {
				t.Errorf("rule %d (%s) missed positive sample %q", rule.ID, rule.Name, sample.Message)
			}
		}
		for _, sample := range sampleCase.Negative {
			matched, _ := rule.Evaluate(sampleToLog(sample, rule))
			if matched {
				t.Errorf("rule %d (%s) fired on negative sample %q", rule.ID, rule.Name, sample.Message)
			}
		}
		for _, boundary := range sampleCase.Boundary {
			matched, _ := rule.Evaluate(sampleToLog(ruleSampleLog{Message: boundary.Text}, rule))
			if matched != boundary.Want {
				t.Errorf("rule %d boundary %q: want %v got %v (%s)", rule.ID, boundary.Text, boundary.Want, matched, boundary.Note)
			}
		}
	}

	for _, rule := range rules {
		if !rule.Enabled || rule.Match == "" {
			continue
		}
		if !seen[rule.ID] {
			t.Errorf("rule %d (%s) has a match expression but no samples", rule.ID, rule.Name)
		}
	}
}

func TestRuleSampleCorpusHasBoundaryCoverage(t *testing.T) {
	corpus := loadSampleCorpus(t)
	withBoundary := 0
	for _, sampleCase := range corpus {
		if len(sampleCase.Boundary) > 0 {
			withBoundary++
		}
	}
	// Boundary samples are what catch regex broadening; keep them from being
	// dropped as the corpus grows.
	if withBoundary < 5 {
		t.Fatalf("expected at least 5 rules with boundary samples, got %d", withBoundary)
	}
}
