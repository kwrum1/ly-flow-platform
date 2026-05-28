package rules

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type RuleLoader struct {
	rulesDir string
}

func NewRuleLoader(rulesDir string) *RuleLoader {
	return &RuleLoader{
		rulesDir: rulesDir,
	}
}

func (l *RuleLoader) LoadRules() ([]models.Rule, error) {
	var allRules []models.Rule

	if _, err := os.Stat(l.rulesDir); err != nil {
		log.Printf("[XDR] 读取规则目录失败: %v", err)
		return nil, err
	}

	err := filepath.WalkDir(l.rulesDir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			log.Printf("[XDR] 遍历规则路径失败 %s: %v", path, walkErr)
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			return nil
		}

		rules, err := l.loadFile(path)
		if err != nil {
			log.Printf("[XDR] 加载规则文件 %s 失败: %v", path, err)
			return nil
		}

		allRules = append(allRules, rules...)
		log.Printf("[XDR] 加载规则文件 %s: %d 条", path, len(rules))
		return nil
	})
	if err != nil {
		return nil, err
	}

	return allRules, nil
}

func (l *RuleLoader) LoadTopLevelRules() ([]models.Rule, error) {
	var allRules []models.Rule

	files, err := os.ReadDir(l.rulesDir)
	if err != nil {
		log.Printf("[XDR] 读取规则目录失败: %v", err)
		return nil, err
	}

	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}

		rules, err := l.loadFile(filepath.Join(l.rulesDir, f.Name()))
		if err != nil {
			log.Printf("[XDR] 加载规则文件 %s 失败: %v", f.Name(), err)
			continue
		}

		allRules = append(allRules, rules...)
		log.Printf("[XDR] 加载规则文件 %s: %d 条", f.Name(), len(rules))
	}

	return allRules, nil
}

func (l *RuleLoader) loadFile(path string) ([]models.Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ruleSet models.RuleSet
	if err := yaml.Unmarshal(data, &ruleSet); err != nil {
		var singleRule models.Rule
		if err2 := yaml.Unmarshal(data, &singleRule); err2 == nil {
			return []models.Rule{singleRule}, nil
		}
		return nil, err
	}

	return ruleSet.Rules, nil
}

func (l *RuleLoader) SaveRule(rule *models.Rule, filename string) error {
	data, err := yaml.Marshal(rule)
	if err != nil {
		return err
	}

	path := filepath.Join(l.rulesDir, filename)
	return os.WriteFile(path, data, 0644)
}

func (l *RuleLoader) UpdateRuleFile(filename string, rules []models.Rule) error {
	ruleSet := models.RuleSet{Rules: rules}
	data, err := yaml.Marshal(ruleSet)
	if err != nil {
		return err
	}

	path := filepath.Join(l.rulesDir, filename)
	return os.WriteFile(path, data, 0644)
}

func (l *RuleLoader) ValidateRule(rule *models.Rule) error {
	if rule.ID <= 0 {
		return fmt.Errorf("规则 ID 必须大于 0")
	}
	if rule.Name == "" {
		return fmt.Errorf("规则名称不能为空")
	}
	if rule.Match == "" && rule.IfSID <= 0 {
		return fmt.Errorf("规则必须有 match 或 if_sid")
	}
	return nil
}
