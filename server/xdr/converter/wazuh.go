package converter

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/lyflow/ly-flow-platform/server/xdr/models"
)

type WazuhConverter struct {
	rulesDir string
}

func NewWazuhConverter(rulesDir string) *WazuhConverter {
	return &WazuhConverter{
		rulesDir: rulesDir,
	}
}

type WazuhRuleGroup struct {
	XMLName xml.Name    `xml:"group"`
	Name   string      `xml:"name,attr"`
	Rules  []WazuhRule `xml:"rule"`
}

type WazuhRule struct {
	XMLName      xml.Name   `xml:"rule"`
	ID           int        `xml:"id,attr"`
	Level        int        `xml:"level,attr"`
	Maxsize      int        `xml:"maxsize,attr"`
	Frequency    int        `xml:"frequency,attr"`
	Timeframe    int        `xml:"timeframe,attr"`
	Ignore       int        `xml:"ignore,attr"`
	Noalert      bool       `xml:"noalert,attr"`
	Overwrite    bool       `xml:"overwrite,attr"`
	DecodedAs    string     `xml:"decoded_as"`
	Match        string     `xml:"match"`
	Regex        string     `xml:"regex"`
	Field        string     `xml:"field"`
	SRcip        string     `xml:"srcip"`
	DstIP        string     `xml:"dstip"`
	User         string     `xml:"user"`
	Program      string     `xml:"program_name"`
	ExtraData    string     `xml:"extra_data"`
	Hostname     string     `xml:"hostname"`
	Description  string     `xml:"description"`
	Group        string     `xml:"group"`
	Groups       string     `xml:"groups"`
	Info         []WazuhInfo `xml:"info"`
	Mitre        WazuhMitre `xml:"mitre"`
	IfSID        string     `xml:"if_sid"`
	SameSrcip    bool       `xml:"same_source_ip"`
	SameUser     bool       `xml:"same_user"`
	NotMatch     string     `xml:"not_match"`
}

type WazuhInfo struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type WazuhMitre struct {
	IDs []string `xml:"id"`
}

func (c *WazuhConverter) DownloadAndConvert() error {
	rules := []string{
		"0095-sshd_rules.xml",
		"0100-syslog_rules.xml",
		"0210-pam_rules.xml",
		"0240-apache_rules.xml",
		"0250-nginx_rules.xml",
		"0355-mysql_rules.xml",
	}

	baseURL := "https://raw.githubusercontent.com/wazuh/wazuh/master/ruleset/rules/"

	for _, ruleFile := range rules {
		if err := c.downloadAndConvertFile(baseURL, ruleFile); err != nil {
			fmt.Printf("下载转换 %s 失败: %v\n", ruleFile, err)
		}
	}

	return nil
}

func (c *WazuhConverter) downloadAndConvertFile(baseURL, filename string) error {
	url := baseURL + filename
	fmt.Printf("下载 Wazuh 规则: %s\n", filename)

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return c.convertXMLToYAML(data, filename)
}

func (c *WazuhConverter) convertXMLToYAML(data []byte, filename string) error {
	var group WazuhRuleGroup
	if err := xml.Unmarshal(data, &group); err != nil {
		return fmt.Errorf("XML 解析失败: %w", err)
	}

	var rules []models.Rule
	for _, wr := range group.Rules {
		rule := c.convertRule(wr)
		rules = append(rules, *rule)
	}

	yamlData, err := yaml.Marshal(struct {
		Source string         `yaml:"source"`
		Rules  []models.Rule  `yaml:"rules"`
	}{
		Source: c.getSourceFromFilename(filename),
		Rules:  rules,
	})
	if err != nil {
		return err
	}

	outputFile := strings.Replace(filename, ".xml", ".yaml", 1)
	outputPath := filepath.Join(c.rulesDir, outputFile)

	return os.WriteFile(outputPath, yamlData, 0644)
}

func (c *WazuhConverter) convertRule(wr WazuhRule) *models.Rule {
	rule := &models.Rule{
		ID:          wr.ID,
		Level:       wr.Level,
		Match:       c.cleanMatchPattern(wr.Match, wr.Regex),
		IsRegex:     wr.Regex != "",
		NotMatch:    wr.NotMatch,
		Frequency:   wr.Frequency,
		Timeframe:   wr.Timeframe,
		SameSrcip:   wr.SameSrcip,
		SameUser:    wr.SameUser,
		Description: wr.Description,
		SrcIP:       wr.SRcip,
		DstIP:       wr.DstIP,
		User:        wr.User,
		Program:     wr.Program,
		ExtraData:   wr.ExtraData,
		NoAlert:     wr.Noalert,
		Ignore:      wr.Ignore,
		Enabled:     true,
	}

	rule.IfSID = c.parseIfSID(wr.IfSID)

	if len(wr.Info) > 0 {
		for _, info := range wr.Info {
			rule.Info = append(rule.Info, models.Info{
				Type:  info.Type,
				Value: info.Value,
			})
		}
	}

	if len(wr.Mitre.IDs) > 0 {
		rule.Mitre = wr.Mitre.IDs
	}

	rule.Groups = c.parseGroups(wr.Group, wr.Groups)

	return rule
}

func (c *WazuhConverter) cleanMatchPattern(match, regex string) string {
	pattern := regex
	if pattern == "" {
		pattern = match
	}

	pattern = strings.ReplaceAll(pattern, "^", "")
	pattern = strings.ReplaceAll(pattern, "$", "")
	pattern = strings.TrimSpace(pattern)

	return pattern
}

func (c *WazuhConverter) parseIfSID(ifSID string) int {
	if ifSID == "" {
		return 0
	}

	re := regexp.MustCompile(`(\d+)`)
	matches := re.FindStringSubmatch(ifSID)
	if len(matches) > 0 {
		var id int
		fmt.Sscanf(matches[1], "%d", &id)
		return id
	}
	return 0
}

func (c *WazuhConverter) parseGroups(group, groups string) []string {
	var result []string

	if group != "" {
		parts := strings.Split(group, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
	}

	if groups != "" {
		parts := strings.Split(groups, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				result = append(result, p)
			}
		}
	}

	return result
}

func (c *WazuhConverter) getSourceFromFilename(filename string) string {
	filename = strings.ToLower(filename)

	switch {
	case strings.Contains(filename, "sshd"):
		return "sshd"
	case strings.Contains(filename, "syslog"):
		return "systemd"
	case strings.Contains(filename, "pam"):
		return "pam"
	case strings.Contains(filename, "apache"):
		return "apache"
	case strings.Contains(filename, "nginx"):
		return "nginx"
	case strings.Contains(filename, "mysql"):
		return "mysql"
	default:
		return "systemd"
	}
}
