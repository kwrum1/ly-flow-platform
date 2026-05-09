package webhook

import (
	"fmt"
	"strings"
	"time"
)

// FeishuMessage represents a Feishu (Lark) webhook message
type FeishuMessage struct {
	MsgType string `json:"msg_type"`
	Content struct {
		Text string `json:"text"`
	} `json:"content"`
}

// FeishuPostContent represents content in a Feishu post message
type FeishuPostContent struct {
	Tag    string `json:"tag"`
	Text   string `json:"text,omitempty"`
	Href   string `json:"href,omitempty"`
	Color  string `json:"color,omitempty"`
	Attrs  []struct {
		Tag  string `json:"tag"`
		Text string `json:"text"`
	} `json:"attrs,omitempty"`
}

// FeishuPostMessage represents a Feishu post message
type FeishuPostMessage struct {
	MsgType string `json:"msg_type"`
	Content struct {
		Post struct {
			ZhCn struct {
				Title   string               `json:"title"`
				Content [][]FeishuPostContent `json:"content"`
			} `json:"zh_cn"`
		} `json:"post"`
	} `json:"content"`
}

// FormatFeishuAlert formats an Alert as a Feishu text message
func FormatFeishuAlert(alert *Alert) *FeishuMessage {
	msg := &FeishuMessage{MsgType: "text"}
	content := fmt.Sprintf("[%s] %s\n类型: %s\n源IP: %s\n目标IP: %s\n域名: %s\n签名: %s\n时间: %s\n详情: %s",
		formatSeverityFeishu(alert.Severity), alert.Category,
		alert.Category, alert.SourceIP, alert.TargetIP,
		alert.Domain, alert.Signature,
		alert.Timestamp.Format("2006-01-02 15:04:05"),
		alert.DetailURL)
	msg.Content.Text = content
	return msg
}

// FormatFeishuAlertWithLink formats an Alert as a Feishu post message with clickable link
func FormatFeishuAlertWithLink(alert *Alert) *FeishuPostMessage {
	msg := &FeishuPostMessage{MsgType: "post"}
	msg.Content.Post.ZhCn.Title = fmt.Sprintf("%s %s", formatSeverityFeishu(alert.Severity), alert.Category)

	postContent := [][]FeishuPostContent{
		{
			{Tag: "text", Text: "类型: "},
			{Tag: "text", Text: alert.Category, Color: "orange"},
		},
		{
			{Tag: "text", Text: "级别: "},
			{Tag: "text", Text: alert.Severity, Color: getSeverityColor(alert.Severity)},
		},
		{
			{Tag: "text", Text: "源IP: "},
			{Tag: "text", Text: alert.SourceIP},
		},
		{
			{Tag: "text", Text: "目标IP: "},
			{Tag: "text", Text: alert.TargetIP},
		},
		{
			{Tag: "text", Text: "域名: "},
			{Tag: "text", Text: alert.Domain},
		},
		{
			{Tag: "text", Text: "签名: "},
			{Tag: "text", Text: alert.Signature},
		},
		{
			{Tag: "text", Text: "时间: "},
			{Tag: "text", Text: alert.Timestamp.Format("2006-01-02 15:04:05")},
		},
		{
			{Tag: "a", Text: "查看详情", Href: alert.DetailURL},
		},
	}

	msg.Content.Post.ZhCn.Content = postContent
	return msg
}

// FormatFeishuDailyReport formats a DailyReport as a Feishu post message
func FormatFeishuDailyReport(report *DailyReport) *FeishuPostMessage {
	msg := &FeishuPostMessage{MsgType: "post"}
	msg.Content.Post.ZhCn.Title = fmt.Sprintf("📊 安全日报 - %s", report.Date.Format("2006-01-02"))

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("**告警统计**: 共 %d 条\n\n", report.TotalAlerts))
	sb.WriteString(fmt.Sprintf("🔴 严重: %d\n", report.Critical))
	sb.WriteString(fmt.Sprintf("🟠 高危: %d\n", report.High))
	sb.WriteString(fmt.Sprintf("🟡 中危: %d\n", report.Medium))
	sb.WriteString(fmt.Sprintf("🟢 低危: %d\n\n", report.Low))

	if len(report.TopSources) > 0 {
		sb.WriteString("**Top 攻击源IP**:\n")
		for i, ip := range report.TopSources {
			if i >= 5 {
				break
			}
			sb.WriteString(fmt.Sprintf("- %s: %d 次\n", ip.IP, ip.Count))
		}
		sb.WriteString("\n")
	}

	if len(report.TopCategories) > 0 {
		sb.WriteString("**Top 攻击类型**:\n")
		for i, cat := range report.TopCategories {
			if i >= 5 {
				break
			}
			sb.WriteString(fmt.Sprintf("- %s: %d 次\n", cat.Category, cat.Count))
		}
	}

	postContent := [][]FeishuPostContent{
		{{Tag: "text", Text: sb.String()}},
	}

	msg.Content.Post.ZhCn.Content = postContent
	return msg
}

// formatSeverityFeishu adds emoji prefix based on severity level
func formatSeverityFeishu(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴 严重"
	case "high":
		return "🟠 高危"
	case "medium":
		return "🟡 中危"
	case "low":
		return "🟢 低危"
	default:
		return severity
	}
}

// getSeverityColor returns Feishu color code for severity
func getSeverityColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "red"
	case "high":
		return "orange"
	case "medium":
		return "yellow"
	case "low":
		return "green"
	default:
		return "default"
	}
}

// FeishuReportText formats a DailyReport as Feishu text message
func FormatFeishuReportText(report *DailyReport) *FeishuMessage {
	msg := &FeishuMessage{MsgType: "text"}
	content := fmt.Sprintf(`📊 安全日报 - %s

告警统计: 共 %d 条
🔴 严重: %d
🟠 高危: %d
🟡 中危: %d
🟢 低危: %d

Top 攻击源IP:
%s

Top 攻击类型:
%s`,
		report.Date.Format("2006-01-02"),
		report.TotalAlerts,
		report.Critical, report.High, report.Medium, report.Low,
		formatTopIPs(report.TopSources),
		formatTopCategories(report.TopCategories))

	msg.Content.Text = content
	return msg
}

func formatTopIPs(ips []IPStat) string {
	if len(ips) == 0 {
		return "无"
	}
	var sb strings.Builder
	for i, ip := range ips {
		if i >= 5 {
			break
		}
		sb.WriteString(fmt.Sprintf("%s: %d 次\n", ip.IP, ip.Count))
	}
	return sb.String()
}

func formatTopCategories(categories []CategoryStat) string {
	if len(categories) == 0 {
		return "无"
	}
	var sb strings.Builder
	for i, cat := range categories {
		if i >= 5 {
			break
		}
		sb.WriteString(fmt.Sprintf("%s: %d 次\n", cat.Category, cat.Count))
	}
	return sb.String()
}

// FilterMatches checks if an alert matches the given filters
func FilterMatches(alert *Alert, severity []string, category []string, tags []string) bool {
	if len(severity) > 0 {
		found := false
		for _, s := range severity {
			if strings.EqualFold(s, alert.Severity) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(category) > 0 {
		found := false
		for _, c := range category {
			if strings.EqualFold(c, alert.Category) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if len(tags) > 0 {
		found := false
		for _, tag := range tags {
			for _, alertTag := range alert.Tags {
				if strings.EqualFold(tag, alertTag) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// Unused function kept for potential future use
func formatTime(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}
