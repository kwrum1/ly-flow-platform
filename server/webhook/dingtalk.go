package webhook

import (
	"fmt"
	"strings"
)

// DingTalkMessage represents a DingTalk webhook message
type DingTalkMessage struct {
	MsgType  string `json:"msgtype"`
	Text     *struct {
		Content string `json:"content"`
	} `json:"text,omitempty"`
	Link *struct {
		Text       string `json:"text"`
		Title      string `json:"title"`
		PicURL     string `json:"picUrl"`
		MessageURL string `json:"messageUrl"`
	} `json:"link,omitempty"`
	Markdown *struct {
		Title string `json:"title"`
		Text  string `json:"text"`
	} `json:"markdown,omitempty"`
	ActionCard *struct {
		Title          string `json:"title"`
		Text           string `json:"text"`
		SingleTitle    string `json:"singleTitle"`
		SingleURL      string `json:"singleUrl"`
		BtnOrientation string `json:"btnOrientation"`
	} `json:"actionCard,omitempty"`
}

// FormatDingTalkAlert formats an Alert as a DingTalk markdown message
func FormatDingTalkAlert(alert *Alert) *DingTalkMessage {
	msg := &DingTalkMessage{MsgType: "markdown"}
	msg.Markdown = &struct {
		Title string `json:"title"`
		Text  string `json:"text"`
	}{
		Title: fmt.Sprintf("🔴 [%s] %s", alert.Severity, alert.Category),
		Text: fmt.Sprintf(`### 安全告警

**类型**: %s
**级别**: %s
**源IP**: %s
**目标IP**: %s
**域名**: %s
**签名**: %s
**时间**: %s

[查看详情](%s)`, formatSeverity(alert.Severity), alert.Category,
			alert.SourceIP, alert.TargetIP, alert.Domain, alert.Signature,
			alert.Timestamp.Format("2006-01-02 15:04:05"), alert.DetailURL),
	}
	return msg
}

// FormatDingTalkText formats an Alert as a DingTalk text message
func FormatDingTalkText(alert *Alert) *DingTalkMessage {
	msg := &DingTalkMessage{MsgType: "text"}
	content := fmt.Sprintf("[%s] %s - 类型: %s, 源IP: %s, 目标IP: %s",
		alert.Severity, alert.Category, alert.Category,
		alert.SourceIP, alert.TargetIP)
	msg.Text = &struct {
		Content string `json:"content"`
	}{
		Content: content,
	}
	return msg
}

// FormatDingTalkLink formats an Alert as a DingTalk link message
func FormatDingTalkLink(alert *Alert) *DingTalkMessage {
	msg := &DingTalkMessage{MsgType: "link"}
	msg.Link = &struct {
		Text       string `json:"text"`
		Title      string `json:"title"`
		PicURL     string `json:"picUrl"`
		MessageURL string `json:"messageUrl"`
	}{
		Text:       fmt.Sprintf("[%s] %s\n源IP: %s\n目标IP: %s", alert.Severity, alert.Category, alert.SourceIP, alert.TargetIP),
		Title:      fmt.Sprintf("🔴 [%s] %s", alert.Severity, alert.Category),
		PicURL:     "",
		MessageURL: alert.DetailURL,
	}
	return msg
}

// FormatDingTalkDailyReport formats a DailyReport as a DingTalk markdown message
func FormatDingTalkDailyReport(report *DailyReport) *DingTalkMessage {
	msg := &DingTalkMessage{MsgType: "markdown"}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`### 📊 安全日报 - %s

**告警统计**: 共 %d 条

| 级别 | 数量 |
|------|------|
`, report.Date.Format("2006-01-02"), report.TotalAlerts))

	sb.WriteString(fmt.Sprintf("| 🔴 严重 | %d |\n", report.Critical))
	sb.WriteString(fmt.Sprintf("| 🟠 高危 | %d |\n", report.High))
	sb.WriteString(fmt.Sprintf("| 🟡 中危 | %d |\n", report.Medium))
	sb.WriteString(fmt.Sprintf("| 🟢 低危 | %d |\n", report.Low))

	if len(report.TopSources) > 0 {
		sb.WriteString("\n**Top 攻击源IP**:\n")
		for i, ip := range report.TopSources {
			if i >= 5 {
				break
			}
			sb.WriteString(fmt.Sprintf("- %s: %d 次\n", ip.IP, ip.Count))
		}
	}

	if len(report.TopCategories) > 0 {
		sb.WriteString("\n**Top 攻击类型**:\n")
		for i, cat := range report.TopCategories {
			if i >= 5 {
				break
			}
			sb.WriteString(fmt.Sprintf("- %s: %d 次\n", cat.Category, cat.Count))
		}
	}

	msg.Markdown = &struct {
		Title string `json:"title"`
		Text  string `json:"text"`
	}{
		Title: fmt.Sprintf("📊 安全日报 - %s", report.Date.Format("2006-01-02")),
		Text:  sb.String(),
	}
	return msg
}

// formatSeverity adds emoji prefix based on severity level
func formatSeverity(severity string) string {
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
