package webhook

import (
	"fmt"
	"strings"
	"time"
)

type IncidentNotification struct {
	ID       string
	Title    string
	Severity string
	Status   string
	Asset    string
	Action   string
	DetailURL string
}

func FormatWeComIncidentMarkdown(incident IncidentNotification) *WeComMessage {
	msg := &WeComMessage{MsgType: "markdown"}
	content := fmt.Sprintf(`### LyFlow P0/P1 Incident

> **%s** %s

**ID**: %s
**状态**: %s
**资产**: %s
**动作**: %s

[查看详情](%s)`, strings.ToUpper(incident.Severity), incident.Title, incident.ID, incident.Status, incident.Asset, incident.Action, incident.DetailURL)
	msg.Markdown = &struct { Content string `json:"content"` }{Content: content}
	return msg
}

// WeComMessage represents a WeCom (Enterprise WeChat) webhook message
type WeComMessage struct {
	MsgType  string `json:"msgtype"`
	Text     *struct {
		Content string `json:"content"`
	} `json:"text,omitempty"`
	Markdown *struct {
		Content string `json:"content"`
	} `json:"markdown,omitempty"`
	News *struct {
		Articles []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			URL         string `json:"url"`
			PicURL      string `json:"picurl"`
		} `json:"articles"`
	} `json:"news,omitempty"`
	Image *struct {
		Base64 string `json:"base64"`
		MD5    string `json:"md5"`
	} `json:"image,omitempty"`
	Voice *struct {
		MediaID string `json:"media_id"`
	} `json:"voice,omitempty"`
	File *struct {
		MediaID string `json:"media_id"`
	} `json:"file,omitempty"`
}

// WeComArticle represents an article in WeCom news message
type WeComArticle struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	URL         string `json:"url"`
	PicURL      string `json:"picurl"`
}

// FormatWeComAlert formats an Alert as a WeCom text message
func FormatWeComAlert(alert *Alert) *WeComMessage {
	msg := &WeComMessage{MsgType: "text"}
	content := fmt.Sprintf("[%s] %s\n类型: %s\n源IP: %s\n目标IP: %s\n域名: %s\n签名: %s\n时间: %s\n详情: %s",
		formatSeverityWeCom(alert.Severity), alert.Category,
		alert.Category, alert.SourceIP, alert.TargetIP,
		alert.Domain, alert.Signature,
		alert.Timestamp.Format("2006-01-02 15:04:05"),
		alert.DetailURL)
	msg.Text = &struct {
		Content string `json:"content"`
	}{
		Content: content,
	}
	return msg
}

// FormatWeComAlertMarkdown formats an Alert as a WeCom markdown message
func FormatWeComAlertMarkdown(alert *Alert) *WeComMessage {
	msg := &WeComMessage{MsgType: "markdown"}
	content := fmt.Sprintf(`### %s %s

> 类型: %s

**源IP**: %s
**目标IP**: %s
**域名**: %s
**签名**: %s
**时间**: %s

[查看详情](%s)`,
		formatSeverityWeCom(alert.Severity), alert.Category,
		alert.Category,
		alert.SourceIP, alert.TargetIP,
		alert.Domain, alert.Signature,
		alert.Timestamp.Format("2006-01-02 15:04:05"),
		alert.DetailURL)
	msg.Markdown = &struct {
		Content string `json:"content"`
	}{
		Content: content,
	}
	return msg
}

// FormatWeComNews formats an Alert as a WeCom news message with article
func FormatWeComNews(alert *Alert) *WeComMessage {
	msg := &WeComMessage{MsgType: "news"}
	msg.News = &struct {
		Articles []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			URL         string `json:"url"`
			PicURL      string `json:"picurl"`
		} `json:"articles"`
	}{
		Articles: []struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			URL         string `json:"url"`
			PicURL      string `json:"picurl"`
		}{
			{
				Title:       fmt.Sprintf("%s %s", formatSeverityWeCom(alert.Severity), alert.Category),
				Description: fmt.Sprintf("类型: %s\n源IP: %s\n目标IP: %s\n时间: %s",
					alert.Category, alert.SourceIP, alert.TargetIP,
					alert.Timestamp.Format("2006-01-02 15:04:05")),
				URL:    alert.DetailURL,
				PicURL: "",
			},
		},
	}
	return msg
}

// FormatWeComDailyReport formats a DailyReport as a WeCom markdown message
func FormatWeComDailyReport(report *DailyReport) *WeComMessage {
	msg := &WeComMessage{MsgType: "markdown"}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### 📊 安全日报 - %s\n\n", report.Date.Format("2006-01-02")))
	sb.WriteString(fmt.Sprintf("**告警统计**: 共 %d 条\n\n", report.TotalAlerts))
	sb.WriteString("| 级别 | 数量 |\n|------|------|\n")
	sb.WriteString(fmt.Sprintf("| 🔴 严重 | %d |\n", report.Critical))
	sb.WriteString(fmt.Sprintf("| 🟠 高危 | %d |\n", report.High))
	sb.WriteString(fmt.Sprintf("| 🟡 中危 | %d |\n", report.Medium))
	sb.WriteString(fmt.Sprintf("| 🟢 低危 | %d |\n\n", report.Low))

	if len(report.TopSources) > 0 {
		sb.WriteString("**Top 攻击源IP**:\n")
		for i, ip := range report.TopSources {
			if i >= 5 {
				break
			}
			sb.WriteString(fmt.Sprintf("> - %s: %d 次\n", ip.IP, ip.Count))
		}
		sb.WriteString("\n")
	}

	if len(report.TopCategories) > 0 {
		sb.WriteString("**Top 攻击类型**:\n")
		for i, cat := range report.TopCategories {
			if i >= 5 {
				break
			}
			sb.WriteString(fmt.Sprintf("> - %s: %d 次\n", cat.Category, cat.Count))
		}
	}

	msg.Markdown = &struct {
		Content string `json:"content"`
	}{
		Content: sb.String(),
	}
	return msg
}

// FormatWeComDailyReportText formats a DailyReport as a WeCom text message
func FormatWeComDailyReportText(report *DailyReport) *WeComMessage {
	msg := &WeComMessage{MsgType: "text"}
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
		formatTopIPsWeCom(report.TopSources),
		formatTopCategoriesWeCom(report.TopCategories))

	msg.Text = &struct {
		Content string `json:"content"`
	}{
		Content: content,
	}
	return msg
}

// formatSeverityWeCom adds emoji prefix based on severity level
func formatSeverityWeCom(severity string) string {
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

func formatTopIPsWeCom(ips []IPStat) string {
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

func formatTopCategoriesWeCom(categories []CategoryStat) string {
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

// SendToWeCom sends a WeCom message to the webhook URL
func SendToWeCom(client *Client, url string, msg *WeComMessage) error {
	webhookMsg := &WebhookMessage{
		Type: "wecom",
		URL:  url,
		Payload: map[string]interface{}{
			"msgtype": msg.MsgType,
		},
	}

	switch msg.MsgType {
	case "text":
		webhookMsg.Payload["text"] = msg.Text
	case "markdown":
		webhookMsg.Payload["markdown"] = msg.Markdown
	case "news":
		webhookMsg.Payload["news"] = msg.News
	}

	return client.Send(webhookMsg)
}

// Unused function kept for future extension
func formatTimeWeCom(t time.Time) string {
	return t.Format("2006-01-02 15:04:05")
}
