package webhook

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lyflow/ly-flow-platform/model"
)

// DailyReport represents a daily security report
type DailyReport struct {
	Date          time.Time       `json:"date"`
	TotalAlerts   int             `json:"total_alerts"`
	Critical      int             `json:"critical"`
	High          int             `json:"high"`
	Medium        int             `json:"medium"`
	Low           int             `json:"low"`
	TopSources    []IPStat        `json:"top_sources"`
	TopCategories []CategoryStat  `json:"top_categories"`
	AttackChains  []*AttackChain  `json:"attack_chains"`
}

// IPStat represents statistics for an IP address
type IPStat struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

// CategoryStat represents statistics for an attack category
type CategoryStat struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// AttackChain represents an attack chain analysis
type AttackChain struct {
	Steps       []AttackStep `json:"steps"`
	SourceIP    string       `json:"source_ip"`
	TargetIPs   []string     `json:"target_ips"`
	Duration    time.Duration `json:"duration"`
	AlertCount  int           `json:"alert_count"`
	Severity    string        `json:"severity"`
}

// AttackStep represents a step in an attack chain
type AttackStep struct {
	Timestamp time.Time `json:"timestamp"`
	Category  string    `json:"category"`
	SourceIP  string    `json:"source_ip"`
	TargetIP  string    `json:"target_ip"`
	Signature string    `json:"signature"`
}

// GenerateDailyReport generates a daily report from alerts
func GenerateDailyReport(alerts []*model.Alert, date time.Time) *DailyReport {
	// Normalize date to start of day
	startOfDay := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, date.Location())
	endOfDay := startOfDay.Add(24 * time.Hour)

	// Filter alerts for the given day
	var dayAlerts []*model.Alert
	for _, alert := range alerts {
		if alert.Timestamp.After(startOfDay) && alert.Timestamp.Before(endOfDay) {
			dayAlerts = append(dayAlerts, alert)
		}
	}

	report := &DailyReport{
		Date:          startOfDay,
		TotalAlerts:   len(dayAlerts),
		TopSources:    make([]IPStat, 0),
		TopCategories: make([]CategoryStat, 0),
		AttackChains:  make([]*AttackChain, 0),
	}

	// Count by severity
	severityCounts := make(map[string]int)
	ipCounts := make(map[string]int)
	categoryCounts := make(map[string]int)

	for _, alert := range dayAlerts {
		severity := strings.ToLower(model.SeverityFromUint8(alert.Severity))
		severityCounts[severity]++

		if alert.SrcIP != "" {
			ipCounts[alert.SrcIP]++
		}

		if alert.Category != "" {
			categoryCounts[alert.Category]++
		}
	}

	report.Critical = severityCounts["critical"]
	report.High = severityCounts["high"]
	report.Medium = severityCounts["medium"]
	report.Low = severityCounts["low"]

	// Get top source IPs
	report.TopSources = getTopStats(ipCounts, 10)

	// Get top categories
	report.TopCategories = getTopCategoryStats(categoryCounts, 10)

	// Detect attack chains
	report.AttackChains = detectAttackChains(dayAlerts)

	return report
}

// GenerateWeeklyReport generates a weekly report from daily reports
func GenerateWeeklyReport(dailyReports []*DailyReport) *DailyReport {
	if len(dailyReports) == 0 {
		return nil
	}

	report := &DailyReport{
		Date:          dailyReports[0].Date,
		TopSources:    make([]IPStat, 0),
		TopCategories: make([]CategoryStat, 0),
		AttackChains:  make([]*AttackChain, 0),
	}

	ipCounts := make(map[string]int)
	categoryCounts := make(map[string]int)

	for _, daily := range dailyReports {
		report.TotalAlerts += daily.TotalAlerts
		report.Critical += daily.Critical
		report.High += daily.High
		report.Medium += daily.Medium
		report.Low += daily.Low

		for _, ip := range daily.TopSources {
			ipCounts[ip.IP] += ip.Count
		}

		for _, cat := range daily.TopCategories {
			categoryCounts[cat.Category] += cat.Count
		}
	}

	report.TopSources = getTopStats(ipCounts, 10)
	report.TopCategories = getTopCategoryStats(categoryCounts, 10)

	return report
}

// FormatReportAsText formats a DailyReport as plain text
func FormatReportAsText(report *DailyReport) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("=================================\n"))
	sb.WriteString(fmt.Sprintf("       安全日报 - %s\n", report.Date.Format("2006-01-02")))
	sb.WriteString(fmt.Sprintf("=================================\n\n"))

	sb.WriteString(fmt.Sprintf("【告警统计】\n"))
	sb.WriteString(fmt.Sprintf("  总计: %d 条\n", report.TotalAlerts))
	sb.WriteString(fmt.Sprintf("  🔴 严重: %d\n", report.Critical))
	sb.WriteString(fmt.Sprintf("  🟠 高危: %d\n", report.High))
	sb.WriteString(fmt.Sprintf("  🟡 中危: %d\n", report.Medium))
	sb.WriteString(fmt.Sprintf("  🟢 低危: %d\n\n", report.Low))

	if len(report.TopSources) > 0 {
		sb.WriteString("【Top 攻击源IP】\n")
		for i, ip := range report.TopSources {
			if i >= 5 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %d. %s - %d 次\n", i+1, ip.IP, ip.Count))
		}
		sb.WriteString("\n")
	}

	if len(report.TopCategories) > 0 {
		sb.WriteString("【Top 攻击类型】\n")
		for i, cat := range report.TopCategories {
			if i >= 5 {
				break
			}
			sb.WriteString(fmt.Sprintf("  %d. %s - %d 次\n", i+1, cat.Category, cat.Count))
		}
		sb.WriteString("\n")
	}

	if len(report.AttackChains) > 0 {
		sb.WriteString(fmt.Sprintf("【检测到的攻击链】: %d\n", len(report.AttackChains)))
		for i, chain := range report.AttackChains {
			if i >= 3 {
				sb.WriteString(fmt.Sprintf("  ... 还有 %d 个攻击链\n", len(report.AttackChains)-3))
				break
			}
			sb.WriteString(fmt.Sprintf("  攻击链 #%d:\n", i+1))
			sb.WriteString(fmt.Sprintf("    源IP: %s\n", chain.SourceIP))
			sb.WriteString(fmt.Sprintf("    涉及目标: %d 个\n", len(chain.TargetIPs)))
			sb.WriteString(fmt.Sprintf("    告警数: %d\n", chain.AlertCount))
			sb.WriteString(fmt.Sprintf("    最高级别: %s\n", chain.Severity))
		}
	}

	sb.WriteString(fmt.Sprintf("\n=================================\n"))
	sb.WriteString(fmt.Sprintf("      报告生成时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("=================================\n"))

	return sb.String()
}

// FormatReportAsJSON formats a DailyReport as JSON string
func FormatReportAsJSON(report *DailyReport) (string, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal report: %w", err)
	}
	return string(data), nil
}

// getTopStats returns the top N stats sorted by count
func getTopStats(counts map[string]int, limit int) []IPStat {
	type kv struct {
		Key   string
		Value int
	}

	var ss []kv
	for k, v := range counts {
		ss = append(ss, kv{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	var result []IPStat
	for i, kv := range ss {
		if i >= limit {
			break
		}
		result = append(result, IPStat{
			IP:    kv.Key,
			Count: kv.Value,
		})
	}

	return result
}

// getTopCategoryStats returns the top N category stats sorted by count
func getTopCategoryStats(counts map[string]int, limit int) []CategoryStat {
	type kv struct {
		Key   string
		Value int
	}

	var ss []kv
	for k, v := range counts {
		ss = append(ss, kv{k, v})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value > ss[j].Value
	})

	var result []CategoryStat
	for i, kv := range ss {
		if i >= limit {
			break
		}
		result = append(result, CategoryStat{
			Category: kv.Key,
			Count:    kv.Value,
		})
	}

	return result
}

// detectAttackChains detects potential attack chains from alerts
func detectAttackChains(alerts []*model.Alert) []*AttackChain {
	if len(alerts) < 2 {
		return nil
	}

	// Group alerts by source IP
	alertsBySource := make(map[string][]*model.Alert)
	for _, alert := range alerts {
		if alert.SrcIP != "" {
			alertsBySource[alert.SrcIP] = append(alertsBySource[alert.SrcIP], alert)
		}
	}

	var chains []*AttackChain

	for sourceIP, sourceAlerts := range alertsBySource {
		if len(sourceAlerts) < 2 {
			continue
		}

		// Sort by timestamp
		sort.Slice(sourceAlerts, func(i, j int) bool {
			return sourceAlerts[i].Timestamp.Before(sourceAlerts[j].Timestamp)
		})

		// Check for temporal correlation (alerts within 1 hour)
		timeWindow := 1 * time.Hour
		var currentChain *AttackChain

		for _, alert := range sourceAlerts {
			if currentChain == nil {
				currentChain = &AttackChain{
					Steps:     make([]AttackStep, 0),
					SourceIP:  sourceIP,
					TargetIPs: make([]string, 0),
				}
			}

			// Check if this alert is related to existing chain
			lastStep := AttackStep{Timestamp: alert.Timestamp}
			if len(currentChain.Steps) > 0 {
				lastStep = currentChain.Steps[len(currentChain.Steps)-1]
			}
			timeDiff := alert.Timestamp.Sub(lastStep.Timestamp)

			if timeDiff > timeWindow && len(currentChain.Steps) > 0 {
				// Start a new chain
				chains = append(chains, currentChain)
				currentChain = &AttackChain{
					Steps:     make([]AttackStep, 0),
					SourceIP:  sourceIP,
					TargetIPs: make([]string, 0),
				}
			}

			// Add step to chain
			step := AttackStep{
				Timestamp: alert.Timestamp,
				Category:  alert.Category,
				SourceIP:  alert.SrcIP,
				TargetIP:  alert.DstIP,
				Signature: alert.Signature,
			}
			currentChain.Steps = append(currentChain.Steps, step)

			// Track target IPs
			found := false
			for _, tip := range currentChain.TargetIPs {
				if tip == alert.DstIP {
					found = true
					break
				}
			}
			if !found && alert.DstIP != "" {
				currentChain.TargetIPs = append(currentChain.TargetIPs, alert.DstIP)
			}

			// Update severity
			severity := model.SeverityFromUint8(alert.Severity)
			if severity == "critical" {
				currentChain.Severity = "critical"
			} else if severity == "high" && currentChain.Severity != "critical" {
				currentChain.Severity = "high"
			}
		}

		if currentChain != nil && len(currentChain.Steps) > 1 {
			chains = append(chains, currentChain)
		}
	}

	// Calculate duration and alert count for each chain
	for _, chain := range chains {
		if len(chain.Steps) > 0 {
			chain.Duration = chain.Steps[len(chain.Steps)-1].Timestamp.Sub(chain.Steps[0].Timestamp)
			chain.AlertCount = len(chain.Steps)
		}
	}

	// Sort chains by alert count (most significant first)
	sort.Slice(chains, func(i, j int) bool {
		return chains[i].AlertCount > chains[j].AlertCount
	})

	// Limit to top 10 chains
	if len(chains) > 10 {
		chains = chains[:10]
	}

	return chains
}

// CalculateTrend calculates the trend of alerts compared to previous period
func CalculateTrend(current, previous int) string {
	if previous == 0 {
		if current > 0 {
			return "新增"
		}
		return "持平"
	}

	diff := current - previous
	percent := float64(diff) / float64(previous) * 100

	if diff > 0 {
		return fmt.Sprintf("↑ %.1f%%", percent)
	} else if diff < 0 {
		return fmt.Sprintf("↓ %.1f%%", -percent)
	}
	return "持平"
}
