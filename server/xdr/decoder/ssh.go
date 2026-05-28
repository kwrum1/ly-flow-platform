package decoder

import (
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SSHDecoder struct{}

func NewSSHDecoder() *SSHDecoder {
	return &SSHDecoder{}
}

func (d *SSHDecoder) Name() string {
	return "sshd"
}

func (d *SSHDecoder) Decode(line string) (*models.NormalizedLog, error) {
	log := models.NewNormalizedLog()
	log.Source = "sshd"
	log.Program = "sshd"
	log.Raw = line

	// Syslog 格式: Apr 15 10:30:45 hostname sshd[1234]: message
	// SSH 消息格式
	log.Timestamp = parseSyslogTime(line)

	// 提取 PID
	if pidMatch := regexp.MustCompile(`sshd\[(\d+)\]`).FindStringSubmatch(line); pidMatch != nil {
		log.Metadata["pid"] = pidMatch[1]
	}

	// 提取消息内容
	if idx := strings.Index(line, ": "); idx != -1 {
		log.Message = line[idx+2:]
	} else {
		log.Message = line
	}

	// 解析 SSH 消息
	d.parseMessage(log, line)

	return log, nil
}

func (d *SSHDecoder) parseMessage(log *models.NormalizedLog, line string) {
	switch {
	case strings.Contains(line, "Failed password"):
		log.Level = "warning"
		d.parseFailedPassword(log, line)
	case strings.Contains(line, "Accepted password"):
		log.Level = "info"
		d.parseAcceptedPassword(log, line)
	case strings.Contains(line, "Invalid user"):
		log.Level = "warning"
		d.parseInvalidUser(log, line)
	case strings.Contains(line, "illegal user"):
		log.Level = "warning"
		d.parseInvalidUser(log, line)
	case strings.Contains(line, "not allowed because"):
		log.Level = "warning"
		d.parseDeniedUser(log, line)
	case strings.Contains(line, "PAM: Authentication"):
		log.Level = "warning"
		d.parsePAMAuth(log, line)
	case strings.Contains(line, "Connection closed by"):
		log.Level = "info"
		d.parseConnectionClosed(log, line)
	case strings.Contains(line, "Did not receive identification"):
		log.Level = "info"
	case strings.Contains(line, "User child"):
		log.Level = "info"
	default:
		if strings.Contains(line, "error") || strings.Contains(line, "Error") {
			log.Level = "error"
		} else {
			log.Level = "info"
		}
	}
}

func (d *SSHDecoder) parseFailedPassword(log *models.NormalizedLog, line string) {
	// Failed password for root from 192.168.1.100 port 22 ssh2
	re := regexp.MustCompile(`Failed password for (\S+) from ([\d.]+) port (\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.User = matches[1]
		log.SrcIP = matches[2]
		log.SrcPort, _ = strconv.Atoi(matches[3])
	}
}

func (d *SSHDecoder) parseAcceptedPassword(log *models.NormalizedLog, line string) {
	// Accepted password for admin from 192.168.1.50 port 54321 ssh2
	re := regexp.MustCompile(`Accepted password for (\S+) from ([\d.]+) port (\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.User = matches[1]
		log.SrcIP = matches[2]
		log.SrcPort, _ = strconv.Atoi(matches[3])
	}
}

func (d *SSHDecoder) parseInvalidUser(log *models.NormalizedLog, line string) {
	// Invalid user admin from 192.168.1.100 port 12345 ssh2
	re := regexp.MustCompile(`(?:Invalid|illegal) user (\S+) from ([\d.]+) port (\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.User = matches[1]
		log.SrcIP = matches[2]
		log.SrcPort, _ = strconv.Atoi(matches[3])
	}
}

func (d *SSHDecoder) parseDeniedUser(log *models.NormalizedLog, line string) {
	// User admin from 192.168.1.100 not allowed because
	re := regexp.MustCompile(`User (\S+) from ([\d.]+) not allowed`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.User = matches[1]
		log.SrcIP = matches[2]
	}
}

func (d *SSHDecoder) parsePAMAuth(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`error: PAM: Authentication failure for user (\S+) from ([\d.]+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.User = matches[1]
		log.SrcIP = matches[2]
	}
}

func (d *SSHDecoder) parseConnectionClosed(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`Connection closed by (?:authenticating )?user (\S+) ([\d.]+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.User = matches[1]
		log.SrcIP = matches[2]
	}
}

func parseSyslogTime(line string) time.Time {
	now := time.Now()
	// 提取月份和日期
	re := regexp.MustCompile(`^(\w+)\s+(\d+)\s+(\d+:\d+:\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		monthStr := matches[1]
		day, _ := strconv.Atoi(matches[2])
		timeStr := matches[3]

		month := parseMonth(monthStr)
		timestamp := time.Date(now.Year(), month, day, 0, 0, 0, 0, time.UTC)
		if parsed, err := time.ParseInLocation("Jan 2 15:04:05", monthStr, time.Local); err == nil {
			timestamp = time.Date(now.Year(), parsed.Month(), day, parsed.Hour(), parsed.Minute(), parsed.Second(), 0, time.Local)
		}
		_ = timeStr

		if timestamp.Month() == time.December && now.Month() == time.January {
			timestamp = timestamp.AddDate(-1, 0, 0)
		} else if timestamp.Month() == time.January && now.Month() == time.December {
			timestamp = timestamp.AddDate(1, 0, 0)
		}

		return timestamp
	}
	return now
}

func parseMonth(s string) time.Month {
	months := map[string]time.Month{
		"Jan": time.January, "Feb": time.February, "Mar": time.March,
		"Apr": time.April, "May": time.May, "Jun": time.June,
		"Jul": time.July, "Aug": time.August, "Sep": time.September,
		"Oct": time.October, "Nov": time.November, "Dec": time.December,
	}
	if m, ok := months[s]; ok {
		return m
	}
	return time.January
}
