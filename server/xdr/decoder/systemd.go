package decoder

import (
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type SystemdDecoder struct{}

func NewSystemdDecoder() *SystemdDecoder {
	return &SystemdDecoder{}
}

func (d *SystemdDecoder) Name() string {
	return "systemd"
}

func (d *SystemdDecoder) Decode(line string) (*models.NormalizedLog, error) {
	log := models.NewNormalizedLog()
	log.Source = "systemd"
	log.Raw = line
	log.Timestamp = time.Now()

	// Journald 格式: Apr 15 10:30:45 hostname program[pid]: message
	// 解析时间
	parts := strings.SplitN(line, " ", 4)
	if len(parts) >= 4 {
		if ts := parseJournalTime(line); ts != nil {
			log.Timestamp = *ts
		}
		log.Program = parts[2]
		log.Message = parts[3]

		if pidIdx := strings.Index(log.Program, "["); pidIdx != -1 {
			if endIdx := strings.Index(log.Program, "]"); endIdx != -1 {
				log.Program = log.Program[:pidIdx]
				if pid, err := strconv.Atoi(log.Program[pidIdx+1:endIdx]); err == nil {
					log.Metadata["pid"] = pid
				}
			}
		}
	} else {
		log.Message = line
	}

	d.parseMessage(log, line)

	return log, nil
}

func (d *SystemdDecoder) parseMessage(log *models.NormalizedLog, line string) {
	switch {
	case strings.Contains(line, "started user"):
		log.Level = "info"
		log.Service = "user-session"
	case strings.Contains(line, "session opened"):
		log.Level = "info"
		log.Service = "session"
	case strings.Contains(line, "session closed"):
		log.Level = "info"
		log.Service = "session"
	case strings.Contains(line, "systemd-logind"):
		d.parseLogind(log, line)
	default:
		if strings.Contains(line, "error") || strings.Contains(line, "failed") {
			log.Level = "error"
		} else if strings.Contains(line, "warning") {
			log.Level = "warning"
		} else {
			log.Level = "info"
		}
	}
}

func (d *SystemdDecoder) parseLogind(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`(?:User|Seat|Session)\s+(\S+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.Metadata["logind_target"] = matches[1]
	}

	if strings.Contains(line, "New session") {
		log.Service = "logind-new-session"
	} else if strings.Contains(line, "Removed session") {
		log.Service = "logind-removed-session"
	}
}

func parseJournalTime(line string) *time.Time {
	re := regexp.MustCompile(`^(\w+)\s+(\d+)\s+(\d+:\d+:\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		monthStr := matches[1]
		day, _ := strconv.Atoi(matches[2])
		timeStr := matches[3]

		now := time.Now()
		month := parseMonth(monthStr)

		t, err := time.ParseInLocation("Jan 2 15:04:05", monthStr+" "+strconv.Itoa(day)+" "+timeStr, time.Local)
		if err != nil {
			return nil
		}

		t = time.Date(now.Year(), month, day, t.Hour(), t.Minute(), t.Second(), 0, time.Local)

		if t.Month() == time.December && now.Month() == time.January {
			t = t.AddDate(-1, 0, 0)
		}

		return &t
	}
	return nil
}

type PAMDecoder struct{}

func NewPAMDecoder() *PAMDecoder {
	return &PAMDecoder{}
}

func (d *PAMDecoder) Name() string {
	return "pam"
}

func (d *PAMDecoder) Decode(line string) (*models.NormalizedLog, error) {
	log := models.NewNormalizedLog()
	log.Source = "pam"
	log.Program = "pam"
	log.Raw = line
	log.Timestamp = time.Now()

	if idx := strings.Index(line, ": "); idx != -1 {
		log.Program = strings.TrimSpace(line[:idx])
		log.Message = line[idx+2:]
	} else {
		log.Message = line
	}

	d.parseMessage(log, line)

	return log, nil
}

func (d *PAMDecoder) parseMessage(log *models.NormalizedLog, line string) {
	switch {
	case strings.Contains(line, "authentication failure"):
		log.Level = "warning"
		d.parseAuthFailure(log, line)
	case strings.Contains(line, "session opened"):
		log.Level = "info"
		d.parseSessionOpened(log, line)
	case strings.Contains(line, "session closed"):
		log.Level = "info"
	case strings.Contains(line, "password check failed"):
		log.Level = "warning"
	default:
		log.Level = "info"
	}
}

func (d *PAMDecoder) parseAuthFailure(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`user=(\S+)\s+service=(\S+)\s+user=(\S+)\s+remote(?:host|ip)=([\d.]+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.User = matches[3]
		log.Service = matches[2]
		log.SrcIP = matches[4]
		log.Message = "PAM 认证失败"
	}
}

func (d *PAMDecoder) parseSessionOpened(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`user=(\S+)\s+session opened for user (\S+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.User = matches[2]
		log.Service = matches[1]
	}
}
