package decoder

import (
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type AuditdDecoder struct{}

func NewAuditdDecoder() *AuditdDecoder {
	return &AuditdDecoder{}
}

func (d *AuditdDecoder) Name() string {
	return "auditd"
}

func (d *AuditdDecoder) Decode(line string) (*models.NormalizedLog, error) {
	log := models.NewNormalizedLog()
	log.Source = "auditd"
	log.Program = "auditd"
	log.Raw = line
	log.Timestamp = time.Now()

	if strings.Contains(line, "type=") {
		d.parseAuditLine(log, line)
	}

	return log, nil
}

func (d *AuditdDecoder) parseAuditLine(log *models.NormalizedLog, line string) {
	// type=SYSCALL msg=audit(1713172245.123:456): arch=c000003e syscall=59 success=yes exit=0
	re := regexp.MustCompile(`type=(\w+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.Metadata["audit_type"] = matches[1]
	}

	if msgMatch := regexp.MustCompile(`msg=audit\(([\d.]+):(\d+)\)`); msgMatch.MatchString(line) {
		if matches := msgMatch.FindStringSubmatch(line); matches != nil {
			if ts, err := strconv.ParseFloat(matches[1], 64); err == nil {
				sec := int64(ts)
				log.Timestamp = time.Unix(sec, 0)
			}
		}
	}

	d.parseAuditType(log, line)
}

func (d *AuditdDecoder) parseAuditType(log *models.NormalizedLog, line string) {
	switch {
	case strings.Contains(line, "type=SYSCALL"):
		d.parseSyscall(log, line)
		log.Service = "syscall"
	case strings.Contains(line, "type=EXECVE"):
		d.parseExecve(log, line)
		log.Service = "execve"
		log.Level = "info"
	case strings.Contains(line, "type=CONNECT"):
		d.parseConnect(log, line)
		log.Service = "network"
	case strings.Contains(line, "type=ACCEPT"):
		d.parseAccept(log, line)
		log.Service = "network"
	case strings.Contains(line, "type=USER_AUTH"):
		d.parseUserAuth(log, line)
		log.Service = "auth"
		log.Level = "warning"
	case strings.Contains(line, "type=USER_LOGIN"):
		d.parseUserLogin(log, line)
		log.Service = "login"
	default:
		if strings.Contains(line, "success=no") {
			log.Level = "warning"
		} else {
			log.Level = "info"
		}
	}
}

func (d *AuditdDecoder) parseSyscall(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`syscall=(\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.Metadata["syscall"] = matches[1]
	}

	if successMatch := regexp.MustCompile(`success=(yes|no)`); successMatch.MatchString(line) {
		if matches := successMatch.FindStringSubmatch(line); matches != nil {
			log.Metadata["success"] = matches[1] == "yes"
			if matches[1] == "no" {
				log.Level = "warning"
			}
		}
	}

	exe := regexp.MustCompile(`exe="([^"]+)"`)
	if matches := exe.FindStringSubmatch(line); matches != nil {
		log.Metadata["exe"] = matches[1]
	}
}

func (d *AuditdDecoder) parseExecve(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`a0="([^"]+)"`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.Metadata["argv0"] = matches[1]
		log.Message = "execve: " + matches[1]
	}

	args := regexp.MustCompile(`a(\d+)="([^"]+)"`)
	if matches := args.FindAllStringSubmatch(line, -1); matches != nil {
		var cmdLine []string
		for _, m := range matches {
			cmdLine = append(cmdLine, m[2])
		}
		log.Metadata["args"] = cmdLine
	}
}

func (d *AuditdDecoder) parseConnect(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`saddr=.*?([\d.]+):(\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.DstIP = matches[1]
		log.DstPort, _ = strconv.Atoi(matches[2])
	}

	re = regexp.MustCompile(`dport=(\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.DstPort, _ = strconv.Atoi(matches[1])
	}

	log.Message = "网络连接"
}

func (d *AuditdDecoder) parseAccept(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`saddr=.*?([\d.]+):(\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.SrcIP = matches[1]
		log.SrcPort, _ = strconv.Atoi(matches[2])
	}

	log.Message = "接受连接"
}

func (d *AuditdDecoder) parseUserAuth(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`exe="([^"]+)"\s+.*?auid=(\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.Metadata["exe"] = matches[1]
		log.Metadata["auid"] = matches[2]
	}

	log.Message = "用户认证"
}

func (d *AuditdDecoder) parseUserLogin(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`msg='(?:user|login)\s+(\S+).*?addr=([\d.]+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.User = matches[1]
		log.SrcIP = matches[2]
	}

	log.Message = "用户登录"
}
