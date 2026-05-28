package decoder

import (
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type NginxDecoder struct{}

func NewNginxDecoder() *NginxDecoder {
	return &NginxDecoder{}
}

func (d *NginxDecoder) Name() string {
	return "nginx"
}

func (d *NginxDecoder) Decode(line string) (*models.NormalizedLog, error) {
	log := models.NewNormalizedLog()
	log.Source = "nginx"
	log.Program = "nginx"
	log.Raw = line
	log.Timestamp = time.Now()

	// Nginx 默认格式
	// 192.168.1.50 - - [15/Apr/2024:10:30:45 +0000] "GET /search?q=1' OR 1=1-- HTTP/1.1" 500 1234
	re := regexp.MustCompile(`^([\d.]+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.SrcIP = matches[1]
		log.User = matches[2]

		if ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[3]); err == nil {
			log.Timestamp = ts
		}

		log.Message = matches[4]

		if status, err := strconv.Atoi(matches[5]); err == nil {
			log.Metadata["status"] = status
			log.SrcPort = status
		}

		if size, err := strconv.Atoi(matches[6]); err == nil {
			log.Metadata["size"] = size
		}

		// 解析请求
		d.parseRequest(log, matches[4])

		// 设置日志级别
		d.setLevelByStatus(log, matches[5])
	}

	return log, nil
}

func (d *NginxDecoder) parseRequest(log *models.NormalizedLog, request string) {
	// GET /search?q=1' OR 1=1-- HTTP/1.1
	re := regexp.MustCompile(`^(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\S+)`)
	if matches := re.FindStringSubmatch(request); matches != nil {
		log.Metadata["method"] = matches[1]
		log.Metadata["path"] = matches[2]
		log.Service = matches[2]
	}

	// 解析查询参数
	if idx := strings.Index(request, "?"); idx != -1 {
		query := request[idx+1:]
		if ampIdx := strings.Index(query, " "); ampIdx != -1 {
			query = query[:ampIdx]
		}
		log.Metadata["query"] = query
	}
}

func (d *NginxDecoder) setLevelByStatus(log *models.NormalizedLog, status string) {
	s, _ := strconv.Atoi(status)
	switch {
	case s >= 500:
		log.Level = "error"
	case s >= 400:
		log.Level = "warning"
	case s >= 300:
		log.Level = "info"
	default:
		log.Level = "info"
	}
}

type NginxErrorDecoder struct{}

func NewNginxErrorDecoder() *NginxErrorDecoder {
	return &NginxErrorDecoder{}
}

func (d *NginxErrorDecoder) Name() string {
	return "nginx_error"
}

func (d *NginxErrorDecoder) Decode(line string) (*models.NormalizedLog, error) {
	log := models.NewNormalizedLog()
	log.Source = "nginx"
	log.Program = "nginx"
	log.Raw = line

	// Nginx error log 格式: 2024/04/15 10:30:45 [error] 1234#0: *1 message
	re := regexp.MustCompile(`^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+\d+#\d+:\s*(.*)$`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		if ts, err := time.Parse("2006/01/02 15:04:05", matches[1]); err == nil {
			log.Timestamp = ts
		}
		log.Level = matches[2]
		log.Message = matches[3]
	} else {
		log.Message = line
		log.Level = "error"
	}

	return log, nil
}
