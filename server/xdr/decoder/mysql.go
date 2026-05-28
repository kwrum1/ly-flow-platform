package decoder

import (
	"github.com/lyflow/ly-flow-platform/server/xdr/models"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type MySQLDecoder struct{}

func NewMySQLDecoder() *MySQLDecoder {
	return &MySQLDecoder{}
}

func (d *MySQLDecoder) Name() string {
	return "mysql"
}

func (d *MySQLDecoder) Decode(line string) (*models.NormalizedLog, error) {
	log := models.NewNormalizedLog()
	log.Source = "mysql"
	log.Program = "mysqld"
	log.Raw = line
	log.Timestamp = time.Now()

	switch {
	case strings.Contains(line, "Access denied"):
		log.Level = "warning"
		d.parseAccessDenied(log, line)
	case strings.Contains(line, "Got error"):
		log.Level = "error"
		d.parseMySQLError(log, line)
	case strings.Contains(line, "Slow query"):
		log.Level = "info"
		d.parseSlowQuery(log, line)
	case strings.Contains(line, "Query"):
		log.Level = "info"
		d.parseQuery(log, line)
	default:
		if strings.Contains(line, "[Note]") {
			log.Level = "info"
		} else if strings.Contains(line, "[Warning]") {
			log.Level = "warning"
		} else if strings.Contains(line, "[Error]") {
			log.Level = "error"
		}
		log.Message = line
	}

	return log, nil
}

func (d *MySQLDecoder) parseAccessDenied(log *models.NormalizedLog, line string) {
	// Access denied for user 'root'@'192.168.1.100' (using password: YES)
	re := regexp.MustCompile(`Access denied for user '(\S+)'@'([\d.]+)'`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.User = matches[1]
		log.SrcIP = matches[2]
		log.Message = "MySQL 访问拒绝"
	}
}

func (d *MySQLDecoder) parseMySQLError(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`Got error (\d+) (?:from|when|while) (.*)$`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		log.Metadata["error_code"] = matches[1]
		log.Metadata["error_context"] = matches[2]
		log.Message = "MySQL 错误: " + matches[2]
	} else {
		log.Message = line
	}
}

func (d *MySQLDecoder) parseSlowQuery(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`# Query_time: ([\d.]+)\s+Lock_time: ([\d.]+)\s+Rows_sent: (\d+)\s+Rows_examined: (\d+)`)
	if matches := re.FindStringSubmatch(line); matches != nil {
		queryTime, _ := strconv.ParseFloat(matches[1], 64)
		rowsExamined, _ := strconv.Atoi(matches[4])
		log.Metadata["query_time"] = queryTime
		log.Metadata["rows_examined"] = rowsExamined
		log.Message = "MySQL 慢查询"
	}
}

func (d *MySQLDecoder) parseQuery(log *models.NormalizedLog, line string) {
	re := regexp.MustCompile(`# Time: (.*)\n# Query_time: ([\d.]+)\s+.*\nuse (\S+);`)
	if matches := re.FindStringSubmatch(strings.ReplaceAll(line, "\n", " ")); matches != nil {
		log.Metadata["query_time"] = matches[2]
		log.Metadata["database"] = matches[3]
		log.Message = "MySQL 查询"
	}
}

type MySQLSlowLogDecoder struct{}

func NewMySQLSlowLogDecoder() *MySQLSlowLogDecoder {
	return &MySQLSlowLogDecoder{}
}

func (d *MySQLSlowLogDecoder) Name() string {
	return "mysql_slow"
}

func (d *MySQLSlowLogDecoder) Decode(line string) (*models.NormalizedLog, error) {
	log := models.NewNormalizedLog()
	log.Source = "mysql"
	log.Program = "mysqld"
	log.Raw = line
	log.Timestamp = time.Now()
	log.Level = "info"

	// MySQL slow query log 格式
	if strings.Contains(line, "# Time:") {
		re := regexp.MustCompile(`# Time: (\d{6}\s+\d+:\d+:\d+)`)
		if matches := re.FindStringSubmatch(line); matches != nil {
			if ts, err := time.Parse("060102 15:04:05", matches[1]); err == nil {
				log.Timestamp = ts
			}
		}
	}

	if strings.Contains(line, "Query_time:") {
		re := regexp.MustCompile(`Query_time: ([\d.]+)`)
		if matches := re.FindStringSubmatch(line); matches != nil {
			if qt, err := strconv.ParseFloat(matches[1], 64); err == nil {
				log.Metadata["query_time"] = qt
				if qt > 5.0 {
					log.Level = "warning"
				}
			}
		}
		log.Message = "MySQL 慢查询"
	}

	return log, nil
}
