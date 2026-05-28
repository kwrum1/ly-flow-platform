package mock

import (
	"fmt"
	"math/rand"
	"time"
)

type Generator struct {
	hostname string
}

func NewGenerator(hostname string) *Generator {
	return &Generator{
		hostname: hostname,
	}
}

func (g *Generator) GenerateSSHLogs(count int) []string {
	logs := make([]string, 0, count)

	failedUsers := []string{"root", "admin", "user", "test", "oracle", "mysql", "postgres", "ubuntu", "centos"}
	srcIPs := []string{"192.168.1.100", "10.0.0.50", "172.16.0.25", "203.0.113.10", "198.51.100.20"}
	ports := []int{22, 2222, 22022}

	baseTime := time.Now().Add(-time.Hour)

	for i := 0; i < count; i++ {
		t := baseTime.Add(time.Duration(i) * time.Minute)
		month := t.Format("Jan")
		day := fmt.Sprintf("%2d", t.Day())
		timeStr := t.Format("15:04:05")

		user := failedUsers[rand.Intn(len(failedUsers))]
		srcIP := srcIPs[rand.Intn(len(srcIPs))]
		port := ports[rand.Intn(len(ports))]

		patterns := []string{
			fmt.Sprintf("%s %s %s sshd[1234]: Failed password for %s from %s port %d ssh2", month, day, timeStr, user, srcIP, port),
			fmt.Sprintf("%s %s %s %s sshd[5678]: Invalid user %s from %s port %d ssh2", month, day, timeStr, g.hostname, user, srcIP, port),
			fmt.Sprintf("%s %s %s sshd[9012]: error: PAM: Authentication failure for user %s from %s", month, day, timeStr, user, srcIP),
		}

		logs = append(logs, patterns[rand.Intn(len(patterns))])
	}

	return logs
}

func (g *Generator) GenerateNginxLogs(count int) []string {
	logs := make([]string, 0, count)

	srcIPs := []string{"192.168.1.50", "10.10.10.100", "203.0.113.5"}
	paths := []string{
		"/admin/login.php",
		"/search?q=1' OR 1=1--",
		"/wp-admin",
		"/phpmyadmin",
		"/api/users?id=1",
		"/",
		"/login",
		"/dashboard",
	}
	statusCodes := []int{200, 200, 200, 301, 400, 401, 403, 404, 404, 404, 500, 502}

	baseTime := time.Now().Add(-time.Hour)

	for i := 0; i < count; i++ {
		t := baseTime.Add(time.Duration(i) * 30 * time.Second)
		timeStr := t.Format("02/Jan/2006:15:04:05 +0000")

		srcIP := srcIPs[rand.Intn(len(srcIPs))]
		path := paths[rand.Intn(len(paths))]
		status := statusCodes[rand.Intn(len(statusCodes))]
		size := rand.Intn(10000) + 100

		logs = append(logs, fmt.Sprintf(`%s - - [%s] "GET %s HTTP/1.1" %d %d`, srcIP, timeStr, path, status, size))
	}

	return logs
}

func (g *Generator) GenerateMySQLLogs(count int) []string {
	logs := make([]string, 0, count)

	srcIPs := []string{"192.168.1.100", "10.0.0.25", "172.16.0.50"}
	users := []string{"root", "admin", "backup", "repl"}

	baseTime := time.Now().Add(-time.Hour)

	for i := 0; i < count; i++ {
		t := baseTime.Add(time.Duration(i) * 2 * time.Minute)

		srcIP := srcIPs[rand.Intn(len(srcIPs))]
		user := users[rand.Intn(len(users))]

		patterns := []string{
			fmt.Sprintf("%sT%s.000000Z 4 [Note] Access denied for user '%s'@'%s' (using password: YES)", t.Format("2006-01-02"), t.Format("15:04:05"), user, srcIP),
			fmt.Sprintf("%sT%s.000000Z 4 [Warning] Aborted connection %d to db: 'test' user: '%s' host: '%s'", t.Format("2006-01-02"), t.Format("15:04:05"), rand.Intn(1000), user, srcIP),
			fmt.Sprintf("%sT%s.000000Z 5 [Note] Got error 1045: 'Access denied for user '%s'@'%s'", t.Format("2006-01-02"), t.Format("15:04:05"), user, srcIP),
		}

		logs = append(logs, patterns[rand.Intn(len(patterns))])
	}

	return logs
}

func (g *Generator) GenerateSystemdLogs(count int) []string {
	logs := make([]string, 0, count)

	services := []string{"sshd", "systemd", "sudo", "login", "cron"}
	messages := []string{
		"Started user manager for UID 1000",
		"session opened for user admin by (uid=0)",
		"session closed for user admin",
		"Authorized uses for admin sudo: all users; run as users matching group %sudo; no cc requirements",
		"COMMAND=/bin/ls /root",
		"Job scheduled-task.service/start running",
	}

	baseTime := time.Now().Add(-time.Hour)

	for i := 0; i < count; i++ {
		t := baseTime.Add(time.Duration(i) * 45 * time.Second)
		month := t.Format("Jan")
		day := fmt.Sprintf("%2d", t.Day())
		timeStr := t.Format("15:04:05")

		service := services[rand.Intn(len(services))]
		message := messages[rand.Intn(len(messages))]

		logs = append(logs, fmt.Sprintf("%s %s %s %s: %s", month, day, timeStr, service, message))
	}

	return logs
}

func (g *Generator) GenerateAuditdLogs(count int) []string {
	logs := make([]string, 0, count)

	users := []string{"root", "admin", "1000", "33"}
	exes := []string{"/bin/bash", "/usr/bin/curl", "/usr/bin/wget", "/bin/sh", "/usr/bin/python3"}

	baseTime := time.Now().Add(-time.Hour)

	for i := 0; i < count; i++ {
		t := baseTime.Add(time.Duration(i) * 30 * time.Second)
		ts := float64(t.Unix()) + float64(rand.Intn(999))/1000.0
		id := rand.Intn(999999)

		user := users[rand.Intn(len(users))]
		exe := exes[rand.Intn(len(exes))]

		success := "yes"
		if rand.Float32() < 0.1 {
			success = "no"
		}

		logs = append(logs, fmt.Sprintf(`type=SYSCALL msg=audit(%.3f:%d): arch=c000003e syscall=59 success=%s exit=0 a0=7fff1234 a1=7fff5678 a2=7fff9abc a3=0 items=2 ppid=%d pid=%d auid=%s uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=4 comm=bash exe="%s"`, ts, id, success, rand.Intn(5000)+1000, rand.Intn(10000)+5000, user, exe))
	}

	return logs
}

func (g *Generator) GenerateMixedLogs(total int) []string {
	totalLogs := make([]string, 0)

	counts := map[string]int{
		"ssh":    total / 3,
		"nginx":  total / 4,
		"mysql":  total / 6,
		"system": total / 5,
		"audit":  total / 10,
	}

	for source, count := range counts {
		switch source {
		case "ssh":
			totalLogs = append(totalLogs, g.GenerateSSHLogs(count)...)
		case "nginx":
			totalLogs = append(totalLogs, g.GenerateNginxLogs(count)...)
		case "mysql":
			totalLogs = append(totalLogs, g.GenerateMySQLLogs(count)...)
		case "system":
			totalLogs = append(totalLogs, g.GenerateSystemdLogs(count)...)
		case "audit":
			totalLogs = append(totalLogs, g.GenerateAuditdLogs(count)...)
		}
	}

	rand.Shuffle(len(totalLogs), func(i, j int) {
		totalLogs[i], totalLogs[j] = totalLogs[j], totalLogs[i]
	})

	return totalLogs
}
