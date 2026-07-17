package redisconfig

import (
	"os"
	"strings"

	"github.com/redis/go-redis/v9"
)

func Options(addr string, db int) *redis.Options {
	username := strings.TrimSpace(os.Getenv("REDIS_ACL_USERNAME"))
	password := os.Getenv("REDIS_ACL_PASSWORD")
	if username == "" || password == "" {
		username = ""
		password = os.Getenv("REDIS_PASSWORD")
	}
	return &redis.Options{Addr: addr, Username: username, Password: password, DB: db}
}
