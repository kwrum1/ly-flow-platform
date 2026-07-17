package main

import "github.com/redis/go-redis/v9"

func redisOptions(cfg *Config) *redis.Options {
	username := cfg.RedisUsername
	password := cfg.RedisPassword
	if username == "" || password == "" {
		username = ""
		password = cfg.RedisLegacyPassword
	}
	return &redis.Options{Addr: cfg.Redis, Username: username, Password: password}
}
