// ly-server - Simplified version
// Uses only standard library + local modules
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// Config holds configuration
type Config struct {
	DBHost     string
	DBPort     int
	DBUser     string
	DBPassword string
	DBName     string
	DBPool     *pgxpool.Pool
	RedisAddr  string
	Redis      *redis.Client
	ServerPort int
}

func loadConfig() *Config {
	cfg := &Config{
		DBHost:     getEnv("DB_HOST", "postgres"),
		DBPort:     toInt(getEnv("DB_PORT", "5432")),
		DBUser:     getEnv("DB_USER", "lyflow"),
		DBPassword: getEnv("DB_PASSWORD", "lyflow_secret_password"),
		DBName:     getEnv("DB_NAME", "lyflow"),
		RedisAddr:  getEnv("REDIS_ADDR", "redis:6379"),
		ServerPort: toInt(getEnv("SERVER_PORT", "8080")),
	}

	// Connect to PostgreSQL
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("Failed to ping PostgreSQL: %v", err)
	}
	cfg.DBPool = pool
	log.Println("PostgreSQL connected")

	// Connect to Redis
	cfg.Redis = redis.NewClient(&redis.Options{
		Addr: cfg.RedisAddr,
	})
	if err := cfg.Redis.Ping(ctx).Err(); err != nil {
		log.Printf("Warning: Redis not connected: %v", err)
	} else {
		log.Println("Redis connected")
	}

	return cfg
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting ly-server v2.0.0...")

	cfg := loadConfig()

	mux := http.NewServeMux()

	// Routes
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/api/v1/health", healthHandler(cfg))
	mux.HandleFunc("/api/v1/stats", statsHandler(cfg))
	mux.HandleFunc("/api/v1/events", eventsHandler(cfg))
	mux.HandleFunc("/api/v1/assets", assetsHandler(cfg))
	mux.HandleFunc("/api/v1/auth/login", loginHandler)

	// Start alert consumer in background
	go startConsumer(cfg)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
		cfg.DBPool.Close()
		cfg.Redis.Close()
	}()

	log.Printf("Server listening on :%d", cfg.ServerPort)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"service": "ly-server",
		"version": "v2.0.0",
		"status":  "running",
	})
}

func healthHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"service":   "ly-server",
		})
	}
}

func statsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		var total, critical, high, medium, low, newEvents int64

		cfg.DBPool.QueryRow(ctx, "SELECT COUNT(*) FROM events").Scan(&total)
		cfg.DBPool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE severity='critical'").Scan(&critical)
		cfg.DBPool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE severity='high'").Scan(&high)
		cfg.DBPool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE severity='medium'").Scan(&medium)
		cfg.DBPool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE severity='low'").Scan(&low)
		cfg.DBPool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE status='new'").Scan(&newEvents)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"total_events":     total,
				"critical_events":  critical,
				"high_events":      high,
				"medium_events":    medium,
				"low_events":       low,
				"new_events":       newEvents,
				"total_assets":     0,
				"online_agents":   0,
				"recent_events_24h": total,
			},
		})
	}
}

func eventsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		limit := toInt(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		offset := toInt(r.URL.Query().Get("offset"))
		if offset < 0 {
			offset = 0
		}

		var total int64
		cfg.DBPool.QueryRow(ctx, "SELECT COUNT(*) FROM events").Scan(&total)

		query := `SELECT id, timestamp, event_type, severity, src_ip, dst_ip, src_port, dst_port, protocol, domain, status
			FROM events ORDER BY timestamp DESC LIMIT $1 OFFSET $2`

		rows, err := cfg.DBPool.Query(ctx, query, limit, offset)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()

		var events []map[string]interface{}
		for rows.Next() {
			var id int64
			var timestamp time.Time
			var eventType, severity, srcIP, dstIP, protocol, domain, status string
			var srcPort, dstPort int
			rows.Scan(&id, &timestamp, &eventType, &severity, &srcIP, &dstIP, &srcPort, &dstPort, &protocol, &domain, &status)
			events = append(events, map[string]interface{}{
				"id":         id,
				"timestamp":  timestamp.Format(time.RFC3339),
				"event_type": eventType,
				"severity":   severity,
				"src_ip":     srcIP,
				"dst_ip":     dstIP,
				"src_port":   srcPort,
				"dst_port":   dstPort,
				"protocol":   protocol,
				"domain":     domain,
				"status":     status,
			})
		}
		if events == nil {
			events = []map[string]interface{}{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"items":  events,
				"total":  total,
				"limit":  limit,
				"offset": offset,
			},
		})
	}
}

func assetsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"items":  []interface{}{},
				"total":  0,
				"limit":  20,
				"offset": 0,
			},
		})
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}

	if req.Username == "admin" && req.Password == "admin123" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"token":      "lyflow-jwt-" + time.Now().Format("20060102150405"),
				"expires_at": time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			},
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(401)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    1,
		"message": "Invalid credentials",
	})
}

// Consumer state
type ConsumerState struct {
	cfg     *Config
	mu      sync.Mutex
	running bool
	stopCh  chan struct{}
}

var consumerState *ConsumerState

func startConsumer(cfg *Config) {
	consumerState = &ConsumerState{
		cfg:     cfg,
		running: true,
		stopCh:  make(chan struct{}),
	}

	go consumerState.run()
	log.Println("Alert consumer started")
}

func (c *ConsumerState) run() {
	for {
		select {
		case <-c.stopCh:
			return
		default:
			c.processAlerts()
			time.Sleep(1 * time.Second)
		}
	}
}

func (c *ConsumerState) processAlerts() {
	ctx := context.Background()

	streams := []string{"alerts:dpi", "alerts:log", "alerts:endpoint"}
	group := "server-workers"

	for _, stream := range streams {
		// Create consumer group if not exists
		c.cfg.Redis.XGroupCreateMkStream(ctx, stream, group, "0")

		// Read new messages
		result, err := c.cfg.Redis.XReadGroup(ctx, &redis.XReadGroupArgs{
			Group:    group,
			Consumer: "server-consumer",
			Streams:  []string{stream, ">"},
			Count:    10,
			Block:    time.Second,
		}).Result()

		if err != nil {
			continue
		}

		for _, sr := range result {
			for _, msg := range sr.Messages {
				c.processMessage(ctx, stream, msg)
				c.cfg.Redis.XAck(ctx, stream, group, msg.ID)
			}
		}
	}
}

func (c *ConsumerState) processMessage(ctx context.Context, stream string, msg redis.XMessage) {
	dataStr, ok := msg.Values["data"].(string)
	if !ok {
		return
	}

	var alert map[string]interface{}
	if err := json.Unmarshal([]byte(dataStr), &alert); err != nil {
		log.Printf("Failed to parse alert: %v", err)
		return
	}

	// Extract fields
	eventType, _ := alert["type"].(string)
	severity := "low"
	if sev, ok := alert["severity"].(float64); ok {
		switch int(sev) {
		case 1:
			severity = "critical"
		case 2:
			severity = "high"
		case 3:
			severity = "medium"
		}
	}

	srcIP, _ := alert["src_ip"].(string)
	dstIP, _ := alert["dst_ip"].(string)
	protocol, _ := alert["protocol"].(string)
	domain, _ := alert["domain"].(string)
	sensorID, _ := alert["sensor_id"].(string)
	category, _ := alert["category"].(string)

	// Insert into events table
	query := `INSERT INTO events (timestamp, event_type, source, severity, src_ip, dst_ip, protocol, domain, tags, status)
		VALUES ($1, $2, $3, $4, $5::inet, $6::inet, $7, $8, $9, $10)`

	_, err := c.cfg.DBPool.Exec(ctx, query,
		time.Now(),
		eventType,
		sensorID,
		severity,
		srcIP,
		dstIP,
		protocol,
		domain,
		[]string{category},
		"new",
	)

	if err != nil {
		log.Printf("Failed to insert event: %v", err)
	}
}