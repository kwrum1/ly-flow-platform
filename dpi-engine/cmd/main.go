package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ly-flow-platform/dpi-engine/config"
	"ly-flow-platform/dpi-engine/core/domain"
	"ly-flow-platform/dpi-engine/core/engine"
	"ly-flow-platform/dpi-engine/core/output"
	"ly-flow-platform/dpi-engine/core/redis"
	"ly-flow-platform/dpi-engine/core/rules"
)

var (
	version = "v1.0.0"
	commit  = "dev"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("ly-dpi-engine %s (%s) 正在启动...", version, commit)

	cfg := config.Load()
	redisUsername, redisPassword := cfg.Redis.Username, cfg.Redis.Password
	if redisUsername == "" || redisPassword == "" {
		redisUsername, redisPassword = "", cfg.Redis.LegacyPassword
	}

	// 初始化域名审计器
	auditor := domain.New()
	if err := auditor.LoadMiningList(cfg.Domain.MiningPath); err != nil {
		log.Printf("[配置] 警告: 加载挖矿列表失败: %v", err)
	}
	if err := auditor.LoadFraudList(cfg.Domain.FraudPath); err != nil {
		log.Printf("[配置] 警告: 加载欺诈列表失败: %v", err)
	}
	if err := auditor.LoadCustomList(cfg.Domain.CustomPath); err != nil {
		log.Printf("[配置] 警告: 加载自定义列表失败: %v", err)
	}
	log.Printf("[域名] 审计器已初始化")

	// 初始化规则引擎
	ruleEngine := rules.New()
	if err := ruleEngine.LoadRulesFile(cfg.Rules.Path); err != nil {
		log.Printf("[配置] 警告: 加载主规则失败: %v", err)
	}

	mainRuleCount := ruleEngine.RuleCount()
	if err := ruleEngine.LoadDatabaseRules(cfg.Rules.DatabaseDir); err != nil {
		log.Fatalf("[配置] 加载数据库规则失败: %v", err)
	}
	log.Printf("[规则] 已加载 %d 条规则 (主规则 %d 条, 数据库规则 %d 条)", ruleEngine.RuleCount(), mainRuleCount, ruleEngine.RuleCount()-mainRuleCount)

	// 初始化 Redis 消费者
	consumer := redis.NewConsumer(
		cfg.Redis.Addr,
		redisUsername,
		redisPassword,
		cfg.Redis.DB,
		cfg.Input.Stream,
		cfg.Output.Stream,
		cfg.Input.Group,
		cfg.Input.Consumer,
		cfg.Engine.Workers,
		cfg.Engine.BlockSeconds,
	)

	// 初始化输出
	out := output.NewWithStreams(consumer.GetClient(), cfg.Output.Stream, cfg.Output.SemanticStream, cfg.Output.SessionStream)

	// 初始化引擎
	eng := engine.New(consumer, auditor, ruleEngine, out)

	// 启动 HTTP 服务器用于健康检查和指标
	mux := http.NewServeMux()
	setupRoutes(mux, eng)

	server := &http.Server{
		Addr:    cfg.HTTP.Addr,
		Handler: mux,
	}

	go func() {
		log.Printf("[http] 在 %s 上启动服务", cfg.HTTP.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[http] 服务器错误: %v", err)
		}
	}()

	// 启动引擎
	if err := eng.Start(); err != nil {
		log.Fatalf("[引擎] 启动失败: %v", err)
	}

	// 等待关闭信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Println("[主程序] 收到关闭信号")

	// 优雅关闭
	eng.Stop()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[http] 关闭错误: %v", err)
	}

	flows, alerts, matched := eng.Stats()
	log.Printf("[主程序] 关闭完成 (flows: %d, alerts: %d, matched: %d)",
		flows, alerts, matched)
}

func setupRoutes(mux *http.ServeMux, eng *engine.Engine) {
	// 健康检查
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","service":"ly-dpi-engine"}`))
	})

	// 统计端点
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		flows, alerts, matched := eng.Stats()
		fmt.Fprintf(w, `{"flows":%d,"alerts":%d,"matched":%d,"version":"%s"}`,
			flows, alerts, matched, version)
	})

	// Prometheus 指标端点
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		flows, alerts, matched := eng.Stats()
		proc, alrt, err := eng.ConsumerStats()
		sent, outErr := eng.OutputStats()
		transportAccounting, _ := eng.TransportAccounting(r.Context())

		fmt.Fprintf(w, "# HELP dpi_engine_flows_total 已处理的总流量数\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_flows_total counter\n")
		fmt.Fprintf(w, "dpi_engine_flows_total %d\n", flows)
		fmt.Fprintf(w, "# HELP dpi_engine_alerts_total 生成的告警总数\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_alerts_total counter\n")
		fmt.Fprintf(w, "dpi_engine_alerts_total %d\n", alerts)
		fmt.Fprintf(w, "# HELP dpi_engine_matched_total 匹配的规则总数\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_matched_total counter\n")
		fmt.Fprintf(w, "dpi_engine_matched_total %d\n", matched)
		fmt.Fprintf(w, "# HELP dpi_engine_processed_total 已处理的消息总数\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_processed_total counter\n")
		fmt.Fprintf(w, "dpi_engine_processed_total %d\n", proc)
		fmt.Fprintf(w, "# HELP dpi_engine_errors_total 错误总数\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_errors_total counter\n")
		fmt.Fprintf(w, "dpi_engine_redis_errors_total %d\n", err)
		fmt.Fprintf(w, "# HELP dpi_engine_sent_total 已发送的告警总数\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_sent_total counter\n")
		fmt.Fprintf(w, "dpi_engine_sent_total %d\n", sent)
		fmt.Fprintf(w, "# HELP dpi_engine_output_errors_total 输出错误总数\n")
		fmt.Fprintf(w, "# TYPE dpi_engine_output_errors_total counter\n")
		fmt.Fprintf(w, "dpi_engine_output_errors_total %d\n", outErr)
		for name, value := range transportAccounting.Metrics() {
			fmt.Fprintf(w, "%s %d\n", name, value)
		}
		_ = alrt
	})
}
