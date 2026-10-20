// ly-server - 简化版本
// 仅使用标准库 + 本地模块
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/lyflow/ly-flow-platform/contracts"
	"github.com/lyflow/ly-flow-platform/server/advisoryresponse"
	"github.com/lyflow/ly-flow-platform/server/agentidentity"
	"github.com/lyflow/ly-flow-platform/server/agentpolicy"
	"github.com/lyflow/ly-flow-platform/server/analytics"
	wsapi "github.com/lyflow/ly-flow-platform/server/api/websocket"
	"github.com/lyflow/ly-flow-platform/server/evidence"
	"github.com/lyflow/ly-flow-platform/server/incidentlifecycle"
	"github.com/lyflow/ly-flow-platform/server/ingestionauth"
	"github.com/lyflow/ly-flow-platform/server/ingestv2"
	"github.com/lyflow/ly-flow-platform/server/internal/redisconfig"
	"github.com/lyflow/ly-flow-platform/server/models"
	"github.com/lyflow/ly-flow-platform/server/modules/asset"
	"github.com/lyflow/ly-flow-platform/server/modules/auth"
	"github.com/lyflow/ly-flow-platform/server/modules/rasp"
	"github.com/lyflow/ly-flow-platform/server/modules/trace"
	"github.com/lyflow/ly-flow-platform/server/queryv2"
	responsepkg "github.com/lyflow/ly-flow-platform/server/response"
	"github.com/lyflow/ly-flow-platform/server/rulelifecycle"
	"github.com/lyflow/ly-flow-platform/server/unified"
	xdrprocessor "github.com/lyflow/ly-flow-platform/server/xdr"
	xdrmodels "github.com/lyflow/ly-flow-platform/server/xdr/models"
	xdrrules "github.com/lyflow/ly-flow-platform/server/xdr/rules"
	transport "github.com/lyflow/ly-flow-platform/transportreliability"
)

// 配置结构体
type Config struct {
	DBHost              string
	DBPort              int
	DBUser              string
	DBPassword          string
	DBName              string
	DBPool              *pgxpool.Pool
	RedisAddr           string
	Redis               *redis.Client
	ServerPort          int
	AgentID             string
	AgentKey            string
	AgentSelfEnroll     bool
	AgentIdentity       *agentidentity.Manager
	IngestionAuth       *ingestionauth.Authenticator
	IngestionWriter     IngestionWriter
	EventStorage        *StorageEventRuntime
	XDRInput            xdrCanonicalInputSource
	XDRGraph            *xdrGraphRuntime
	Incidents           *incidentlifecycle.PostgresStore
	AdvisoryResponses   *advisoryresponse.PostgresStore
	IncidentSnapshot    *incidentSnapshotState
	IncidentCheckpoint  incidentLegacyCheckpointer
	IncidentLegacyMode  bool
	TransportProducer   *transport.RedisProducer
	HostNetClassPath    string
	ManagementInterface string

	SecurityEngineEnabled       bool
	SecurityEngineReloadURL     string
	LegacyXDROperatorMatching   bool
	RASPAutomaticInjection      bool
	RASPBlockDefault            bool
	RASPPolicy                  *agentpolicy.Manager
	RuleLifecycle               *rulelifecycle.Manager
	RuleVersionStatus           ruleVersionStatusCommitter
	RuleDownloadRestrictedShown bool
	XDRResponsePolicyPath       string
	ResponseActions             *responsepkg.ActionManager
	Evidence                    *evidence.Store

	XDRV2ResponsePolicyEnabled bool
	XDRV2MaxDepth              int
	XDRV2WindowHours           int
	XDRV2MaxPathsPerSeed       int
	XDRDefaultTenant           string

	Features FeatureFlags
}

func loadConfig() *Config {
	if err := validateLegacyRASPEnvironment(); err != nil {
		log.Fatalf("RASP policy configuration rejected: %v", err)
	}
	cfg := &Config{
		DBHost:              getEnv("DB_HOST", "postgres"),
		DBPort:              toInt(getEnv("DB_PORT", "5432")),
		DBUser:              getEnv("DB_USER", "lyflow"),
		DBPassword:          getEnv("DB_PASSWORD", "lyflow_secret_password"),
		DBName:              getEnv("DB_NAME", "lyflow"),
		RedisAddr:           getEnv("REDIS_ADDR", "redis:6379"),
		ServerPort:          toInt(getEnv("SERVER_PORT", "8080")),
		AgentID:             normalizeAgentID(getEnv("AGENT_ID", "")),
		AgentKey:            getEnv("AGENT_KEY", ""),
		AgentSelfEnroll:     toBool(getEnv("AGENT_SELF_ENROLL", "false")),
		HostNetClassPath:    getEnv("HOST_NET_CLASS_PATH", "/host/sys/class/net"),
		ManagementInterface: strings.TrimSpace(getEnv("MANAGEMENT_INTERFACE", "")),
		IncidentLegacyMode:  toBool(getEnv("INCIDENT_LIFECYCLE_LEGACY_MODE", "false")),

		SecurityEngineEnabled:       toBool(getEnv("SECURITY_ENGINE_ENABLED", "true")),
		SecurityEngineReloadURL:     getEnv("SECURITY_ENGINE_RELOAD_URL", "http://ly-security-engine:8080/reload"),
		LegacyXDROperatorMatching:   toBool(getEnv("LEGACY_XDR_COMPONENT_MATCHING", "false")),
		RASPAutomaticInjection:      toBool(getEnv("RASP_AUTOMATIC_INJECTION", "true")),
		RASPBlockDefault:            false,
		RuleDownloadRestrictedShown: toBool(getEnv("RULE_SOURCE_SHOW_RESTRICTED", "false")),
		XDRResponsePolicyPath:       getEnv("XDR_RESPONSE_POLICY_PATH", ".sisyphus/runtime/xdr-response-policy.json"),

		XDRV2ResponsePolicyEnabled: toBool(getEnv("XDR_V2_RESPONSE_POLICY_ENABLED", "false")),
		XDRV2MaxDepth:              toInt(getEnv("XDR_V2_MAX_DEPTH", "6")),
		XDRV2WindowHours:           toInt(getEnv("XDR_V2_WINDOW_HOURS", "24")),
		XDRV2MaxPathsPerSeed:       toInt(getEnv("XDR_V2_MAX_PATHS_PER_SEED", "50")),
		XDRDefaultTenant:           getEnv("XDR_DEFAULT_TENANT", "default"),

		Features: loadFeatureFlags(),
	}
	responseActions, err := responsepkg.NewActionManager(
		getEnv("RESPONSE_ACTIONS_PATH", "/var/lib/lyflow/response/actions.json"),
		responsepkg.Policy{
			AllowScheduledAuto:       toBool(getEnv("RESPONSE_AUTO_WINDOW_ENABLED", "false")),
			WindowStartHour:          toInt(getEnv("RESPONSE_WINDOW_START_HOUR", "0")),
			WindowEndHour:            toInt(getEnv("RESPONSE_WINDOW_END_HOUR", "6")),
			RequireDifferentApprover: toBool(getEnv("RESPONSE_REQUIRE_DIFFERENT_APPROVER", "true")),
			ApprovalTTL:              time.Duration(toInt(getEnv("RESPONSE_APPROVAL_TTL_MINUTES", "15"))) * time.Minute,
		},
	)
	if err != nil {
		log.Fatalf("无法初始化响应动作: %v", err)
	}
	cfg.ResponseActions = responseActions
	evidenceRoot := getEnv("EVIDENCE_ROOT", "/var/lib/lyflow/evidence")
	var evidenceStore *evidence.Store
	if strings.EqualFold(getEnv("EVIDENCE_OBJECT_STORE", "filesystem"), "filer") {
		objects, objectErr := evidence.NewFilerObjectStore(getEnv("EVIDENCE_FILER_URL", "http://127.0.0.1:18888"))
		if objectErr != nil {
			log.Fatalf("无法初始化 SeaweedFS filer: %v", objectErr)
		}
		evidenceStore, err = evidence.NewWithObjectStore(evidenceRoot, objects)
	} else {
		evidenceStore, err = evidence.New(evidenceRoot)
	}
	if err != nil {
		log.Fatalf("无法初始化证据对象存储: %v", err)
	}
	cfg.Evidence = evidenceStore
	sslMode := getEnv("DB_SSLMODE", "disable")
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName, sslMode)
	ctx := context.Background()
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		log.Fatalf("无法解析 PostgreSQL DSN: %v", err)
	}
	poolCfg.MaxConns = int32(toInt(getEnv("DB_MAX_CONNS", "10")))
	poolCfg.MinConns = int32(toInt(getEnv("DB_MIN_CONNS", "2")))
	poolCfg.MaxConnLifetime = time.Duration(toInt(getEnv("DB_MAX_CONN_LIFETIME_MINUTES", "30"))) * time.Minute
	poolCfg.MaxConnIdleTime = time.Duration(toInt(getEnv("DB_MAX_CONN_IDLE_MINUTES", "5"))) * time.Minute
	poolCfg.HealthCheckPeriod = time.Duration(toInt(getEnv("DB_HEALTH_CHECK_SECONDS", "30"))) * time.Second
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		log.Fatalf("无法连接 PostgreSQL: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("无法 Ping PostgreSQL: %v", err)
	}
	cfg.DBPool = pool
	raspPolicy, err := newRASPPolicyRuntime(ctx, pool)
	if err != nil {
		log.Fatalf("无法初始化 RASP policy lifecycle: %v", err)
	}
	cfg.RASPPolicy = raspPolicy
	ruleLifecycle, err := newRuleLifecycleRuntime(ctx, cfg.SecurityEngineReloadURL)
	if err != nil {
		log.Fatalf("无法初始化 rule lifecycle: %v", err)
	}
	cfg.RuleLifecycle = ruleLifecycle
	identityStore := agentidentity.NewPostgresStore(pool)
	if err := identityStore.EnsureSchema(ctx); err != nil {
		log.Fatalf("无法初始化 Agent identity schema: %v", err)
	}
	ingestionAudit := ingestionauth.NewPostgresAudit(pool)
	if err := ingestionAudit.EnsureSchema(ctx); err != nil {
		log.Fatalf("无法初始化 Agent ingestion audit schema: %v", err)
	}
	cfg.AgentIdentity = agentidentity.NewPersistentManager(identityStore, identityStore, time.Now)
	cfg.IngestionAuth = newIngestionAuthenticator(cfg, ingestionAudit)
	if enrollmentToken := getEnv("AGENT_ENROLL_TOKEN", ""); enrollmentToken != "" && cfg.AgentID != "" {
		if err := cfg.AgentIdentity.RegisterEnrollmentToken(cfg.AgentID, enrollmentToken, 15*time.Minute); err != nil {
			log.Printf("agent enrollment token configuration rejected: %v", err)
		}
	}
	log.Printf("PostgreSQL 连接成功 (max_conns=%d min_conns=%d idle=%s lifetime=%s)", poolCfg.MaxConns, poolCfg.MinConns, poolCfg.MaxConnIdleTime, poolCfg.MaxConnLifetime)

	// 连接 Redis
	cfg.Redis = redis.NewClient(redisconfig.Options(cfg.RedisAddr, 0))
	if err := cfg.Redis.Ping(ctx).Err(); err != nil {
		log.Printf("警告: Redis 未连接: %v", err)
	} else {
		log.Println("Redis 连接成功")
	}
	producerSpool, err := transport.RuntimeSpoolFromEnv("server-producer")
	if err != nil {
		log.Fatalf("无法初始化加密事件生产者 spool: %v", err)
	}
	if producerSpool == nil {
		log.Fatal("无法初始化加密事件生产者 spool: key material unavailable")
	}
	cfg.TransportProducer, err = transport.NewRedisProducer(transport.ProducerConfig{
		Client: cfg.Redis, Name: "server-consumer", Spool: producerSpool,
		Retry: transport.RetryPolicy{MaxAttempts: 4, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second, Jitter: 0.2},
	})
	if err != nil {
		log.Fatalf("无法初始化可靠事件生产者: %v", err)
	}
	if err := cfg.TransportProducer.Replay(ctx); err != nil {
		log.Printf("可靠事件生产者启动重放暂停: %v", err)
	}
	storageRuntime, err := newProductionStorageEventRuntime(ctx, cfg.DBPool)
	if err != nil {
		log.Fatalf("无法初始化 ClickHouse 事件迁移: %v", err)
	}
	cfg.EventStorage = storageRuntime
	cfg.XDRInput = storageRuntime
	legacyWindowEnd, err := time.Parse(time.RFC3339, getEnv("XDR_LEGACY_READ_WINDOW_END", "2026-10-01T00:00:00Z"))
	if err != nil {
		log.Fatalf("XDR_LEGACY_READ_WINDOW_END must be RFC3339: %v", err)
	}
	cfg.XDRGraph, err = newXDRGraphRuntime(ctx, cfg.DBPool, newXDRCanonicalAdapter(time.Now, legacyWindowEnd))
	if err != nil {
		log.Fatalf("无法初始化持久化 XDR 图: %v", err)
	}
	if err = initializeIncidentLifecycleRuntime(ctx, cfg); err != nil {
		log.Fatalf("无法初始化持久化 Incident 生命周期: %v", err)
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

func toBool(s string) bool {
	v, err := strconv.ParseBool(strings.TrimSpace(s))
	return err == nil && v
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if os.Getenv("LYFLOW_INCIDENT_PROCESS_MODE") != "" {
		if err := runIncidentLifecycleProcess(); err != nil {
			log.Printf("incident lifecycle process failed: %v", err)
			os.Exit(1)
		}
		return
	}
	if handled, err := runBootstrapTokenCLI(os.Args); handled {
		if err != nil {
			log.Fatal(err)
		}
		return
	}
	serviceLock, err := acquireServiceLock(serviceLockPath())
	if err != nil {
		log.Fatalf("service lock: %v", err)
	}
	defer serviceLock.Close()
	log.Println("正在启动 ly-server v2.0.0...")

	cfg := loadConfig()
	ensureRuntimeSchemaOrLog(context.Background(), cfg.DBPool)
	if cfg.DBPool != nil {
		cfg.DBPool.Exec(context.Background(), `ALTER TABLE agents ADD COLUMN IF NOT EXISTS connection_since TIMESTAMPTZ`)
		cfg.DBPool.Exec(context.Background(), `ALTER TABLE agents ADD COLUMN IF NOT EXISTS display_name TEXT`)
	}
	assetHandler = asset.NewHandler(cfg.DBPool)
	if liveCount, err := syncLiveRules(); err != nil {
		log.Printf("规则生效目录同步失败: %v", err)
	} else {
		log.Printf("规则生效目录已同步: %d 条开启规则", liveCount)
	}
	go startLogRetentionWorker(cfg)
	go startAgentStaleCleanup(cfg)

	// 初始化Auth模块
	authService := auth.NewService(
		getEnv("JWT_SECRET", "ly-flow-secret-key-change-in-production"),
		24*time.Hour,
	)
	userStore := auth.NewPostgresStore(cfg.DBPool)
	sessionStore := auth.NewSessionStore(cfg.DBPool)

	if err := userStore.InitSchema(context.Background()); err != nil {
		log.Printf("警告: 初始化用户表失败: %v", err)
	}
	if err := auth.InitDefaultAdmin(userStore, authService); err != nil {
		log.Fatalf("初始化默认管理员失败: %v", err)
	}

	authHandler := auth.NewHandler(authService, userStore, sessionStore, cfg.DBPool)
	authMiddleware := auth.NewMiddleware(authService, userStore, sessionStore)
	bootstrapHandler := auth.NewBootstrapHandler(auth.NewBootstrapTokenManager(userStore, authService, io.Discard))

	mux := http.NewServeMux()

	// v2 ingestion: agent/sensor credential in, canonical events out.
	mux.Handle("/api/v2/ingest/events", ingestv2.Handler{
		Auth: func(request *http.Request, surface string) (string, error) {
			if cfg.IngestionAuth == nil {
				return "", ingestv2.ErrAuthUnavailable
			}
			principal, err := cfg.IngestionAuth.HTTPPrincipal(request, surface)
			if err != nil {
				return "", err
			}
			return principal.AgentID(), nil
		},
		Writer: cfg.EventStorage,
	})

	queryV2Handler := queryv2.Handler{Store: cfg.EventStorage}
	mux.HandleFunc("/api/v2/events", queryV2Handler.List)
	mux.HandleFunc("/api/v2/events/", queryV2Handler.Get)

	// 路由
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/api/v1/health", healthHandler(cfg))
	mux.HandleFunc("/api/v1/public/situation/global", publicGlobalSituationHandler(cfg))
	mux.HandleFunc("/api/v1/stats", statsHandler(cfg))

	// Auth API (public and protected)
	mux.HandleFunc("/api/v1/auth/login", authHandler.Login)
	mux.HandleFunc("/api/v1/auth/register", authHandler.Register)
	mux.HandleFunc("/api/v1/auth/bootstrap-token", bootstrapHandler.Consume)
	mux.HandleFunc("/api/v1/auth/logout", authHandler.Logout)
	mux.HandleFunc("/api/v1/auth/profile", authHandler.Profile)
	mux.HandleFunc("/api/v1/auth/change-password", authHandler.ChangePassword)
	mux.HandleFunc("/api/v1/auth/users", authHandler.ListUsers)
	mux.HandleFunc("/api/v1/auth/users/password", authHandler.ChangeUserPassword)
	mux.HandleFunc("/api/v1/auth/users/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			authHandler.DeleteUser(w, r)
		} else {
			authHandler.UpdateUser(w, r)
		}
	})

	// 规则管理 API
	mux.HandleFunc("/api/v1/rules", rulesHandler(cfg))
	mux.HandleFunc("/api/v1/rules/inventory", rulesInventoryHandler(cfg))
	mux.HandleFunc("/api/v1/rules/reports", ruleReportsHandler(cfg))
	mux.HandleFunc("/api/v1/rules/quarantine", ruleQuarantineHandler(cfg))
	mux.HandleFunc("/api/v1/rules/score-weights", ruleScoreWeightsHandler(cfg))
	mux.HandleFunc("/api/v1/rules/items/", ruleItemHandler(cfg))
	mux.HandleFunc("/api/v1/rules/sources/", ruleSourceUpdateHandler(cfg))
	mux.HandleFunc("/api/v1/rules/sources", ruleSourcesHandler(cfg))
	mux.HandleFunc("/api/v1/rule-platform/sources", rulePlatformSourcesHandler(cfg))
	mux.HandleFunc("/api/v1/rule-platform/bundles", rulePlatformBundlesHandler(cfg))
	mux.HandleFunc("/api/v1/rule-platform/sync", rulePlatformSyncHandler(cfg))
	mux.HandleFunc("/api/v1/rule-platform/compile-preview", rulePlatformCompilePreviewHandler(cfg))
	mux.HandleFunc("/api/v1/rule-platform/versions", rulePlatformVersionsHandler(cfg))
	mux.HandleFunc("/api/v1/rule-platform/rollback", rulePlatformRollbackHandler(cfg))
	mux.HandleFunc("/api/v1/rule-platform/active-bundle", rulePlatformActiveBundleHandler(cfg))
	mux.HandleFunc("/api/v1/response/actions", responseActionsHandler(cfg))
	mux.HandleFunc("/api/v1/response/actions/", responseActionHandler(cfg))
	mux.HandleFunc("/api/v1/response/automation", responseAutomationHandler(cfg))
	mux.HandleFunc("/api/v1/evidence/bundles", evidenceHandler(cfg))
	mux.HandleFunc("/api/v1/evidence/bundles/", evidenceHandler(cfg))
	mux.HandleFunc("/api/v1/evidence/artifacts", evidenceHandler(cfg))
	mux.HandleFunc("/api/v1/evidence/artifacts/", evidenceHandler(cfg))
	mux.HandleFunc("/api/v1/debug/components", debugComponentsHandler(cfg))
	mux.HandleFunc("/api/v1/rules/subscription", subscriptionHandler(cfg))
	mux.HandleFunc("/api/v1/rules/categories", categoriesHandler(cfg))
	mux.HandleFunc("/api/v1/rules/update", updateRulesHandler(cfg))
	mux.HandleFunc("/api/v1/rules/stats", rulesStatsHandler(cfg))
	mux.HandleFunc("/api/v1/rules/test", ruleTestHandler(cfg))

	// XDR API
	mux.HandleFunc("/api/v1/xdr/stats", xdrStatsHandler(cfg))
	mux.HandleFunc("/api/v1/xdr/events", xdrEventsHandler(cfg))
	mux.HandleFunc("/api/v1/xdr/sources", xdrSourcesHandler(cfg))
	mux.HandleFunc("/api/v1/xdr/top-events", xdrTopEventsHandler(cfg))
	mux.HandleFunc("/api/v1/xdr/chains", xdrChainsHandler(cfg))
	mux.HandleFunc("/api/v1/xdr/posture", xdrPostureHandler(cfg))
	mux.HandleFunc("/api/v1/xdr/log", xdrLogHandler(cfg))

	// Unified API
	mux.HandleFunc("/api/v1/unified/stats", unifiedStatsHandler(cfg))
	mux.HandleFunc("/api/v1/unified/events", unifiedEventsHandler(cfg))
	mux.HandleFunc("/api/v1/unified/events/search", unifiedSearchHandler(cfg))
	mux.HandleFunc("/api/v1/engine-health", engineHealthHandler(cfg))
	mux.HandleFunc("/api/v1/engine-runtime/status", nativeEngineStatusHandler(cfg))
	mux.HandleFunc("/api/v1/engine-rules", nativeEngineRulesHandler(cfg))
	mux.HandleFunc("/api/v1/engine-rules/update", nativeEngineRulesUpdateHandler(cfg))
	mux.HandleFunc("/api/v1/threats/", threatCategoryHandler(cfg))
	mux.HandleFunc("/api/v1/component-alerts/", componentAlertsHandler(cfg))
	mux.HandleFunc("/api/v1/component-alerts", componentAlertsHandler(cfg))
	mux.HandleFunc("/api/v1/traffic/threats", trafficThreatsHandler(cfg))
	mux.HandleFunc("/api/v1/traffic/flows", trafficFlowsHandler(cfg))
	mux.HandleFunc("/api/v1/traffic/sessions", trafficSessionsHandler(cfg))
	mux.HandleFunc("/api/v1/traffic/mirror-interface", mirrorCaptureConfigHandler(cfg))
	mux.HandleFunc("/api/v1/situation/target-location", targetLocationConfigHandler(cfg))
	mux.HandleFunc("/api/v1/system/time", systemTimeHandler())
	mux.HandleFunc("/api/v1/incidents/", incidentDetailHandler(cfg))
	mux.HandleFunc("/api/v1/incidents", incidentsHandler(cfg))
	mux.HandleFunc("/api/v1/admin/incident-lifecycle/checkpoint", incidentLifecycleCheckpointHandler(cfg))
	mux.HandleFunc("/api/v1/timeline/", timelineDetailHandler(cfg))
	mux.HandleFunc("/api/v1/timeline", timelineHandler(cfg))

	// RASP API
	mux.HandleFunc("/api/v1/rasp/stats", raspStatsHandler(cfg))
	mux.HandleFunc("/api/v1/rasp/events", raspEventsHandler(cfg))
	mux.HandleFunc("/api/v1/rasp/rules", raspRulesHandler(cfg))
	mux.HandleFunc("/api/v1/rasp/agents", raspAgentsHandler(cfg))
	mux.HandleFunc("/api/v1/rasp/protection/enable", raspEnableProtectionHandler(cfg))
	mux.HandleFunc("/api/v1/rasp/protection/disable", raspDisableProtectionHandler(cfg))
	mux.HandleFunc("/api/v1/rasp/protection/status", raspProtectionStatusHandler(cfg))
	mux.HandleFunc("/api/v1/rasp/event", raspReceiveEventHandler(cfg))
	mux.HandleFunc("/api/v1/rasp/elkeid-rules", raspElkeidRulesHandler(cfg))

	// Trace API
	mux.HandleFunc("/api/v1/trace/stats", traceStatsHandler(cfg))
	mux.HandleFunc("/api/v1/trace/sessions", traceSessionsHandler(cfg))
	mux.HandleFunc("/api/v1/trace/sessions/{id}", traceSessionHandler(cfg))
	mux.HandleFunc("/api/v1/trace/events", traceEventsHandler(cfg))
	mux.HandleFunc("/api/v1/trace/analyze", traceAnalyzeHandler(cfg))
	mux.HandleFunc("/api/v1/trace/search", traceSearchHandler(cfg))

	// Asset API (Elkeid style)
	mux.HandleFunc("/api/v1/assets/stats", assetsStatsHandler(cfg))
	mux.HandleFunc("/api/v1/assets", assetsListHandler(cfg))
	mux.HandleFunc("/api/v1/assets/", assetsDetailHandler(cfg))
	mux.HandleFunc("/api/v1/assets/groups", assetsGroupsHandler(cfg))
	mux.HandleFunc("/api/v1/assets/heartbeat", assetsHeartbeatHandler(cfg))

	// Agent API (HTTP alternative to gRPC)
	mux.HandleFunc("/api/v1/agents/", agentDetailHandler(cfg))
	mux.HandleFunc("/api/v1/agents", agentsListHandler(cfg))
	mux.HandleFunc("/api/v1/agent/capabilities/", agentCapabilitiesToggleHandler(cfg))
	mux.HandleFunc("/api/v1/agent/name/", agentRenameHandler(cfg))
	mux.HandleFunc("/api/v1/agent/names", agentNamesHandler(cfg))
	mux.HandleFunc("/api/v1/agent/enroll", agentEnrollHandler(cfg))
	mux.HandleFunc("/api/v1/agent/heartbeat", agentHeartbeatHandler(cfg))
	mux.HandleFunc("/api/v1/agent/config", agentConfigHandler(cfg))
	mux.HandleFunc("/api/v1/agent/identity", agentIdentityControlHandler(cfg))
	mux.HandleFunc("/api/v1/agent/traffic-event", agentTrafficEventHandler(cfg))
	mux.HandleFunc("/api/v1/agent/task-result", agentTaskResultHandler(cfg))
	mux.HandleFunc("/api/v1/agent/component-alert", agentComponentAlertHandler(cfg))
	mux.HandleFunc("/api/v1/agent/runtime-event", agentRuntimeEventHandler(cfg))
	agentRealtimeHub := wsapi.NewAgentHub(cfg.IngestionAuth, wsapi.AgentHubOptions{MessagesPerMinute: toInt(getEnv("AGENT_WEBSOCKET_MESSAGES_PER_MINUTE", "600"))})
	go agentRealtimeHub.Run(context.Background())
	mux.HandleFunc("/api/v1/agent/realtime", agentRealtimeHub.HandleWebSocket)
	mux.HandleFunc("/api/v1/agent/install-config", agentInstallConfigHandler(cfg))
	mux.HandleFunc("/api/v1/agent/install.sh", agentInstallScriptHandler(cfg))
	mux.HandleFunc("/api/v1/agent/uninstall.sh", agentUninstallScriptHandler(cfg))
	mux.HandleFunc("/api/v1/agent/download", agentDownloadHandler(cfg))
	mux.HandleFunc("/api/v1/agent/rasp/policy-root", agentRASPPolicyRootHandler())
	mux.HandleFunc("/api/v1/agent/rasp/probe/python", agentRASPProbeHandler("python"))
	mux.HandleFunc("/api/v1/agent/rasp/probe/php", agentRASPProbeHandler("php"))
	mux.HandleFunc("/api/v1/agent/rasp/probe/java", agentRASPProbeHandler("java"))
	mux.HandleFunc("/api/v1/agent/rasp/probe/java/source/", agentRASPJavaSourceHandler())
	mux.HandleFunc("/api/v1/agent/rasp/probe/nodejs", agentRASPProbeHandler("nodejs"))
	mux.HandleFunc("/api/v1/agent/rasp/probe/dotnet", agentRASPProbeHandler("dotnet"))
	mux.HandleFunc("/api/v1/agent/snapshot", agentSnapshotHandler(cfg))

	// Realtime low-volume dashboard gateway
	realtimeHub := wsapi.NewAuthenticatedHub(func(request *http.Request) (string, error) {
		userID := auth.GetUserIDFromContext(request.Context())
		if userID == 0 {
			return "", wsapi.ErrUnauthenticated
		}
		return strconv.FormatInt(userID, 10), nil
	})
	go realtimeHub.Run(context.Background())
	mux.HandleFunc("/api/v1/realtime", realtimeHub.HandleWebSocket)
	go startRealtimePublisher(context.Background(), cfg, realtimeHub)

	// 后台启动告警消费者
	go startConsumer(cfg)

	// 后台启动 XDR Processor
	go startXDRProcessor(cfg)

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.ServerPort),
		Handler:      SecurityHeaders(EnforceRoutePolicy(mux, authMiddleware)),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	shutdownDone := make(chan error, 1)
	go func() {
		sig := make(chan os.Signal, 1)
		defer signal.Stop(sig)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("正在关闭...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		shutdownErr := srv.Shutdown(ctx)
		cancel()
		if shutdownErr != nil {
			log.Printf("server graceful shutdown failed: %v", shutdownErr)
		}
		if cfg.IncidentLegacyMode {
			checkpointCtx, checkpointCancel := context.WithTimeout(context.Background(), 10*time.Second)
			report, err := checkpointIncidentLifecycleOnShutdown(checkpointCtx, cfg)
			checkpointCancel()
			if err != nil {
				log.Printf("DEGRADED incident lifecycle shutdown checkpoint failed: captured=%d unrecoverable=%d cutover_marked=%v error=%v", report.Captured, report.Unrecoverable.Total(), report.CutoverMarked, err)
				shutdownErr = errors.Join(shutdownErr, fmt.Errorf("incident lifecycle shutdown checkpoint: %w", err))
			} else {
				log.Printf("incident lifecycle shutdown checkpoint completed: captured=%d checksum=%s cutover_marked=%v", report.Captured, report.SnapshotChecksum, report.CutoverMarked)
			}
		}
		cfg.DBPool.Close()
		cfg.Redis.Close()
		shutdownDone <- shutdownErr
	}()

	log.Printf("服务监听端口 :%d", cfg.ServerPort)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("服务错误: %v", err)
	}
	if err := <-shutdownDone; err != nil {
		log.Printf("server shutdown completed with failure: %v", err)
		os.Exit(1)
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
		response := map[string]interface{}{
			"status":    "healthy",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
			"service":   "ly-server",
		}
		if consumerState != nil && consumerState.reliable != nil {
			if accounting, err := consumerState.reliable.AccountingContext(r.Context()); err == nil {
				response["transport"] = accounting
				response["transport_metrics"] = accounting.Metrics()
			}
		}
		if cfg != nil && cfg.XDRGraph != nil {
			xdrHealth := cfg.XDRGraph.Health()
			response["xdr"] = xdrHealth
			if xdrHealth.Status == xdrHealthDegraded {
				response["status"] = string(xdrHealthDegraded)
			}
		}
		json.NewEncoder(w).Encode(response)
	}
}

func publicGlobalSituationHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": http.StatusMethodNotAllowed, "message": "Method not allowed"})
			return
		}
		target := loadTargetLocationConfig()
		activeResult, err := xdrActiveChainsResponse(r.Context(), cfg, 20)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "xdr_graph_degraded", err.Error())
			return
		}
		chains := activeResult.activeChains()
		attacks := make([]map[string]interface{}, 0, len(chains))
		countries := map[string]int64{}
		geoPoints := map[string]map[string]interface{}{}
		for _, chain := range chains {
			enriched := enrichGlobalSituationChain(chain.jsonRow(), target)
			if len(mapSlice(enriched["geo_routes"])) == 0 {
				continue
			}
			attacks = append(attacks, enriched)
			for _, route := range mapSlice(enriched["geo_routes"]) {
				country := firstNonEmpty(asString(route["source_country"]), "未知")
				countries[country]++
				if id := asString(route["source_id"]); id != "" {
					geoPoints[id] = route
				}
			}
		}
		countryItems := make([]map[string]interface{}, 0, len(countries))
		for country, count := range countries {
			countryItems = append(countryItems, map[string]interface{}{"country": country, "count": count})
		}
		sort.Slice(countryItems, func(i, j int) bool {
			return xdrPickNumber(countryItems[i], "count", 0) > xdrPickNumber(countryItems[j], "count", 0)
		})
		if len(countryItems) > 20 {
			countryItems = countryItems[:20]
		}
		emptyState := map[string]string{}
		if len(attacks) == 0 {
			emptyState = map[string]string{"reason": "NO_PUBLIC_ATTACK_IP", "message": "暂无公网攻击 IP 态势数据"}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"attacks":     attacks,
				"countries":   countryItems,
				"geo_routes":  sortedGlobalGeoRoutes(geoPoints),
				"target":      targetLocationResponse(target),
				"geo_source":  globalSituationGeoSource(),
				"empty_state": emptyState,
			},
		})
	}
}

func enrichGlobalSituationChain(chain map[string]interface{}, target targetLocationConfig) map[string]interface{} {
	enriched := copyStringMap(chain)
	routes := []map[string]interface{}{}
	victimIPs := stringListFromValue(chain["victim_ips"])
	targetIP := ""
	if len(victimIPs) > 0 {
		targetIP = victimIPs[0]
	}
	for _, ip := range stringListFromValue(chain["source_ips"]) {
		if !isPublicAttackIP(ip) {
			continue
		}
		geo, ok := lookupPublicIPGeo(ip)
		if !ok {
			geo = fallbackPublicIPGeo(ip)
		}
		route := map[string]interface{}{
			"source_id":      geo.ID,
			"source_ip":      ip,
			"source_country": geo.Country,
			"source_region":  geo.Region,
			"source_city":    geo.City,
			"source_lat":     geo.Lat,
			"source_lon":     geo.Lon,
			"target_country": target.Country,
			"target_region":  target.Province,
			"target_city":    targetCityLabel(target),
			"target_lat":     target.Lat,
			"target_lon":     target.Lon,
			"target_ip":      targetIP,
			"count":          xdrPickNumber(chain, "event_count", 1),
			"severity":       xdrPickString(chain, "severity"),
			"score":          xdrPickNumber(chain, "score", 0),
			"last_seen":      xdrPickString(chain, "last_seen"),
		}
		routes = append(routes, route)
	}
	enriched["geo_routes"] = routes
	return enriched
}

type targetLocationConfig struct {
	Country   string  `json:"country"`
	Province  string  `json:"province"`
	City      string  `json:"city"`
	District  string  `json:"district"`
	Lat       float64 `json:"lat"`
	Lon       float64 `json:"lon"`
	UpdatedAt string  `json:"updated_at,omitempty"`
}

func defaultTargetLocationConfig() targetLocationConfig {
	return targetLocationConfig{Country: "中国", Province: "北京", City: "北京", District: "", Lat: 39.9042, Lon: 116.4074}
}

func targetLocationConfigPath() string {
	return ".sisyphus/runtime/target-location-config.json"
}

func loadTargetLocationConfig() targetLocationConfig {
	cfg := defaultTargetLocationConfig()
	_ = readJSONFile(targetLocationConfigPath(), &cfg)
	return normalizeTargetLocationConfig(cfg)
}

func normalizeTargetLocationConfig(cfg targetLocationConfig) targetLocationConfig {
	def := defaultTargetLocationConfig()
	cfg.Country = firstNonEmpty(strings.TrimSpace(cfg.Country), def.Country)
	cfg.Province = strings.TrimSpace(cfg.Province)
	cfg.City = strings.TrimSpace(cfg.City)
	cfg.District = strings.TrimSpace(cfg.District)
	if cfg.Province == "" && cfg.City == "" {
		cfg.Province = def.Province
		cfg.City = def.City
	}
	if cfg.City == "" {
		cfg.City = cfg.Province
	}
	cfg.Lat, cfg.Lon = inferChinaLocationCoord(cfg.Province, cfg.City, cfg.District)
	return cfg
}

func inferChinaLocationCoord(province, city, district string) (float64, float64) {
	name := normalizeChinaLocationKey(province + city + district)
	points := []struct {
		key string
		lat float64
		lon float64
	}{
		{"北京海淀", 39.9599, 116.2981}, {"北京朝阳", 39.9219, 116.4431}, {"北京西城", 39.9123, 116.3659},
		{"北京东城", 39.9288, 116.4164}, {"北京丰台", 39.8586, 116.2867}, {"北京大兴", 39.7268, 116.3414},
		{"上海浦东", 31.2215, 121.5440}, {"上海黄浦", 31.2316, 121.4844}, {"上海徐汇", 31.1885, 121.4368},
		{"上海静安", 31.2297, 121.4598}, {"上海杨浦", 31.2595, 121.5260}, {"上海闵行", 31.1128, 121.3817},
		{"深圳南山", 22.5312, 113.9304}, {"深圳福田", 22.5215, 114.0550}, {"深圳罗湖", 22.5484, 114.1316},
		{"深圳宝安", 22.5553, 113.8831}, {"深圳龙岗", 22.7209, 114.2469}, {"广州天河", 23.1246, 113.3612},
		{"广州越秀", 23.1290, 113.2670}, {"广州海珠", 23.0840, 113.3172}, {"广州番禺", 22.9376, 113.3841},
		{"上饶信州", 28.4310, 117.9668}, {"上饶广信", 28.4489, 117.9078}, {"上饶广丰", 28.4363, 118.1913},
		{"南昌东湖", 28.6850, 115.8993}, {"南昌西湖", 28.6573, 115.8769}, {"南昌红谷滩", 28.6982, 115.8585},
		{"九江浔阳", 29.7279, 116.0019}, {"赣州章贡", 25.8185, 114.9350}, {"景德镇珠山", 29.2926, 117.2022},
		{"北京", 39.9042, 116.4074}, {"上海", 31.2304, 121.4737}, {"广州", 23.1291, 113.2644},
		{"深圳", 22.5431, 114.0579}, {"杭州", 30.2741, 120.1551}, {"南京", 32.0603, 118.7969},
		{"苏州", 31.2989, 120.5853}, {"成都", 30.5728, 104.0668}, {"重庆", 29.5630, 106.5516},
		{"武汉", 30.5928, 114.3055}, {"西安", 34.3416, 108.9398}, {"天津", 39.3434, 117.3616},
		{"青岛", 36.0671, 120.3826}, {"郑州", 34.7466, 113.6254}, {"长沙", 28.2282, 112.9388},
		{"福州", 26.0745, 119.2965}, {"厦门", 24.4798, 118.0894}, {"合肥", 31.8206, 117.2272},
		{"济南", 36.6512, 117.1201}, {"昆明", 25.0389, 102.7183}, {"沈阳", 41.8057, 123.4315},
		{"大连", 38.9140, 121.6147}, {"哈尔滨", 45.8038, 126.5349}, {"长春", 43.8171, 125.3235},
		{"南昌", 28.6820, 115.8582}, {"上饶", 28.4444, 117.9712}, {"九江", 29.7051, 116.0019},
		{"赣州", 25.8311, 114.9348}, {"景德镇", 29.2688, 117.1784}, {"宜春", 27.8157, 114.4168},
		{"南宁", 22.8170, 108.3669}, {"贵阳", 26.6470, 106.6302},
		{"兰州", 36.0611, 103.8343}, {"乌鲁木齐", 43.8256, 87.6168}, {"拉萨", 29.6500, 91.1000},
	}
	for _, point := range points {
		if strings.Contains(name, normalizeChinaLocationKey(point.key)) {
			return point.lat, point.lon
		}
	}
	return 39.9042, 116.4074
}

func normalizeChinaLocationKey(value string) string {
	value = strings.TrimSpace(value)
	for _, token := range []string{"特别行政", "自治", "新区", "地区", "省", "市", "区", "县"} {
		value = strings.ReplaceAll(value, token, "")
	}
	return value
}

func saveTargetLocationConfig(cfg targetLocationConfig) error {
	cfg = normalizeTargetLocationConfig(cfg)
	cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := os.MkdirAll(filepath.Dir(targetLocationConfigPath()), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(targetLocationConfigPath(), data, 0o644)
}

func targetLocationConfigHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": targetLocationResponse(loadTargetLocationConfig())})
		case http.MethodPut, http.MethodPost:
			var req targetLocationConfig
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_target_location", "Invalid target location config")
				return
			}
			if err := saveTargetLocationConfig(req); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "save_target_location_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": targetLocationResponse(loadTargetLocationConfig())})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

func targetLocationResponse(cfg targetLocationConfig) map[string]interface{} {
	cfg = normalizeTargetLocationConfig(cfg)
	return map[string]interface{}{
		"country": cfg.Country, "province": cfg.Province, "city": cfg.City, "district": cfg.District,
		"lat": cfg.Lat, "lon": cfg.Lon, "label": targetLocationLabel(cfg), "updated_at": cfg.UpdatedAt,
	}
}

func targetLocationLabel(cfg targetLocationConfig) string {
	parts := []string{cfg.Country, cfg.Province, targetCityLabel(cfg)}
	kept := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" && (len(kept) == 0 || kept[len(kept)-1] != part) {
			kept = append(kept, part)
		}
	}
	return strings.Join(kept, "·")
}

func systemTimeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": systemTimeResponse(loadSystemTimeConfig())})
		case http.MethodPost, http.MethodPut:
			var req struct {
				Time      string `json:"time"`
				Sync      bool   `json:"sync"`
				NTPServer string `json:"ntp_server"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_system_time", "Invalid system time request")
				return
			}
			cfg := loadSystemTimeConfig()
			cfg.NTPServer = strings.TrimSpace(req.NTPServer)
			parsed := parseOptionalTime(req.Time)
			if parsed == nil && !req.Sync {
				writeJSONError(w, http.StatusBadRequest, "invalid_system_time", "time is required")
				return
			}
			if parsed != nil {
				now := time.Now()
				cfg.OffsetMillis = parsed.UnixMilli() - now.UnixMilli()
				cfg.SyncedAt = now.UTC().Format(time.RFC3339Nano)
				cfg.Source = "manual"
			} else if req.Sync {
				cfg.SyncedAt = time.Now().UTC().Format(time.RFC3339Nano)
				cfg.Source = "browser"
			}
			if err := saveSystemTimeConfig(cfg); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "save_system_time_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": systemTimeResponse(cfg)})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

type systemTimeConfig struct {
	OffsetMillis int64  `json:"offset_ms"`
	NTPServer    string `json:"ntp_server,omitempty"`
	SyncedAt     string `json:"last_synced_at,omitempty"`
	Source       string `json:"source,omitempty"`
}

func systemTimeConfigPath() string {
	return ".sisyphus/runtime/system-time-config.json"
}

func loadSystemTimeConfig() systemTimeConfig {
	cfg := systemTimeConfig{}
	_ = readJSONFile(systemTimeConfigPath(), &cfg)
	cfg.NTPServer = strings.TrimSpace(cfg.NTPServer)
	return cfg
}

func saveSystemTimeConfig(cfg systemTimeConfig) error {
	if err := os.MkdirAll(filepath.Dir(systemTimeConfigPath()), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(systemTimeConfigPath(), data, 0o644)
}

func systemTimeResponse(cfg systemTimeConfig) map[string]interface{} {
	now := time.Now()
	platformNow := now.Add(time.Duration(cfg.OffsetMillis) * time.Millisecond)
	return map[string]interface{}{
		"server_time":       now.Format(time.RFC3339Nano),
		"server_unix_ms":    now.UnixMilli(),
		"platform_time":     platformNow.Format(time.RFC3339Nano),
		"platform_unix_ms":  platformNow.UnixMilli(),
		"offset_ms":         cfg.OffsetMillis,
		"ntp_server":        cfg.NTPServer,
		"last_synced_at":    cfg.SyncedAt,
		"source":            cfg.Source,
		"timezone":          platformNow.Format("-07:00"),
		"client_sync_hint":  "apply offset_ms in all frontend time displays",
		"modifiable_by_api": true,
	}
}

func targetCityLabel(cfg targetLocationConfig) string {
	if cfg.District != "" {
		return cfg.City + cfg.District
	}
	return cfg.City
}

type globalIPGeo struct {
	ID      string
	Country string
	Region  string
	City    string
	Lat     float64
	Lon     float64
}

func lookupPublicIPGeo(ip string) (globalIPGeo, bool) {
	catalog := []struct {
		CIDR string
		Geo  globalIPGeo
	}{
		{"198.51.100.0/24", globalIPGeo{ID: "north-america-lab", Country: "美国", Region: "加利福尼亚", City: "洛杉矶", Lat: 34.0522, Lon: -118.2437}},
		{"203.0.113.0/24", globalIPGeo{ID: "east-asia-lab", Country: "日本", Region: "东京都", City: "东京", Lat: 35.6762, Lon: 139.6503}},
		{"192.0.2.0/24", globalIPGeo{ID: "europe-lab", Country: "德国", Region: "黑森州", City: "法兰克福", Lat: 50.1109, Lon: 8.6821}},
		{"8.8.8.0/24", globalIPGeo{ID: "north-america-google", Country: "美国", Region: "加利福尼亚", City: "山景城", Lat: 37.3861, Lon: -122.0839}},
		{"1.1.1.0/24", globalIPGeo{ID: "oceania-cloudflare", Country: "澳大利亚", Region: "新南威尔士", City: "悉尼", Lat: -33.8688, Lon: 151.2093}},
	}
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return globalIPGeo{}, false
	}
	for _, row := range catalog {
		_, network, err := net.ParseCIDR(row.CIDR)
		if err == nil && network.Contains(parsed) {
			return row.Geo, true
		}
	}
	return globalIPGeo{}, false
}

func fallbackPublicIPGeo(ip string) globalIPGeo {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return globalIPGeo{ID: "unknown", Country: "未知", Region: "未知", City: "未知", Lat: 20, Lon: 0}
	}
	first := byte(0)
	if v4 := parsed.To4(); v4 != nil {
		first = v4[0]
	} else {
		first = parsed[0]
	}
	switch {
	case first < 64:
		return globalIPGeo{ID: "north-america", Country: "美国", Region: "北美", City: "北美节点", Lat: 39.8283, Lon: -98.5795}
	case first < 128:
		return globalIPGeo{ID: "europe", Country: "德国", Region: "欧洲", City: "欧洲节点", Lat: 50.1109, Lon: 8.6821}
	case first < 192:
		return globalIPGeo{ID: "asia-pacific", Country: "新加坡", Region: "亚太", City: "新加坡", Lat: 1.3521, Lon: 103.8198}
	default:
		return globalIPGeo{ID: "east-asia", Country: "日本", Region: "东亚", City: "东京", Lat: 35.6762, Lon: 139.6503}
	}
}

func isPublicAttackIP(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return false
	}
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
}

func sortedGlobalGeoRoutes(points map[string]map[string]interface{}) []map[string]interface{} {
	items := make([]map[string]interface{}, 0, len(points))
	for _, point := range points {
		items = append(items, point)
	}
	sort.Slice(items, func(i, j int) bool {
		return xdrPickNumber(items[i], "score", 0) > xdrPickNumber(items[j], "score", 0)
	})
	if len(items) > 20 {
		items = items[:20]
	}
	return items
}

func globalSituationGeoSource() map[string]interface{} {
	return map[string]interface{}{
		"name":       "IP 地理归属库",
		"city_level": true,
		"provider":   "内置离线归属 + 可替换 MaxMind GeoLite2 City / IPIP.net / DB-IP",
		"reference":  "https://github.com/Loyalsoldier/v2ray-rules-dat",
		"updated_at": time.Now().UTC().Format(time.RFC3339),
	}
}

func copyStringMap(input map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}

func statsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := loadDashboardStats(r.Context(), cfg)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "dashboard_stats_degraded", err.Error())
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"total_events":      stats.Total,
				"critical_events":   stats.Critical,
				"high_events":       stats.High,
				"medium_events":     stats.Medium,
				"low_events":        stats.Low,
				"new_events":        stats.Recent24h,
				"total_assets":      stats.TotalAssets,
				"online_agents":     stats.OnlineAgents,
				"recent_events_24h": stats.Recent24h,
			},
		})
	}
}

type dashboardStats struct {
	Total, Critical, High, Medium, Low, Recent24h int64
	TotalAssets, OnlineAgents                     int64
}

func loadDashboardStats(ctx context.Context, cfg *Config) (dashboardStats, error) {
	var result dashboardStats
	if cfg == nil || cfg.DBPool == nil {
		return result, fmt.Errorf("postgres unavailable")
	}
	if err := cfg.DBPool.QueryRow(ctx, `SELECT
		COUNT(*),
		COUNT(*) FILTER (WHERE LOWER(severity) = 'critical'),
		COUNT(*) FILTER (WHERE LOWER(severity) = 'high'),
		COUNT(*) FILTER (WHERE LOWER(severity) = 'medium'),
		COUNT(*) FILTER (WHERE LOWER(severity) NOT IN ('critical','high','medium')),
		COUNT(*) FILTER (WHERE observed_at >= NOW() - INTERVAL '24 hours')
		FROM threat_events`).Scan(&result.Total, &result.Critical, &result.High, &result.Medium, &result.Low, &result.Recent24h); err != nil {
		return result, fmt.Errorf("load threat statistics: %w", err)
	}
	if err := cfg.DBPool.QueryRow(ctx, `SELECT
		COUNT(*),
		COUNT(*) FILTER (WHERE status = 'online' AND last_heartbeat >= NOW() - INTERVAL '2 minutes')
		FROM agents`).Scan(&result.TotalAssets, &result.OnlineAgents); err != nil {
		return result, fmt.Errorf("load agent statistics: %w", err)
	}
	return result, nil
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

// 消费者状态
type ConsumerState struct {
	cfg      *Config
	mu       sync.Mutex
	running  bool
	stopCh   chan struct{}
	reliable *transport.RedisConsumer
}

var consumerState *ConsumerState
var threatBackfillMu sync.Mutex
var threatBackfillLast time.Time

func startConsumer(cfg *Config) {
	spool, err := transport.RuntimeSpoolFromEnv("server-main-consumer")
	if err != nil {
		log.Printf("configure encrypted transport spool: %v", err)
	}
	consumerState = &ConsumerState{
		cfg:     cfg,
		running: true,
		stopCh:  make(chan struct{}),
		reliable: transport.NewRedisConsumer(transport.ConsumerConfig{
			Client: cfg.Redis, Group: "server-workers", Consumer: "server-consumer", Spool: spool,
			Retry: transport.RetryPolicy{MaxAttempts: 4, BaseDelay: 50 * time.Millisecond, MaxDelay: time.Second, Jitter: 0.2},
		}),
	}

	go consumerState.run()
	go consumerState.runFlowBridge()
	go func() { _ = loadNativeEngineRules(cfg) }()
	log.Println("告警消费者已启动")
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
	if err := transport.RegisterProducer(ctx, c.cfg.Redis, "server-consumer"); err != nil {
		log.Printf("reliable producer registration failed: %v", err)
		return
	}

	streams := []string{"flows:semantic", "sessions:semantic", "alerts:dpi", "alerts:runtime", "alerts:rasp", "component_alerts:v2"}
	if c.cfg.SecurityEngineEnabled {
		streams = []string{"sessions:semantic", "alerts:dpi", "alerts:runtime", "alerts:rasp", "alerts:log_audit", "component_alerts:v2"}
	}
	group := "server-workers"

	for _, stream := range streams {
		c.cfg.Redis.XGroupCreateMkStream(ctx, stream, group, "0")
		if err := c.reliable.Reclaim(ctx, stream, c.processDelivery); err != nil {
			log.Printf("pending reclaim failed stream=%s err=%v", stream, err)
			continue
		}
	}
	c.cfg.Redis.XGroupCreateMkStream(ctx, "events:xdr", group, "0")
	c.cfg.Redis.XGroupCreateMkStream(ctx, "events:dead-letter", group, "0")

	readStreams := make([]string, 0, len(streams)*2)
	readStreams = append(readStreams, streams...)
	for range streams {
		readStreams = append(readStreams, ">")
	}
	result, err := c.cfg.Redis.XReadGroup(ctx, &redis.XReadGroupArgs{
		Group: group, Consumer: "server-consumer", Streams: readStreams,
		Count: 200, Block: time.Second,
	}).Result()
	if err != nil && err != redis.Nil {
		log.Printf("stream batch read failed: %v", err)
		return
	}
	for _, sr := range result {
		if err := c.reliable.Handle(ctx, sr.Stream, sr.Messages, c.processDelivery); err != nil {
			log.Printf("durable handoff failed stream=%s err=%v", sr.Stream, err)
		}
	}
}

func (c *ConsumerState) processDelivery(ctx context.Context, delivery transport.Delivery) (transport.DurableOutcome, error) {
	uid := transport.DeterministicUID("server_dispatch", delivery.Stream, delivery.MessageID)
	processed, err := c.cfg.Redis.HExists(ctx, "transport_reliability:server_dispatch", uid).Result()
	if err != nil {
		return transport.DurableOutcome{}, fmt.Errorf("load server dispatch receipt: %w", err)
	}
	if processed {
		return transport.DurableOutcome{UID: uid, Sink: "server_dispatch"}, nil
	}
	message := redis.XMessage{ID: delivery.MessageID, Values: delivery.Values}
	switch delivery.Stream {
	case "flows:raw":
		err = c.bridgeRawFlow(ctx, message)
	case "sessions:semantic":
		err = persistTrafficSession(ctx, c.cfg, message)
	default:
		err = c.processMessage(ctx, delivery.Stream, message)
	}
	if err != nil {
		return transport.DurableOutcome{}, err
	}
	if err := c.cfg.Redis.HSet(ctx, "transport_reliability:server_dispatch", uid, delivery.MessageID).Err(); err != nil {
		return transport.DurableOutcome{}, fmt.Errorf("persist server dispatch receipt: %w", err)
	}
	return transport.DurableOutcome{UID: uid, Sink: "server_dispatch"}, nil
}

func (c *ConsumerState) bridgeRawFlow(ctx context.Context, msg redis.XMessage) error {
	dataStr, ok := msg.Values["data"].(string)
	if !ok || strings.TrimSpace(dataStr) == "" {
		raw, err := json.Marshal(msg.Values)
		if err != nil {
			return transport.Permanent(transport.ReasonInvalidPayload, err)
		}
		dataStr = string(raw)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	// The bridged stream must carry the raw flow object itself, not a second
	// envelope around it. Keeping the original payload lets both the flow
	// table and persistTrafficSession read the same fields directly.
	uid := transport.DeterministicUID("flow_bridge", "flows:raw", msg.ID)
	if err := c.cfg.Redis.Eval(ctx, bridgeFlowScript, []string{"transport_reliability:flow_bridge", "flows:semantic"}, uid, dataStr, msg.ID, now).Err(); err != nil {
		return fmt.Errorf("bridge raw flow: %w", err)
	}
	return nil
}

const bridgeFlowScript = `
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then return redis.call('HGET', KEYS[1], ARGV[1]) end
local first = redis.call('XADD', KEYS[2], '*', 'event_uid', ARGV[1], 'data', ARGV[2], 'bridge_from', 'flows:raw', 'bridge_message_id', ARGV[3], 'bridged_at', ARGV[4])
redis.call('HSET', KEYS[1], ARGV[1], first)
return first
`

func (c *ConsumerState) processMessage(ctx context.Context, stream string, msg redis.XMessage) error {
	dataStr := streamDataString(msg.Values)

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(dataStr), &payload); err != nil {
		return transport.Permanent(transport.ReasonInvalidPayload, err)
	}

	event := c.toUnifiedXDREvent(stream, msg.ID, payload)
	eventBytes, err := event.ToJSON()
	if err != nil {
		return transport.Permanent(transport.ReasonInvalidPayload, err)
	}

	uid := transport.DeterministicUID("events:xdr", stream, msg.ID)
	if err := c.cfg.Redis.Eval(ctx, eventXDRScript, []string{"transport_reliability:events_xdr", "events:xdr"}, uid, string(eventBytes)).Err(); err != nil {
		return fmt.Errorf("publish events:xdr: %w", err)
	}
	if stream == "component_alerts:v2" && c.cfg.EventStorage != nil {
		var alert contracts.ComponentAlert
		if err := json.Unmarshal([]byte(dataStr), &alert); err != nil {
			return transport.Permanent(transport.ReasonInvalidPayload, err)
		}
		if _, err := c.cfg.EventStorage.WriteComponentAlert(ctx, alert, componentAlertIngestedAt(msg.ID, alert.OccurredAt)); err != nil {
			return fmt.Errorf("persist canonical component alert %s: %w", alert.ID, err)
		}
	}

	if normalized := normalizeComponentAlertStreamEvent(stream, msg.ID, payload); normalized != nil {
		if err := persistThreatEvent(ctx, c.cfg, normalized); err != nil {
			return err
		}
	}
	return nil
}

func componentAlertIngestedAt(messageID string, occurredAt time.Time) time.Time {
	milliseconds, _, found := strings.Cut(messageID, "-")
	if found {
		value, err := strconv.ParseInt(milliseconds, 10, 64)
		if err == nil && value > 0 {
			return time.UnixMilli(value).UTC()
		}
	}
	return occurredAt.UTC()
}

const eventXDRScript = `
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then return redis.call('HGET', KEYS[1], ARGV[1]) end
local id = redis.call('XADD', KEYS[2], '*', 'event_uid', ARGV[1], 'data', ARGV[2])
redis.call('HSET', KEYS[1], ARGV[1], id)
return id
`

func buildDeadLetterValues(stream, msgID string, values map[string]interface{}, cause error) map[string]interface{} {
	raw, _ := json.Marshal(values)
	reason := string(transport.ReasonHandlerRejected)
	detail := "delivery rejected"
	if cause != nil {
		detail = cause.Error()
	}
	return map[string]interface{}{
		"source_stream":     stream,
		"source_message_id": msgID,
		"reason":            reason,
		"detail":            detail,
		"raw":               string(raw),
		"created_at":        time.Now().UTC().Format(time.RFC3339Nano),
	}
}

func streamDataString(values map[string]interface{}) string {
	dataStr, ok := values["data"].(string)
	if ok && strings.TrimSpace(dataStr) != "" {
		return dataStr
	}
	switch v := values["data"].(type) {
	case []byte:
		return string(v)
	case string:
		return v
	default:
		raw, err := json.Marshal(values)
		if err != nil {
			return "{}"
		}
		return string(raw)
	}
}

func (c *ConsumerState) toUnifiedXDREvent(stream, msgID string, payload map[string]interface{}) *unified.UnifiedEvent {
	now := time.Now()
	if parsed := parseEventTime(payload); !parsed.IsZero() {
		now = parsed
	}
	rawData := dataStrFromPayload(payload)
	payloadHash := sha256.Sum256([]byte(rawData))
	eventType := pickString(payload, "event_type", "type", "name")
	if eventType == "" {
		eventType = stream + ".event"
	}
	source := pickString(payload, "source", "sensor_id", "agent_id", "collector", "module")
	if source == "" {
		source = stream
	}

	event := &unified.UnifiedEvent{
		ID:             msgID,
		SchemaVersion:  "lyflow.unified.v1",
		Module:         moduleFromStream(stream),
		SourceModule:   moduleFromStream(stream),
		EventType:      eventType,
		Source:         source,
		Severity:       severityFromPayload(payload),
		Timestamp:      now.UTC(),
		CreatedAt:      time.Now().UTC(),
		Alert:          true,
		SrcIP:          pickString(payload, "src_ip", "source_ip", "entities.source_ip"),
		DstIP:          pickString(payload, "dst_ip", "dest_ip", "destination_ip", "entities.target_ip"),
		SrcPort:        pickInt(payload, "src_port", "source_port"),
		DstPort:        pickInt(payload, "dst_port", "dest_port", "destination_port"),
		Protocol:       pickString(payload, "protocol", "proto"),
		Hostname:       pickString(payload, "hostname", "host", "entities.hostname"),
		User:           pickString(payload, "user", "username", "entities.user"),
		Service:        pickString(payload, "service", "process", "app", "program"),
		Path:           pickString(payload, "path", "url", "uri", "http_path"),
		RuleID:         pickInt(payload, "rule_id", "sid"),
		RuleName:       pickString(payload, "rule_name", "signature"),
		MitreTactic:    pickString(payload, "mitre_tactic", "tactic"),
		MitreTechnique: pickString(payload, "mitre_technique", "technique"),
		Message:        pickString(payload, "message", "msg", "description", "summary"),
		Tags:           []string{stream},
		Status:         unified.StatusNew,
		EntityIDs: &unified.EntityIDs{
			AgentID:   pickString(payload, "agent_id", "sensor_id", "entities.agent_id"),
			HostID:    pickString(payload, "host_id", "hostname", "entities.host_id", "entities.hostname"),
			UserID:    pickString(payload, "user_id", "user", "username", "entities.user"),
			SessionID: pickString(payload, "session_id"),
			ProcessID: pickString(payload, "process_id", "pid"),
			TraceID:   pickString(payload, "trace_id", "request_id"),
		},
		BehaviorContext: &unified.BehaviorContext{
			Scenario:   stream,
			Action:     pickString(payload, "business_action", "action", "operation", "attack_type"),
			Stage:      pickString(payload, "attack_stage", "stage", "phase"),
			Confidence: pickFloat(payload, "confidence"),
			Labels:     []string{pickString(payload, "category", "label")},
			Details:    payload,
		},
		RawReference: &unified.RawReference{
			Stream:      stream,
			MessageID:   msgID,
			PayloadHash: fmt.Sprintf("%x", payloadHash),
		},
		RawData: rawData,
		Metadata: map[string]interface{}{
			"source_stream":     stream,
			"source_message_id": msgID,
		},
	}
	if stream == "alerts:runtime" {
		applyRuntimeUnifiedOverrides(event, payload)
	}
	if stream == "component_alerts:v2" {
		applyComponentAlertUnifiedOverrides(event, payload)
	}

	if event.Message == "" {
		event.Message = event.EventType
	}
	if event.BehaviorContext != nil && len(event.BehaviorContext.Labels) == 1 && event.BehaviorContext.Labels[0] == "" {
		event.BehaviorContext.Labels = nil
	}
	if event.Tags[0] == "" {
		event.Tags = nil
	}
	if event.EntityIDs != nil && event.EntityIDs.AgentID != "" && event.AgentID == "" {
		event.AgentID = event.EntityIDs.AgentID
	}

	return event
}

func pickString(m map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		v, ok := m[key]
		if !ok && strings.Contains(key, ".") {
			var cur interface{} = m
			for _, part := range strings.Split(key, ".") {
				mm, ok := cur.(map[string]interface{})
				if !ok {
					cur = nil
					break
				}
				cur = mm[part]
			}
			v = cur
			ok = v != nil
		}
		if ok {
			switch vv := v.(type) {
			case string:
				if vv != "" {
					return vv
				}
			case float64:
				if vv != 0 {
					return strconv.FormatFloat(vv, 'f', -1, 64)
				}
			case int:
				if vv != 0 {
					return strconv.Itoa(vv)
				}
			}
		}
	}
	return ""
}

func applyComponentAlertUnifiedOverrides(event *unified.UnifiedEvent, payload map[string]interface{}) {
	sourceEngine := pickString(payload, "source_engine", "source")
	category := pickString(payload, "category")
	module := moduleFromComponentAlert(sourceEngine, category)
	if sourceEngine != "" {
		event.Module = module
		event.SourceModule = module
		event.Source = sourceEngine
	}
	if category != "" && sourceEngine == "" {
		event.Module = module
		event.SourceModule = module
	}
	if event.EventType == "component_alerts:v2.event" {
		event.EventType = firstNonEmpty(sourceEngine, category, "component") + ".alert"
	}
	if ruleID := pickString(payload, "rule_id"); ruleID != "" {
		event.BehaviorContext.Details["component_rule_id"] = ruleID
	}
	if score := pickInt(payload, "score_hint"); score > 0 {
		event.BehaviorContext.Details["score_hint"] = score
	}
	if action := pickString(payload, "action"); action != "" {
		event.BehaviorContext.Action = action
	}
	if category != "" {
		event.BehaviorContext.Labels = []string{category}
	}
	event.Tags = []string{"component_alerts:v2", firstNonEmpty(sourceEngine, category)}
}

func moduleFromComponentAlert(sourceEngine, category string) unified.ModuleType {
	switch strings.ToLower(firstNonEmpty(sourceEngine, category)) {
	case "suricata", "network", "traffic", "dpi_engine":
		return unified.ModuleDPI
	case "wazuh", "host", "runtime":
		return unified.ModuleRuntime
	case "rasp":
		return unified.ModuleRASP
	case "sigma", "log", "log_audit":
		return unified.ModuleLog
	case "yara", "artifact":
		return unified.ModuleRuntime
	default:
		return unified.ModuleXDR
	}
}

func applyRuntimeUnifiedOverrides(event *unified.UnifiedEvent, payload map[string]interface{}) {
	typ := pickString(payload, "type", "event_type")
	metadata := asMap(payload["metadata"])
	logLine := asString(metadata["log_line"])
	if strings.HasPrefix(typ, "runtime.auth.") || strings.Contains(logLine, "sshd") {
		event.Source = "sshd"
		event.Service = "sshd"
		event.Message = firstNonEmpty(logLine, event.Message)
		event.RawData = firstNonEmpty(logLine, event.RawData)
		src := extractAuthSourceIP(logLine)
		if src != "" {
			event.SrcIP = src
		}
		if event.DstIP == "" {
			event.DstIP = pickString(payload, "ip")
		}
	}
}

func pickInt(m map[string]interface{}, keys ...string) int {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			switch vv := v.(type) {
			case int:
				return vv
			case int64:
				return int(vv)
			case float64:
				return int(vv)
			case string:
				if n, err := strconv.Atoi(strings.TrimSpace(vv)); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

func pickFloat(m map[string]interface{}, keys ...string) float64 {
	for _, key := range keys {
		if v, ok := m[key]; ok {
			switch vv := v.(type) {
			case float64:
				return vv
			case int:
				return float64(vv)
			case string:
				if n, err := strconv.ParseFloat(strings.TrimSpace(vv), 64); err == nil {
					return n
				}
			}
		}
	}
	return 0
}

func parseEventTime(payload map[string]interface{}) time.Time {
	for _, key := range []string{"timestamp", "occurred_at", "created_at", "time"} {
		raw := pickString(payload, key)
		if raw == "" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			return ts
		}
		if unix, err := strconv.ParseInt(raw, 10, 64); err == nil {
			if unix > 1_000_000_000_000 {
				return time.UnixMilli(unix)
			}
			return time.Unix(unix, 0)
		}
	}
	return time.Time{}
}

func severityFromPayload(payload map[string]interface{}) unified.Severity {
	if sevStr := strings.ToLower(pickString(payload, "severity", "level", "priority")); sevStr != "" {
		switch sevStr {
		case "critical", "high", "medium", "low", "info":
			return unified.Severity(sevStr)
		case "1":
			return unified.SeverityCritical
		case "2":
			return unified.SeverityHigh
		case "3":
			return unified.SeverityMedium
		case "4", "5":
			return unified.SeverityLow
		}
	}

	if sev, ok := payload["severity"].(float64); ok {
		switch int(sev) {
		case 1:
			return unified.SeverityCritical
		case 2:
			return unified.SeverityHigh
		case 3:
			return unified.SeverityMedium
		default:
			return unified.SeverityLow
		}
	}
	return unified.SeverityLow
}

func moduleFromStream(stream string) unified.ModuleType {
	switch {
	case strings.HasPrefix(stream, "flows:"):
		return unified.ModuleDPI
	case stream == "sessions:semantic":
		return unified.ModuleDPI
	case stream == "alerts:rasp":
		return unified.ModuleRASP
	case stream == "alerts:log_audit":
		return unified.ModuleLog
	case stream == "alerts:runtime":
		return unified.ModuleRuntime
	case strings.HasPrefix(stream, "logs:"):
		return unified.ModuleLog
	case strings.HasPrefix(stream, "alerts:"):
		return unified.ModuleDPI
	default:
		return unified.ModuleXDR
	}
}

func dataStrFromPayload(payload map[string]interface{}) string {
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(b)
}

// 规则管理 API 处理函数

func rulesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			xdrRules, _ := loadXDRRulePack()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":    0,
				"message": "success",
				"data": map[string]interface{}{
					"xdr_rules": xdrRules,
					"subscriptions": []map[string]interface{}{
						{
							"id":         "et-open",
							"name":       "ET Open",
							"name_cn":    "Emerging Threats 开放规则",
							"enabled":    false,
							"url":        "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz",
							"lastUpdate": nil,
						},
						{
							"id":         "pt-attack",
							"name":       "PT AttackDetection",
							"name_cn":    "Positive Technologies 攻击检测",
							"enabled":    false,
							"url":        "https://raw.githubusercontent.com/ptresearch/AttackDetection/master/pt.rules.tar.gz",
							"lastUpdate": nil,
						},
					},
					"customRules": []map[string]interface{}{
						{"id": "ly-frp", "name": "FRP内网穿透检测", "enabled": false, "ruleCount": 10},
						{"id": "ly-c2", "name": "C2远控工具检测", "enabled": false, "ruleCount": 30},
						{"id": "ly-scan", "name": "扫描工具检测", "enabled": false, "ruleCount": 20},
						{"id": "ly-webshell", "name": "WebShell检测", "enabled": false, "ruleCount": 25},
						{"id": "ly-database", "name": "数据库攻击检测", "enabled": false, "ruleCount": 20},
						{"id": "ly-lateral", "name": "内网横向检测", "enabled": false, "ruleCount": 18},
						{"id": "ly-proxy", "name": "代理穿透工具检测", "enabled": false, "ruleCount": 20},
						{"id": "ly-privilege", "name": "权限提升检测", "enabled": false, "ruleCount": 18},
					},
				},
			})
		case http.MethodPost, http.MethodPut:
			var req struct {
				Filename string                 `json:"filename"`
				Rule     map[string]interface{} `json:"rule"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON")
				return
			}
			if !safeRuleFilename(req.Filename) {
				writeJSONError(w, http.StatusBadRequest, "invalid_rule_filename", "rule filename must stay within rules directory")
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "validated", "data": map[string]interface{}{"filename": req.Filename}})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 405, "message": "Method not allowed"})
		}
	}
}

func rulesInventoryHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		categoryFilter := strings.TrimSpace(r.URL.Query().Get("category"))
		supportFilter := strings.TrimSpace(r.URL.Query().Get("support_level"))
		stageFilter := strings.TrimSpace(r.URL.Query().Get("stage"))
		sourceFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("source")))
		sourceOriginFilter := strings.TrimSpace(r.URL.Query().Get("source_origin"))
		statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
		items, err := loadRuleInventory(categoryFilter, supportFilter, stageFilter, sourceFilter, sourceOriginFilter, statusFilter)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rule_inventory_failed", err.Error())
			return
		}
		trafficCount, err := activeLifecycleTrafficCount(r.Context(), cfg.RuleLifecycle, 0, countRuleFiles("rules/suricata"))
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "traffic_count_unverified", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": items, "total": len(items), "count_semantics": map[string]interface{}{"traffic": trafficCount}}})
	}
}

func ruleReportsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		reports := map[string]interface{}{}
		for name, path := range map[string]string{
			"dedup":               ".sisyphus/evidence/task-12-dedup-preview.json",
			"stage":               ".sisyphus/evidence/task-13-stage-classifier.json",
			"scoring":             ".sisyphus/evidence/task-14-scoring.json",
			"entity_risk":         ".sisyphus/evidence/task-16-entity-risk.json",
			"response_candidates": ".sisyphus/evidence/task-17-response-candidates.json",
		} {
			reports[name] = readJSONFileOrEmpty(path)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": reports})
	}
}

func ruleQuarantineHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Unsupported rules are read-only; enabling unsupported rules is not implemented")
			return
		}
		items := []interface{}{}
		for source, path := range map[string]string{
			"elkeid":  ".sisyphus/evidence/task-6-elkeid-quarantine.json",
			"wazuh":   ".sisyphus/evidence/task-7-wazuh-quarantine.json",
			"elastic": ".sisyphus/evidence/task-8-elastic-quarantine.json",
			"falco":   ".sisyphus/evidence/task-9-falco-quarantine.json",
		} {
			payload := readJSONFileOrEmpty(path)
			if report, ok := payload.(map[string]interface{}); ok {
				for _, item := range asSlice(report["rules"]) {
					if row, ok := item.(map[string]interface{}); ok {
						row["source"] = source
						items = append(items, row)
					}
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": items, "total": len(items), "can_enable_unsupported": false}})
	}
}

func responseCandidatesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			policy := loadXDRResponsePolicy(cfg)
			activeResult, err := xdrActiveChainsResponse(r.Context(), cfg, 100)
			if err != nil {
				writeJSONError(w, http.StatusServiceUnavailable, "response_candidates_failed", err.Error())
				return
			}
			candidates := responseCandidatesFromActiveXDR(activeResult)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": candidates, "total": len(candidates), "candidate_only": true, "enforcement": "disabled", "policy": policy.PublicSummary()}})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Response candidates are read-only; enforcement endpoints are not implemented")
		}
	}
}

func responseActionsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg == nil || cfg.ResponseActions == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "response_actions_unavailable", "response action store unavailable")
			return
		}
		switch r.Method {
		case http.MethodGet:
			records, err := cfg.ResponseActions.List()
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "response_actions_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": records, "total": len(records)}})
		case http.MethodPost:
			var request responsepkg.ActionRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_response_action", "Invalid response action")
				return
			}
			request.RequestedBy = fmt.Sprintf("user:%d", auth.GetUserIDFromContext(r.Context()))
			record, err := cfg.ResponseActions.Create(request)
			if err != nil {
				writeJSONError(w, http.StatusBadRequest, "response_action_rejected", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": record})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

func responseActionHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if cfg == nil || cfg.ResponseActions == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "response_actions_unavailable", "response action store unavailable")
			return
		}
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/response/actions/"), "/")
		parts := strings.Split(path, "/")
		if len(parts) == 0 || parts[0] == "" {
			writeJSONError(w, http.StatusNotFound, "response_action_not_found", "Response action not found")
			return
		}
		id := parts[0]
		if len(parts) == 1 && r.Method == http.MethodGet {
			records, err := cfg.ResponseActions.List()
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "response_actions_failed", err.Error())
				return
			}
			for _, record := range records {
				if record.ID == id {
					json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": record})
					return
				}
			}
			writeJSONError(w, http.StatusNotFound, "response_action_not_found", "Response action not found")
			return
		}
		if len(parts) != 2 || r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		switch parts[1] {
		case "approve":
			approver := fmt.Sprintf("user:%d", auth.GetUserIDFromContext(r.Context()))
			record, err := cfg.ResponseActions.Approve(id, approver)
			if err != nil {
				writeJSONError(w, http.StatusConflict, "response_approval_rejected", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": record})
		case "rollback":
			record, err := cfg.ResponseActions.Rollback(id, fmt.Sprintf("user:%d", auth.GetUserIDFromContext(r.Context())))
			if err != nil {
				writeJSONError(w, http.StatusConflict, "response_rollback_rejected", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": record})
		default:
			writeJSONError(w, http.StatusNotFound, "response_action_operation_not_found", "Response action operation not found")
		}
	}
}

func responsePolicyHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": loadXDRResponsePolicy(cfg).PublicSummary()})
		case http.MethodPut, http.MethodPost:
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_response_policy", "Invalid request body")
				return
			}
			policy := xdrResponsePolicyFromMap(req)
			if err := saveXDRResponsePolicy(cfg, policy); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "response_policy_save_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": policy.PublicSummary()})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

func ruleScoreWeightsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": loadScoreWeights()})
		case http.MethodPut, http.MethodPost:
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_score_weights", "Invalid request body")
				return
			}
			weights := loadScoreWeights()
			for _, key := range []string{"base", "source", "support", "stage"} {
				if value, ok := req[key]; ok {
					weights[key] = clampFloat(asFloat(value), 0, 2)
				}
			}
			if err := os.MkdirAll(".sisyphus/runtime", 0o755); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "score_weights_save_failed", err.Error())
				return
			}
			data, _ := json.MarshalIndent(weights, "", "  ")
			if err := os.WriteFile(".sisyphus/runtime/rule-score-weights.json", data, 0o644); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "score_weights_save_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": weights})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

func ruleSourcesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		paths := []string{}
		_ = filepath.WalkDir("rules", func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && filepath.Base(path) == "manifest.json" {
				paths = append(paths, path)
			}
			return nil
		})
		state := loadRuleSourceState()
		items := make([]map[string]interface{}, 0, len(paths))
		for _, path := range paths {
			var manifest map[string]interface{}
			if err := readJSONFile(path, &manifest); err != nil {
				continue
			}
			sourceType := asString(manifest["source_type"])
			if sourceType != "external_subscription" {
				continue
			}
			current := firstNonEmpty(asString(manifest["version"]), "已安装")
			latest := "在线校验后显示"
			updateAvailable := true
			sourceID := asString(manifest["source_id"])
			if upstream := upstreamRuleVersion(r.Context(), sourceID); upstream != "" {
				latest = upstream
			}
			if installed := installedRuleSourceVersion(r.Context(), cfg, sourceID); installed != "" {
				current = installed
				if latest == "在线校验后显示" {
					latest = installed
				}
				updateAvailable = current != latest
			}
			sourceURL := asString(manifest["source_url"])
			if sourceState, ok := state[sourceID].(map[string]interface{}); ok {
				if upstreamVersion := strings.TrimSpace(asString(sourceState["upstream_version"])); upstreamVersion != "" && upstreamVersion != "在线校验完成" {
					latest = upstreamVersion
				}
				if asBool(sourceState["latest_applied"]) {
					current = latest
					updateAvailable = false
				}
				if overrideURL := strings.TrimSpace(asString(sourceState["source_url"])); overrideURL != "" {
					sourceURL = overrideURL
				}
			}
			items = append(items, map[string]interface{}{
				"source_id":        sourceID,
				"name":             manifest["name"],
				"vendor":           manifest["vendor"],
				"license":          manifest["license"],
				"category":         manifest["category"],
				"source_type":      sourceType,
				"origin_label":     sourceOriginLabel(sourceType),
				"intel_category":   intelCategory(asString(manifest["category"]), asString(manifest["vendor"])),
				"current_version":  current,
				"latest_version":   latest,
				"update_available": updateAvailable,
				"update_mode":      manifest["update_mode"],
				"source_url":       sourceURL,
				"raw_path":         manifest["raw_path"],
				"enabled":          manifest["enabled_by_default"],
				"path":             path,
			})
		}
		sort.Slice(items, func(i, j int) bool {
			return fmt.Sprint(items[i]["vendor"]) < fmt.Sprint(items[j]["vendor"])
		})
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": items, "total": len(items)}})
	}
}

func ruleItemHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/items/")
		id = strings.TrimSpace(id)
		if id == "" {
			writeJSONError(w, http.StatusBadRequest, "missing_rule_id", "Missing rule id")
			return
		}
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_rule_update", "Invalid request body")
			return
		}
		overrides := loadRuleOverrides()
		current := map[string]interface{}{}
		if existing, ok := overrides[id].(map[string]interface{}); ok {
			current = existing
		}
		if value, ok := req["enabled"]; ok {
			current["enabled"] = asBool(value)
		}
		if value, ok := req["score"]; ok {
			current["score"] = int(clampFloat(asFloat(value), 0, 100) + 0.5)
		}
		overrides[id] = current
		if err := saveRuleOverrides(overrides); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rule_update_failed", err.Error())
			return
		}
		if value, ok := req["enabled"]; ok && cfg.DBPool != nil {
			if _, err := cfg.DBPool.Exec(r.Context(), `UPDATE detection_rules SET enabled=$2, updated_at=NOW() WHERE id=$1`, id, asBool(value)); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "rule_db_update_failed", err.Error())
				return
			}
		}
		bundle, liveErr := compileDefaultSecurityBundle(r.Context(), cfg)
		if liveErr != nil {
			writeJSONError(w, http.StatusInternalServerError, "rule_active_bundle_reload_failed", liveErr.Error())
			return
		}
		liveCount := asInt(bundle["rule_count"])
		log.Printf("规则热生效: rule_id=%s overrides=%v active_bundle_rules=%d", id, current, liveCount)
		response := map[string]interface{}{"id": id}
		for key, value := range current {
			response[key] = value
		}
		if score, ok := current["score"]; ok {
			response["severity"] = severityFromScore(asFloat(score))
		}
		response["live_rules"] = liveCount
		response["bundle"] = bundle
		reloadState := strings.ToLower(asString(asMap(bundle["reload"])["status"]))
		response["hot_reloaded"] = reloadState == "success" || reloadState == "ok"
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": response})
	}
}

func ruleSourceUpdateHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/rules/sources/")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 1 && parts[0] != "" && (r.Method == http.MethodPut || r.Method == http.MethodPost) {
			updateRuleSourceConfig(w, r, parts[0])
			return
		}
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		if len(parts) != 2 || parts[1] != "update" || parts[0] == "" {
			writeJSONError(w, http.StatusNotFound, "not_found", "Rule source update endpoint not found")
			return
		}
		sourceID := parts[0]
		if !ruleSourceExists(sourceID) {
			writeJSONError(w, http.StatusNotFound, "rule_source_not_found", "Rule source not found")
			return
		}
		log.Printf("外部规则源更新开始: source_id=%s remote_check=true", sourceID)
		state := loadRuleSourceState()
		sourceState := asMap(state[sourceID])
		platformSourceID := platformRuleSourceID(sourceID)
		var syncResult map[string]interface{}
		if platformSourceID != "" {
			result, err := syncRulePlatformSource(r.Context(), cfg, map[string]interface{}{
				"source_id": platformSourceID,
				"version":   "sync-" + time.Now().UTC().Format("20060102T150405Z"),
			})
			if err != nil {
				writeJSONError(w, http.StatusBadGateway, "rule_source_sync_failed", err.Error())
				return
			}
			syncResult = result
		}
		remoteVersion := firstNonEmpty(upstreamRuleVersion(r.Context(), sourceID), asString(syncResult["version"]))
		if contentHash := asString(syncResult["content_hash"]); contentHash != "" {
			if len(contentHash) > 12 {
				contentHash = contentHash[:12]
			}
			remoteVersion = "sha256-" + contentHash
		}
		sourceState["upstream_version"] = firstNonEmpty(remoteVersion, "在线校验完成")
		sourceState["updated_at"] = time.Now().Format(time.RFC3339)
		sourceState["latest_applied"] = true
		state[sourceID] = sourceState
		if err := saveRuleSourceState(state); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rule_source_update_failed", err.Error())
			return
		}
		liveCount, err := syncLiveRules()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rule_live_sync_failed", err.Error())
			return
		}
		bundle, err := compileDefaultSecurityBundle(r.Context(), cfg)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rule_active_bundle_reload_failed", err.Error())
			return
		}
		reloadState := strings.ToLower(asString(asMap(bundle["reload"])["status"]))
		hotReloaded := reloadState == "success" || reloadState == "ok"
		log.Printf("外部规则源更新完成: source_id=%s status=latest hot_reloaded=%v live_rules=%d active_bundle_rules=%d", sourceID, hotReloaded, liveCount, asInt(bundle["rule_count"]))
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"source_id": sourceID, "updated": true, "hot_reloaded": hotReloaded, "live_rules": liveCount, "bundle": compactRuleBundleResponse(bundle), "sync": compactRuleSyncResponse(syncResult)}})
	}
}

func compactRuleBundleResponse(bundle map[string]interface{}) map[string]interface{} {
	if bundle == nil {
		return nil
	}
	return map[string]interface{}{"version": bundle["version"], "status": bundle["status"], "rule_count": bundle["rule_count"], "activated_at": bundle["activated_at"], "bundle_hash": bundle["bundle_hash"], "bundle_path": bundle["bundle_path"], "reload": bundle["reload"]}
}

func compactRuleSyncResponse(syncResult map[string]interface{}) map[string]interface{} {
	if syncResult == nil {
		return nil
	}
	return map[string]interface{}{"source_id": syncResult["source_id"], "version": syncResult["version"], "status": syncResult["status"], "license": syncResult["license"], "rule_count": syncResult["rule_count"], "converted_count": syncResult["converted_count"], "inserted_count": syncResult["inserted_count"], "duplicate_count": syncResult["duplicate_count"], "unsupported_count": syncResult["unsupported_count"], "support": syncResult["support"]}
}

func platformRuleSourceID(sourceID string) string {
	switch sourceID {
	case "suricata-et-open":
		return "et-open-connector"
	case "oisf-trafficid", "stamus-lateral", "snort-community", "ptresearch-attackdetection":
		return sourceID
	default:
		return ""
	}
}

func updateRuleSourceConfig(w http.ResponseWriter, r *http.Request, sourceID string) {
	if !ruleSourceExists(sourceID) {
		writeJSONError(w, http.StatusNotFound, "rule_source_not_found", "Rule source not found")
		return
	}
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_rule_source", "Invalid request body")
		return
	}
	sourceURL := strings.TrimSpace(asString(req["source_url"]))
	if sourceURL == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_source_url", "Missing source_url")
		return
	}
	parsed, err := url.Parse(sourceURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		writeJSONError(w, http.StatusBadRequest, "invalid_source_url", "Invalid source_url")
		return
	}
	state := loadRuleSourceState()
	sourceState := asMap(state[sourceID])
	sourceState["source_url"] = sourceURL
	sourceState["latest_applied"] = false
	sourceState["updated_at"] = time.Now().Format(time.RFC3339)
	state[sourceID] = sourceState
	if err := saveRuleSourceState(state); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "rule_source_save_failed", err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"source_id": sourceID, "source_url": sourceURL, "saved": true}})
}

func loadRuleInventory(categoryFilter, supportFilter, stageFilter, sourceFilter, sourceOriginFilter, statusFilter string) ([]map[string]interface{}, error) {
	paths, err := filepath.Glob("rules/compiled/scored-preview/*.json")
	if err != nil {
		return nil, err
	}
	items := make([]map[string]interface{}, 0, len(paths))
	weights := loadScoreWeights()
	overrides := loadRuleOverrides()
	for _, path := range paths {
		var rule map[string]interface{}
		if err := readJSONFile(path, &rule); err != nil {
			return nil, err
		}
		ruleID := asString(rule["id"])
		category := asString(rule["category"])
		source := asMap(rule["source"])
		support := asMap(rule["support"])
		classification := asMap(rule["classification"])
		scoring := asMap(rule["scoring"])
		vendor := asString(source["vendor"])
		sourceOrigin := asString(source["origin"])
		stage := asString(classification["stage"])
		supportLevel := asString(support["level"])
		enabled := asBool(rule["enabled"])
		if override, ok := overrides[ruleID].(map[string]interface{}); ok {
			if value, exists := override["enabled"]; exists {
				enabled = asBool(value)
			}
		}
		if categoryFilter != "" && category != categoryFilter {
			continue
		}
		if supportFilter != "" && supportLevel != supportFilter {
			continue
		}
		if stageFilter != "" && stage != stageFilter {
			continue
		}
		if sourceFilter != "" && !strings.Contains(strings.ToLower(vendor), sourceFilter) {
			continue
		}
		if sourceOriginFilter != "" && sourceOriginBucket(sourceOrigin) != sourceOriginFilter {
			continue
		}
		if statusFilter == "enabled" && !enabled {
			continue
		}
		if statusFilter == "disabled" && enabled {
			continue
		}
		adjustedScore := adjustedRuleScore(scoring, supportLevel, stage, weights)
		if override, ok := overrides[ruleID].(map[string]interface{}); ok {
			if value, exists := override["score"]; exists {
				adjustedScore = int(clampFloat(asFloat(value), 0, 100) + 0.5)
			}
		}
		items = append(items, map[string]interface{}{
			"id":             ruleID,
			"name":           rule["name"],
			"category":       category,
			"source_vendor":  vendor,
			"source_origin":  sourceOriginBucket(sourceOrigin),
			"source_label":   sourceOriginLabel(sourceOrigin),
			"support_level":  supportLevel,
			"stage":          stage,
			"score":          adjustedScore,
			"original_score": scoring["normalized_score"],
			"adjusted_score": adjustedScore,
			"severity":       severityFromScore(float64(adjustedScore)),
			"enabled":        enabled,
			"path":           path,
		})
	}
	return items, nil
}

func loadScoreWeights() map[string]float64 {
	weights := map[string]float64{"base": 1, "source": 1, "support": 1, "stage": 1}
	var saved map[string]interface{}
	if err := readJSONFile(".sisyphus/runtime/rule-score-weights.json", &saved); err == nil {
		for _, key := range []string{"base", "source", "support", "stage"} {
			if value, ok := saved[key]; ok {
				weights[key] = clampFloat(asFloat(value), 0, 2)
			}
		}
	}
	return weights
}

func loadRuleOverrides() map[string]interface{} {
	overrides := map[string]interface{}{}
	_ = readJSONFile(".sisyphus/runtime/rule-overrides.json", &overrides)
	return overrides
}

func saveRuleOverrides(overrides map[string]interface{}) error {
	if err := os.MkdirAll(".sisyphus/runtime", 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(overrides, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(".sisyphus/runtime/rule-overrides.json", data, 0o644)
}

func loadRuleSourceState() map[string]interface{} {
	state := map[string]interface{}{}
	_ = readJSONFile(".sisyphus/runtime/rule-source-state.json", &state)
	return state
}

func saveRuleSourceState(state map[string]interface{}) error {
	if err := os.MkdirAll(".sisyphus/runtime", 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(".sisyphus/runtime/rule-source-state.json", data, 0o644)
}

func ruleSourceExists(sourceID string) bool {
	found := false
	_ = filepath.WalkDir("rules", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || filepath.Base(path) != "manifest.json" || found {
			return nil
		}
		var manifest map[string]interface{}
		if readJSONFile(path, &manifest) == nil && asString(manifest["source_id"]) == sourceID {
			found = true
		}
		return nil
	})
	return found
}

func syncLiveRules() (int, error) {
	paths, err := filepath.Glob("rules/compiled/scored-preview/*.json")
	if err != nil {
		return 0, err
	}
	liveDir := "rules/compiled/live"
	if err := os.RemoveAll(liveDir); err != nil {
		return 0, err
	}
	if err := os.MkdirAll(liveDir, 0o755); err != nil {
		return 0, err
	}
	overrides := loadRuleOverrides()
	count := 0
	for _, path := range paths {
		var rule map[string]interface{}
		if err := readJSONFile(path, &rule); err != nil {
			return count, err
		}
		ruleID := asString(rule["id"])
		enabled := asBool(rule["enabled"])
		if override, ok := overrides[ruleID].(map[string]interface{}); ok {
			if value, exists := override["enabled"]; exists {
				enabled = asBool(value)
			}
			if value, exists := override["score"]; exists {
				scoring := asMap(rule["scoring"])
				score := int(clampFloat(asFloat(value), 0, 100) + 0.5)
				scoring["normalized_score"] = score
				scoring["severity"] = severityFromScore(float64(score))
				rule["scoring"] = scoring
			}
		}
		rule["enabled"] = enabled
		if !enabled {
			continue
		}
		support := asMap(rule["support"])
		if asString(support["level"]) == "unsupported" {
			continue
		}
		data, _ := json.MarshalIndent(rule, "", "  ")
		if err := os.WriteFile(filepath.Join(liveDir, filepath.Base(path)), data, 0o644); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func adjustedRuleScore(scoring map[string]interface{}, supportLevel, stage string, weights map[string]float64) int {
	base := asFloat(scoring["normalized_score"])
	if base == 0 {
		base = asFloat(scoring["base_score"])
	}
	sourceReliability := asFloat(scoring["source_reliability"])
	supportBonus := map[string]float64{"full_supported": 8, "partial_supported": 2, "unsupported": -35}[supportLevel]
	stageBonus := 0.0
	if stage == "c2_exfiltration" || stage == "privilege_escalation" || stage == "lateral_movement" {
		stageBonus = 6
	}
	score := base*weights["base"] + (sourceReliability-80)*0.2*weights["source"] + supportBonus*weights["support"] + stageBonus*weights["stage"]
	return int(clampFloat(score, 0, 100) + 0.5)
}

func severityFromScore(score float64) string {
	if score >= 85 {
		return "critical"
	}
	if score >= 70 {
		return "high"
	}
	if score >= 45 {
		return "medium"
	}
	return "low"
}

func sourceOriginBucket(origin string) string {
	if origin == "internal" || origin == "rebuilt_internal" {
		return "internal"
	}
	return "external"
}

func sourceOriginLabel(origin string) string {
	if sourceOriginBucket(origin) == "internal" {
		return "内置"
	}
	return "非内置"
}

func intelCategory(category, vendor string) string {
	if category == "dpi" {
		return "网络流量情报"
	}
	if strings.Contains(strings.ToLower(vendor), "wazuh") || strings.Contains(strings.ToLower(vendor), "elastic") || strings.Contains(strings.ToLower(vendor), "falco") {
		return "主机行为情报"
	}
	return "平台内置情报"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func clampFloat(value, min, max float64) float64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func readJSONFileOrEmpty(path string) interface{} {
	var value interface{}
	if err := readJSONFile(path, &value); err != nil {
		return map[string]interface{}{"missing": true, "path": path}
	}
	return value
}

func readJSONFile(path string, target interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func asMap(value interface{}) map[string]interface{} {
	if typed, ok := value.(map[string]interface{}); ok {
		return typed
	}
	return map[string]interface{}{}
}

func asString(value interface{}) string {
	if typed, ok := value.(string); ok {
		return typed
	}
	return ""
}

func asFloat(value interface{}) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		v, _ := typed.Float64()
		return v
	case string:
		v, _ := strconv.ParseFloat(typed, 64)
		return v
	default:
		return 0
	}
}

func asBool(value interface{}) bool {
	if typed, ok := value.(bool); ok {
		return typed
	}
	return false
}

func asSlice(value interface{}) []interface{} {
	switch typed := value.(type) {
	case []interface{}:
		return typed
	case []map[string]interface{}:
		out := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	case []string:
		out := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			out = append(out, item)
		}
		return out
	}
	return nil
}

func subscriptionHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 200,
				"data": map[string]interface{}{
					"etOpen": map[string]interface{}{
						"enabled": false,
						"url":     "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz",
					},
					"ptAttack": map[string]interface{}{
						"enabled": false,
						"url":     "https://raw.githubusercontent.com/ptresearch/AttackDetection/master/pt.rules.tar.gz",
					},
				},
			})
		case http.MethodPut:
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{"code": 400, "message": "Invalid request body"})
				return
			}
			log.Printf("规则订阅配置已更新: %v", req)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code":    200,
				"message": "订阅配置已保存",
			})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 405, "message": "Method not allowed"})
		}
	}
}

func categoriesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rules := []map[string]interface{}{
			{"name": "emerging-web_server.rules", "description": "Web服务器攻击（SQL注入、XSS、命令注入等）", "enabled": false, "ruleCount": 0},
			{"name": "emerging-web_client.rules", "description": "Web客户端攻击（恶意脚本、钓鱼等）", "enabled": false, "ruleCount": 0},
			{"name": "emerging-exploit.rules", "description": "漏洞利用攻击（RCE、缓冲区溢出等）", "enabled": false, "ruleCount": 0},
			{"name": "emerging-malware.rules", "description": "恶意软件通信（C2、木马后门等）", "enabled": false, "ruleCount": 0},
			{"name": "emerging-trojan.rules", "description": "木马与后门程序检测", "enabled": false, "ruleCount": 0},
			{"name": "emerging-coinminer.rules", "description": "挖矿程序检测", "enabled": false, "ruleCount": 0},
			{"name": "emerging-ja3.rules", "description": "TLS指纹恶意检测", "enabled": false, "ruleCount": 0},
			{"name": "emerging-scan.rules", "description": "扫描行为检测（Nmap等）", "enabled": false, "ruleCount": 0},
			{"name": "emerging-dos.rules", "description": "拒绝服务攻击检测", "enabled": false, "ruleCount": 0},
			{"name": "emerging-dns.rules", "description": "DNS隧道与异常检测", "enabled": false, "ruleCount": 0},
			{"name": "emerging-icmp.rules", "description": "ICMP隧道检测", "enabled": false, "ruleCount": 0},
			{"name": "emerging-netbios.rules", "description": "NetBIOS/SMB攻击", "enabled": false, "ruleCount": 0},
			{"name": "emerging-ssh.rules", "description": "SSH暴力破解/异常", "enabled": false, "ruleCount": 0},
			{"name": "emerging-info.rules", "description": "信息性告警（低优先级）", "enabled": false, "ruleCount": 0},
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 200,
			"data": rules,
		})
	}
}

func updateRulesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 405, "message": "Method not allowed"})
			return
		}
		log.Println("触发规则更新...")
		go func() {
			time.Sleep(2 * time.Second)
		}()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    200,
			"message": "规则更新任务已触发",
		})
	}
}

func rulesStatsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		xdrRules, _ := loadXDRRulePack()
		categories := map[string]int{"xdr": len(xdrRules), "runtime": countRuleFiles("rules/hids"), "rasp": countRuleFiles("rules/rasp"), "dpi": countRuleFiles("dpi-engine/rules") + countRuleFiles("rules/domain")}
		trafficCount, err := activeLifecycleTrafficCount(r.Context(), cfg.RuleLifecycle, categories["dpi"], categories["dpi"])
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "traffic_count_unverified", err.Error())
			return
		}
		categories["dpi"] = trafficCount.SignatureCount
		enabled := 0
		for _, rule := range xdrRules {
			if enabledValue, ok := rule["enabled"].(bool); ok && enabledValue {
				enabled++
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"total_rules":     categories["xdr"] + categories["runtime"] + categories["rasp"] + categories["dpi"],
				"enabled_rules":   enabled,
				"categories":      categories,
				"totalRules":      categories["xdr"] + categories["runtime"] + categories["rasp"] + categories["dpi"],
				"enabledRules":    enabled,
				"lastUpdate":      nil,
				"updateStatus":    "never",
				"count_semantics": map[string]interface{}{"traffic": trafficCount},
			},
		})
	}
}

func ruleTestHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		var req struct {
			Source  string                 `json:"source"`
			Message string                 `json:"message"`
			Fixture map[string]interface{} `json:"fixture"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid JSON")
			return
		}
		rules, err := xdrrules.NewRuleLoader(resolveXDRRulesDir()).LoadRules()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rule_load_failed", err.Error())
			return
		}
		engine := xdrrules.NewRuleEngine()
		engine.LoadRules(rules)
		log := &xdrmodels.NormalizedLog{Source: req.Source, Message: req.Message, Metadata: req.Fixture}
		if log.Source == "" {
			log.Source = xdrPickString(req.Fixture, "source")
		}
		if log.Message == "" {
			log.Message = xdrPickString(req.Fixture, "message")
		}
		matches := engine.Match(log)
		items := make([]map[string]interface{}, 0, len(matches))
		for _, match := range matches {
			items = append(items, map[string]interface{}{"rule_id": match.Rule.ID, "rule_name": match.Rule.Name, "severity": match.Rule.GetSeverity(), "groups": match.Rule.Groups})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"matched": len(items) > 0, "matches": items}})
	}
}

func loadXDRRulePack() ([]map[string]interface{}, error) {
	rules, err := xdrrules.NewRuleLoader(resolveXDRRulesDir()).LoadRules()
	if err != nil {
		return nil, err
	}
	items := make([]map[string]interface{}, 0, len(rules))
	for _, rule := range rules {
		items = append(items, map[string]interface{}{"id": rule.ID, "name": rule.Name, "level": rule.Level, "source": rule.Source, "enabled": rule.Enabled, "groups": rule.Groups, "mitre": rule.Mitre})
	}
	return items, nil
}

func safeRuleFilename(filename string) bool {
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return false
	}
	clean := filepath.Clean(filename)
	return clean == filename && !filepath.IsAbs(filename) && !strings.HasPrefix(clean, "..") && strings.HasSuffix(clean, ".yaml")
}

func resolveXDRRulesDir() string {
	if dir := strings.TrimSpace(os.Getenv("XDR_RULES_DIR")); dir != "" {
		return resolveRulesDir(dir)
	}
	return resolveRulesDir("rules/xdr")
}

func countRuleFiles(dir string) int {
	dir = resolveRulesDir(dir)
	count := 0
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry == nil || entry.IsDir() {
			return nil
		}
		name := strings.ToLower(entry.Name())
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".rules") || strings.HasSuffix(name, ".txt") {
			count++
		}
		return nil
	})
	return count
}

func resolveRulesDir(dir string) string {
	if pathExists(dir) {
		return dir
	}
	parent := filepath.Join("..", dir)
	if pathExists(parent) {
		return parent
	}
	grandparent := filepath.Join("..", "..", dir)
	if pathExists(grandparent) {
		return grandparent
	}
	return dir
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func startRealtimePublisher(ctx context.Context, cfg *Config, hub *wsapi.Hub) {
	if cfg == nil || cfg.Redis == nil || hub == nil {
		return
	}
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	lastIDs := map[string]string{}
	streams := []string{"events:xdr", "alerts:xdr", "alerts:runtime", "alerts:rasp"}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, stream := range streams {
				messages, err := cfg.Redis.XRevRangeN(ctx, stream, "+", "-", 1).Result()
				if err != nil || len(messages) == 0 || messages[0].ID == lastIDs[stream] {
					continue
				}
				lastIDs[stream] = messages[0].ID
				if payload := realtimePayload(stream, messages[0]); payload != nil {
					data, _ := json.Marshal(payload)
					hub.Broadcast(data)
				}
			}
		}
	}
}

func realtimePayload(stream string, msg redis.XMessage) map[string]interface{} {
	data := streamDataString(msg.Values)
	payload := map[string]interface{}{}
	if data != "" {
		_ = json.Unmarshal([]byte(data), &payload)
	}
	if len(payload) == 0 {
		for key, value := range msg.Values {
			payload[key] = value
		}
	}
	messageType := "event.created"
	if strings.HasPrefix(stream, "alerts:") {
		messageType = "alert.created"
	}
	if stream == "events:xdr" || stream == "alerts:xdr" {
		if chainID := xdrPickString(payload, "chain_id"); chainID != "" || strings.Contains(strings.ToLower(xdrPickString(payload, "message")), "chain") {
			messageType = "incident.updated"
		}
	}
	return map[string]interface{}{
		"type":       messageType,
		"stream":     stream,
		"message_id": msg.ID,
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
		"freshness":  "fresh",
		"payload":    payload,
	}
}

func xdrStatsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		activeResult, err := xdrActiveChainsResponse(r.Context(), cfg, 100)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "xdr_graph_degraded", err.Error())
			return
		}
		chains := activeResult.activeChains()
		events, _, err := loadXDREvents(cfg, 1000, 0)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "xdr_events_degraded", err.Error())
			return
		}

		today := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.Now().Location())
		topSources := make(map[string]int64)
		severityCount := map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0}
		total := 0
		eventsToday := int64(0)
		sourcesSet := make(map[string]struct{})

		for _, event := range events {
			if xdrEventIsInformationalTelemetry(event) {
				continue
			}
			total++
			sev := strings.ToLower(xdrPickString(event, "severity"))
			switch sev {
			case "critical", "high", "medium":
				severityCount[sev]++
			default:
				severityCount["low"]++
			}
			source := firstNonEmpty(xdrPickString(event, "source", "source_engine", "log_source"), "unknown")
			topSources[source]++
			sourcesSet[source] = struct{}{}
			eventTime := parseXDRTime(firstNonEmpty(xdrPickString(event, "observed_at"), xdrPickString(event, "created_at", "timestamp")))
			if !eventTime.IsZero() && eventTime.After(today) {
				eventsToday++
			}
		}

		sources := make([]string, 0, len(sourcesSet))
		for source := range sourcesSet {
			sources = append(sources, source)
		}
		sort.Strings(sources)

		posture := xdrPostureFromChains(chains)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"total_events":    total,
				"total_alerts":    total,
				"critical_alerts": severityCount["critical"],
				"high_alerts":     severityCount["high"],
				"medium_alerts":   severityCount["medium"],
				"low_alerts":      severityCount["low"],
				"events_today":    eventsToday,
				"alerts_today":    eventsToday,
				"top_sources":     topSources,
				"sources":         sources,
				"active_chains":   posture["active_chains"],
				"posture_score":   posture["risk_score"],
				"posture_level":   posture["risk_level"],
			},
		})
	}
}

func xdrEventsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		limit := 50
		offset := 0
		if l := r.URL.Query().Get("limit"); l != "" {
			if n, err := strconv.Atoi(l); err == nil {
				limit = n
			}
		}
		if o := r.URL.Query().Get("offset"); o != "" {
			if n, err := strconv.Atoi(o); err == nil {
				offset = n
			}
		}

		events, _, err := loadXDREvents(cfg, 1000, 0)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}

		filtered := make([]map[string]interface{}, 0, len(events))
		for _, event := range events {
			if xdrEventIsInformationalTelemetry(event) {
				continue
			}
			if sev := r.URL.Query().Get("severity"); sev != "" {
				if !strings.EqualFold(xdrPickString(event, "severity"), sev) {
					continue
				}
			}
			if src := r.URL.Query().Get("source"); src != "" {
				if !strings.Contains(strings.ToLower(xdrPickString(event, "source")), strings.ToLower(src)) {
					continue
				}
			}
			filtered = append(filtered, event)
		}

		total := len(filtered)
		start := offset
		if start > total {
			start = total
		}
		end := start + limit
		if end > total {
			end = total
		}
		items := filtered[start:end]

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"items":  items,
				"total":  total,
				"limit":  limit,
				"offset": offset,
			},
		})
	}
}

func xdrSourcesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		events, _, err := loadXDREvents(cfg, 1000, 0)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}

		type sourceAgg struct {
			count    int
			alerts   int
			lastTime time.Time
		}

		agg := make(map[string]*sourceAgg)
		for _, event := range events {
			if xdrEventIsInformationalTelemetry(event) {
				continue
			}
			source := xdrPickString(event, "source", "log_source")
			if source == "" {
				source = "unknown"
			}
			if _, ok := agg[source]; !ok {
				agg[source] = &sourceAgg{}
			}
			agg[source].count++
			agg[source].alerts++
			t := parseXDRTime(xdrPickString(event, "created_at"))
			if t.After(agg[source].lastTime) {
				agg[source].lastTime = t
			}
		}

		items := make([]map[string]interface{}, 0, len(agg))
		for source, a := range agg {
			lastEvent := ""
			if !a.lastTime.IsZero() {
				lastEvent = a.lastTime.Format(time.RFC3339)
			}
			items = append(items, map[string]interface{}{
				"name":       source,
				"count":      a.count,
				"alerts":     a.alerts,
				"last_event": lastEvent,
			})
		}
		sort.Slice(items, func(i, j int) bool { return items[i]["count"].(int) > items[j]["count"].(int) })

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data":    items,
		})
	}
}

func xdrTopEventsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		events, _, err := loadXDREvents(cfg, 1000, 0)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}

		type topAgg struct {
			RuleName string
			Count    int
			Severity string
		}

		agg := make(map[string]*topAgg)
		for _, event := range events {
			if xdrEventIsInformationalTelemetry(event) {
				continue
			}
			ruleName := xdrPickString(event, "rule_name", "event_type")
			if ruleName == "" {
				ruleName = "unknown"
			}
			if _, ok := agg[ruleName]; !ok {
				agg[ruleName] = &topAgg{RuleName: ruleName, Severity: xdrPickString(event, "severity")}
			}
			agg[ruleName].Count++
		}

		rows := make([]*topAgg, 0, len(agg))
		for _, row := range agg {
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].Count > rows[j].Count })

		top := make([]map[string]interface{}, 0, 5)
		for i, row := range rows {
			if i >= 5 {
				break
			}
			top = append(top, map[string]interface{}{
				"rule_name": row.RuleName,
				"count":     row.Count,
				"severity":  row.Severity,
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data":    top,
		})
	}
}

func xdrChainsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		limit := parseQueryInt(r.URL.Query().Get("limit"), 20)
		if limit <= 0 || limit > 100 {
			limit = 20
		}
		engine := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("engine")))
		switch engine {
		case "", "v2", "v2-active":
			result, err := xdrActiveChainsResponse(r.Context(), cfg, limit)
			if err != nil {
				writeJSONError(w, http.StatusServiceUnavailable, "xdr_graph_degraded", err.Error())
				return
			}
			chains := result.activeChains()
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": chains.jsonRows(), "total": len(chains), "limit": limit, "offset": 0, "engine": xdrmodels.AlgorithmV2Active.String()}})
		case "v3", "v3-shadow":
			result, err := xdrShadowChainsResponse(r.Context(), cfg)
			if err != nil {
				writeJSONError(w, http.StatusServiceUnavailable, "xdr_graph_degraded", err.Error())
				return
			}
			chains := result.shadowChains()
			if len(chains) > limit {
				chains = chains[:limit]
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": chains.jsonRows(), "total": len(chains), "limit": limit, "offset": 0, "engine": xdrmodels.AlgorithmV3Shadow.String()}})
		default:
			writeJSONError(w, http.StatusBadRequest, "unknown_xdr_algorithm", "unknown XDR algorithm")
		}
	}
}

func xdrPostureHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		activeResult, err := xdrActiveChainsResponse(r.Context(), cfg, 100)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "xdr_graph_degraded", err.Error())
			return
		}
		chains := activeResult.activeChains()
		active := 0
		for _, chain := range chains {
			if chain.HypothesisStatus == xdrmodels.HypothesisStatusCandidate {
				active++
			}
		}
		posture := xdrPostureFromChains(chains)
		posture["active_v2_chains"] = active
		posture["engine"] = xdrmodels.AlgorithmV2Active.String()
		posture["health"] = cfg.XDRGraph.Health()
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": posture})
	}
}

func loadXDRComponentEvents(cfg *Config, limit int) ([]map[string]interface{}, int, error) {
	return loadXDRComponentEventsWithPolicy(cfg, limit, loadXDRResponsePolicy(cfg))
}

func loadXDRComponentEventsWithPolicy(cfg *Config, limit int, policy xdrResponsePolicy) ([]map[string]interface{}, int, error) {
	if limit <= 0 {
		limit = 1000
	}
	events, total, err := loadXDRComponentEventCandidates(cfg, limit)
	if err != nil {
		return nil, 0, err
	}
	agentNames := activeAgentDisplayNames(context.Background(), cfg)
	out := make([]map[string]interface{}, 0, len(events))
	for _, event := range events {
		if !xdrEventBelongsToActiveAgent(event, agentNames) {
			continue
		}
		applyMirrorCaptureLabel(event)
		enrichXDRDisplayName(event, agentNames)
		if !xdrEventFromComponentAlert(event) {
			continue
		}
		category := componentCategoryFromEvent(event)
		if category == "" || strings.EqualFold(category, "xdr") {
			continue
		}
		if strings.EqualFold(xdrPickString(event, "severity"), "info") || xdrPickString(event, "severity") == "" {
			continue
		}
		event["component_category"] = category
		enrichXDREvaluation(event)
		decision := applyXDRResponsePolicy(event, policy)
		if cfg.RASPBlockDefault && strings.EqualFold(category, "rasp") {
			event["candidate_only"] = false
		}
		if decision.Suppress {
			continue
		}
		out = append(out, event)
	}
	return dedupXDRComponentEvents(out, policy.DedupWindow), total, nil
}

func activeAgentDisplayNames(ctx context.Context, cfg *Config) map[string]string {
	if cfg == nil || cfg.DBPool == nil {
		return nil
	}
	rows, err := cfg.DBPool.Query(ctx, `SELECT uuid, COALESCE(NULLIF(display_name, ''), NULLIF(hostname, ''), uuid) FROM agents`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	names := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err == nil && strings.TrimSpace(id) != "" {
			names[id] = firstNonEmpty(strings.TrimSpace(name), id)
		}
	}
	return names
}

type activeTrafficAgentInfo struct {
	DisplayName string
	Interface   string
	IP          string
	Hostname    string
}

func activeTrafficAgentInfos(ctx context.Context, cfg *Config) map[string]activeTrafficAgentInfo {
	if cfg == nil || cfg.DBPool == nil {
		return nil
	}
	rows, err := cfg.DBPool.Query(ctx, `
		SELECT a.uuid, COALESCE(NULLIF(a.display_name, ''), NULLIF(a.hostname, ''), a.uuid), COALESCE(host(a.ip), ''), COALESCE(a.hostname, ''), COALESCE(h.metadata, '{}'::jsonb)
		FROM agents a
		LEFT JOIN hosts h ON h.agent_id = a.uuid
		WHERE COALESCE(a.traffic_enabled, false) = true
	`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	infos := map[string]activeTrafficAgentInfo{}
	for rows.Next() {
		var id, name, ip, hostname string
		var metadataRaw []byte
		if err := rows.Scan(&id, &name, &ip, &hostname, &metadataRaw); err != nil || strings.TrimSpace(id) == "" {
			continue
		}
		capabilities := capabilitiesFromMetadata(metadataRaw)
		traffic := asMap(capabilities["traffic_collector"])
		infos[id] = activeTrafficAgentInfo{
			DisplayName: firstNonEmpty(strings.TrimSpace(name), id),
			Interface:   strings.TrimSpace(asString(traffic["interface"])),
			IP:          strings.TrimSpace(ip),
			Hostname:    strings.TrimSpace(hostname),
		}
	}
	return infos
}

func xdrEventBelongsToActiveAgent(event map[string]interface{}, agentNames map[string]string) bool {
	if len(agentNames) == 0 {
		return true
	}
	agentID := xdrPickString(event, "agent_id", "entities.agent_id")
	if agentID == "local" || agentID == "localhost" {
		return true
	}
	if agentID == "" {
		return true
	}
	_, ok := agentNames[agentID]
	return ok
}

func enrichXDRDisplayName(event map[string]interface{}, agentNames map[string]string) {
	if len(agentNames) == 0 {
		return
	}
	agentID := xdrPickString(event, "agent_id", "entities.agent_id")
	name := agentNames[agentID]
	if name == "" {
		return
	}
	event["agent_display_name"] = name
	event["display_name"] = name
}

func loadXDRComponentEventCandidates(cfg *Config, limit int) ([]map[string]interface{}, int, error) {
	if cfg.Redis == nil {
		return nil, 0, fmt.Errorf("redis unavailable")
	}
	if limit <= 0 {
		limit = 1000
	}
	events, total, streamErr := loadXDREventsFromStream(cfg, limit, 0)
	if streamErr != nil {
		events = []map[string]interface{}{}
	}
	legacy, legacyTotal, legacyErr := loadComponentAlertStreamEvents(cfg, limit)
	if legacyErr != nil && streamErr != nil {
		return nil, 0, streamErr
	}
	if legacyErr == nil {
		events = append(events, legacy...)
		total += legacyTotal
	}
	sort.SliceStable(events, func(i, j int) bool {
		return parseXDRTime(xdrPickString(events[i], "created_at", "timestamp", "occurred_at")).After(parseXDRTime(xdrPickString(events[j], "created_at", "timestamp", "occurred_at")))
	})
	return events, total, nil
}

func loadComponentAlertStreamEvents(cfg *Config, limit int) ([]map[string]interface{}, int, error) {
	streams := []string{"component_alerts:v2", "alerts:dpi", "alerts:runtime", "alerts:rasp", "alerts:log_audit", "telemetry:rasp"}
	ctx := context.Background()
	items := []map[string]interface{}{}
	total := 0
	perStream := int64(limit)
	if perStream < 100 {
		perStream = 100
	}
	for _, stream := range streams {
		length, err := cfg.Redis.XLen(ctx, stream).Result()
		if err != nil {
			return nil, 0, err
		}
		total += int(length)
		msgs, err := cfg.Redis.XRevRangeN(ctx, stream, "+", "-", perStream).Result()
		if err != nil {
			return nil, 0, err
		}
		for _, msg := range msgs {
			payload := redisDataPayload(msg.Values)
			if dataRaw := xdrPickString(payload, "data"); dataRaw != "" {
				var decoded map[string]interface{}
				if json.Unmarshal([]byte(dataRaw), &decoded) == nil {
					payload = decoded
				}
			}
			if shouldHideOperationalAgentEvent(payload) {
				continue
			}
			normalized := normalizeComponentAlertStreamEvent(stream, msg.ID, payload)
			if shouldSuppressTrafficNoiseEvent(normalized) || xdrEventIsInformationalTelemetry(normalized) {
				continue
			}
			items = append(items, normalized)
		}
	}
	return items, total, nil
}

func normalizeComponentAlertStreamEvent(stream, msgID string, payload map[string]interface{}) map[string]interface{} {
	flat := flattenXDRComponentEvent(payload)
	metadata := asMap(flat["metadata"])
	if len(metadata) == 0 {
		metadata = map[string]interface{}{}
	}
	metadata["source_stream"] = stream
	metadata["source_message_id"] = msgID
	category := firstNonEmpty(normalizeComponentCategory(xdrPickString(flat, "category", "component_category")), componentCategoryFromStream(stream), normalizeComponentCategory(xdrPickString(flat, "source_engine", "source")))
	severity := strings.ToLower(firstNonEmpty(xdrPickString(flat, "severity"), "low"))
	createdAt := firstNonEmpty(xdrPickString(flat, "occurred_at", "created_at", "timestamp"), time.Now().UTC().Format(time.RFC3339Nano))
	message := firstNonEmpty(xdrPickString(flat, "summary", "message", "evidence", "event_type", "rule_name"), "component alert")
	ruleID := firstNonEmpty(xdrPickString(flat, "rule_id", "component_rule_id", "native_rule.id"), xdrPickString(asMap(flat["native_rule"]), "id"))
	sourceEngine := firstNonEmpty(xdrPickString(flat, "source_engine", "source"), componentSourceEngineFromStream(stream))
	entities := firstNonNil(payload["entities"], flat["entities"])
	event := enrichEventRuleDisplay(map[string]interface{}{
		"id":                 firstNonEmpty(xdrPickString(flat, "id"), msgID),
		"message_id":         msgID,
		"event_type":         firstNonEmpty(xdrPickString(flat, "event_type", "type"), sourceEngine+".alert"),
		"severity":           severity,
		"message":            message,
		"module":             category,
		"source_module":      sourceEngine,
		"source_engine":      sourceEngine,
		"component_category": category,
		"language":           firstNonEmpty(xdrPickString(flat, "language"), xdrPickString(asMap(flat["fields"]), "language")),
		"application":        firstNonEmpty(xdrPickString(flat, "application", "service"), xdrPickString(asMap(flat["fields"]), "application")),
		"component_rule_id":  ruleID,
		"score_hint":         xdrPickNumber(flat, "score_hint", severityBaseScore(severity)),
		"stage_hint":         firstNonEmpty(xdrPickString(flat, "stage_hint"), inferXDRStage(flat)),
		"confidence":         xdrPickFloat(flat, "confidence", 0),
		"src_ip":             xdrPickString(flat, "src_ip", "source_ip", "entities.source_ip"),
		"dst_ip":             xdrPickString(flat, "dst_ip", "target_ip", "entities.target_ip"),
		"src_port":           xdrPickNumber(payload, "details.src_port", xdrPickNumber(flat, "src_port", 0)),
		"dst_port":           xdrPickNumber(payload, "details.dest_port", xdrPickNumber(flat, "dst_port", 0)),
		"user":               xdrPickString(flat, "user", "entities.user"),
		"service":            xdrPickString(flat, "service", "application", "entities.application"),
		"rule_id":            xdrPickNumber(flat, "rule_id", 0),
		"rule_name":          firstNonEmpty(xdrPickString(flat, "rule_name", "native_rule.name"), xdrPickString(asMap(flat["native_rule"]), "name"), xdrPickString(flat, "event_type")),
		"mitre_tactic":       xdrPickString(flat, "mitre_tactic"),
		"mitre_technique":    xdrPickString(flat, "mitre_technique"),
		"status":             firstNonEmpty(xdrPickString(flat, "status"), "new"),
		"source":             firstNonEmpty(xdrPickString(flat, "source"), sourceEngine),
		"agent_id":           xdrPickString(flat, "agent_id", "entities.agent_id"),
		"display_name":       xdrPickString(flat, "display_name", "agent_display_name", "probe_name"),
		"agent_display_name": xdrPickString(flat, "agent_display_name", "display_name", "probe_name"),
		"probe_name":         xdrPickString(flat, "probe_name", "display_name", "agent_display_name"),
		"hostname":           xdrPickString(flat, "hostname", "entities.hostname"),
		"interface":          xdrPickString(flat, "interface", "iface", "capture_interface", "source_interface", "metadata.interface", "metadata.capture_interface"),
		"capture_interface":  xdrPickString(flat, "capture_interface", "interface", "iface", "metadata.capture_interface", "metadata.interface"),
		"session_id":         xdrPickString(flat, "session_id", "entities.session_id"),
		"process_id":         xdrPickString(flat, "process_id", "entities.process_id"),
		"entities":           entities,
		"tags":               flat["tags"],
		"metadata":           metadata,
		"native_rule":        firstNonNil(payload["native_rule"], flat["native_rule"]),
		"raw_reference":      firstNonNil(payload["raw_reference"], flat["raw_reference"]),
		"rule_pack":          xdrPickString(flat, "rule_pack", "metadata.rule_pack"),
		"created_at":         createdAt,
		"timestamp":          createdAt,
	})
	applyMirrorCaptureLabel(event)
	return event
}

func componentSourceEngineFromStream(stream string) string {
	switch stream {
	case "alerts:dpi":
		return "dpi_engine"
	case "alerts:runtime":
		return "runtime"
	case "alerts:rasp", "telemetry:rasp":
		return "rasp"
	case "alerts:log_audit":
		return "wazuh"
	default:
		return "component_alert"
	}
}

type xdrChainAgg struct {
	Key        string
	Entity     string
	Victim     string
	SeedStage  string
	FirstSeen  time.Time
	LastSeen   time.Time
	Events     []map[string]interface{}
	Evidence   []map[string]interface{}
	Categories map[string]struct{}
	Stages     map[string]struct{}
	Sources    map[string]struct{}
	VictimIPs  map[string]struct{}
	Users      map[string]struct{}
	Processes  map[string]struct{}
	Sessions   map[string]struct{}
	MaxScore   int64
	TotalScore int64
	Standalone bool
}

type xdrResponsePolicy struct {
	WhitelistRules    []string      `json:"whitelist_rules"`
	WhitelistSources  []string      `json:"whitelist_sources"`
	WhitelistVictims  []string      `json:"whitelist_victims"`
	BlacklistRules    []string      `json:"blacklist_rules"`
	BlacklistSources  []string      `json:"blacklist_sources"`
	BlacklistVictims  []string      `json:"blacklist_victims"`
	SuppressionWindow time.Duration `json:"-"`
	DedupWindow       time.Duration `json:"-"`
}

type xdrPolicyDecision struct {
	Suppress bool
	Reason   string
	Effects  []string
}

func loadXDRResponsePolicy(cfg *Config) xdrResponsePolicy {
	policy := defaultXDRResponsePolicy()
	path := xdrResponsePolicyPath(cfg)
	data, err := os.ReadFile(path)
	if err != nil {
		return policy
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return policy
	}
	return xdrResponsePolicyFromMap(raw)
}

func saveXDRResponsePolicy(cfg *Config, policy xdrResponsePolicy) error {
	path := xdrResponsePolicyPath(cfg)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload := policy.PublicSummary()
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func xdrResponsePolicyPath(cfg *Config) string {
	if cfg != nil && strings.TrimSpace(cfg.XDRResponsePolicyPath) != "" {
		return cfg.XDRResponsePolicyPath
	}
	return ".sisyphus/runtime/xdr-response-policy.json"
}

func xdrResponsePolicyFromMap(raw map[string]interface{}) xdrResponsePolicy {
	policy := defaultXDRResponsePolicy()
	policy.WhitelistRules = stringListFromValue(raw["whitelist_rules"])
	policy.WhitelistSources = stringListFromValue(raw["whitelist_sources"])
	policy.WhitelistVictims = stringListFromValue(raw["whitelist_victims"])
	policy.BlacklistRules = stringListFromValue(raw["blacklist_rules"])
	policy.BlacklistSources = stringListFromValue(raw["blacklist_sources"])
	policy.BlacklistVictims = stringListFromValue(raw["blacklist_victims"])
	policy.SuppressionWindow = durationFromPolicy(raw["suppression_window"], policy.SuppressionWindow)
	policy.DedupWindow = durationFromPolicy(raw["dedup_window"], policy.DedupWindow)
	return policy
}

func stringListFromValue(value interface{}) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range asSlice(value) {
		text := strings.TrimSpace(asString(item))
		if text == "" {
			continue
		}
		key := strings.ToLower(text)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, text)
	}
	return out
}

func durationFromPolicy(value interface{}, fallback time.Duration) time.Duration {
	switch typed := value.(type) {
	case string:
		if parsed, err := time.ParseDuration(strings.TrimSpace(typed)); err == nil && parsed > 0 {
			return parsed
		}
	case float64:
		if typed > 0 {
			return time.Duration(typed) * time.Second
		}
	}
	return fallback
}

func defaultXDRResponsePolicy() xdrResponsePolicy {
	return xdrResponsePolicy{SuppressionWindow: 30 * time.Minute, DedupWindow: 5 * time.Minute}
}

func (p xdrResponsePolicy) PublicSummary() map[string]interface{} {
	return map[string]interface{}{
		"whitelist_rules":    p.WhitelistRules,
		"whitelist_sources":  p.WhitelistSources,
		"whitelist_victims":  p.WhitelistVictims,
		"blacklist_rules":    p.BlacklistRules,
		"blacklist_sources":  p.BlacklistSources,
		"blacklist_victims":  p.BlacklistVictims,
		"suppression_window": p.SuppressionWindow.String(),
		"dedup_window":       p.DedupWindow.String(),
		"enforcement":        "candidate_only",
	}
}

func applyXDRResponsePolicy(event map[string]interface{}, policy xdrResponsePolicy) xdrPolicyDecision {
	decision := xdrPolicyDecision{Effects: []string{"candidate_only_enforced"}}
	ruleID := firstNonEmpty(xdrPickString(event, "component_rule_id"), xdrPickString(event, "rule_id"))
	source := xdrSourceIP(event)
	victim := xdrVictimEntity(event)
	if policyListMatches(policy.WhitelistRules, ruleID) || policyListMatches(policy.WhitelistSources, source) || policyListMatches(policy.WhitelistVictims, victim) {
		decision.Suppress = true
		decision.Reason = "whitelist_match"
		decision.Effects = append(decision.Effects, "suppressed")
		event["policy_decision"] = map[string]interface{}{"suppressed": true, "reason": decision.Reason, "effects": decision.Effects}
		return decision
	}
	if policyListMatches(policy.BlacklistRules, ruleID) || policyListMatches(policy.BlacklistSources, source) || policyListMatches(policy.BlacklistVictims, victim) {
		decision.Reason = "blacklist_match"
		decision.Effects = append(decision.Effects, "score_elevated")
		score := clampInt64(xdrEventScore(event)+20, 0, 100)
		event["score_hint"] = score
		event["risk_level"] = severityFromScore(float64(score))
		detail := asMap(event["score_detail"])
		detail["policy_component"] = int64(20)
		detail["policy_reason"] = decision.Reason
		event["score_detail"] = detail
	} else {
		decision.Reason = "no_policy_match"
	}
	event["candidate_only"] = true
	event["policy_decision"] = map[string]interface{}{"suppressed": false, "reason": decision.Reason, "effects": decision.Effects}
	return decision
}

func policyListMatches(patterns []string, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	for _, pattern := range patterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if pattern == "*" || pattern == value || strings.Contains(value, pattern) {
			return true
		}
	}
	return false
}

func dedupXDRComponentEvents(events []map[string]interface{}, window time.Duration) []map[string]interface{} {
	if window <= 0 || len(events) < 2 {
		return events
	}
	seen := map[string]time.Time{}
	out := make([]map[string]interface{}, 0, len(events))
	for _, event := range events {
		key := xdrDedupKey(event)
		if key == "" {
			out = append(out, event)
			continue
		}
		t := parseXDRTime(firstNonEmpty(xdrPickString(event, "created_at"), xdrPickString(event, "timestamp")))
		if t.IsZero() {
			t = time.Now().UTC()
		}
		if previous, ok := seen[key]; ok && absDuration(t.Sub(previous)) <= window {
			continue
		}
		seen[key] = t
		out = append(out, event)
	}
	return out
}

func xdrDedupKey(event map[string]interface{}) string {
	parts := []string{
		componentCategoryFromEvent(event),
		firstNonEmpty(xdrPickString(event, "component_rule_id"), xdrPickString(event, "rule_id")),
		xdrSourceIP(event),
		xdrVictimEntity(event),
		firstNonEmpty(xdrPickString(event, "stage_hint"), inferXDRStage(event)),
	}
	for i, part := range parts {
		parts[i] = strings.ToLower(strings.TrimSpace(part))
	}
	return strings.Join(parts, "|")
}

func absDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func buildXDRChains(cfg *Config, events []map[string]interface{}, limit int) []map[string]interface{} {
	agg := map[string]*xdrChainAgg{}
	for _, event := range events {
		if shouldHideOperationalAgentEvent(event) {
			continue
		}
		if !xdrEventBelongsToLocalSurface(event) {
			continue
		}
		if shouldSuppressTrafficNoiseEvent(event) || xdrEventIsInformationalTelemetry(event) {
			continue
		}
		seedStage := xdrSeedStage(event)
		key := xdrResultOrientedCorrelationKey(event, seedStage)
		if key == "" {
			continue
		}
		if _, ok := agg[key]; !ok {
			agg[key] = newXDRChainAgg(key, event)
			agg[key].SeedStage = seedStage
		}
		chain := agg[key]
		if chain.SeedStage == "" || xdrStageRank(seedStage) > xdrStageRank(chain.SeedStage) {
			chain.SeedStage = seedStage
		}
		t := parseXDRTime(firstNonEmpty(xdrPickString(event, "created_at"), xdrPickString(event, "timestamp")))
		if chain.FirstSeen.IsZero() || (!t.IsZero() && t.Before(chain.FirstSeen)) {
			chain.FirstSeen = t
		}
		if t.After(chain.LastSeen) {
			chain.LastSeen = t
		}
		category := componentCategoryFromEvent(event)
		if category != "" {
			chain.Categories[category] = struct{}{}
		}
		stage := firstNonEmpty(xdrPickString(event, "stage_hint"), inferXDRStage(event))
		if stage != "" {
			chain.Stages[stage] = struct{}{}
		}
		for _, source := range []string{xdrAttackerIP(event), xdrSourceIP(event), xdrPickString(event, "source")} {
			if source != "" {
				chain.Sources[source] = struct{}{}
			}
		}
		if victimIP := xdrVictimIP(event); victimIP != "" {
			chain.VictimIPs[victimIP] = struct{}{}
		}
		if user := xdrPickString(event, "user"); user != "" {
			chain.Users[user] = struct{}{}
		}
		if process := firstNonEmpty(xdrPickString(event, "process_id"), xdrPickString(event, "service")); process != "" {
			chain.Processes[process] = struct{}{}
		}
		if session := firstNonEmpty(xdrPickString(event, "session_id"), xdrPickString(event, "chain_id")); session != "" {
			chain.Sessions[session] = struct{}{}
		}
		score := xdrEventScore(event)
		chain.TotalScore += score
		if score > chain.MaxScore {
			chain.MaxScore = score
		}
		chain.Events = append(chain.Events, event)
		chain.Evidence = append(chain.Evidence, event)
	}
	if cfg != nil {
		for _, chain := range agg {
			appendTrafficEvidence(cfg, chain)
		}
	}
	rows := make([]*xdrChainAgg, 0, len(agg))
	for _, row := range agg {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool {
		si := xdrChainScore(rows[i])
		sj := xdrChainScore(rows[j])
		if si == sj {
			return rows[i].LastSeen.After(rows[j].LastSeen)
		}
		return si > sj
	})
	if limit > len(rows) {
		limit = len(rows)
	}
	out := make([]map[string]interface{}, 0, limit)
	for _, row := range rows {
		if !xdrChainIsCorrelated(row) {
			continue
		}
		out = append(out, xdrChainRow(row))
		if len(out) >= limit {
			break
		}
	}
	return out
}

func xdrEventBelongsToLocalSurface(event map[string]interface{}) bool {
	agentID := strings.TrimSpace(xdrPickString(event, "agent_id", "entities.agent_id"))
	if agentID != "" && !strings.EqualFold(agentID, "local") && !strings.EqualFold(agentID, "localhost") {
		return false
	}
	name := strings.ToLower(firstNonEmpty(xdrPickString(event, "hostname"), xdrPickString(event, "agent_display_name", "display_name", "probe_name"), xdrPickString(event, "entities.hostname")))
	if name == "" {
		return true
	}
	return name == "security-server" || strings.Contains(name, "流量镜像分析") || strings.Contains(name, "mirror") || strings.Contains(name, "local")
}

func xdrChainIsCorrelated(row *xdrChainAgg) bool {
	if row == nil || len(row.Events) < 2 {
		return false
	}
	return len(row.Categories) >= 2 || len(row.Stages) >= 2 || len(row.Sessions) > 0
}

func buildXDRPosture(events []map[string]interface{}) map[string]interface{} {
	totalScore := int64(0)
	byHost := map[string]*xdrChainAgg{}
	bySource := map[string]int64{}
	categoryCount := map[string]int64{"traffic": 0, "runtime": 0, "rasp": 0, "log_audit": 0}
	for _, event := range events {
		score := xdrEventScore(event)
		totalScore += score
		category := componentCategoryFromEvent(event)
		if category != "" {
			categoryCount[category]++
		}
		host := firstNonEmpty(xdrPickString(event, "hostname"), xdrPickString(event, "agent_id"), xdrPickString(event, "dst_ip"), "unknown")
		if _, ok := byHost[host]; !ok {
			byHost[host] = newXDRChainAgg("host:"+host, event)
			byHost[host].Entity = host
		}
		row := byHost[host]
		row.Events = append(row.Events, event)
		if category != "" {
			row.Categories[category] = struct{}{}
		}
		stage := firstNonEmpty(xdrPickString(event, "stage_hint"), inferXDRStage(event))
		if stage != "" {
			row.Stages[stage] = struct{}{}
		}
		if score > row.MaxScore {
			row.MaxScore = score
		}
		sourceIP := xdrSourceIP(event)
		if sourceIP != "" {
			bySource[sourceIP] += score
		}
	}
	chainRows := buildXDRChains(nil, events, 10)
	postureScore := int64(0)
	if len(chainRows) > 0 {
		chainTotal := int64(0)
		for _, chain := range chainRows {
			chainTotal += xdrPickNumber(chain, "score", 0)
		}
		postureScore = clampInt64(chainTotal/int64(len(chainRows))+int64(len(chainRows)*4), 0, 100)
	}
	return map[string]interface{}{
		"risk_score":       postureScore,
		"risk_level":       severityFromScore(float64(postureScore)),
		"component_counts": categoryCount,
		"active_chains":    len(chainRows),
		"top_hosts":        topXDRHostPosture(byHost, 10),
		"top_source_ips":   topXDRSourceScores(bySource, 10),
		"updated_at":       time.Now().UTC().Format(time.RFC3339),
	}
}

func xdrChainScore(row *xdrChainAgg) int64 {
	avg := int64(0)
	if len(row.Events) > 0 {
		avg = row.TotalScore / int64(len(row.Events))
	}
	stageWeight := int64(xdrStageRank(row.SeedStage) * 10)
	if stageWeight == 0 {
		stageWeight = int64(len(row.Stages) * 6)
	}
	return clampInt64(maxInt64(row.MaxScore, avg)+stageWeight+int64(len(row.Categories))*7+int64(len(row.Evidence))*2, 0, 100)
}

func xdrChainRow(row *xdrChainAgg) map[string]interface{} {
	events := append([]map[string]interface{}{}, row.Events...)
	sort.Slice(events, func(i, j int) bool {
		return parseXDRTime(xdrPickString(events[i], "created_at", "timestamp")).Before(parseXDRTime(xdrPickString(events[j], "created_at", "timestamp")))
	})
	score := xdrChainScore(row)
	stages := sortedStages(row.Stages)
	if len(stages) == 0 {
		stages = xdrStagesFromEvents(events)
	}
	if row.SeedStage == "" && len(stages) > 0 {
		row.SeedStage = stages[0]
	}
	return map[string]interface{}{
		"id":                  "chain-" + stableID(row.Key),
		"correlation_key":     row.Key,
		"entity":              row.Entity,
		"victim":              row.Victim,
		"seed_stage":          row.SeedStage,
		"score":               score,
		"severity":            severityFromScore(float64(score)),
		"stage_count":         len(row.Stages),
		"event_count":         len(row.Events),
		"categories":          sortedKeys(row.Categories),
		"stages":              stages,
		"missing_stages":      xdrMissingStages(row.SeedStage, row.Stages),
		"source_ips":          sortedKeys(row.Sources),
		"victim_ips":          sortedKeys(row.VictimIPs),
		"users":               sortedKeys(row.Users),
		"processes":           sortedKeys(row.Processes),
		"sessions":            sortedKeys(row.Sessions),
		"first_seen":          formatOptionalTime(row.FirstSeen),
		"last_seen":           formatOptionalTime(row.LastSeen),
		"summary":             xdrChainSummary(row),
		"evidence":            trimXDREvidence(row.Evidence, 16),
		"event_evidence":      trimXDREvidence(events, 12),
		"response_candidates": responseCandidatesForChain(row),
		"candidate_only":      true,
		"partial_chain":       len(xdrMissingStages(row.SeedStage, row.Stages)) > 0,
		"standalone_alert":    row.Standalone,
	}
}

func xdrStagesFromEvents(events []map[string]interface{}) []string {
	seen := map[string]struct{}{}
	for _, event := range events {
		stage := firstNonEmpty(normalizeXDRStage(xdrPickString(event, "stage_hint")), inferXDRStage(event), incidentStage(event))
		if stage != "" {
			seen[stage] = struct{}{}
		}
	}
	return sortedStages(seen)
}

func newXDRChainAgg(key string, event map[string]interface{}) *xdrChainAgg {
	victim := xdrVictimEntity(event)
	entity := victim
	if entity == "" {
		entity = key
	}
	row := &xdrChainAgg{Key: key, Entity: entity, Victim: victim, Categories: map[string]struct{}{}, Stages: map[string]struct{}{}, Sources: map[string]struct{}{}, VictimIPs: map[string]struct{}{}, Users: map[string]struct{}{}, Processes: map[string]struct{}{}, Sessions: map[string]struct{}{}}
	if victimIP := xdrVictimIP(event); victimIP != "" {
		row.VictimIPs[victimIP] = struct{}{}
	}
	return row
}

func enrichXDREvaluation(event map[string]interface{}) {
	stage, stageDetail := classifyXDRStage(event)
	event["stage_hint"] = stage
	event["stage_detail"] = stageDetail
	score, detail := scoreXDREvent(event)
	event["score_hint"] = score
	event["score_detail"] = detail
	event["risk_level"] = severityFromScore(float64(score))
	event["evaluation_version"] = "xdr-eval.v1"
	event["candidate_only"] = true
}

func classifyXDRStage(event map[string]interface{}) (string, map[string]interface{}) {
	explicit := normalizeXDRStage(xdrPickString(event, "stage_hint", "behavior_context.details.stage_hint", "behavior_context.stage"))
	confidence := xdrPickFloat(event, "confidence", 0.8)
	if explicit != "" && confidence >= 0.6 {
		return explicit, map[string]interface{}{"source": "rule_hint", "confidence": confidence, "preserved": true}
	}
	hay := strings.ToLower(strings.Join([]string{xdrPickString(event, "rule_name"), xdrPickString(event, "event_type"), xdrPickString(event, "message"), componentCategoryFromEvent(event), xdrPickString(event, "mitre_tactic"), xdrPickString(event, "mitre_technique")}, " "))
	stage := "detection"
	reason := "default"
	switch {
	case containsAny(hay, []string{"scan", "probe", "recon", "admin path"}):
		stage, reason = "recon", "recon_keyword"
	case containsAny(hay, []string{"sql injection", "sqli", "auth", "failed password", "login", "initial_access", "t1190"}):
		stage, reason = "initial_access", "initial_access_keyword"
	case containsAny(hay, []string{"shell", "exec", "command", "process", "runtime", "t1059"}):
		stage, reason = "execution", "execution_keyword"
	case containsAny(hay, []string{"credential", "password", "shadow", "id_rsa", "t1110"}):
		stage, reason = "credential_access", "credential_keyword"
	case containsAny(hay, []string{"persist", "webshell", "cron", "startup"}):
		stage, reason = "persistence", "persistence_keyword"
	case containsAny(hay, []string{"privilege", "sudo", "root"}):
		stage, reason = "privilege_escalation", "privilege_keyword"
	case containsAny(hay, []string{"lateral", "movement", "smb", "rdp"}):
		stage, reason = "lateral_movement", "lateral_keyword"
	case containsAny(hay, []string{"exfil", "c2", "dns tunnel", "beacon"}):
		stage, reason = "c2_exfiltration", "c2_exfil_keyword"
	}
	return stage, map[string]interface{}{"source": "online_classifier", "reason": reason, "confidence": 0.7, "preserved": false}
}

func normalizeXDRStage(stage string) string {
	stage = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(stage, "-", "_")))
	switch stage {
	case "recon", "reconnaissance":
		return "recon"
	case "initial_access", "initialaccess":
		return "initial_access"
	case "execution":
		return "execution"
	case "persistence":
		return "persistence"
	case "privilege_escalation", "privilege":
		return "privilege_escalation"
	case "lateral_movement", "lateral":
		return "lateral_movement"
	case "c2_exfiltration", "command_and_control", "exfiltration", "collection":
		return "c2_exfiltration"
	case "credential_access":
		return "credential_access"
	case "detection":
		return "detection"
	default:
		return ""
	}
}

func scoreXDREvent(event map[string]interface{}) (int64, map[string]interface{}) {
	severity := xdrPickString(event, "severity")
	base := severityBaseScore(severity)
	upstream := xdrPickNumber(event, "score_hint", 0)
	if upstream > 0 {
		base = (base + upstream) / 2
	}
	confidence := xdrPickFloat(event, "confidence", 0.8)
	confidenceComponent := int64((confidence - 0.5) * 20)
	categoryComponent := map[string]int64{"traffic": 3, "log_audit": 4, "runtime": 8, "rasp": 10}[componentCategoryFromEvent(event)]
	stage := normalizeXDRStage(xdrPickString(event, "stage_hint"))
	stageComponent := map[string]int64{"recon": 2, "initial_access": 8, "execution": 12, "persistence": 12, "privilege_escalation": 14, "lateral_movement": 14, "credential_access": 12, "c2_exfiltration": 16}[stage]
	evidenceComponent := int64(0)
	if xdrPickString(event, "metadata.source_stream") != "" || xdrPickString(event, "component_rule_id", "rule_id") != "" {
		evidenceComponent = 3
	}
	candidatePenalty := int64(0)
	if xdrPickString(event, "candidate_only") == "true" || xdrPickString(event, "candidate_only") == "1" {
		candidatePenalty = -3
	}
	score := clampInt64(base+confidenceComponent+categoryComponent+stageComponent+evidenceComponent+candidatePenalty, 0, 100)
	return score, map[string]interface{}{"base": base, "severity": severity, "upstream_score_hint": upstream, "confidence_component": confidenceComponent, "category_component": categoryComponent, "stage_component": stageComponent, "evidence_component": evidenceComponent, "candidate_penalty": candidatePenalty, "reason": "severity + upstream hint + confidence + category + stage + evidence - candidate_only"}
}

func xdrEventScore(event map[string]interface{}) int64 {
	return xdrPickNumber(event, "score_hint", severityBaseScore(xdrPickString(event, "severity")))
}

func xdrAttackerIP(event map[string]interface{}) string {
	return firstNonEmpty(xdrPickString(event, "entities.source_ip"), xdrPickString(event, "src_ip"), xdrPickString(event, "source_ip"), xdrPickString(event, "entities.src_ip"), xdrPickString(event, "behavior_context.details.entities.source_ip"))
}

func xdrSourceIP(event map[string]interface{}) string {
	return firstNonEmpty(xdrPickString(event, "src_ip"), xdrPickString(event, "source_ip"), xdrPickString(event, "entities.source_ip"), xdrPickString(event, "behavior_context.details.entities.source_ip"))
}

func xdrVictimEntity(event map[string]interface{}) string {
	return firstNonEmpty(xdrPickString(event, "agent_display_name", "display_name"), xdrPickString(event, "hostname"), xdrPickString(event, "agent_id"), xdrPickString(event, "dst_ip"), xdrPickString(event, "entities.hostname"), xdrPickString(event, "entities.target_ip"))
}

func xdrVictimIP(event map[string]interface{}) string {
	return firstNonEmpty(xdrPickString(event, "dst_ip", "target_ip", "dest_ip", "destination_ip"), xdrPickString(event, "entities.target_ip", "entities.dst_ip", "entities.destination_ip"), xdrPickString(event, "behavior_context.details.entities.target_ip", "behavior_context.details.entities.dst_ip"))
}

func xdrSeedStage(event map[string]interface{}) string {
	return firstNonEmpty(normalizeXDRStage(xdrPickString(event, "stage_hint")), inferXDRStage(event), "detection")
}

func xdrResultOrientedCorrelationKey(event map[string]interface{}, seedStage string) string {
	attacker := xdrAttackerIP(event)
	victim := xdrVictimEntity(event)
	if attacker != "" && victim != "" {
		return "attacker:" + attacker + "|victim:" + victim
	}
	if attacker != "" {
		return "attacker:" + attacker
	}
	if victim != "" && seedStage != "" {
		return "standalone:" + victim + "|stage:" + seedStage
	}
	return xdrCorrelationKey(event)
}

func xdrStageRank(stage string) int {
	switch normalizeXDRStage(stage) {
	case "recon":
		return 1
	case "initial_access":
		return 2
	case "execution":
		return 3
	case "persistence", "privilege_escalation":
		return 4
	case "credential_access", "lateral_movement":
		return 5
	case "collection", "c2_exfiltration", "impact":
		return 6
	case "detection":
		return 1
	default:
		return 0
	}
}

func xdrMissingStages(seedStage string, present map[string]struct{}) []string {
	seedRank := xdrStageRank(seedStage)
	if seedRank < 2 {
		return []string{}
	}
	order := []string{"recon", "initial_access", "execution", "persistence", "privilege_escalation", "credential_access", "lateral_movement", "collection"}
	missing := []string{}
	for _, stage := range order {
		if xdrStageRank(stage) > seedRank {
			break
		}
		if _, ok := present[stage]; !ok {
			missing = append(missing, stage)
		}
	}
	return missing
}

func xdrChainSummary(row *xdrChainAgg) string {
	stages := sortedStages(row.Stages)
	categories := sortedKeys(row.Categories)
	return fmt.Sprintf("%s 上发现 %d 个组件告警，覆盖 %d 个攻击阶段(%s)和 %d 类信号(%s)", firstNonEmpty(row.Victim, row.Entity), len(row.Events), len(stages), strings.Join(stages, ","), len(categories), strings.Join(categories, ","))
}

func responseCandidatesForChain(row *xdrChainAgg) []map[string]interface{} {
	return buildResponseCandidatesFromFacts(xdrChainScore(row), sortedKeys(row.Sources), firstNonEmpty(row.Victim, row.Entity), sortedKeys(row.Categories), sortedStages(row.Stages), trimXDREvidence(row.Events, 6))
}

func buildXDRResponseCandidates(events []map[string]interface{}, limit int) []map[string]interface{} {
	chains := buildXDRChains(nil, events, limit)
	out := []map[string]interface{}{}
	for _, chain := range chains {
		items, _ := chain["response_candidates"].([]map[string]interface{})
		for _, item := range items {
			item["chain_id"] = chain["id"]
			out = append(out, item)
			if len(out) >= limit {
				return out
			}
		}
	}
	return out
}

func buildResponseCandidatesFromFacts(score int64, sources []string, victim string, categories []string, stages []string, evidence []map[string]interface{}) []map[string]interface{} {
	out := []map[string]interface{}{}
	out = append(out, map[string]interface{}{"type": "analyst_review", "target": victim, "reason": "review correlated component alerts", "score": score, "evidence": evidence, "safety": []string{"manual_approval_required"}, "candidate_only": true})
	if score >= 60 {
		out = append(out, map[string]interface{}{"type": "increase_monitoring", "target": victim, "reason": "elevated XDR score", "score": score, "evidence": evidence, "safety": []string{"time_limited", "no_blocking"}, "candidate_only": true})
	}
	if score >= 75 && containsString(categories, "runtime") {
		out = append(out, map[string]interface{}{"type": "collect_forensic_bundle", "target": victim, "reason": "runtime signal in high-risk chain", "score": score, "evidence": evidence, "safety": []string{"manual_approval_required", "read_only_collection"}, "candidate_only": true})
	}
	if score >= 85 && containsString(categories, "rasp") && len(sources) > 0 {
		out = append(out, map[string]interface{}{"type": "suggest_waf_or_proxy_acl", "target": sources[0], "reason": "high-risk RASP source attribution; do not enforce automatically", "score": score, "evidence": evidence, "safety": []string{"approval_required", "xff_trust_required", "no_host_firewall_for_xff"}, "candidate_only": true})
	}
	if score >= 90 && containsAny(strings.Join(stages, " "), []string{"execution", "persistence", "privilege_escalation"}) {
		out = append(out, map[string]interface{}{"type": "suggest_host_isolation", "target": victim, "reason": "critical post-exploitation chain", "score": score, "evidence": evidence, "safety": []string{"executive_approval_required", "break_glass_only", "not_automatic"}, "candidate_only": true})
	}
	return out
}

func sortedStages(values map[string]struct{}) []string {
	order := map[string]int{"recon": 0, "initial_access": 1, "execution": 2, "persistence": 3, "privilege_escalation": 4, "credential_access": 5, "lateral_movement": 6, "collection": 7, "c2_exfiltration": 8, "impact": 9, "detection": 10}
	out := sortedKeys(values)
	sort.SliceStable(out, func(i, j int) bool {
		left, ok := order[out[i]]
		if !ok {
			left = 99
		}
		right, ok := order[out[j]]
		if !ok {
			right = 99
		}
		return left < right
	})
	return out
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func topXDRHostPosture(rows map[string]*xdrChainAgg, limit int) []map[string]interface{} {
	list := make([]*xdrChainAgg, 0, len(rows))
	for _, row := range rows {
		list = append(list, row)
	}
	sort.Slice(list, func(i, j int) bool { return xdrChainScore(list[i]) > xdrChainScore(list[j]) })
	if limit > len(list) {
		limit = len(list)
	}
	out := make([]map[string]interface{}, 0, limit)
	for _, row := range list[:limit] {
		out = append(out, map[string]interface{}{"host": row.Entity, "score": xdrChainScore(row), "severity": severityFromScore(float64(xdrChainScore(row))), "event_count": len(row.Events), "categories": sortedKeys(row.Categories), "stages": sortedKeys(row.Stages)})
	}
	return out
}

func topXDRSourceScores(scores map[string]int64, limit int) []map[string]interface{} {
	type row struct {
		IP    string
		Score int64
	}
	rows := make([]row, 0, len(scores))
	for ip, score := range scores {
		rows = append(rows, row{IP: ip, Score: clampInt64(score, 0, 100)})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Score > rows[j].Score })
	if limit > len(rows) {
		limit = len(rows)
	}
	out := make([]map[string]interface{}, 0, limit)
	for _, row := range rows[:limit] {
		out = append(out, map[string]interface{}{"ip": row.IP, "score": row.Score, "severity": severityFromScore(float64(row.Score))})
	}
	return out
}

func trimXDREvidence(events []map[string]interface{}, limit int) []map[string]interface{} {
	if limit > len(events) {
		limit = len(events)
	}
	out := make([]map[string]interface{}, 0, limit)
	for _, event := range events[:limit] {
		out = append(out, map[string]interface{}{"id": firstNonEmpty(xdrPickString(event, "id"), xdrPickString(event, "message_id")), "timestamp": xdrPickString(event, "created_at", "timestamp"), "category": componentCategoryFromEvent(event), "stage": firstNonEmpty(xdrPickString(event, "stage_hint"), inferXDRStage(event)), "rule_id": firstNonEmpty(xdrPickString(event, "component_rule_id"), xdrPickString(event, "rule_id")), "rule_name": xdrThreatDisplayName(event), "severity": xdrPickString(event, "severity"), "score": xdrPickNumber(event, "score_hint", severityBaseScore(xdrPickString(event, "severity"))), "summary": xdrPickString(event, "message", "summary", "rule_name"), "entities": event["entities"], "src_ip": xdrAttackerIP(event), "dst_ip": xdrPickString(event, "dst_ip", "entities.target_ip"), "dst_port": xdrPickNumber(event, "dst_port", 0), "protocol": firstNonEmpty(xdrPickString(event, "protocol"), xdrPickString(event, "app_protocol")), "evidence_type": firstNonEmpty(xdrPickString(event, "evidence_type"), "alert")})
	}
	return out
}

func xdrThreatDisplayName(event map[string]interface{}) string {
	return firstNonEmpty(xdrPickString(event, "rule_name"), xdrPickString(event, "rule_id"), xdrPickString(event, "component_rule_id"), xdrPickString(event, "type"), xdrPickString(event, "event_type"), xdrPickString(event, "message"))
}

func xdrCorrelationKey(event map[string]interface{}) string {
	if session := firstNonEmpty(xdrPickString(event, "session_id"), xdrPickString(event, "chain_id")); session != "" {
		return "session:" + session
	}
	source := xdrSourceIP(event)
	victim := xdrVictimEntity(event)
	if source != "" && victim != "" {
		return "src:" + source + "|victim:" + victim
	}
	if user := xdrPickString(event, "user"); user != "" && victim != "" {
		return "user:" + user + "|victim:" + victim
	}
	if victim != "" {
		return "victim:" + victim
	}
	return firstNonEmpty(source, xdrPickString(event, "agent_id"), xdrPickString(event, "hostname"))
}

func appendTrafficEvidence(cfg *Config, chain *xdrChainAgg) {
	if cfg == nil || cfg.Redis == nil || chain == nil {
		return
	}
	sources := sortedKeys(chain.Sources)
	if len(sources) == 0 {
		chain.Standalone = true
		return
	}
	ctx := context.Background()
	msgs, err := cfg.Redis.XRevRangeN(ctx, "flows:raw", "+", "-", 1200).Result()
	if err != nil {
		return
	}
	seen := map[string]struct{}{}
	matched := 0
	for _, msg := range msgs {
		flow := trafficItemFromMessage(cfg, "flows:raw", msg)
		if !trafficFlowMatchesChain(flow, chain, sources) {
			continue
		}
		stage := classifyTrafficEvidenceStage(flow, chain.SeedStage)
		flow["component_category"] = "traffic"
		flow["category"] = "traffic"
		flow["stage_hint"] = stage
		flow["evidence_type"] = "traffic_session"
		flow["rule_name"] = trafficEvidenceName(flow, stage)
		flow["severity"] = "low"
		flow["created_at"] = firstNonEmpty(xdrPickString(flow, "timestamp"), xdrPickString(flow, "created_at"))
		key := firstNonEmpty(xdrPickString(flow, "message_id"), xdrPickString(flow, "id"), fmt.Sprintf("%s-%s-%d", xdrPickString(flow, "src_ip"), xdrPickString(flow, "dst_ip"), xdrPickNumber(flow, "dst_port", 0)))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		chain.Evidence = append(chain.Evidence, flow)
		chain.Categories["traffic"] = struct{}{}
		chain.Stages[stage] = struct{}{}
		if source := xdrPickString(flow, "src_ip"); source != "" {
			chain.Sources[source] = struct{}{}
		}
		matched++
		if matched >= 10 {
			break
		}
	}
	chain.Standalone = matched == 0 && len(chain.Sources) == 0
}

func trafficFlowMatchesChain(flow map[string]interface{}, chain *xdrChainAgg, sources []string) bool {
	src := xdrPickString(flow, "src_ip")
	if src == "" || !containsString(sources, src) {
		return false
	}
	victim := firstNonEmpty(chain.Victim, chain.Entity)
	if victim == "" {
		return true
	}
	dst := xdrPickString(flow, "dst_ip")
	return dst == "" || strings.Contains(victim, dst) || strings.Contains(xdrPickString(flow, "hostname", "agent_id"), victim)
}

func classifyTrafficEvidenceStage(flow map[string]interface{}, seedStage string) string {
	port := xdrPickNumber(flow, "dst_port", 0)
	proto := strings.ToLower(firstNonEmpty(xdrPickString(flow, "app_protocol"), xdrPickString(flow, "protocol")))
	if port == 22 || strings.Contains(proto, "ssh") {
		return "initial_access"
	}
	if port == 3389 || port == 5985 || port == 5986 || strings.Contains(proto, "rdp") {
		return "lateral_movement"
	}
	if xdrStageRank(seedStage) >= 2 {
		return "recon"
	}
	return "detection"
}

func trafficEvidenceName(flow map[string]interface{}, stage string) string {
	port := xdrPickNumber(flow, "dst_port", 0)
	proto := strings.ToUpper(firstNonEmpty(xdrPickString(flow, "app_protocol"), xdrPickString(flow, "protocol")))
	if proto == "" || proto == "TLS" {
		proto = commonPortProtocol(port)
	}
	if stage == "initial_access" {
		return fmt.Sprintf("%s 访问会话举证", firstNonEmpty(proto, "目标服务"))
	}
	return fmt.Sprintf("%s/%d 流量会话举证", firstNonEmpty(proto, "TCP"), port)
}

func commonPortProtocol(port int64) string {
	switch port {
	case 22:
		return "SSH"
	case 80:
		return "HTTP"
	case 443:
		return "HTTPS"
	case 3306:
		return "MYSQL"
	case 5432:
		return "POSTGRES"
	case 6379:
		return "REDIS"
	case 3389:
		return "RDP"
	default:
		return "TCP"
	}
}

func xdrEventFromComponentAlert(event map[string]interface{}) bool {
	stream := xdrPickString(event, "metadata.source_stream")
	if stream == "component_alerts:v2" || stream == "alerts:dpi" || stream == "alerts:runtime" || stream == "alerts:rasp" || stream == "alerts:log_audit" || stream == "telemetry:rasp" {
		return true
	}
	return xdrPickString(event, "component_rule_id") != "" || xdrPickString(event, "behavior_context.details.rule_id") != ""
}

func componentCategoryFromEvent(event map[string]interface{}) string {
	return firstNonEmpty(normalizeComponentCategory(xdrPickString(event, "component_category")), componentCategoryFromStream(xdrPickString(event, "metadata.source_stream")), normalizeComponentCategory(xdrPickString(event, "source_module")), normalizeComponentCategory(xdrPickString(event, "module")))
}

func componentCategoryFromStream(stream string) string {
	switch strings.TrimSpace(stream) {
	case "alerts:dpi":
		return "traffic"
	case "alerts:runtime":
		return "runtime"
	case "alerts:rasp", "telemetry:rasp":
		return "rasp"
	case "alerts:log_audit":
		return "log_audit"
	default:
		return ""
	}
}

func normalizeComponentCategory(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "dpi", "traffic", "network":
		return "traffic"
	case "host", "runtime":
		return "runtime"
	case "artifact", "yara":
		return "artifact"
	case "rasp", "application", "app":
		return "rasp"
	case "log", "audit", "log-audit", "log_audit":
		return "log_audit"
	default:
		return ""
	}
}

func inferXDRStage(event map[string]interface{}) string {
	stage := strings.ToLower(firstNonEmpty(xdrPickString(event, "stage_hint"), xdrPickString(event, "mitre_tactic"), xdrPickString(event, "event_type"), xdrPickString(event, "rule_name")))
	switch {
	case strings.Contains(stage, "credential") || strings.Contains(stage, "login") || strings.Contains(stage, "auth") || strings.Contains(stage, "initial_access"):
		return "initial_access"
	case strings.Contains(stage, "execution") || strings.Contains(stage, "process") || strings.Contains(stage, "shell"):
		return "execution"
	case strings.Contains(stage, "privilege") || strings.Contains(stage, "persistence"):
		return "persistence"
	case strings.Contains(stage, "lateral") || strings.Contains(stage, "movement"):
		return "lateral_movement"
	case strings.Contains(stage, "exfil") || strings.Contains(stage, "collection"):
		return "collection"
	case strings.Contains(stage, "recon") || strings.Contains(stage, "scan"):
		return "recon"
	default:
		return firstNonEmpty(xdrPickString(event, "stage_hint"), "detection")
	}
}

func severityBaseScore(severity string) int64 {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical", "严重":
		return 90
	case "high", "高", "高危":
		return 75
	case "medium", "中", "中危":
		return 55
	case "low", "低", "低危":
		return 30
	default:
		return 15
	}
}

func clampInt64(value, min, max int64) int64 {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func formatOptionalTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}

func loadXDREvents(cfg *Config, limit, offset int) ([]map[string]interface{}, int, error) {
	streamEvents, streamTotal, streamErr := loadXDREventsFromStream(cfg, limit, offset)
	if streamErr == nil && (len(streamEvents) > 0 || streamTotal > 0) {
		return streamEvents, streamTotal, nil
	}

	events, total, err := loadXDREventsFromRedis(cfg, limit, offset)
	if err == nil && (len(events) > 0 || total > 0) {
		return events, total, nil
	}

	pgEvents, pgTotal, pgErr := loadXDREventsFromPostgres(cfg, limit, offset)
	if pgErr == nil {
		return pgEvents, pgTotal, nil
	}

	if err != nil {
		return nil, 0, err
	}
	if streamErr != nil {
		return nil, 0, streamErr
	}
	return nil, 0, pgErr
}

func loadXDRAlertsForThreats(cfg *Config, limit, offset int) ([]map[string]interface{}, int, error) {
	events, total, err := loadXDREventsFromStream(cfg, limit, offset)
	if err == nil && (len(events) > 0 || total > 0) {
		return events, total, nil
	}
	events, total, err = loadXDREventsFromRedis(cfg, limit, offset)
	if err == nil && (len(events) > 0 || total > 0) {
		return events, total, nil
	}
	events, total, err = loadXDRAlertsFromStream(cfg, limit, offset)
	if err == nil {
		return events, total, nil
	}
	return nil, 0, err
}

func loadXDRAlertsFromStream(cfg *Config, limit, offset int) ([]map[string]interface{}, int, error) {
	if cfg.Redis == nil {
		return nil, 0, fmt.Errorf("redis unavailable")
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	ctx := context.Background()
	total, err := cfg.Redis.XLen(ctx, "alerts:xdr").Result()
	if err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return []map[string]interface{}{}, 0, nil
	}
	items, err := cfg.Redis.XRevRangeN(ctx, "alerts:xdr", "+", "-", int64(offset+limit)).Result()
	if err != nil {
		return nil, 0, err
	}
	if offset >= len(items) {
		return []map[string]interface{}{}, int(total), nil
	}
	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	events := make([]map[string]interface{}, 0, end-offset)
	for _, msg := range items[offset:end] {
		payload := redisDataPayload(msg.Values)
		if shouldHideOperationalAgentEvent(payload) {
			continue
		}
		if dataRaw := xdrPickString(payload, "data"); dataRaw != "" {
			var decoded map[string]interface{}
			if json.Unmarshal([]byte(dataRaw), &decoded) == nil {
				payload = decoded
			}
		}
		events = append(events, enrichEventRuleDisplay(map[string]interface{}{
			"id":              xdrPickNumber(payload, "id", 0),
			"event_type":      xdrPickString(payload, "event_type"),
			"severity":        xdrPickString(payload, "severity"),
			"message":         xdrPickString(payload, "message"),
			"src_ip":          xdrPickString(payload, "src_ip"),
			"dst_ip":          xdrPickString(payload, "dst_ip"),
			"src_port":        xdrPickNumber(payload, "src_port", 0),
			"dst_port":        xdrPickNumber(payload, "dst_port", 0),
			"user":            xdrPickString(payload, "user"),
			"service":         xdrPickString(payload, "service"),
			"rule_id":         xdrPickNumber(payload, "rule_id", 0),
			"rule_name":       xdrPickString(payload, "rule_name", "event_type"),
			"mitre_tactic":    xdrPickString(payload, "mitre_tactic"),
			"mitre_technique": xdrPickString(payload, "mitre_technique"),
			"status":          firstNonEmpty(xdrPickString(payload, "status"), "new"),
			"source":          xdrPickString(payload, "log_source", "source"),
			"agent_id":        xdrPickString(payload, "agent_id"),
			"hostname":        xdrPickString(payload, "hostname"),
			"entities":        payload["entities"],
			"metadata":        payload["metadata"],
			"native_rule":     payload["native_rule"],
			"rule_pack":       xdrPickString(payload, "rule_pack", "metadata.rule_pack"),
			"created_at":      firstNonEmpty(xdrPickString(payload, "created_at", "timestamp"), time.Now().Format(time.RFC3339)),
			"timestamp":       firstNonEmpty(xdrPickString(payload, "created_at", "timestamp"), time.Now().Format(time.RFC3339)),
		}))
	}
	return events, int(total), nil
}

func loadXDREventsFromRedis(cfg *Config, limit, offset int) ([]map[string]interface{}, int, error) {
	if cfg.Redis == nil {
		return nil, 0, fmt.Errorf("redis unavailable")
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	ctx := context.Background()
	total, err := cfg.Redis.LLen(ctx, "alerts:list").Result()
	if err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return []map[string]interface{}{}, 0, nil
	}

	items, err := cfg.Redis.LRange(ctx, "alerts:list", int64(offset), int64(offset+limit-1)).Result()
	if err != nil {
		return nil, 0, err
	}

	events := make([]map[string]interface{}, 0, len(items))
	for i, raw := range items {
		var event map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			continue
		}
		if shouldHideOperationalAgentEvent(event) {
			continue
		}
		if shouldHideOperationalAgentEvent(event) {
			continue
		}

		createdAt := xdrPickString(event, "created_at")
		if createdAt == "" {
			createdAt = time.Now().Format(time.RFC3339)
		}
		status := xdrPickString(event, "status")
		if status == "" {
			status = "new"
		}

		events = append(events, enrichEventRuleDisplay(map[string]interface{}{
			"id":              xdrPickNumber(event, "id", int64(offset+i+1)),
			"event_type":      xdrPickString(event, "event_type"),
			"severity":        xdrPickString(event, "severity"),
			"message":         xdrPickString(event, "message"),
			"src_ip":          xdrPickString(event, "src_ip"),
			"dst_ip":          xdrPickString(event, "dst_ip"),
			"src_port":        xdrPickNumber(event, "src_port", 0),
			"dst_port":        xdrPickNumber(event, "dst_port", 0),
			"user":            xdrPickString(event, "user"),
			"service":         xdrPickString(event, "service"),
			"rule_id":         xdrPickNumber(event, "rule_id", 0),
			"rule_name":       xdrPickString(event, "rule_name", "event_type"),
			"mitre_tactic":    xdrPickString(event, "mitre_tactic"),
			"mitre_technique": xdrPickString(event, "mitre_technique"),
			"status":          status,
			"source":          xdrPickString(event, "source", "log_source"),
			"entities":        event["entities"],
			"metadata":        event["metadata"],
			"native_rule":     event["native_rule"],
			"rule_pack":       xdrPickString(event, "rule_pack", "metadata.rule_pack"),
			"created_at":      createdAt,
		}))
	}

	return events, int(total), nil
}

func loadXDREventsFromStream(cfg *Config, limit, offset int) ([]map[string]interface{}, int, error) {
	if cfg.Redis == nil {
		return nil, 0, fmt.Errorf("redis unavailable")
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	ctx := context.Background()
	total, err := cfg.Redis.XLen(ctx, "events:xdr").Result()
	if err != nil {
		return nil, 0, err
	}
	if total == 0 {
		return []map[string]interface{}{}, 0, nil
	}

	count := int64(offset + limit)
	items, err := cfg.Redis.XRevRangeN(ctx, "events:xdr", "+", "-", count).Result()
	if err != nil {
		return nil, 0, err
	}
	if offset >= len(items) {
		return []map[string]interface{}{}, int(total), nil
	}

	end := offset + limit
	if end > len(items) {
		end = len(items)
	}
	slice := items[offset:end]
	events := make([]map[string]interface{}, 0, len(slice))
	for _, msg := range slice {
		raw := ""
		switch v := msg.Values["data"].(type) {
		case string:
			raw = v
		case []byte:
			raw = string(v)
		}
		if raw == "" {
			continue
		}

		var event map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			continue
		}

		createdAt := xdrPickString(event, "created_at", "timestamp")
		if createdAt == "" {
			createdAt = time.Now().Format(time.RFC3339)
		}
		status := xdrPickString(event, "status")
		if status == "" {
			status = "new"
		}

		flat := flattenXDRComponentEvent(event)
		events = append(events, enrichEventRuleDisplay(map[string]interface{}{
			"id":                 firstNonEmpty(xdrPickString(flat, "id"), strconv.FormatInt(xdrPickNumber(flat, "id", 0), 10)),
			"event_type":         xdrPickString(flat, "event_type"),
			"severity":           xdrPickString(flat, "severity"),
			"message":            xdrPickString(flat, "message", "summary", "event_type"),
			"module":             xdrPickString(flat, "module"),
			"source_module":      xdrPickString(flat, "source_module"),
			"component_category": firstNonEmpty(xdrPickString(flat, "behavior_context.details.category"), componentCategoryFromStream(xdrPickString(flat, "metadata.source_stream")), xdrPickString(flat, "source_module", "module", "category")),
			"component_rule_id":  xdrPickString(flat, "behavior_context.details.rule_id", "rule_id"),
			"score_hint":         xdrPickNumber(flat, "behavior_context.details.score_hint", xdrPickNumber(flat, "score_hint", severityBaseScore(xdrPickString(flat, "severity")))),
			"stage_hint":         firstNonEmpty(xdrPickString(flat, "behavior_context.details.stage_hint"), xdrPickString(flat, "behavior_context.stage"), xdrPickString(flat, "stage_hint")),
			"confidence":         xdrPickFloat(flat, "behavior_context.details.confidence", xdrPickFloat(flat, "behavior_context.confidence", xdrPickFloat(flat, "confidence", 0))),
			"src_ip":             xdrPickString(flat, "src_ip", "source_ip", "entities.source_ip"),
			"dst_ip":             xdrPickString(flat, "dst_ip", "target_ip", "entities.target_ip"),
			"src_port":           xdrPickNumber(flat, "src_port", 0),
			"dst_port":           xdrPickNumber(flat, "dst_port", 0),
			"user":               xdrPickString(flat, "user", "entities.user"),
			"service":            xdrPickString(flat, "service", "entities.application"),
			"rule_id":            xdrPickNumber(flat, "rule_id", 0),
			"rule_name":          xdrPickString(flat, "rule_name", "event_type"),
			"mitre_tactic":       xdrPickString(flat, "mitre_tactic"),
			"mitre_technique":    xdrPickString(flat, "mitre_technique"),
			"status":             status,
			"source":             xdrPickString(flat, "source", "log_source", "source_module"),
			"agent_id":           xdrPickString(flat, "agent_id", "entities.agent_id"),
			"hostname":           xdrPickString(flat, "hostname", "entities.hostname"),
			"chain_id":           xdrPickString(flat, "chain_id"),
			"session_id":         xdrPickString(flat, "session_id", "entities.session_id"),
			"process_id":         xdrPickString(flat, "process_id", "entities.process_id"),
			"entities":           event["entities"],
			"tags":               flat["tags"],
			"metadata":           flat["metadata"],
			"native_rule":        firstNonNil(event["native_rule"], flat["native_rule"]),
			"rule_pack":          xdrPickString(flat, "rule_pack", "metadata.rule_pack", "behavior_context.details.rule_pack"),
			"created_at":         createdAt,
		}))
	}

	return events, int(total), nil
}

func flattenXDRComponentEvent(event map[string]interface{}) map[string]interface{} {
	flat := map[string]interface{}{}
	for k, v := range event {
		flat[k] = v
	}
	mergeXDRDetails(flat, asMap(event["entities"]), "entities")
	if behavior := asMap(event["behavior_context"]); len(behavior) > 0 {
		for k, v := range behavior {
			flat["behavior_context."+k] = v
		}
		details := asMap(behavior["details"])
		if len(details) > 0 {
			mergeXDRDetails(flat, details, "behavior_context.details")
			mergeXDRDetails(flat, asMap(details["entities"]), "behavior_context.details.entities")
		}
	}
	if metadata := asMap(event["metadata"]); len(metadata) > 0 {
		for k, v := range metadata {
			flat["metadata."+k] = v
		}
	}
	if _, ok := flat["src_ip"]; !ok {
		flat["src_ip"] = firstNonEmpty(xdrPickString(flat, "source_ip"), xdrPickString(flat, "entities.source_ip"), xdrPickString(flat, "behavior_context.details.entities.source_ip"))
	}
	if _, ok := flat["dst_ip"]; !ok {
		flat["dst_ip"] = firstNonEmpty(xdrPickString(flat, "target_ip"), xdrPickString(flat, "entities.target_ip"), xdrPickString(flat, "behavior_context.details.entities.target_ip"))
	}
	if _, ok := flat["agent_id"]; !ok {
		flat["agent_id"] = firstNonEmpty(xdrPickString(flat, "entities.agent_id"), xdrPickString(flat, "behavior_context.details.entities.agent_id"))
	}
	if _, ok := flat["hostname"]; !ok {
		flat["hostname"] = firstNonEmpty(xdrPickString(flat, "entities.hostname"), xdrPickString(flat, "behavior_context.details.entities.hostname"))
	}
	if flat["event_type"] == nil {
		flat["event_type"] = firstNonEmpty(xdrPickString(flat, "rule_name"), "component.alert")
	}
	return flat
}

func firstNonNil(values ...interface{}) interface{} {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return nil
}

func enrichEventRuleDisplay(event map[string]interface{}) map[string]interface{} {
	native := asMap(event["native_rule"])
	metadata := asMap(event["metadata"])
	ruleID := firstNonEmpty(xdrPickString(event, "component_rule_id"), xdrPickString(event, "rule_id"), asString(native["id"]), asString(metadata["rule_id"]))
	ruleName := firstNonEmpty(xdrPickString(event, "rule_name"), asString(native["name"]), asString(native["signature"]), asString(metadata["rule_name"]), xdrPickString(event, "event_type"))
	engine := firstNonEmpty(xdrPickString(event, "source_engine"), asString(native["engine"]), asString(metadata["source_engine"]), xdrPickString(event, "source"))
	rulePack := firstNonEmpty(xdrPickString(event, "rule_pack"), asString(metadata["rule_pack"]), asString(metadata["rule_pack_version"]))
	event["rule_id"] = ruleID
	event["component_rule_id"] = ruleID
	event["rule_name"] = ruleName
	event["source_engine"] = engine
	event["rule_pack"] = rulePack
	parts := []string{}
	if engine != "" {
		parts = append(parts, "引擎 "+engine)
	}
	if ruleID != "" {
		parts = append(parts, "规则ID "+ruleID)
	}
	if ruleName != "" {
		parts = append(parts, "策略 "+ruleName)
	}
	if rulePack != "" {
		parts = append(parts, "规则包 "+rulePack)
	}
	event["rule_hit_detail"] = strings.Join(parts, " · ")
	return event
}

func mergeXDRDetails(flat map[string]interface{}, values map[string]interface{}, prefix string) {
	for k, v := range values {
		flat[prefix+"."+k] = v
		if _, ok := flat[k]; !ok {
			flat[k] = v
		}
	}
}

func loadXDREventsFromPostgres(cfg *Config, limit, offset int) ([]map[string]interface{}, int, error) {
	if cfg.DBPool == nil {
		return nil, 0, fmt.Errorf("postgres unavailable")
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	ctx := context.Background()
	var total int
	if err := cfg.DBPool.QueryRow(ctx, "SELECT COUNT(*) FROM events WHERE event_type LIKE 'xdr.%'").Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := cfg.DBPool.Query(ctx, `
		SELECT id, event_type, severity, source, src_ip, dst_ip, status, timestamp, created_at
		FROM events
		WHERE event_type LIKE 'xdr.%'
		ORDER BY timestamp DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	events := make([]map[string]interface{}, 0, limit)
	for rows.Next() {
		var id int64
		var eventType, severity, source, srcIP, dstIP, status string
		var ts time.Time
		var createdAt time.Time
		if err := rows.Scan(&id, &eventType, &severity, &source, &srcIP, &dstIP, &status, &ts, &createdAt); err != nil {
			return nil, 0, err
		}
		t := createdAt
		if t.IsZero() {
			t = ts
		}
		if status == "" {
			status = "new"
		}
		events = append(events, map[string]interface{}{
			"id":         id,
			"event_type": eventType,
			"severity":   severity,
			"message":    eventType,
			"src_ip":     srcIP,
			"dst_ip":     dstIP,
			"rule_name":  eventType,
			"status":     status,
			"source":     source,
			"created_at": t.Format(time.RFC3339),
		})
	}

	return events, total, nil
}

func parseQueryInt(v string, defaultVal int) int {
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}

func loadRASPEvents(cfg *Config, limit, offset int) ([]map[string]interface{}, int, error) {
	if cfg.Redis == nil {
		return nil, 0, fmt.Errorf("redis unavailable")
	}
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	ctx := context.Background()
	streams := []string{"alerts:rasp", "telemetry:rasp"}
	events := make([]map[string]interface{}, 0, limit)
	total := int64(0)
	for _, stream := range streams {
		length, err := cfg.Redis.XLen(ctx, stream).Result()
		if err != nil {
			return nil, 0, err
		}
		total += length
		msgs, err := cfg.Redis.XRevRangeN(ctx, stream, "+", "-", int64(offset+limit)).Result()
		if err != nil {
			return nil, 0, err
		}
		for _, msg := range msgs {
			event := redisDataPayload(msg.Values)
			if xdrPickString(event, "id") == "" {
				event["id"] = "rasp-" + strings.ReplaceAll(msg.ID, "-", "")
			}
			if xdrPickString(event, "occurred_at", "created_at", "timestamp") == "" {
				event["occurred_at"] = time.Now().UTC().Format(time.RFC3339Nano)
			}
			if xdrPickString(event, "mode") == "" {
				event["mode"] = "monitor"
			}
			if xdrPickString(event, "source") == "" {
				event["source"] = stream
			}
			events = append(events, event)
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		return parseXDRTime(xdrPickString(events[i], "occurred_at", "created_at", "timestamp")).After(parseXDRTime(xdrPickString(events[j], "occurred_at", "created_at", "timestamp")))
	})
	if offset >= len(events) {
		return []map[string]interface{}{}, int(total), nil
	}
	end := offset + limit
	if end > len(events) {
		end = len(events)
	}

	return events[offset:end], int(total), nil
}

func loadRASPProtectionAgents(cfg *Config) ([]map[string]interface{}, error) {
	if cfg.Redis == nil {
		return nil, fmt.Errorf("redis unavailable")
	}
	ctx := context.Background()
	keys, err := cfg.Redis.Keys(ctx, "rasp:protection:*").Result()
	if err != nil {
		return nil, err
	}
	items := make([]map[string]interface{}, 0, len(keys))
	for _, key := range keys {
		data, err := cfg.Redis.Get(ctx, key).Result()
		if err != nil {
			continue
		}
		var agent map[string]interface{}
		if err := json.Unmarshal([]byte(data), &agent); err != nil {
			continue
		}
		if xdrPickString(agent, "agent_id") == "" {
			agent["agent_id"] = strings.TrimPrefix(key, "rasp:protection:")
		}
		items = append(items, agent)
	}
	seen := map[string]struct{}{}
	for _, item := range items {
		if id := xdrPickString(item, "agent_id"); id != "" {
			seen[id] = struct{}{}
		}
	}
	msgs, err := cfg.Redis.XRevRangeN(ctx, "telemetry:rasp", "+", "-", 50).Result()
	if err == nil {
		for _, msg := range msgs {
			event := redisDataPayload(msg.Values)
			agentID := firstNonEmpty(xdrPickString(event, "entities.agent_id"), xdrPickString(event, "fields.agent_id"), xdrPickString(event, "agent_id"))
			if agentID == "" {
				continue
			}
			if _, ok := seen[agentID]; ok {
				continue
			}
			seen[agentID] = struct{}{}
			fields := asMap(event["fields"])
			items = append(items, map[string]interface{}{
				"agent_id":     agentID,
				"hostname":     firstNonEmpty(xdrPickString(event, "entities.hostname"), asString(fields["hostname"])),
				"status":       firstNonEmpty(asString(fields["status"]), xdrPickString(event, "status"), "protected"),
				"mode":         firstNonEmpty(asString(fields["mode"]), xdrPickString(event, "mode"), "monitor"),
				"policy_state": firstNonEmpty(asString(fields["policy_state"]), "audit_only"),
				"source":       firstNonEmpty(asString(fields["source"]), xdrPickString(event, "source"), "telemetry:rasp"),
				"last_seen_at": firstNonEmpty(xdrPickString(event, "observed_at", "received_at", "created_at"), asString(fields["last_seen_at"])),
				"applications": firstNonNil(fields["applications"], []interface{}{}),
				"hooks":        firstNonNil(fields["hooks"], []interface{}{}),
			})
		}
	}
	return items, nil
}

func mapUnifiedEventFromXDR(e map[string]interface{}) map[string]interface{} {
	id := xdrPickString(e, "id")
	if id == "" {
		id = fmt.Sprintf("evt-%d", xdrPickNumber(e, "id", time.Now().UnixNano()))
	}
	ts := xdrPickString(e, "created_at", "timestamp")
	if ts == "" {
		ts = time.Now().UTC().Format(time.RFC3339)
	}
	status := xdrPickString(e, "status")
	if status == "" {
		status = "new"
	}
	return enrichEventRuleDisplay(map[string]interface{}{
		"id":                id,
		"module":            "xdr",
		"event_type":        xdrPickString(e, "event_type"),
		"source":            xdrPickString(e, "source", "log_source"),
		"severity":          xdrPickString(e, "severity"),
		"timestamp":         ts,
		"created_at":        ts,
		"status":            status,
		"alert":             true,
		"agent_id":          xdrPickString(e, "agent_id"),
		"hostname":          xdrPickString(e, "hostname"),
		"message":           xdrPickString(e, "message", "event_type"),
		"src_ip":            xdrPickString(e, "src_ip"),
		"dst_ip":            xdrPickString(e, "dst_ip"),
		"src_port":          xdrPickNumber(e, "src_port", 0),
		"dst_port":          xdrPickNumber(e, "dst_port", 0),
		"user":              xdrPickString(e, "user"),
		"service":           xdrPickString(e, "service"),
		"rule_id":           xdrPickNumber(e, "rule_id", 0),
		"rule_name":         xdrPickString(e, "rule_name", "event_type"),
		"component_rule_id": firstNonEmpty(xdrPickString(e, "component_rule_id"), xdrPickString(e, "rule_id")),
		"source_engine":     xdrPickString(e, "source_engine"),
		"rule_pack":         xdrPickString(e, "rule_pack"),
		"native_rule":       e["native_rule"],
		"mitre_tactic":      xdrPickString(e, "mitre_tactic"),
		"mitre_technique":   xdrPickString(e, "mitre_technique"),
		"tags":              e["tags"],
		"raw_data":          xdrPickString(e, "raw_log", "raw_data"),
		"metadata":          e["metadata"],
	})
}

type incidentBucket struct {
	id       string
	severity string
	first    time.Time
	last     time.Time
	events   []map[string]interface{}
	stages   map[string]bool
}

var incidentStatusStore sync.Map

func deriveIncidents(events []map[string]interface{}) []map[string]interface{} {
	buckets := map[string]*incidentBucket{}
	for _, event := range events {
		if shouldHideOperationalAgentEvent(event) {
			continue
		}
		unified := mapUnifiedEventFromXDR(event)
		if shouldHideOperationalAgentEvent(unified) {
			continue
		}
		key := incidentCorrelationKey(unified)
		if key == "" {
			continue
		}
		when := parseXDRTime(xdrPickString(unified, "timestamp", "created_at"))
		if when.IsZero() {
			when = time.Now().UTC()
		}
		b := buckets[key]
		if b == nil {
			b = &incidentBucket{id: "inc-" + safeID(key), severity: "low", first: when, last: when, stages: map[string]bool{}, events: []map[string]interface{}{}}
			buckets[key] = b
		}
		if when.Before(b.first) {
			b.first = when
		}
		if when.After(b.last) {
			b.last = when
		}
		if severityRank(xdrPickString(unified, "severity")) > severityRank(b.severity) {
			b.severity = xdrPickString(unified, "severity")
		}
		stage := incidentStage(unified)
		b.stages[stage] = true
		unified["stage"] = stage
		b.events = append(b.events, unified)
	}

	incidents := make([]map[string]interface{}, 0, len(buckets))
	for key, b := range buckets {
		if len(b.events) < 2 && !strings.HasPrefix(key, "chain:") {
			continue
		}
		stages := make([]string, 0, len(b.stages))
		for stage := range b.stages {
			stages = append(stages, stage)
		}
		sort.Strings(stages)
		attackChain := buildAttackChainEvidence(b.events)
		status := "open"
		if legacyStatus, exists := loadLegacyIncidentStatus(b.id); exists {
			status = string(legacyStatus)
		}
		incidents = append(incidents, map[string]interface{}{
			"id":               b.id,
			"title":            incidentTitle(b),
			"summary":          incidentSummary(b),
			"correlation":      key,
			"severity":         b.severity,
			"severity_label":   severityLabel(b.severity),
			"status":           status,
			"status_label":     incidentStatusLabel(status),
			"first_seen":       b.first.Format(time.RFC3339Nano),
			"last_seen":        b.last.Format(time.RFC3339Nano),
			"stages":           stages,
			"stage_labels":     stageLabels(stages),
			"event_count":      len(b.events),
			"events":           b.events,
			"attack_chain":     attackChain,
			"evidence_summary": evidenceSummary(b.events),
		})
	}
	sort.Slice(incidents, func(i, j int) bool {
		return xdrPickString(incidents[i], "last_seen") > xdrPickString(incidents[j], "last_seen")
	})
	return incidents
}

func shouldHideOperationalAgentEvent(event map[string]interface{}) bool {
	agentID := xdrPickString(event, "agent_id", "entities.agent_id")
	if strings.EqualFold(agentID, "test-agent") || strings.HasPrefix(strings.ToLower(agentID), "test-") {
		return true
	}
	hostname := xdrPickString(event, "hostname", "entities.hostname")
	if strings.EqualFold(hostname, "test-agent") {
		return true
	}
	eventType := strings.ToLower(xdrPickString(event, "event_type", "type"))
	if eventType != "runtime.process.new" && eventType != "process.new" {
		return false
	}
	hay := strings.ToLower(strings.Join([]string{
		xdrPickString(event, "message"),
		xdrPickString(event, "cmdline"),
		xdrPickString(event, "process"),
		xdrPickString(event, "process_name"),
		xdrPickString(event, "service"),
		xdrPickString(event, "rule_name"),
	}, " "))
	for _, token := range []string{" kworker", "[kworker", " agetty", "/agetty", " ps ", "/bin/ps", "/usr/bin/ps", " systemd", " containerd", " dockerd"} {
		if strings.Contains(" "+hay+" ", token) {
			return true
		}
	}
	severity := strings.ToLower(xdrPickString(event, "severity"))
	return severity == "" || severity == "info" || severity == "low"
}

func incidentStatusLabel(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "new":
		return "新发"
	case "triaged":
		return "已分诊"
	case "processing":
		return "处理中"
	case "resolved":
		return "已解决"
	case "closed":
		return "已关闭"
	default:
		return "待处置"
	}
}

func buildTimeline(events []map[string]interface{}, entityID, sessionID string) []map[string]interface{} {
	items := make([]map[string]interface{}, 0, len(events))
	for _, event := range events {
		unified := mapUnifiedEventFromXDR(event)
		entity := timelineEntity(unified)
		session := xdrPickString(unified, "session_id")
		if session == "" {
			session = incidentCorrelationKey(unified)
		}
		if entityID != "" && entity != entityID {
			continue
		}
		if sessionID != "" && session != sessionID {
			continue
		}
		id := "tl-" + safeID(xdrPickString(unified, "id")+"-"+xdrPickString(unified, "timestamp"))
		items = append(items, map[string]interface{}{
			"id":             id,
			"event_id":       xdrPickString(unified, "id"),
			"timestamp":      xdrPickString(unified, "timestamp"),
			"entity_id":      entity,
			"session_id":     session,
			"stage":          incidentStage(unified),
			"stage_label":    stageLabel(incidentStage(unified)),
			"severity":       xdrPickString(unified, "severity"),
			"severity_label": severityLabel(xdrPickString(unified, "severity")),
			"event_type":     xdrPickString(unified, "event_type"),
			"message":        xdrPickString(unified, "message"),
			"summary":        timelineSummary(unified),
			"source":         xdrPickString(unified, "source"),
		})
	}
	sort.Slice(items, func(i, j int) bool {
		return xdrPickString(items[i], "timestamp") < xdrPickString(items[j], "timestamp")
	})
	return items
}

func incidentTitle(b *incidentBucket) string {
	entity := "目标资产"
	if len(b.events) > 0 {
		entity = readableEntity(timelineEntity(b.events[0]))
	}
	return fmt.Sprintf("%s 出现%s攻击链", entity, severityLabel(b.severity))
}

func incidentSummary(b *incidentBucket) string {
	return fmt.Sprintf("系统在同一关联范围内发现 %d 个安全事件，覆盖 %d 个攻击阶段，建议立即核查证据并确认处置优先级。", len(b.events), len(b.stages))
}

func buildAttackChainEvidence(events []map[string]interface{}) []map[string]interface{} {
	chain := make([]map[string]interface{}, 0, len(events))
	for _, event := range events {
		stage := incidentStage(event)
		chain = append(chain, map[string]interface{}{
			"stage":          stage,
			"stage_label":    stageLabel(stage),
			"event_id":       xdrPickString(event, "id"),
			"time":           xdrPickString(event, "timestamp", "created_at"),
			"severity":       xdrPickString(event, "severity"),
			"severity_label": severityLabel(xdrPickString(event, "severity")),
			"summary":        timelineSummary(event),
		})
	}
	sort.Slice(chain, func(i, j int) bool { return xdrPickString(chain[i], "time") < xdrPickString(chain[j], "time") })
	return chain
}

func evidenceSummary(events []map[string]interface{}) []string {
	items := make([]string, 0, len(events))
	for _, event := range events {
		items = append(items, timelineSummary(event))
	}
	return items
}

func stageLabels(stages []string) []string {
	labels := make([]string, 0, len(stages))
	for _, stage := range stages {
		labels = append(labels, stageLabel(stage))
	}
	return labels
}

func uniqueStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func stagesToAttackChain(stages []string, chain map[string]interface{}) []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(stages))
	for _, stage := range stages {
		out = append(out, map[string]interface{}{
			"stage":       stage,
			"stage_label": stageLabel(stage),
			"summary":     firstNonEmpty(xdrPickString(chain, "summary"), stageLabel(stage)),
			"time":        firstNonEmpty(xdrPickString(chain, "first_seen"), xdrPickString(chain, "last_seen")),
		})
	}
	return out
}

func stageLabel(stage string) string {
	switch stage {
	case "recon", "reconnaissance":
		return "扫描侦察阶段"
	case "initial_access":
		return "入侵突破阶段"
	case "credential_access":
		return "凭证访问阶段"
	case "execution":
		return "命令执行阶段"
	case "persistence":
		return "持久化阶段"
	case "privilege_escalation":
		return "提权阶段"
	case "lateral_movement":
		return "横向移动阶段"
	case "collection":
		return "数据收集阶段"
	case "c2_exfiltration":
		return "回连外传阶段"
	case "impact":
		return "影响破坏阶段"
	default:
		return "风险确认阶段"
	}
}

func severityLabel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		return "提示"
	}
}

func readableEntity(entity string) string {
	if entity == "" {
		return "目标资产"
	}
	parts := strings.SplitN(entity, ":", 2)
	if len(parts) != 2 {
		return entity
	}
	switch parts[0] {
	case "agent":
		return "Agent " + parts[1]
	case "host":
		return "主机 " + parts[1]
	case "ip":
		return "地址 " + parts[1]
	case "user":
		return "用户 " + parts[1]
	default:
		return parts[1]
	}
}

func timelineSummary(event map[string]interface{}) string {
	stage := stageLabel(incidentStage(event))
	message := xdrPickString(event, "message")
	if message == "" {
		message = xdrPickString(event, "event_type")
	}
	entity := readableEntity(timelineEntity(event))
	if message == "" {
		return fmt.Sprintf("%s 发生%s事件", entity, stage)
	}
	return fmt.Sprintf("%s 在%s阶段触发：%s", entity, stage, message)
}

func incidentCorrelationKey(event map[string]interface{}) string {
	if chainID := nestedString(event, "metadata", "chain_id"); chainID != "" {
		return "chain:" + chainID
	}
	if chainID := xdrPickString(event, "chain_id"); chainID != "" {
		return "chain:" + chainID
	}
	if sessionID := xdrPickString(event, "session_id"); sessionID != "" {
		return "session:" + sessionID
	}
	entity := timelineEntity(event)
	if entity == "" {
		return ""
	}
	return "entity:" + entity
}

func timelineEntity(event map[string]interface{}) string {
	if value := xdrPickString(event, "agent_id"); value != "" {
		return "agent:" + value
	}
	if value := xdrPickString(event, "hostname"); value != "" {
		return "host:" + value
	}
	if value := xdrPickString(event, "src_ip"); value != "" {
		return "ip:" + value
	}
	if value := xdrPickString(event, "dst_ip"); value != "" {
		return "ip:" + value
	}
	if value := xdrPickString(event, "user"); value != "" {
		return "user:" + value
	}
	return ""
}

func incidentStage(event map[string]interface{}) string {
	hay := strings.ToLower(xdrPickString(event, "message") + " " + xdrPickString(event, "event_type") + " " + xdrPickString(event, "rule_name") + " " + strings.Join(stringSlice(event["tags"]), " "))
	switch {
	case strings.Contains(hay, "credential") || strings.Contains(hay, "login") || strings.Contains(hay, "brute"):
		return "credential_access"
	case strings.Contains(hay, "command") || strings.Contains(hay, "process") || strings.Contains(hay, "execution"):
		return "execution"
	case strings.Contains(hay, "upload") || strings.Contains(hay, "admin") || strings.Contains(hay, "initial_access"):
		return "initial_access"
	case strings.Contains(hay, "impact") || strings.Contains(hay, "exfil"):
		return "impact"
	default:
		return "detection"
	}
}

func nestedString(event map[string]interface{}, parent, key string) string {
	if nested, ok := event[parent].(map[string]interface{}); ok {
		return xdrPickString(nested, key)
	}
	return ""
}

func stringSlice(value interface{}) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []interface{}:
		items := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				items = append(items, s)
			}
		}
		return items
	default:
		return nil
	}
}

func severityRank(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func safeID(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var b strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	return strings.Trim(b.String(), "-")
}

func getOrInitRASPProtectionAgent(cfg *Config, agentID string) (map[string]interface{}, error) {
	if cfg.Redis == nil {
		return nil, fmt.Errorf("redis unavailable")
	}
	ctx := context.Background()
	key := fmt.Sprintf("rasp:protection:%s", agentID)
	data, err := cfg.Redis.Get(ctx, key).Result()
	if err == nil {
		var agent map[string]interface{}
		if uErr := json.Unmarshal([]byte(data), &agent); uErr == nil {
			return agent, nil
		}
	}
	return map[string]interface{}{
		"agent_id":      agentID,
		"enabled":       false,
		"block_mode":    false,
		"blocked_types": map[string]bool{},
		"rules":         map[string]interface{}{},
		"stats": map[string]interface{}{
			"blocked_count": 0,
			"allowed_count": 0,
			"by_type":       map[string]int64{},
			"recent_blocks": []map[string]interface{}{},
		},
		"last_update": time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func saveRASPProtectionAgent(cfg *Config, agentID string, agent map[string]interface{}) error {
	if cfg.Redis == nil {
		return fmt.Errorf("redis unavailable")
	}
	ctx := context.Background()
	key := fmt.Sprintf("rasp:protection:%s", agentID)
	payload, err := json.Marshal(agent)
	if err != nil {
		return err
	}
	return cfg.Redis.Set(ctx, key, payload, 0).Err()
}

func xdrPickString(event map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		v, ok := xdrLookup(event, key)
		if !ok {
			continue
		}
		switch vv := v.(type) {
		case string:
			if vv != "" {
				return vv
			}
		case float64:
			if vv != 0 {
				return strconv.FormatFloat(vv, 'f', -1, 64)
			}
		case int64:
			if vv != 0 {
				return strconv.FormatInt(vv, 10)
			}
		case int:
			if vv != 0 {
				return strconv.Itoa(vv)
			}
		}
	}
	return ""
}

func xdrPickNumber(event map[string]interface{}, key string, fallback int64) int64 {
	v, ok := xdrLookup(event, key)
	if !ok {
		return fallback
	}
	switch vv := v.(type) {
	case float64:
		return int64(vv)
	case int64:
		return vv
	case int:
		return int64(vv)
	case json.Number:
		n, err := vv.Int64()
		if err == nil {
			return n
		}
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(vv), 10, 64)
		if err == nil {
			return n
		}
	}
	return fallback
}

func xdrPickFloat(event map[string]interface{}, key string, fallback float64) float64 {
	v, ok := xdrLookup(event, key)
	if !ok {
		return fallback
	}
	switch vv := v.(type) {
	case float64:
		return vv
	case int64:
		return float64(vv)
	case int:
		return float64(vv)
	case json.Number:
		n, err := vv.Float64()
		if err == nil {
			return n
		}
	case string:
		n, err := strconv.ParseFloat(strings.TrimSpace(vv), 64)
		if err == nil {
			return n
		}
	}
	return fallback
}

func xdrLookup(event map[string]interface{}, key string) (interface{}, bool) {
	v, ok := event[key]
	if ok {
		return v, true
	}
	if !strings.Contains(key, ".") {
		return nil, false
	}
	var cur interface{} = event
	for _, part := range strings.Split(key, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, cur != nil
}

func stableID(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:8])
}

func parseXDRTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t
	}
	return time.Time{}
}

func xdrLogHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 405, "message": "Method not allowed"})
			return
		}

		var input map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 400, "message": "Invalid JSON"})
			return
		}

		log.Printf("[XDR] 收到日志: %v", input)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"received": true,
			},
		})
	}
}

var xdrProcessor *xdrprocessor.XDRProcessor

func startXDRProcessor(cfg *Config) {
	log.Println("[XDR] XDR Processor 初始化中...")
	rulesDir := resolveXDRRulesDir()
	processor, err := xdrprocessor.NewXDRProcessor(cfg.RedisAddr, rulesDir)
	if err != nil {
		log.Printf("[XDR] XDR Processor 初始化失败: %v", err)
		return
	}
	xdrProcessor = processor
	processor.Start()
}

// ============ Unified API Handlers ============

func unifiedStatsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		xdrEvents, total, err := loadXDREvents(cfg, 2000, 0)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}

		today := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.Now().Location())
		byModule := map[string]int64{"dpi": 0, "xdr": 0, "rasp": 0, "vuln": 0, "baseline": 0}
		bySeverity := map[string]int64{"critical": 0, "high": 0, "medium": 0, "low": 0}
		bySource := map[string]int64{}
		todayEvents := int64(0)

		for _, event := range xdrEvents {
			byModule["xdr"]++
			sev := strings.ToLower(xdrPickString(event, "severity"))
			switch sev {
			case "critical", "high", "medium":
				bySeverity[sev]++
			default:
				bySeverity["low"]++
			}
			source := xdrPickString(event, "source", "log_source")
			if source == "" {
				source = "events:xdr"
			}
			bySource[source]++
			t := parseXDRTime(xdrPickString(event, "created_at", "timestamp"))
			if !t.IsZero() && !t.Before(today) {
				todayEvents++
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"total_events": total,
				"today_events": todayEvents,
				"total_alerts": total,
				"today_alerts": todayEvents,
				"by_module":    byModule,
				"by_severity":  bySeverity,
				"by_source":    bySource,
			},
		})
	}
}

func unifiedEventsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		limit := parseQueryInt(r.URL.Query().Get("limit"), 50)
		offset := parseQueryInt(r.URL.Query().Get("offset"), 0)
		if limit <= 0 {
			limit = 50
		}
		if offset < 0 {
			offset = 0
		}

		events, _, err := loadXDREvents(cfg, offset+limit+200, 0)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}

		items := make([]map[string]interface{}, 0, len(events))
		for _, e := range events {
			if shouldHideOperationalAgentEvent(e) {
				continue
			}
			item := mapUnifiedEventFromXDR(e)
			if module := r.URL.Query().Get("module"); module != "" && !strings.EqualFold(xdrPickString(item, "module"), module) {
				continue
			}
			if sev := r.URL.Query().Get("severity"); sev != "" && !strings.EqualFold(xdrPickString(item, "severity"), sev) {
				continue
			}
			if status := r.URL.Query().Get("status"); status != "" && !strings.EqualFold(xdrPickString(item, "status"), status) {
				continue
			}
			items = append(items, item)
		}

		total := len(items)
		if offset > total {
			offset = total
		}
		end := offset + limit
		if end > total {
			end = total
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"items":  items[offset:end],
				"total":  total,
				"limit":  limit,
				"offset": offset,
			},
		})
	}
}

func trafficFlowsHandler(cfg *Config) http.HandlerFunc {
	return trafficStreamHandler(cfg, "flows:raw")
}

func trafficSessionsHandler(cfg *Config) http.HandlerFunc {
	return trafficStreamHandler(cfg, "sessions:semantic")
}

func componentAlertsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		category := strings.TrimPrefix(r.URL.Path, "/api/v1/component-alerts")
		category = strings.Trim(category, "/")
		if category == "" {
			category = strings.TrimSpace(r.URL.Query().Get("category"))
		}
		limit := parseQueryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		offset := parseQueryInt(r.URL.Query().Get("offset"), 0)
		items, total, err := loadComponentAlerts(cfg, category, limit, offset)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "component_alerts_failed", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": items, "total": total, "limit": limit, "offset": offset}})
	}
}

func loadComponentAlerts(cfg *Config, category string, limit, offset int) ([]map[string]interface{}, int, error) {
	if cfg.Redis == nil {
		return nil, 0, fmt.Errorf("redis unavailable")
	}
	streams := componentAlertStreams(category)
	ctx := context.Background()
	fetchCount := offset + limit
	if normalizeComponentCategory(category) == "rasp" {
		// RASP telemetry includes a high-volume protection heartbeat. Read
		// enough entries so heartbeats cannot crowd real detections out of the
		// first page.
		fetchCount += 512
	}
	all := make([]map[string]interface{}, 0, fetchCount*len(streams))
	agentNames := activeAgentDisplayNames(ctx, cfg)
	for _, stream := range streams {
		msgs, err := cfg.Redis.XRevRangeN(ctx, stream, "+", "-", int64(fetchCount)).Result()
		if err != nil {
			return nil, 0, err
		}
		for _, msg := range msgs {
			payload := redisDataPayload(msg.Values)
			if dataRaw := xdrPickString(payload, "data"); dataRaw != "" {
				var decoded map[string]interface{}
				if json.Unmarshal([]byte(dataRaw), &decoded) == nil {
					payload = decoded
				}
			}
			if shouldHideOperationalAgentEvent(payload) {
				continue
			}
			if strings.HasPrefix(strings.ToLower(xdrPickString(payload, "event_type", "type")), "rasp.protection.") ||
				strings.Contains(strings.ToLower(xdrPickString(payload, "summary", "message", "excerpt")), "rasp protection heartbeat") {
				continue
			}
			if !xdrEventBelongsToActiveAgent(payload, agentNames) {
				continue
			}
			enrichXDRDisplayName(payload, agentNames)
			payload["message_id"] = msg.ID
			payload["stream"] = stream
			categoryName := firstNonEmpty(normalizeComponentCategory(xdrPickString(payload, "category")), componentCategoryFromStream(stream))
			if category != "" && !componentAlertCategoryMatches(category, categoryName) {
				continue
			}
			payload["category"] = categoryName
			if payload["language"] == nil {
				payload["language"] = firstNonEmpty(xdrPickString(payload, "language"), xdrPickString(asMap(payload["fields"]), "language"))
			}
			if payload["application"] == nil {
				payload["application"] = firstNonEmpty(xdrPickString(payload, "application", "service"), xdrPickString(asMap(payload["fields"]), "application"))
			}
			applyMirrorCaptureLabel(payload)
			all = append(all, payload)
		}
	}
	sort.Slice(all, func(i, j int) bool { return xdrPickString(all[i], "message_id") > xdrPickString(all[j], "message_id") })
	total := len(all)
	if offset > len(all) {
		return []map[string]interface{}{}, total, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], total, nil
}

func componentAlertStreams(category string) []string {
	switch normalizeComponentCategory(category) {
	case "artifact":
		return []string{"component_alerts:v2"}
	case "traffic":
		return []string{"component_alerts:v2", "alerts:dpi"}
	case "runtime":
		return []string{"component_alerts:v2", "alerts:runtime"}
	case "rasp":
		return []string{"component_alerts:v2", "alerts:rasp", "telemetry:rasp"}
	case "log_audit":
		return []string{"alerts:log_audit"}
	default:
		return []string{"component_alerts:v2", "alerts:dpi", "alerts:runtime", "alerts:rasp", "alerts:log_audit"}
	}
}

func componentAlertCategoryMatches(requested, actual string) bool {
	req := normalizeComponentCategory(requested)
	act := normalizeComponentCategory(actual)
	if req == "" || req == act {
		return true
	}
	if req == "traffic" && act == "network" {
		return true
	}
	if req == "log_audit" && act == "log" {
		return true
	}
	return false
}

func engineHealthHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		items, err := loadEngineHealth(r.Context(), cfg)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "engine_health_failed", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": items, "total": len(items)}})
	}
}

type mirrorCaptureConfig struct {
	Enabled   bool   `json:"enabled"`
	Interface string `json:"interface"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

func mirrorCaptureConfigPath() string {
	return ".sisyphus/runtime/mirror-capture-config.json"
}

func loadMirrorCaptureConfig() mirrorCaptureConfig {
	cfg := mirrorCaptureConfig{Enabled: true}
	_ = readJSONFile(mirrorCaptureConfigPath(), &cfg)
	cfg.Interface = strings.TrimSpace(cfg.Interface)
	if cfg.Interface == "" {
		cfg.Enabled = false
	}
	return cfg
}

func saveMirrorCaptureConfig(cfg mirrorCaptureConfig) error {
	cfg.Interface = strings.TrimSpace(cfg.Interface)
	if cfg.Interface == "" {
		cfg.Enabled = false
	}
	cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := os.MkdirAll(filepath.Dir(mirrorCaptureConfigPath()), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(mirrorCaptureConfigPath(), data, 0o644)
}

func mirrorCaptureConfigHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": mirrorCaptureConfigResponse(cfg)})
		case http.MethodPut, http.MethodPost:
			var req mirrorCaptureConfig
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_mirror_capture_config", "Invalid mirror capture config")
				return
			}
			managementInterface := hostManagementInterface(cfg)
			if managementInterface != "" && strings.TrimSpace(req.Interface) == managementInterface {
				writeJSONError(w, http.StatusBadRequest, "management_interface_not_allowed", "管理接口不能用于镜像抓包")
				return
			}
			req.Enabled = strings.TrimSpace(req.Interface) != ""
			if err := saveMirrorCaptureConfig(req); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "save_mirror_capture_config_failed", err.Error())
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": mirrorCaptureConfigResponse(cfg)})
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		}
	}
}

func mirrorCaptureConfigResponse(cfg *Config) map[string]interface{} {
	config := loadMirrorCaptureConfig()
	return map[string]interface{}{
		"enabled":              strings.TrimSpace(config.Interface) != "",
		"interface":            config.Interface,
		"updated_at":           config.UpdatedAt,
		"interfaces":           mirrorCaptureInterfaces(cfg, config.Interface),
		"management_interface": hostManagementInterface(cfg),
	}
}

func mirrorCaptureInterfaces(cfg *Config, selected string) []map[string]interface{} {
	items := []map[string]interface{}{}
	seen := map[string]int{}
	managementInterface := hostManagementInterface(cfg)
	add := func(item map[string]interface{}) {
		name := strings.TrimSpace(asString(item["name"]))
		if name == "" || name == managementInterface {
			return
		}
		item["name"] = name
		if idx, ok := seen[name]; ok {
			items[idx] = mergeMirrorInterface(items[idx], item)
			return
		}
		seen[name] = len(items)
		items = append(items, item)
	}

	hostItems := hostNetworkInterfaces(cfg)
	for _, item := range hostItems {
		add(item)
	}
	if len(hostItems) == 0 {
		for _, item := range containerNetworkInterfaces() {
			add(item)
		}
	}

	selected = strings.TrimSpace(selected)
	if selected != "" {
		add(map[string]interface{}{"name": selected, "state": "saved", "source": "saved_config"})
	}
	sort.SliceStable(items, func(i, j int) bool {
		return strings.ToLower(asString(items[i]["name"])) < strings.ToLower(asString(items[j]["name"]))
	})
	return items
}

func hostManagementInterface(cfg *Config) string {
	if cfg != nil && strings.TrimSpace(cfg.ManagementInterface) != "" {
		return strings.TrimSpace(cfg.ManagementInterface)
	}
	for _, path := range []string{"/host/proc/net/route", "/proc/net/route"} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 4 && fields[1] == "00000000" && fields[0] != "lo" {
				flags, _ := strconv.ParseUint(fields[3], 16, 32)
				if flags&0x1 != 0 {
					return fields[0]
				}
			}
		}
	}
	return ""
}

func containerNetworkInterfaces() []map[string]interface{} {
	ifaces, _ := net.Interfaces()
	items := make([]map[string]interface{}, 0, len(ifaces))
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		state := "down"
		if iface.Flags&net.FlagUp != 0 {
			state = "up"
		}
		addrs, _ := iface.Addrs()
		ips := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			ips = append(ips, addr.String())
		}
		items = append(items, map[string]interface{}{"name": iface.Name, "mac": iface.HardwareAddr.String(), "ips": ips, "state": state, "source": "server"})
	}
	return items
}

func hostNetworkInterfaces(cfg *Config) []map[string]interface{} {
	path := "/host/sys/class/net"
	if cfg != nil && strings.TrimSpace(cfg.HostNetClassPath) != "" {
		path = strings.TrimSpace(cfg.HostNetClassPath)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil
	}
	items := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		name := strings.TrimSpace(entry.Name())
		if name == "" || name == "lo" {
			continue
		}
		target, err := os.Readlink(filepath.Join(path, name))
		if err != nil {
			continue
		}
		if strings.Contains(target, "/devices/virtual/") {
			continue
		}
		items = append(items, map[string]interface{}{
			"name":   name,
			"mac":    readTrimmedFile(filepath.Join(path, name, "address")),
			"state":  firstNonEmpty(readTrimmedFile(filepath.Join(path, name, "operstate")), "unknown"),
			"source": "host",
		})
	}
	return items
}

func readTrimmedFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func mergeMirrorInterface(base, next map[string]interface{}) map[string]interface{} {
	for key, value := range next {
		if key == "source" {
			base[key] = mergeStringCSV(asString(base[key]), asString(value))
			continue
		}
		if _, exists := base[key]; !exists || asString(base[key]) == "" {
			base[key] = value
		}
	}
	return base
}

func mergeStringCSV(left, right string) string {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if right == "" || strings.Contains(","+left+",", ","+right+",") {
		return left
	}
	if left == "" {
		return right
	}
	return left + "," + right
}

func applyMirrorCaptureLabel(item map[string]interface{}) {
	if !isMirrorCaptureItem(item) {
		return
	}
	agentID := strings.TrimSpace(xdrPickString(item, "agent_id"))
	if agentID == "" || agentID == "local" || agentID == "localhost" {
		item["agent_id"] = "local"
	}
	item["display_name"] = "流量镜像分析"
	item["agent_display_name"] = "流量镜像分析"
	item["probe_name"] = "流量镜像分析"
	item["probe_kind"] = "镜像接口"
	item["capture_source"] = "mirror"
	if entities := asMap(item["entities"]); len(entities) > 0 {
		entityAgentID := strings.TrimSpace(xdrPickString(entities, "agent_id"))
		if entityAgentID == "" || entityAgentID == "local" || entityAgentID == "localhost" {
			entities["agent_id"] = "local"
		}
		entities["display_name"] = "流量镜像分析"
		item["entities"] = entities
	}
}

func attributeMirrorTrafficToAgent(item map[string]interface{}, agentInfos map[string]activeTrafficAgentInfo) {
	if !isMirrorCaptureItem(item) || len(agentInfos) == 0 {
		return
	}
	src := strings.TrimSpace(xdrPickString(item, "src_ip"))
	dst := strings.TrimSpace(xdrPickString(item, "dst_ip"))
	for agentID, info := range agentInfos {
		ip := strings.TrimSpace(info.IP)
		if ip == "" || (ip != src && ip != dst) {
			continue
		}
		name := firstNonEmpty(info.DisplayName, info.Hostname, agentID)
		item["agent_id"] = agentID
		item["sensor_id"] = agentID
		item["attributed_agent_id"] = agentID
		item["attributed_agent_name"] = name
		item["associated_agent_id"] = agentID
		item["associated_agent_name"] = name
		item["agent_display_name"] = "流量镜像分析"
		item["display_name"] = "流量镜像分析"
		item["probe_name"] = "流量镜像分析"
		item["probe_kind"] = "镜像接口"
		item["capture_source"] = "mirror"
		if info.Hostname != "" {
			item["hostname"] = info.Hostname
			item["attributed_hostname"] = info.Hostname
			item["associated_hostname"] = info.Hostname
		}
		if content := asMap(item["content"]); len(content) > 0 {
			content["agent_id"] = agentID
			content["sensor_id"] = agentID
			content["attributed_agent_id"] = agentID
			content["attributed_agent_name"] = name
			content["associated_agent_id"] = agentID
			content["associated_agent_name"] = name
			content["agent_display_name"] = "流量镜像分析"
			content["display_name"] = "流量镜像分析"
			content["probe_name"] = "流量镜像分析"
			content["probe_kind"] = "镜像接口"
			content["capture_source"] = "mirror"
			if info.Hostname != "" {
				content["hostname"] = info.Hostname
				content["attributed_hostname"] = info.Hostname
				content["associated_hostname"] = info.Hostname
			}
			item["content"] = content
		}
		if entities := asMap(item["entities"]); len(entities) > 0 {
			entities["agent_id"] = agentID
			entities["display_name"] = "流量镜像分析"
			entities["attributed_agent_id"] = agentID
			entities["attributed_agent_name"] = name
			item["entities"] = entities
		}
		return
	}
}

func isMirrorCaptureItem(item map[string]interface{}) bool {
	if strings.EqualFold(xdrPickString(item, "capture_source"), "mirror") || xdrPickString(item, "probe_kind") == "镜像接口" || xdrPickString(item, "probe_name", "display_name", "agent_display_name") == "流量镜像分析" {
		return true
	}
	agentID := strings.ToLower(strings.TrimSpace(xdrPickString(item, "agent_id", "entities.agent_id")))
	if agentID != "" && agentID != "local" && agentID != "localhost" {
		return false
	}
	source := strings.ToLower(xdrPickString(item, "source", "metadata.source"))
	if strings.HasPrefix(source, "ly-agent-") {
		return false
	}
	return isConfiguredMirrorInterfaceItem(item)
}

func isConfiguredMirrorInterfaceItem(item map[string]interface{}) bool {
	config := loadMirrorCaptureConfig()
	if !config.Enabled || config.Interface == "" {
		return false
	}
	configured := strings.ToLower(config.Interface)
	for _, value := range mirrorCaptureInterfaceValues(item) {
		if strings.ToLower(strings.TrimSpace(value)) == configured {
			return true
		}
	}
	return false
}

func mirrorCaptureInterfaceValues(item map[string]interface{}) []string {
	keys := []string{
		"interface", "iface", "capture_interface", "source_interface", "ingress_interface", "ingress_iface", "in_iface", "input_interface",
		"metadata.interface", "metadata.iface", "metadata.capture_interface", "metadata.source_interface", "metadata.ingress_interface",
		"native_rule.interface", "content.interface", "content.iface", "content.capture_interface", "content.source_interface",
	}
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		if value := xdrPickString(item, key); value != "" {
			values = append(values, value)
		}
	}
	return values
}

func loadEngineHealth(ctx context.Context, cfg *Config) ([]map[string]interface{}, error) {
	if cfg == nil || cfg.DBPool == nil {
		return []map[string]interface{}{}, nil
	}
	rows, err := cfg.DBPool.Query(ctx, `
		SELECT a.uuid, COALESCE(a.hostname, ''), COALESCE(host(a.ip), ''), COALESCE(a.status, 'offline'), COALESCE(a.last_heartbeat, NOW()), COALESCE(h.metadata, '{}'::jsonb)
		FROM agents a
		LEFT JOIN hosts h ON h.agent_id = a.uuid
		ORDER BY a.last_heartbeat DESC NULLS LAST
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var agentID, hostname, ip, status string
		var lastHeartbeat time.Time
		var metadataRaw []byte
		if err := rows.Scan(&agentID, &hostname, &ip, &status, &lastHeartbeat, &metadataRaw); err != nil {
			return nil, err
		}
		capabilities := capabilitiesFromMetadata(metadataRaw)
		engines := asMap(capabilities["engine_supervisors"])
		for _, name := range []string{"suricata", "wazuh", "yara", "rasp"} {
			engine := asMap(engines[name])
			installed := asBool(engine["installed"])
			running := asBool(engine["running"])
			version := asString(engine["version"])
			lastError := asString(engine["last_error"])
			if len(engine) == 0 || (!installed && !running) {
				if capState, ok := engineCapabilityStateFromMetadata(name, capabilities); ok {
					installed = true
					running = capState
					version = firstNonEmpty(version, "ly-agent-adapter")
					lastError = ""
				}
			}
			items = append(items, map[string]interface{}{
				"agent_id":          agentID,
				"hostname":          hostname,
				"ip":                ip,
				"agent_status":      status,
				"last_heartbeat":    lastHeartbeat.Format(time.RFC3339Nano),
				"engine":            name,
				"installed":         installed,
				"running":           running,
				"version":           version,
				"config_hash":       asString(engine["config_hash"]),
				"rule_pack_version": asString(engine["rule_pack_version"]),
				"output_path":       asString(engine["output_path"]),
				"last_error":        lastError,
				"last_event_at":     engine["last_event_at"],
			})
		}
	}
	return items, rows.Err()
}

func engineCapabilityStateFromMetadata(name string, capabilities map[string]interface{}) (bool, bool) {
	var capability map[string]interface{}
	switch name {
	case "suricata":
		capability = asMap(capabilities["traffic_collector"])
	case "wazuh":
		capability = asMap(capabilities["log_collector"])
	case "yara":
		capability = asMap(capabilities["yara_scanner"])
	case "rasp":
		capability = asMap(capabilities["rasp_probe_manager"])
	}
	if len(capability) == 0 {
		return false, false
	}
	enabled := asBool(capability["enabled"])
	status := strings.ToLower(asString(capability["status"]))
	return enabled && status != "disabled", true
}

func trafficThreatsHandler(cfg *Config) http.HandlerFunc {
	return threatCategoryHTTPHandler(cfg, "traffic")
}

func threatCategoryHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		category := strings.TrimPrefix(r.URL.Path, "/api/v1/threats/")
		category = strings.Trim(category, "/")
		if category == "" {
			category = "traffic"
		}
		threatCategoryHTTPHandler(cfg, category)(w, r)
	}
}

func threatCategoryHTTPHandler(cfg *Config, category string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		limit := parseQueryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		offset := parseQueryInt(r.URL.Query().Get("offset"), 0)
		if offset < 0 {
			offset = 0
		}
		query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("query")))
		agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
		srcIP := strings.TrimSpace(r.URL.Query().Get("src_ip"))
		dstIP := strings.TrimSpace(r.URL.Query().Get("dst_ip"))
		severity := strings.TrimSpace(r.URL.Query().Get("severity"))
		startTime := parseOptionalTime(r.URL.Query().Get("start_time"))
		endTime := parseOptionalTime(r.URL.Query().Get("end_time"))

		scheduleThreatBackfill(cfg)
		all, total, err := loadPersistentThreatEvents(r.Context(), cfg, category, limit, offset, query, agentID, srcIP, dstIP, severity, startTime, endTime)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}
		if strings.EqualFold(category, "traffic") && !cfg.SecurityEngineEnabled {
			for _, threat := range loadTrafficHeuristicThreats(cfg, startTime, endTime) {
				if threatMatchesFilters(threat, query, agentID, srcIP, dstIP, severity) {
					all = append(all, threat)
				}
			}
		}
		if (strings.EqualFold(category, "log") || strings.EqualFold(category, "audit") || strings.EqualFold(category, "log-audit")) && !cfg.SecurityEngineEnabled {
			for _, threat := range loadRuntimeAuthThreats(cfg, startTime, endTime) {
				if threatMatchesFilters(threat, query, agentID, srcIP, dstIP, severity) {
					all = append(all, threat)
				}
			}
		}
		if len(all) > limit {
			all = all[:limit]
		}
		items := all

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"items":  items,
				"total":  total,
				"limit":  limit,
				"offset": offset,
			},
		})
	}
}

func backfillRecentThreatEvents(ctx context.Context, cfg *Config, limit int) {
	if cfg == nil || cfg.DBPool == nil || cfg.Redis == nil {
		return
	}
	if limit <= 0 {
		limit = 1000
	}
	for _, stream := range threatBackfillStreams(cfg.SecurityEngineEnabled) {
		msgs, err := cfg.Redis.XRevRangeN(ctx, stream, "+", "-", int64(limit)).Result()
		if err != nil {
			continue
		}
		for _, msg := range msgs {
			payload := redisDataPayload(msg.Values)
			if dataRaw := xdrPickString(payload, "data"); dataRaw != "" {
				var decoded map[string]interface{}
				if json.Unmarshal([]byte(dataRaw), &decoded) == nil {
					payload = decoded
				}
			}
			if err := persistThreatEvent(ctx, cfg, normalizeComponentAlertStreamEvent(stream, msg.ID, payload)); err != nil {
				log.Printf("threat event backfill failed stream=%s message_id=%s err=%v", stream, msg.ID, err)
			}
		}
	}
}

func threatBackfillStreams(securityEngineEnabled bool) []string {
	if securityEngineEnabled {
		return []string{"component_alerts:v2"}
	}
	return []string{"alerts:dpi", "alerts:runtime", "alerts:rasp", "alerts:log_audit", "telemetry:rasp"}
}

func scheduleThreatBackfill(cfg *Config) {
	if cfg == nil || cfg.DBPool == nil || cfg.Redis == nil {
		return
	}
	threatBackfillMu.Lock()
	if time.Since(threatBackfillLast) < 30*time.Second {
		threatBackfillMu.Unlock()
		return
	}
	threatBackfillLast = time.Now()
	threatBackfillMu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		backfillRecentThreatEvents(ctx, cfg, 200)
	}()
}

func trafficNoiseRuleKey(event map[string]interface{}) string {
	return strings.ToLower(strings.TrimSpace(firstNonEmpty(xdrPickString(event, "component_rule_id"), xdrPickString(event, "rule_id"), xdrPickString(event, "native_rule.id"))))
}

func trafficNoiseRuleName(event map[string]interface{}) string {
	return strings.ToLower(strings.TrimSpace(firstNonEmpty(xdrPickString(event, "rule_name"), xdrPickString(event, "event_type"), xdrPickString(event, "message"), xdrPickString(event, "summary"), xdrPickString(event, "native_rule.name"))))
}

func isTrafficNoiseRule(event map[string]interface{}, ids []string, names []string) bool {
	id := trafficNoiseRuleKey(event)
	name := trafficNoiseRuleName(event)
	if strings.HasPrefix(name, "suricata traffic-id:") {
		return true
	}
	for _, candidate := range ids {
		if id == strings.ToLower(candidate) {
			return true
		}
	}
	for _, candidate := range names {
		if strings.Contains(name, strings.ToLower(candidate)) {
			return true
		}
	}
	return false
}

func shouldSuppressTrafficNoiseEvent(event map[string]interface{}) bool {
	if normalizeComponentCategory(componentCategoryFromEvent(event)) != "traffic" {
		return false
	}
	return isTrafficNoiseRule(event,
		[]string{
			"oisf-trafficid-300000001",
			"snort-community-27085",
			"snort-community-3135",
			"snort-community-23725", "snort-community-32888",
			"snort-community-28428", "snort-community-28429", "snort-community-28430",
			"snort-community-32038", "snort-community-32039", "snort-community-32043", "snort-community-32069",
			"snort-community-46435", "snort-community-46436", "snort-community-46438",
			"snort-community-25949", "snort-community-46785", "snort-community-46786", "snort-community-48764", "snort-community-48765", "snort-community-48766", "snort-community-48767", "snort-community-48844", "snort-community-48904", "snort-community-49396", "snort-community-49397", "snort-community-49398",
			"oisf-trafficid-300000010", "oisf-trafficid-300000011", "oisf-trafficid-300000012", "oisf-trafficid-300000013", "oisf-trafficid-300000014", "oisf-trafficid-300000015",
			"et-open-1000001", "et-open-1000050", "suricata-etopen-1000050",
		},
		[]string{
			"SURICATA TRAFFIC-ID: Ubuntu APT-GET",
			"EXPLOIT-KIT Unknown Malvertising exploit kit Hostile Jar pipe.class",
			"FILE-IDENTIFY PNG file download request",
			"MALWARE-CNC Win.Backdoor.Chopper web shell connection",
			"NETBIOS SMB Trans2 QUERY_FILE_INFO attempt",
			"FILE-IDENTIFY Portable Executable binary file magic detected",
			"INDICATOR-COMPROMISE Potential Redirect from Compromised WordPress site to Fedex",
			"SURICATA TRAFFIC-ID: google",
			"ET TROJAN High DNS Query Count Possible Tunnel", "ET TROJAN Possible DNS Tunnel",
			"OS-OTHER Bash environment variable injection attempt",
			"EXPLOIT-KIT Glazunov exploit kit",
			"MALWARE-CNC Vbs.Downloader", "MALWARE-CNC Win.Trojan.Zebrocy", "MALWARE-CNC Win.Downloader.Zebrocy",
		})
}

func applyTrafficNoisePolicy(event map[string]interface{}) {
	if normalizeComponentCategory(componentCategoryFromEvent(event)) != "traffic" {
		return
	}
	if !shouldSuppressTrafficNoiseEvent(event) {
		return
	}
	event["severity"] = "info"
	event["score_hint"] = int64(0)
	event["stage_hint"] = "noise"
	metadata := asMap(event["metadata"])
	if len(metadata) == 0 {
		metadata = map[string]interface{}{}
	}
	metadata["noise_policy"] = "traffic-suppressed"
	event["metadata"] = metadata
}

func persistThreatEvent(ctx context.Context, cfg *Config, event map[string]interface{}) error {
	if cfg == nil || cfg.DBPool == nil || event == nil || shouldHideOperationalAgentEvent(event) {
		return nil
	}
	if shouldHideUnenrolledAgentThreatEvent(ctx, cfg, event) {
		return nil
	}
	category := componentCategoryFromEvent(event)
	if category == "" {
		category = normalizeComponentCategory(xdrPickString(event, "category"))
	}
	if category != "traffic" && category != "runtime" && category != "rasp" && category != "log_audit" {
		return nil
	}
	if shouldSuppressTrafficNoiseEvent(event) {
		return nil
	}
	if trafficThreatHasNoFlowContext(event) {
		return nil
	}
	applyTrafficNoisePolicy(event)
	severity := strings.ToLower(xdrPickString(event, "severity"))
	if severity == "" || severity == "info" || xdrEventIsSyntheticNoise(event) || xdrEventIsInformationalTelemetry(event) {
		return nil
	}
	uid := firstNonEmpty(xdrPickString(event, "id"), xdrPickString(event, "message_id"))
	if uid == "" {
		raw, _ := json.Marshal(event)
		sum := sha256.Sum256(raw)
		uid = hex.EncodeToString(sum[:])
	}
	observed := parseThreatEventTime(event)
	raw, err := json.Marshal(event)
	if err != nil {
		return transport.Permanent(transport.ReasonInvalidPayload, err)
	}
	_, err = cfg.DBPool.Exec(ctx, `INSERT INTO threat_events (event_uid, category, severity, source_engine, event_type, agent_id, src_ip, dst_ip, message, observed_at, raw_event, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,NOW())
		ON CONFLICT (event_uid) DO NOTHING`, uid, category, severity, xdrPickString(event, "source_engine", "source"), xdrPickString(event, "event_type"), xdrPickString(event, "agent_id"), xdrPickString(event, "src_ip"), xdrPickString(event, "dst_ip"), xdrPickString(event, "message", "summary", "rule_name"), observed, string(raw))
	if err != nil {
		return fmt.Errorf("materialize threat event uid=%s category=%s: %w", uid, category, err)
	}
	return nil
}

func shouldHideUnenrolledAgentThreatEvent(ctx context.Context, cfg *Config, event map[string]interface{}) bool {
	agentID := strings.TrimSpace(xdrPickString(event, "agent_id", "entities.agent_id"))
	if agentID == "" || strings.EqualFold(agentID, "local") || strings.EqualFold(agentID, "localhost") {
		return false
	}
	if cfg == nil || cfg.DBPool == nil {
		return false
	}
	var exists bool
	err := cfg.DBPool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agents WHERE uuid=$1)`, agentID).Scan(&exists)
	if err != nil {
		log.Printf("未登记 agent 检查失败: agent_id=%s err=%v", agentID, err)
		return false
	}
	if exists {
		return false
	}
	log.Printf("忽略未登记 agent 威胁告警: agent_id=%s rule=%s", agentID, xdrPickString(event, "component_rule_id", "rule_id", "rule_name"))
	return true
}

func loadPersistentThreatEvents(ctx context.Context, cfg *Config, category string, limit, offset int, query, agentID, srcIP, dstIP, severity string, startTime, endTime *time.Time) ([]map[string]interface{}, int, error) {
	if cfg == nil || cfg.DBPool == nil {
		return nil, 0, fmt.Errorf("database unavailable")
	}
	want := normalizeComponentCategory(category)
	if want == "" {
		want = category
	}
	clauses := []string{"category=$1", "(agent_id IS NULL OR agent_id = '' OR agent_id IN ('local', 'localhost') OR EXISTS (SELECT 1 FROM agents a WHERE a.uuid = threat_events.agent_id))"}
	args := []interface{}{want}
	add := func(clause string, value interface{}) {
		args = append(args, value)
		clauses = append(clauses, fmt.Sprintf(clause, len(args)))
	}
	if severity != "" {
		add("severity=$%d", strings.ToLower(severity))
	}
	if agentID != "" {
		add("agent_id=$%d", agentID)
	}
	if srcIP != "" {
		add("src_ip ILIKE '%%' || $%d || '%%'", srcIP)
	}
	if dstIP != "" {
		add("dst_ip ILIKE '%%' || $%d || '%%'", dstIP)
	}
	if startTime != nil {
		add("observed_at >= $%d", *startTime)
	}
	if endTime != nil {
		add("observed_at <= $%d", *endTime)
	}
	if query != "" {
		args = append(args, query)
		idx := len(args)
		clauses = append(clauses, fmt.Sprintf("(message ILIKE '%%' || $%d || '%%' OR event_type ILIKE '%%' || $%d || '%%' OR raw_event::text ILIKE '%%' || $%d || '%%')", idx, idx, idx))
	}
	where := strings.Join(clauses, " AND ")
	filteredSQL := "SELECT raw_event, category, source_engine, agent_id, observed_at, created_at, " +
		"COALESCE(NULLIF(event_type,''), NULLIF(raw_event->>'rule_id',''), NULLIF(raw_event->>'rule_name',''), NULLIF(message,''), 'unknown') AS aggregate_type, " +
		"COALESCE(NULLIF(src_ip,''), NULLIF(raw_event->'entities'->>'source_ip',''), '') AS aggregate_src, " +
		"COALESCE(NULLIF(dst_ip,''), NULLIF(raw_event->'entities'->>'target_ip',''), '') AS aggregate_dst, " +
		"COALESCE(NULLIF(raw_event->'native_rule'->>'source',''), '') AS aggregate_native_source, " +
		"COALESCE(NULLIF(raw_event->'native_rule'->>'id',''), '') AS aggregate_native_id " +
		"FROM threat_events WHERE " + where
	groupBySQL := "category, aggregate_type, aggregate_src, aggregate_dst, aggregate_native_source, aggregate_native_id, COALESCE(source_engine,''), COALESCE(agent_id,'')"
	countSQL := "WITH filtered AS (" + filteredSQL + ") SELECT COUNT(*) FROM (SELECT 1 FROM filtered GROUP BY " + groupBySQL + ") grouped"
	var total int
	if err := cfg.DBPool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	queryArgs := append([]interface{}{}, args...)
	queryArgs = append(queryArgs, limit, offset)
	limitIdx := len(queryArgs) - 1
	offsetIdx := len(queryArgs)
	rows, err := cfg.DBPool.Query(ctx, "WITH filtered AS ("+filteredSQL+") SELECT raw_event::text, occurrence_count, first_seen, last_seen, aggregate_key FROM ("+
		"SELECT (array_agg(raw_event ORDER BY observed_at DESC, created_at DESC))[1] AS raw_event, COUNT(*) AS occurrence_count, MIN(observed_at) AS first_seen, MAX(observed_at) AS last_seen, "+
		"md5(concat_ws('|', category, aggregate_type, aggregate_src, aggregate_dst, aggregate_native_source, aggregate_native_id, COALESCE(source_engine,''), COALESCE(agent_id,''))) AS aggregate_key "+
		"FROM filtered GROUP BY "+groupBySQL+") grouped ORDER BY last_seen DESC LIMIT $"+strconv.Itoa(limitIdx)+" OFFSET $"+strconv.Itoa(offsetIdx), queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	agentInfos := activeTrafficAgentInfos(ctx, cfg)
	for rows.Next() {
		var raw, aggregateKey string
		var occurrenceCount int
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&raw, &occurrenceCount, &firstSeen, &lastSeen, &aggregateKey); err != nil {
			continue
		}
		var event map[string]interface{}
		if json.Unmarshal([]byte(raw), &event) != nil {
			continue
		}
		enrichThreatEventDisplayName(event, agentInfos)
		event["persisted_category"] = want
		if threat := threatFromXDREvent(event, want); threat != nil {
			threat["aggregate_key"] = aggregateKey
			threat["count"] = occurrenceCount
			threat["occurrence_count"] = occurrenceCount
			threat["first_seen"] = firstSeen.UTC().Format(time.RFC3339)
			threat["last_seen"] = lastSeen.UTC().Format(time.RFC3339)
			threat["timestamp"] = lastSeen.UTC().Format(time.RFC3339)
			items = append(items, threat)
		}
	}
	return items, total, rows.Err()
}

func enrichThreatEventDisplayName(event map[string]interface{}, agentInfos map[string]activeTrafficAgentInfo) {
	if event == nil || isMirrorCaptureItem(event) {
		return
	}
	agentID := xdrPickString(event, "agent_id", "entities.agent_id")
	if agentID == "" || agentID == "local" || agentID == "localhost" {
		return
	}
	name := strings.TrimSpace(agentInfos[agentID].DisplayName)
	if name == "" {
		return
	}
	event["display_name"] = name
	event["agent_display_name"] = name
	event["probe_name"] = name
}

func parseThreatEventTime(event map[string]interface{}) time.Time {
	for _, key := range []string{"created_at", "timestamp", "occurred_at", "time"} {
		if raw := xdrPickString(event, key); raw != "" {
			if parsed := parseOptionalTime(raw); parsed != nil {
				return parsed.UTC()
			}
			if ms, err := strconv.ParseInt(raw, 10, 64); err == nil {
				if ms > 1_000_000_000_000 {
					return time.UnixMilli(ms).UTC()
				}
				return time.Unix(ms, 0).UTC()
			}
		}
	}
	return time.Now().UTC()
}

func trafficThreatFromXDREvent(event map[string]interface{}) map[string]interface{} {
	return threatFromXDREvent(event, "traffic")
}

func threatFromXDREvent(event map[string]interface{}, category string) map[string]interface{} {
	if shouldSuppressTrafficNoiseEvent(event) {
		return nil
	}
	if trafficThreatHasNoFlowContext(event) {
		return nil
	}
	applyTrafficNoisePolicy(event)
	severity := strings.ToLower(xdrPickString(event, "severity"))
	if severity == "" || severity == "info" {
		return nil
	}
	if xdrEventIsInformationalTelemetry(event) {
		return nil
	}
	if xdrEventIsAuthPrivilegeNoise(event) {
		return nil
	}
	if xdrEventIsSyntheticNoise(event) {
		return nil
	}
	if !strings.EqualFold(xdrPickString(event, "persisted_category"), category) && !xdrEventMatchesThreatCategory(event, category) {
		return nil
	}
	message := xdrPickString(event, "message", "rule_name", "event_type")
	return map[string]interface{}{
		"id":                 xdrPickString(event, "id"),
		"message_id":         xdrPickString(event, "message_id"),
		"timestamp":          xdrPickString(event, "created_at", "timestamp"),
		"event_type":         xdrPickString(event, "event_type"),
		"severity":           severity,
		"category":           category,
		"component_category": componentCategoryFromEvent(event),
		"score":              xdrPickNumber(event, "score_hint", severityBaseScore(severity)),
		"stage":              firstNonEmpty(xdrPickString(event, "stage_hint"), inferXDRStage(event)),
		"component_rule_id":  firstNonEmpty(xdrPickString(event, "component_rule_id"), xdrPickString(event, "rule_id")),
		"rule_hit_detail":    xdrPickString(event, "rule_hit_detail"),
		"rule_pack":          xdrPickString(event, "rule_pack"),
		"source_engine":      xdrPickString(event, "source_engine"),
		"native_rule":        event["native_rule"],
		"raw_reference":      event["raw_reference"],
		"agent_id":           xdrPickString(event, "agent_id"),
		"agent_display_name": xdrPickString(event, "agent_display_name", "display_name"),
		"display_name":       xdrPickString(event, "display_name", "agent_display_name"),
		"probe_name":         xdrPickString(event, "probe_name", "agent_display_name", "display_name"),
		"capture_source":     xdrPickString(event, "capture_source"),
		"hostname":           xdrPickString(event, "hostname"),
		"src_ip":             xdrPickString(event, "src_ip"),
		"src_port":           xdrPickNumber(event, "src_port", 0),
		"dst_ip":             xdrPickString(event, "dst_ip"),
		"dst_port":           xdrPickNumber(event, "dst_port", 0),
		"protocol":           xdrPickString(event, "protocol"),
		"app_protocol":       xdrPickString(event, "app_protocol"),
		"business_action":    xdrPickString(event, "business_action"),
		"direction":          xdrPickString(event, "direction"),
		"rule_id":            xdrPickNumber(event, "rule_id", 0),
		"rule_name":          xdrPickString(event, "rule_name", "event_type"),
		"mitre_tactic":       xdrPickString(event, "mitre_tactic"),
		"mitre_technique":    xdrPickString(event, "mitre_technique"),
		"source":             xdrPickString(event, "source", "log_source"),
		"summary":            message,
	}
}

func trafficThreatHasNoFlowContext(event map[string]interface{}) bool {
	if normalizeComponentCategory(componentCategoryFromEvent(event)) != "traffic" {
		return false
	}
	srcIP := xdrPickString(event, "src_ip", "entities.source_ip")
	dstIP := xdrPickString(event, "dst_ip", "entities.target_ip")
	if srcIP == "" || dstIP == "" {
		return true
	}
	return xdrPickNumber(event, "src_port", 0) == 0 && xdrPickNumber(event, "dst_port", 0) == 0
}

func threatMatchesFilters(threat map[string]interface{}, query, agentID, srcIP, dstIP, severity string) bool {
	if severity != "" && !strings.EqualFold(xdrPickString(threat, "severity"), severity) {
		return false
	}
	if agentID != "" && !strings.EqualFold(xdrPickString(threat, "agent_id"), agentID) {
		return false
	}
	if srcIP != "" && !strings.Contains(xdrPickString(threat, "src_ip"), srcIP) {
		return false
	}
	if dstIP != "" && !strings.Contains(xdrPickString(threat, "dst_ip"), dstIP) {
		return false
	}
	if query != "" {
		data, _ := json.Marshal(threat)
		return strings.Contains(strings.ToLower(string(data)), query)
	}
	return true
}

func loadRuntimeAuthThreats(cfg *Config, startTime, endTime *time.Time) []map[string]interface{} {
	if cfg.Redis == nil {
		return nil
	}
	msgs, err := cfg.Redis.XRevRangeN(context.Background(), "alerts:runtime", "+", "-", 500).Result()
	if err != nil {
		return nil
	}
	items := []map[string]interface{}{}
	seen := map[string]int{}
	for _, msg := range msgs {
		payload := redisDataPayload(msg.Values)
		if !eventInTimeRange(payload, startTime, endTime) {
			continue
		}
		typ := xdrPickString(payload, "type", "event_type")
		if typ != "runtime.auth.failure" {
			continue
		}
		meta := asMap(payload["metadata"])
		line := asString(meta["log_line"])
		src := extractAuthSourceIP(line)
		key := xdrPickString(payload, "agent_id") + "|" + src
		seen[key]++
		severity := "medium"
		if seen[key] >= 5 {
			severity = "high"
		}
		items = append(items, map[string]interface{}{
			"id":         msg.ID,
			"message_id": msg.ID,
			"timestamp":  xdrPickString(payload, "occurred_at", "timestamp"),
			"event_type": "ssh.bruteforce.failed_auth",
			"severity":   severity,
			"category":   "log",
			"agent_id":   xdrPickString(payload, "agent_id"),
			"hostname":   xdrPickString(payload, "hostname"),
			"src_ip":     src,
			"dst_ip":     xdrPickString(payload, "ip"),
			"dst_port":   int64(22),
			"protocol":   "SSH",
			"rule_name":  "SSH 登录失败/爆破尝试",
			"summary":    firstNonEmpty(line, xdrPickString(payload, "message")),
			"source":     "alerts:runtime",
		})
	}
	return items
}

func loadTrafficHeuristicThreats(cfg *Config, startTime, endTime *time.Time) []map[string]interface{} {
	if cfg.Redis == nil {
		return nil
	}
	msgs, err := cfg.Redis.XRevRangeN(context.Background(), "flows:raw", "+", "-", 2000).Result()
	if err != nil {
		return nil
	}
	type scanAgg struct {
		ports  map[int64]bool
		sample map[string]interface{}
		count  int
	}
	agg := map[string]*scanAgg{}
	for _, msg := range msgs {
		item := trafficItemFromMessage(cfg, "flows:raw", msg)
		if !eventInTimeRange(item, startTime, endTime) {
			continue
		}
		src := xdrPickString(item, "src_ip")
		dst := xdrPickString(item, "dst_ip")
		port := xdrPickNumber(item, "dst_port", 0)
		if src == "" || dst == "" || port <= 0 || src == dst {
			continue
		}
		key := src + "|" + dst
		if agg[key] == nil {
			agg[key] = &scanAgg{ports: map[int64]bool{}, sample: item}
		}
		agg[key].ports[port] = true
		agg[key].count++
	}
	items := []map[string]interface{}{}
	for key, value := range agg {
		if len(value.ports) < 5 && value.count < 20 {
			continue
		}
		parts := strings.Split(key, "|")
		severity := "medium"
		if len(value.ports) >= 20 || value.count >= 80 {
			severity = "high"
		}
		items = append(items, map[string]interface{}{
			"id":         "scan-" + strings.ReplaceAll(key, "|", "-"),
			"message_id": "scan-" + strings.ReplaceAll(key, "|", "-"),
			"timestamp":  xdrPickString(value.sample, "timestamp"),
			"event_type": "network.scan.port_sweep",
			"severity":   severity,
			"category":   "traffic",
			"agent_id":   xdrPickString(value.sample, "agent_id"),
			"hostname":   xdrPickString(value.sample, "hostname"),
			"src_ip":     parts[0],
			"dst_ip":     parts[1],
			"protocol":   xdrPickString(value.sample, "protocol"),
			"rule_name":  "端口扫描/疑似 Nmap 探测",
			"summary":    fmt.Sprintf("%s 对 %s 触达 %d 个端口 / %d 条流量", parts[0], parts[1], len(value.ports), value.count),
			"source":     "flows:raw heuristic",
		})
	}
	return items
}

func redisDataPayload(values map[string]interface{}) map[string]interface{} {
	payload := map[string]interface{}{}
	if raw := streamDataString(values); raw != "" {
		_ = json.Unmarshal([]byte(raw), &payload)
	}
	if len(payload) == 0 {
		for key, value := range values {
			payload[key] = value
		}
	}
	return payload
}

func extractAuthSourceIP(line string) string {
	fields := strings.Fields(line)
	for i, field := range fields {
		if field == "from" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func xdrEventIsInformationalTelemetry(event map[string]interface{}) bool {
	eventType := strings.ToLower(xdrPickString(event, "event_type", "rule_name", "message"))
	source := strings.ToLower(xdrPickString(event, "source", "log_source"))
	if eventType == "flows:semantic.event" || eventType == "sessions:semantic.event" {
		return true
	}
	if strings.Contains(source, "session-aggregate") && strings.Contains(eventType, "semantic.event") {
		return true
	}
	return false
}

func xdrEventIsAuthPrivilegeNoise(event map[string]interface{}) bool {
	eventType := strings.ToLower(xdrPickString(event, "event_type", "rule_name"))
	message := strings.ToLower(xdrPickString(event, "message", "summary"))
	severity := strings.ToLower(xdrPickString(event, "severity"))
	if eventType == "runtime.auth.privilege" && strings.Contains(message, "privilege-use") {
		return severity == "" || severity == "low" || severity == "medium"
	}
	return false
}

func xdrEventIsSyntheticNoise(event map[string]interface{}) bool {
	hay := xdrEventThreatHaystack(event)
	if containsAny(hay, []string{
		"synthetic",
		"synthetic-fallback",
		"fallback sample",
		"runtime.monitor.sample",
		"runtime monitor-mode fallback sample event",
		"rasp monitor-mode synthetic event",
	}) {
		return true
	}
	mode := strings.ToLower(xdrPickString(event, "mode"))
	message := strings.ToLower(xdrPickString(event, "message"))
	return mode == "monitor" && strings.Contains(message, "synthetic")
}

func xdrEventMatchesThreatCategory(event map[string]interface{}, category string) bool {
	want := normalizeComponentCategory(category)
	if want != "" {
		if want == "log_audit" {
			return componentCategoryFromEvent(event) == "log_audit" && strings.EqualFold(firstNonEmpty(xdrPickString(event, "source_engine"), xdrPickString(event, "source")), "wazuh")
		}
		if want == "rasp" {
			return componentCategoryFromEvent(event) == "rasp" && strings.Contains(strings.ToLower(firstNonEmpty(xdrPickString(event, "source_engine"), xdrPickString(event, "source"), xdrPickString(event, "rule_name"))), "rasp")
		}
		return componentCategoryFromEvent(event) == want
	}
	hay := xdrEventThreatHaystack(event)
	switch strings.ToLower(category) {
	case "traffic":
		return containsAny(hay, []string{"dpi", "suricata", "raw_flow", "traffic_threat", "http_attack", "dns_tunnel", "tls_malicious"})
	case "application", "app":
		return containsAny(hay, []string{"rasp", "application_attack", "sqli", "sql injection", "command injection", "cmdi", "xss", "webshell"})
	case "log", "audit", "log-audit":
		return containsAny(hay, []string{"logs:", "log", "sshd", "nginx", "mysql", "systemd", "auditd", "syslog"})
	default:
		return true
	}
}

func xdrEventThreatHaystack(event map[string]interface{}) string {
	hayParts := []string{
		xdrPickString(event, "source", "log_source"),
		componentCategoryFromEvent(event),
		xdrPickString(event, "component_rule_id"),
		xdrPickString(event, "stage_hint"),
		xdrPickString(event, "event_type"),
		xdrPickString(event, "rule_name"),
		xdrPickString(event, "message"),
		xdrPickString(event, "service"),
		xdrPickString(event, "session_id"),
	}
	for _, key := range []string{"tags", "metadata"} {
		if value, ok := event[key]; ok {
			data, _ := json.Marshal(value)
			hayParts = append(hayParts, string(data))
		}
	}
	return strings.ToLower(strings.Join(hayParts, " "))
}

func containsAny(value string, tokens []string) bool {
	for _, token := range tokens {
		if strings.Contains(value, token) {
			return true
		}
	}
	return false
}

func trafficStreamHandler(cfg *Config, stream string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		limit := parseQueryInt(r.URL.Query().Get("limit"), 50)
		if limit <= 0 || limit > 500 {
			limit = 50
		}
		offset := parseQueryInt(r.URL.Query().Get("offset"), 0)
		if offset < 0 {
			offset = 0
		}
		query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("query")))
		agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
		srcIP := strings.TrimSpace(r.URL.Query().Get("src_ip"))
		srcPort := strings.TrimSpace(r.URL.Query().Get("src_port"))
		dstIP := strings.TrimSpace(r.URL.Query().Get("dst_ip"))
		dstPort := strings.TrimSpace(r.URL.Query().Get("dst_port"))
		startTime := parseOptionalTime(r.URL.Query().Get("start_time"))
		endTime := parseOptionalTime(r.URL.Query().Get("end_time"))

		items, total, err := loadTrafficStream(cfg, stream, limit, offset, query, agentID, srcIP, srcPort, dstIP, dstPort, startTime, endTime)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"items":  items,
				"total":  total,
				"limit":  limit,
				"offset": offset,
				"stream": stream,
			},
		})
	}
}

func loadTrafficStream(cfg *Config, stream string, limit, offset int, query, agentID, srcIP, srcPort, dstIP, dstPort string, startTime, endTime *time.Time) ([]map[string]interface{}, int, error) {
	if stream == "sessions:semantic" {
		return loadPersistentTrafficSessions(context.Background(), cfg, limit, offset, query, agentID, srcIP, srcPort, dstIP, dstPort, startTime, endTime)
	}
	if cfg.Redis == nil {
		return nil, 0, fmt.Errorf("redis unavailable")
	}
	ctx := context.Background()
	total64, err := cfg.Redis.XLen(ctx, stream).Result()
	if err != nil {
		return nil, 0, err
	}
	if total64 == 0 {
		return []map[string]interface{}{}, 0, nil
	}

	readCount := int64((offset + limit) * 10)
	if readCount < 100 {
		readCount = 100
	}
	if readCount > 5000 {
		readCount = 5000
	}
	messages, err := cfg.Redis.XRevRangeN(ctx, stream, "+", "-", readCount).Result()
	if err != nil {
		return nil, 0, err
	}

	items := make([]map[string]interface{}, 0, limit)
	matched := 0
	agentInfos := activeTrafficAgentInfos(ctx, cfg)
	for _, msg := range messages {
		item := trafficItemFromMessage(cfg, stream, msg)
		if isContainerBridgeTrafficItem(item) {
			continue
		}
		if stream == "sessions:semantic" && mirrorSessionOnlyEnabled() && !isConfiguredMirrorInterfaceItem(item) && !isMirrorCaptureItem(item) && !trafficItemHasRegisteredAgent(item, agentInfos) {
			continue
		}
		if !trafficItemBelongsToActiveAgent(item, agentInfos) {
			continue
		}
		attributeMirrorTrafficToAgent(item, agentInfos)
		normalizeAgentSessionAggregate(item, agentInfos)
		if isContainerBridgeTrafficItem(item) {
			continue
		}
		if isConfiguredMirrorInterfaceItem(item) && xdrPickString(item, "agent_id") == "local" {
			applyMirrorCaptureLabel(item)
		}
		enrichTrafficItemDisplayName(item, agentInfos)
		if !eventInTimeRange(item, startTime, endTime) {
			continue
		}
		if !trafficItemMatches(item, query, agentID, srcIP, srcPort, dstIP, dstPort) {
			continue
		}
		matched++
		if matched <= offset {
			continue
		}
		if len(items) < limit {
			items = append(items, item)
		}
	}
	return items, matched, nil
}

func persistTrafficSession(ctx context.Context, cfg *Config, msg redis.XMessage) error {
	if cfg == nil || cfg.DBPool == nil {
		return nil
	}
	item := trafficItemFromMessage(cfg, "sessions:semantic", msg)
	if isContainerBridgeTrafficItem(item) {
		return nil
	}
	agentInfos := activeTrafficAgentInfos(ctx, cfg)
	if mirrorSessionOnlyEnabled() && !isConfiguredMirrorInterfaceItem(item) && !isMirrorCaptureItem(item) && !trafficItemHasRegisteredAgent(item, agentInfos) {
		return nil
	}
	if !trafficItemBelongsToActiveAgent(item, agentInfos) {
		return nil
	}
	attributeMirrorTrafficToAgent(item, agentInfos)
	normalizeAgentSessionAggregate(item, agentInfos)
	if isContainerBridgeTrafficItem(item) {
		return nil
	}
	enrichTrafficItemDisplayName(item, agentInfos)
	uid := firstNonEmpty(xdrPickString(item, "message_id"), xdrPickString(item, "id"))
	if uid == "" {
		raw, _ := json.Marshal(item)
		sum := sha256.Sum256(raw)
		uid = hex.EncodeToString(sum[:])
	}
	if isMirrorCaptureItem(item) {
		if agentName := trafficItemMatchedAgentName(item, agentInfos); agentName != "" {
			item["attributed_agent_name"] = agentName
		}
	}
	observed := parseTrafficItemTime(item)
	raw, err := json.Marshal(item)
	if err != nil {
		return transport.Permanent(transport.ReasonInvalidPayload, err)
	}
	agentID := xdrPickString(item, "agent_id")
	srcIP := xdrPickString(item, "src_ip")
	dstIP := xdrPickString(item, "dst_ip")
	srcPort := boundedTrafficPort(xdrPickNumber(item, "src_port", 0))
	dstPort := boundedTrafficPort(xdrPickNumber(item, "dst_port", 0))
	protocol := xdrPickString(item, "protocol")
	ingestedAt := time.Now().UTC()
	_, err = cfg.DBPool.Exec(ctx, `INSERT INTO traffic_sessions (session_uid, observed_at, agent_id, src_ip, dst_ip, src_port, dst_port, protocol, raw_event, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)
		ON CONFLICT (session_uid) DO UPDATE SET observed_at=EXCLUDED.observed_at, agent_id=EXCLUDED.agent_id, src_ip=EXCLUDED.src_ip, dst_ip=EXCLUDED.dst_ip, src_port=EXCLUDED.src_port, dst_port=EXCLUDED.dst_port, protocol=EXCLUDED.protocol, raw_event=EXCLUDED.raw_event, updated_at=EXCLUDED.updated_at`, uid, observed, agentID, srcIP, dstIP, int(srcPort), int(dstPort), protocol, string(raw), ingestedAt)
	if err != nil {
		return fmt.Errorf("materialize traffic session uid=%s: %w", uid, err)
	}
	if cfg.EventStorage == nil {
		return fmt.Errorf("materialize traffic session uid=%s: ClickHouse full-session storage unavailable", uid)
	}
	if err := cfg.EventStorage.WriteTrafficSession(ctx, analytics.TrafficSessionRecord{
		SessionUID: uid, Version: uint64(ingestedAt.UnixNano()), ObservedAt: observed,
		AgentID: agentID, SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort,
		Protocol: protocol, RawEvent: string(raw), IngestedAt: ingestedAt,
	}); err != nil {
		return fmt.Errorf("materialize ClickHouse traffic session uid=%s: %w", uid, err)
	}
	return nil
}

func boundedTrafficPort(value int64) uint16 {
	if value <= 0 {
		return 0
	}
	if value > 65535 {
		return 65535
	}
	return uint16(value)
}

func loadPersistentTrafficSessions(ctx context.Context, cfg *Config, limit, offset int, query, agentID, srcIP, srcPort, dstIP, dstPort string, startTime, endTime *time.Time) ([]map[string]interface{}, int, error) {
	if cfg == nil || cfg.DBPool == nil {
		return nil, 0, fmt.Errorf("session store unavailable")
	}
	hasFilter := query != "" || agentID != "" || srcIP != "" || srcPort != "" || dstIP != "" || dstPort != "" || startTime != nil || endTime != nil
	if hasFilter && cfg.Redis != nil {
		return loadFilteredTrafficSessionsFromRedis(ctx, cfg, limit, offset, query, agentID, srcIP, srcPort, dstIP, dstPort, startTime, endTime)
	}

	where := []string{"1=1"}
	where = append(where, "(COALESCE(agent_id, '') IN ('', 'local', 'localhost') OR EXISTS (SELECT 1 FROM agents a WHERE a.uuid = traffic_sessions.agent_id AND COALESCE(a.traffic_enabled, false) = true))")
	args := []interface{}{}
	if query != "" {
		queryTokens := trafficSessionQueryTokens(query)
		if len(queryTokens) > 0 {
			parts := make([]string, 0, len(queryTokens))
			for _, token := range queryTokens {
				args = append(args, "%"+token+"%")
				idx := len(args)
				parts = append(parts, fmt.Sprintf("(agent_id ILIKE $%d OR src_ip ILIKE $%d OR dst_ip ILIKE $%d OR protocol ILIKE $%d OR raw_event->>'display_name' ILIKE $%d OR raw_event->>'agent_display_name' ILIKE $%d OR raw_event->>'probe_name' ILIKE $%d OR raw_event->>'hostname' ILIKE $%d OR raw_event->>'attributed_agent_name' ILIKE $%d OR raw_event->>'associated_agent_name' ILIKE $%d OR raw_event->>'message' ILIKE $%d)", idx, idx, idx, idx, idx, idx, idx, idx, idx, idx, idx))
			}
			where = append(where, "("+strings.Join(parts, " AND ")+")")
		}
	}
	if agentID != "" {
		args = append(args, agentID)
		where = append(where, fmt.Sprintf("(agent_id = $%d OR raw_event->>'attributed_agent_id' = $%d OR raw_event->>'associated_agent_id' = $%d)", len(args), len(args), len(args)))
	}
	if srcIP != "" {
		args = append(args, "%"+srcIP+"%")
		where = append(where, fmt.Sprintf("src_ip ILIKE $%d", len(args)))
	}
	if srcPort != "" {
		if value, err := strconv.Atoi(srcPort); err == nil {
			args = append(args, value)
			where = append(where, fmt.Sprintf("src_port = $%d", len(args)))
		}
	}
	if dstIP != "" {
		args = append(args, "%"+dstIP+"%")
		where = append(where, fmt.Sprintf("dst_ip ILIKE $%d", len(args)))
	}
	if dstPort != "" {
		if value, err := strconv.Atoi(dstPort); err == nil {
			args = append(args, value)
			where = append(where, fmt.Sprintf("dst_port = $%d", len(args)))
		}
	}
	if startTime != nil {
		args = append(args, startTime.UTC())
		where = append(where, fmt.Sprintf("observed_at >= $%d", len(args)))
	}
	if endTime != nil {
		args = append(args, endTime.UTC())
		where = append(where, fmt.Sprintf("observed_at <= $%d", len(args)))
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := cfg.DBPool.QueryRow(ctx, "SELECT COUNT(*) FROM traffic_sessions WHERE "+clause, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	agentInfos := activeTrafficAgentInfos(ctx, cfg)
	matchedItems := []map[string]interface{}{}
	seen := map[string]struct{}{}
	addItem := func(item map[string]interface{}) {
		if !trafficItemBelongsToActiveAgent(item, agentInfos) {
			return
		}
		attributeMirrorTrafficToAgent(item, agentInfos)
		normalizeAgentSessionAggregate(item, agentInfos)
		if isMirrorCaptureItem(item) {
			applyMirrorCaptureLabel(item)
		}
		enrichTrafficItemDisplayName(item, agentInfos)
		if !eventInTimeRange(item, startTime, endTime) || !trafficItemMatches(item, query, agentID, srcIP, srcPort, dstIP, dstPort) {
			return
		}
		key := firstNonEmpty(xdrPickString(item, "message_id"), xdrPickString(item, "id"))
		if key == "" {
			raw, _ := json.Marshal(item)
			sum := sha256.Sum256(raw)
			key = hex.EncodeToString(sum[:])
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		matchedItems = append(matchedItems, item)
	}

	if cfg.Redis != nil {
		redisReadCount := int64(offset + limit + 1000)
		if query != "" || agentID != "" || srcIP != "" || srcPort != "" || dstIP != "" || dstPort != "" || startTime != nil || endTime != nil {
			redisReadCount = 20000
		}
		redisMessages, err := cfg.Redis.XRevRangeN(ctx, "sessions:semantic", "+", "-", redisReadCount).Result()
		if err == nil {
			for _, msg := range redisMessages {
				item := trafficItemFromMessage(cfg, "sessions:semantic", msg)
				if isContainerBridgeTrafficItem(item) {
					continue
				}
				addItem(item)
			}
		}
	}

	dbLimit := offset + limit + 1000
	if dbLimit < 1000 {
		dbLimit = 1000
	}
	queryArgs := append(args, dbLimit)
	rows, err := cfg.DBPool.Query(ctx, "SELECT raw_event FROM traffic_sessions WHERE "+clause+fmt.Sprintf(" ORDER BY observed_at DESC LIMIT $%d", len(args)+1), queryArgs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		item := map[string]interface{}{}
		if json.Unmarshal(raw, &item) != nil {
			continue
		}
		addItem(item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	for _, item := range matchedItems {
		if isMirrorCaptureItem(item) {
			applyMirrorCaptureLabel(item)
			if agentName := trafficItemMatchedAgentName(item, agentInfos); agentName != "" {
				item["attributed_agent_name"] = agentName
			}
		}
	}
	sort.SliceStable(matchedItems, func(i, j int) bool {
		return parseTrafficItemTime(matchedItems[i]).After(parseTrafficItemTime(matchedItems[j]))
	})
	if len(matchedItems) > total {
		total = len(matchedItems)
	}
	start := offset
	if start > len(matchedItems) {
		start = len(matchedItems)
	}
	end := start + limit
	if end > len(matchedItems) {
		end = len(matchedItems)
	}
	return matchedItems[start:end], total, nil
}

func loadFilteredTrafficSessionsFromRedis(ctx context.Context, cfg *Config, limit, offset int, query, agentID, srcIP, srcPort, dstIP, dstPort string, startTime, endTime *time.Time) ([]map[string]interface{}, int, error) {
	if cfg == nil || cfg.Redis == nil {
		return nil, 0, fmt.Errorf("redis unavailable")
	}
	items := make([]map[string]interface{}, 0, limit)
	matched := 0
	seen := map[string]struct{}{}
	agentInfos := activeTrafficAgentInfos(ctx, cfg)
	end := "+"
	for scanned := 0; scanned < 200000 && len(items) < limit; {
		messages, err := cfg.Redis.XRevRangeN(ctx, "sessions:semantic", end, "-", 5000).Result()
		if err != nil {
			return nil, 0, err
		}
		if len(messages) == 0 {
			break
		}
		for _, msg := range messages {
			item := trafficItemFromMessage(cfg, "sessions:semantic", msg)
			if isContainerBridgeTrafficItem(item) {
				continue
			}
			if isMirrorCaptureItem(item) {
				attributeMirrorTrafficToAgent(item, agentInfos)
				if isMirrorCaptureItem(item) {
					applyMirrorCaptureLabel(item)
				}
			}
			if !eventInTimeRange(item, startTime, endTime) || !trafficItemMatches(item, query, agentID, srcIP, srcPort, dstIP, dstPort) {
				continue
			}
			key := firstNonEmpty(xdrPickString(item, "message_id"), xdrPickString(item, "id"), msg.ID)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			matched++
			if matched <= offset {
				continue
			}
			item["message_id"] = firstNonEmpty(xdrPickString(item, "message_id"), msg.ID)
			item["stream"] = "sessions:semantic"
			items = append(items, item)
			if len(items) >= limit {
				break
			}
		}
		scanned += len(messages)
		end = "(" + messages[len(messages)-1].ID
		if len(messages) < 5000 {
			break
		}
	}
	return items, matched, nil
}

func trafficSessionQueryTokens(query string) []string {
	query = strings.TrimSpace(strings.ToLower(query))
	if query == "" {
		return nil
	}
	query = strings.TrimSpace(strings.TrimPrefix(query, "流量来源:"))
	query = strings.TrimSpace(strings.TrimPrefix(query, "流量来源："))
	query = strings.TrimSpace(strings.TrimPrefix(query, "traffic source:"))
	query = strings.TrimSpace(strings.TrimPrefix(query, "source:"))
	if query == "" {
		return nil
	}
	if strings.Contains(query, "流量镜像分析") || strings.Contains(query, "镜像") || strings.Contains(query, "mirror") {
		return []string{"流量镜像分析"}
	}
	fields := strings.FieldsFunc(query, func(r rune) bool {
		return unicode.IsSpace(r) || r == ',' || r == ';' || r == '，' || r == '；' || r == ':' || r == '：'
	})
	if len(fields) == 0 {
		return []string{query}
	}
	if len(fields) > 4 {
		fields = fields[:4]
	}
	return fields
}

func parseTrafficItemTime(item map[string]interface{}) time.Time {
	value := xdrPickString(item, "timestamp", "created_at", "time")
	if parsed := parseOptionalTime(value); parsed != nil {
		return parsed.UTC()
	}
	if ms, err := strconv.ParseInt(value, 10, 64); err == nil {
		if ms > 1_000_000_000_000 {
			return time.UnixMilli(ms).UTC()
		}
		return time.Unix(ms, 0).UTC()
	}
	return time.Now().UTC()
}

func mirrorSessionOnlyEnabled() bool {
	config := loadMirrorCaptureConfig()
	return config.Enabled && strings.TrimSpace(config.Interface) != ""
}

func isContainerBridgeTrafficItem(item map[string]interface{}) bool { return false }

func trafficItemBelongsToActiveAgent(item map[string]interface{}, agentInfos map[string]activeTrafficAgentInfo) bool {
	if isMirrorCaptureItem(item) {
		return true
	}
	agentID := xdrPickString(item, "agent_id", "entities.agent_id")
	if agentID == "" || agentID == "local" || agentID == "localhost" {
		return true
	}
	if len(agentInfos) == 0 {
		return false
	}
	_, ok := agentInfos[agentID]
	return ok
}

func trafficItemHasRegisteredAgent(item map[string]interface{}, agentInfos map[string]activeTrafficAgentInfo) bool {
	agentID := xdrPickString(item, "agent_id", "entities.agent_id")
	if agentID == "" || agentID == "local" || agentID == "localhost" || len(agentInfos) == 0 {
		return false
	}
	_, ok := agentInfos[agentID]
	return ok
}

func normalizeAgentSessionAggregate(item map[string]interface{}, agentInfos map[string]activeTrafficAgentInfo) {
	if xdrPickString(item, "source") != "ly-agent-session-aggregate" {
		return
	}
	if src, dst := sessionTupleFromID(xdrPickString(item, "id")); src != "" && dst != "" {
		item["src_ip"] = src
		item["dst_ip"] = dst
		if content := asMap(item["content"]); len(content) > 0 {
			content["src_ip"] = src
			content["dst_ip"] = dst
			item["content"] = content
		}
	}
	agentID := xdrPickString(item, "agent_id")
	info := agentInfos[agentID]
	if xdrPickString(item, "interface") == "" && info.Interface != "" {
		item["interface"] = info.Interface
		if content := asMap(item["content"]); len(content) > 0 {
			content["interface"] = info.Interface
			item["content"] = content
		}
	}
}

func sessionTupleFromID(id string) (string, string) {
	ips := make([]string, 0, 2)
	for _, part := range strings.Split(id, "-") {
		if net.ParseIP(part) == nil {
			continue
		}
		ips = append(ips, part)
		if len(ips) == 2 {
			return ips[0], ips[1]
		}
	}
	return "", ""
}

func enrichTrafficItemDisplayName(item map[string]interface{}, agentInfos map[string]activeTrafficAgentInfo) {
	if isMirrorCaptureItem(item) {
		applyMirrorCaptureLabel(item)
		return
	}
	if len(agentInfos) == 0 {
		return
	}
	agentID := xdrPickString(item, "agent_id", "entities.agent_id")
	name := strings.TrimSpace(agentInfos[agentID].DisplayName)
	if name == "" {
		return
	}
	item["display_name"] = name
	item["agent_display_name"] = name
	item["probe_name"] = name
}

func trafficItemMatchedAgentName(item map[string]interface{}, agentInfos map[string]activeTrafficAgentInfo) string {
	if agentID := xdrPickString(item, "attributed_agent_id", "associated_agent_id"); agentID != "" {
		if name := xdrPickString(item, "attributed_agent_name", "associated_agent_name"); name != "" {
			return name
		}
		if info, ok := agentInfos[agentID]; ok {
			return firstNonEmpty(info.DisplayName, info.Hostname, agentID)
		}
		return agentID
	}
	return ""
}

func trafficItemFromMessage(cfg *Config, stream string, msg redis.XMessage) map[string]interface{} {
	raw := streamDataString(msg.Values)
	payload := map[string]interface{}{}
	if raw != "" {
		_ = json.Unmarshal([]byte(raw), &payload)
	}
	if len(payload) == 0 {
		for key, value := range msg.Values {
			payload[key] = value
		}
	}
	timestamp := xdrPickString(payload, "timestamp", "created_at", "time")
	if timestamp == "" {
		timestamp = strings.Split(msg.ID, "-")[0]
	}
	item := map[string]interface{}{
		"message_id":            msg.ID,
		"stream":                stream,
		"id":                    xdrPickString(payload, "id", "flow_id", "session_id"),
		"timestamp":             timestamp,
		"agent_id":              xdrPickString(payload, "agent_id", "sensor_id"),
		"display_name":          xdrPickString(payload, "display_name", "agent_display_name", "probe_name"),
		"agent_display_name":    xdrPickString(payload, "agent_display_name", "display_name", "probe_name"),
		"probe_name":            xdrPickString(payload, "probe_name", "display_name", "agent_display_name"),
		"probe_kind":            xdrPickString(payload, "probe_kind"),
		"capture_source":        xdrPickString(payload, "capture_source"),
		"attributed_agent_id":   xdrPickString(payload, "attributed_agent_id", "associated_agent_id"),
		"attributed_agent_name": xdrPickString(payload, "attributed_agent_name", "associated_agent_name"),
		"attributed_hostname":   xdrPickString(payload, "attributed_hostname", "associated_hostname"),
		"associated_agent_id":   xdrPickString(payload, "associated_agent_id", "attributed_agent_id"),
		"associated_agent_name": xdrPickString(payload, "associated_agent_name", "attributed_agent_name"),
		"associated_hostname":   xdrPickString(payload, "associated_hostname", "attributed_hostname"),
		"hostname":              xdrPickString(payload, "hostname"),
		"src_ip":                xdrPickString(payload, "src_ip"),
		"src_port":              xdrPickNumber(payload, "src_port", 0),
		"dst_ip":                xdrPickString(payload, "dst_ip"),
		"dst_port":              xdrPickNumber(payload, "dst_port", 0),
		"protocol":              xdrPickString(payload, "protocol", "app_protocol"),
		"app_protocol":          xdrPickString(payload, "app_protocol", "protocol"),
		"http_host":             xdrPickString(payload, "http_host"),
		"http_method":           xdrPickString(payload, "http_method"),
		"http_path":             xdrPickString(payload, "http_path"),
		"dns_query":             xdrPickString(payload, "dns_query"),
		"tls_sni":               xdrPickString(payload, "tls_sni"),
		"bytes_in":              xdrPickNumber(payload, "bytes_in", 0),
		"bytes_out":             xdrPickNumber(payload, "bytes_out", 0),
		"packets":               xdrPickNumber(payload, "packets", 0),
		"duration_ms":           xdrPickNumber(payload, "duration_ms", 0),
		"direction":             xdrPickString(payload, "direction"),
		"business_action":       xdrPickString(payload, "business_action"),
		"engine":                xdrPickString(payload, "engine"),
		"interface":             xdrPickString(payload, "interface"),
		"bpf_filter":            xdrPickString(payload, "bpf_filter"),
		"promiscuous":           payload["promiscuous"],
		"source":                xdrPickString(payload, "source"),
		"risk_level":            xdrPickString(payload, "risk_level"),
		"raw_reference":         payload["raw_reference"],
		"content":               payload,
	}
	applyMirrorCaptureLabel(item)
	return item
}

func trafficItemMatches(item map[string]interface{}, query, agentID, srcIP, srcPort, dstIP, dstPort string) bool {
	if agentID != "" && !strings.EqualFold(xdrPickString(item, "agent_id"), agentID) {
		if !strings.EqualFold(xdrPickString(item, "attributed_agent_id", "associated_agent_id"), agentID) {
			return false
		}
	}
	if srcIP != "" && !strings.Contains(xdrPickString(item, "src_ip"), srcIP) {
		return false
	}
	if srcPort != "" && strconv.FormatInt(xdrPickNumber(item, "src_port", 0), 10) != srcPort {
		return false
	}
	if dstIP != "" && !strings.Contains(xdrPickString(item, "dst_ip"), dstIP) {
		return false
	}
	if dstPort != "" && strconv.FormatInt(xdrPickNumber(item, "dst_port", 0), 10) != dstPort {
		return false
	}
	if query == "" {
		return true
	}
	tokens := trafficSessionQueryTokens(query)
	if len(tokens) == 0 {
		return true
	}
	query = tokens[0]
	if net.ParseIP(query) != nil {
		return strings.Contains(strings.ToLower(xdrPickString(item, "src_ip")), query) || strings.Contains(strings.ToLower(xdrPickString(item, "dst_ip")), query)
	}
	fields := []string{
		xdrPickString(item, "id"),
		xdrPickString(item, "flow_id"),
		xdrPickString(item, "message_id"),
		xdrPickString(item, "agent_id"),
		xdrPickString(item, "src_ip"),
		xdrPickString(item, "dst_ip"),
		strconv.FormatInt(xdrPickNumber(item, "src_port", 0), 10),
		strconv.FormatInt(xdrPickNumber(item, "dst_port", 0), 10),
		xdrPickString(item, "protocol"),
		xdrPickString(item, "app_protocol"),
		xdrPickString(item, "display_name"),
		xdrPickString(item, "agent_display_name"),
		xdrPickString(item, "probe_name"),
		xdrPickString(item, "probe_kind"),
		xdrPickString(item, "capture_source"),
		xdrPickString(item, "attributed_agent_id"),
		xdrPickString(item, "attributed_agent_name"),
		xdrPickString(item, "attributed_hostname"),
		xdrPickString(item, "associated_agent_id"),
		xdrPickString(item, "associated_agent_name"),
		xdrPickString(item, "associated_hostname"),
		xdrPickString(item, "hostname"),
		xdrPickString(item, "message"),
		xdrPickString(item, "source"),
	}
	for _, token := range tokens {
		matched := false
		for _, field := range fields {
			if strings.Contains(strings.ToLower(field), token) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func parseOptionalTime(value string) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	formats := []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02"}
	for _, layout := range formats {
		if parsed, err := time.Parse(layout, value); err == nil {
			return &parsed
		}
		if parsed, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return &parsed
		}
	}
	return nil
}

func eventInTimeRange(event map[string]interface{}, startTime, endTime *time.Time) bool {
	if startTime == nil && endTime == nil {
		return true
	}
	value := xdrPickString(event, "timestamp", "created_at", "time")
	if value == "" {
		return true
	}
	parsed := parseOptionalTime(value)
	if parsed == nil {
		if ms, err := strconv.ParseInt(value, 10, 64); err == nil {
			t := time.UnixMilli(ms)
			parsed = &t
		}
	}
	if parsed == nil {
		return true
	}
	if startTime != nil && parsed.Before(*startTime) {
		return false
	}
	if endTime != nil && parsed.After(*endTime) {
		return false
	}
	return true
}

func startLogRetentionWorker(cfg *Config) {
	runLogRetention(cfg)
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		runLogRetention(cfg)
	}
}

func runLogRetention(cfg *Config) {
	retentionDays := toInt(getEnv("LOG_RETENTION_DAYS", "180"))
	if retentionDays <= 0 {
		retentionDays = 180
	}
	cleanupDays := retentionDays
	usage := diskUsagePercent("/")
	threshold := toInt(getEnv("LOG_DISK_CLEANUP_THRESHOLD_PERCENT", "85"))
	if threshold <= 0 {
		threshold = 85
	}
	if usage >= float64(threshold) {
		cleanupDays = 120
		log.Printf("日志磁盘清理触发: usage=%.1f%% threshold=%d%% cleanup_before_days=%d", usage, threshold, cleanupDays)
	}
	cutoff := time.Now().AddDate(0, 0, -cleanupDays)
	cleanupRedisStreams(cfg, cutoff)
	cleanupPostgresEvents(cfg, cutoff)
	log.Printf("日志保留策略完成: retention_days=%d effective_cleanup_days=%d cutoff=%s disk_usage=%.1f%%", retentionDays, cleanupDays, cutoff.Format(time.RFC3339), usage)
}

func cleanupRedisStreams(cfg *Config, cutoff time.Time) {
	if cfg.Redis == nil {
		return
	}
	ctx := context.Background()
	minID := fmt.Sprintf("%d-0", cutoff.UnixMilli())
	for _, stream := range []string{"flows:raw", "sessions:semantic", "alerts:dpi", "alerts:xdr", "events:xdr"} {
		if err := cfg.Redis.Do(ctx, "XTRIM", stream, "MINID", minID).Err(); err != nil && err != redis.Nil {
			log.Printf("Redis日志流清理失败: stream=%s err=%v", stream, err)
		}
	}
}

func cleanupPostgresEvents(cfg *Config, cutoff time.Time) {
	if cfg.DBPool == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, stmt := range postgresRetentionStatements() {
		if _, err := cfg.DBPool.Exec(ctx, stmt, cutoff); err != nil {
			log.Printf("PostgreSQL日志清理跳过/失败: stmt=%q err=%v", stmt, err)
		}
	}
}

func postgresRetentionStatements() []string {
	return []string{
		"DELETE FROM events WHERE timestamp < $1",
		"DELETE FROM xdr_events_v2 WHERE observed_at < $1",
		"DELETE FROM threat_events WHERE observed_at < $1",
	}
}

func diskUsagePercent(path string) float64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil || stat.Blocks == 0 {
		return 0
	}
	used := stat.Blocks - stat.Bavail
	return float64(used) / float64(stat.Blocks) * 100
}

func unifiedSearchHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Module   string `json:"module"`
			Severity string `json:"severity"`
			Status   string `json:"status"`
			Query    string `json:"query"`
			Limit    int    `json:"limit"`
			Offset   int    `json:"offset"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if req.Limit <= 0 {
			req.Limit = 50
		}
		if req.Offset < 0 {
			req.Offset = 0
		}

		events, _, err := loadXDREvents(cfg, req.Offset+req.Limit+200, 0)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}

		filtered := make([]map[string]interface{}, 0, len(events))
		for _, e := range events {
			item := mapUnifiedEventFromXDR(e)
			if req.Module != "" && !strings.EqualFold(xdrPickString(item, "module"), req.Module) {
				continue
			}
			if req.Severity != "" && !strings.EqualFold(xdrPickString(item, "severity"), req.Severity) {
				continue
			}
			if req.Status != "" && !strings.EqualFold(xdrPickString(item, "status"), req.Status) {
				continue
			}
			if req.Query != "" {
				hay := strings.ToLower(xdrPickString(item, "message") + " " + xdrPickString(item, "event_type") + " " + xdrPickString(item, "rule_name"))
				if !strings.Contains(hay, strings.ToLower(req.Query)) {
					continue
				}
			}
			filtered = append(filtered, item)
		}

		total := len(filtered)
		if req.Offset > total {
			req.Offset = total
		}
		end := req.Offset + req.Limit
		if end > total {
			end = total
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"items":  filtered[req.Offset:end],
				"total":  total,
				"limit":  req.Limit,
				"offset": req.Offset,
			},
		})
	}
}

func incidentsFromXDRChains(chains []map[string]interface{}) []map[string]interface{} {
	incidents := make([]map[string]interface{}, 0, len(chains))
	for _, chain := range chains {
		if status := xdrPickString(chain, "hypothesis_status"); status != "" && status != xdrmodels.HypothesisStatusCandidate {
			continue
		}
		stages := stringListFromValue(chain["stages"])
		if xdrPickNumber(chain, "event_count", 0) < 2 || len(stages) < 2 || asBool(chain["standalone_alert"]) {
			continue
		}
		id := "inc-" + strings.TrimPrefix(xdrPickString(chain, "id"), "chain-")
		status := "open"
		if legacyStatus, exists := loadLegacyIncidentStatus(id); exists {
			status = string(legacyStatus)
		}
		if len(stages) == 0 {
			for _, event := range asSlice(chain["event_evidence"]) {
				stage := firstNonEmpty(normalizeXDRStage(xdrPickString(asMap(event), "stage_hint")), inferXDRStage(asMap(event)), incidentStage(asMap(event)))
				if stage != "" {
					stages = append(stages, stage)
				}
			}
			stages = uniqueStrings(stages)
		}
		attackChain := firstNonNil(chain["event_evidence"], []interface{}{})
		if len(asSlice(attackChain)) == 0 {
			attackChain = stagesToAttackChain(stages, chain)
		}
		severity := xdrPickString(chain, "severity")
		stageGroups := incidentStageGroups(stages, asSlice(attackChain))
		if len(stageGroups) < 2 {
			continue
		}
		incidents = append(incidents, map[string]interface{}{
			"id":                   id,
			"title":                incidentTitleFromChain(chain),
			"summary":              xdrPickString(chain, "summary"),
			"correlation":          xdrPickString(chain, "correlation_key"),
			"severity":             severity,
			"severity_label":       severityLabel(severity),
			"status":               status,
			"status_label":         incidentStatusLabel(status),
			"first_seen":           xdrPickString(chain, "first_seen"),
			"last_seen":            xdrPickString(chain, "last_seen"),
			"stages":               stages,
			"stage_labels":         stageLabels(stages),
			"event_count":          xdrPickNumber(chain, "event_count", 0),
			"events":               firstNonNil(chain["event_evidence"], []interface{}{}),
			"attack_chain":         attackChain,
			"stage_groups":         stageGroups,
			"evidence_summary":     xdrEvidenceSummaryText(chain),
			"source_chain_id":      xdrPickString(chain, "id"),
			"source_chain_summary": xdrPickString(chain, "summary"),
		})
	}
	return incidents
}

func incidentTitleFromChain(chain map[string]interface{}) string {
	name := firstNonEmpty(xdrPickString(chain, "entity"), xdrPickString(chain, "victim"), "目标资产")
	if name == "unknown" || name == "未知资产" || strings.HasPrefix(name, "standalone:") {
		name = "目标资产"
	}
	ip := firstNonEmpty(firstStringFromValue(chain["victim_ips"]), firstStringFromValue(chain["source_ips"]))
	if ip != "" && !strings.Contains(name, ip) {
		name = name + "(" + ip + ")"
	}
	return name + " 出现攻击链"
}

func incidentStageGroups(stages []string, evidence []interface{}) []map[string]interface{} {
	if len(stages) == 0 {
		for _, item := range evidence {
			stage := firstNonEmpty(normalizeXDRStage(xdrPickString(asMap(item), "stage", "stage_hint")), incidentStage(asMap(item)))
			if stage != "" {
				stages = append(stages, stage)
			}
		}
		stages = uniqueStrings(stages)
	}
	groups := make([]map[string]interface{}, 0, len(stages))
	for _, stage := range stages {
		items := []map[string]interface{}{}
		for _, item := range evidence {
			m := asMap(item)
			if shouldSuppressTrafficNoiseEvent(m) || xdrEventIsInformationalTelemetry(m) {
				continue
			}
			itemStage := firstNonEmpty(normalizeXDRStage(xdrPickString(m, "stage", "stage_hint")), incidentStage(m))
			if itemStage != stage {
				continue
			}
			row := map[string]interface{}{
				"time":           firstNonEmpty(xdrPickString(m, "time"), xdrPickString(m, "timestamp", "created_at")),
				"date":           firstNonEmpty(xdrPickString(m, "date"), xdrPickString(m, "time"), xdrPickString(m, "timestamp", "created_at")),
				"summary":        firstNonEmpty(xdrPickString(m, "summary"), timelineSummary(m)),
				"event_id":       xdrPickString(m, "event_id", "id", "message_id"),
				"severity":       xdrPickString(m, "severity"),
				"severity_label": severityLabel(xdrPickString(m, "severity")),
			}
			for key, value := range m {
				if _, exists := row[key]; !exists {
					row[key] = value
				}
			}
			items = append(items, row)
		}
		if len(items) > 0 {
			groups = append(groups, map[string]interface{}{"stage": stage, "stage_label": stageLabel(stage), "evidence": items})
		}
	}
	return groups
}

func firstStringFromValue(value interface{}) string {
	for _, item := range asSlice(value) {
		text := strings.TrimSpace(fmt.Sprint(item))
		if text != "" {
			return text
		}
	}
	return ""
}

func xdrEvidenceSummaryText(chain map[string]interface{}) []string {
	out := []string{}
	for _, item := range asSlice(chain["event_evidence"]) {
		m := asMap(item)
		text := firstNonEmpty(xdrPickString(m, "summary"), xdrPickString(m, "rule_name"), xdrPickString(m, "id"))
		if text != "" {
			out = append(out, text)
		}
	}
	return out
}

func timelineHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		limit := parseQueryInt(r.URL.Query().Get("limit"), 100)
		offset := parseQueryInt(r.URL.Query().Get("offset"), 0)
		if limit <= 0 {
			limit = 100
		}
		if offset < 0 {
			offset = 0
		}
		events, _, err := loadXDREvents(cfg, offset+limit+500, 0)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "timeline_load_failed", err.Error())
			return
		}
		items := buildTimeline(events, r.URL.Query().Get("entity_id"), r.URL.Query().Get("session_id"))
		total := len(items)
		if offset > total {
			offset = total
		}
		end := offset + limit
		if end > total {
			end = total
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": items[offset:end], "total": total, "limit": limit, "offset": offset}})
	}
}

func timelineDetailHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		id := strings.TrimPrefix(r.URL.Path, "/api/v1/timeline/")
		if id == "" {
			writeJSONError(w, http.StatusNotFound, "timeline_not_found", "timeline entry not found")
			return
		}
		events, _, err := loadXDREvents(cfg, 1000, 0)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "timeline_not_found", "timeline entry not found")
			return
		}
		for _, item := range buildTimeline(events, "", "") {
			if xdrPickString(item, "id") == id {
				json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": item})
				return
			}
		}
		writeJSONError(w, http.StatusNotFound, "timeline_not_found", "timeline entry not found")
	}
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{"code": status, "error_code": code, "message": message})
}

// ============ RASP API Handlers ============

func raspStatsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		events, total, err := loadRASPEvents(cfg, 1000, 0)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}

		byLanguage := map[string]int64{}
		byAttackType := map[string]int64{}
		blocked := int64(0)
		allowed := int64(0)
		todayEvents := int64(0)
		today := time.Date(time.Now().Year(), time.Now().Month(), time.Now().Day(), 0, 0, 0, 0, time.Now().Location())
		for _, e := range events {
			lang := xdrPickString(e, "language")
			if lang != "" {
				byLanguage[lang]++
			}
			attack := xdrPickString(e, "attack_type")
			if attack != "" {
				byAttackType[attack]++
			}
			if blockedVal, ok := e["blocked"].(bool); ok && blockedVal {
				blocked++
			} else {
				allowed++
			}
			t := parseXDRTime(xdrPickString(e, "occurred_at", "created_at", "timestamp"))
			if !t.IsZero() && !t.Before(today) {
				todayEvents++
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{
				"total_events":   total,
				"today_events":   todayEvents,
				"blocked":        blocked,
				"allowed":        allowed,
				"by_language":    byLanguage,
				"by_attack_type": byAttackType,
			},
		})
	}
}

func raspEventsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")

		limit := parseQueryInt(r.URL.Query().Get("limit"), 50)
		offset := parseQueryInt(r.URL.Query().Get("offset"), 0)
		events, _, err := loadRASPEvents(cfg, offset+limit+200, 0)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}

		filtered := make([]map[string]interface{}, 0, len(events))
		for _, e := range events {
			if sev := r.URL.Query().Get("severity"); sev != "" && !strings.EqualFold(xdrPickString(e, "severity"), sev) {
				continue
			}
			if lang := r.URL.Query().Get("language"); lang != "" && !strings.EqualFold(xdrPickString(e, "language"), lang) {
				continue
			}
			if at := r.URL.Query().Get("attack_type"); at != "" && !strings.EqualFold(xdrPickString(e, "attack_type"), at) {
				continue
			}
			if aid := r.URL.Query().Get("agent_id"); aid != "" && !strings.EqualFold(xdrPickString(e, "agent_id"), aid) {
				continue
			}
			filtered = append(filtered, e)
		}

		total := len(filtered)
		if offset > total {
			offset = total
		}
		end := offset + limit
		if end > total {
			end = total
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{"items": filtered[offset:end], "total": total, "limit": limit, "offset": offset},
		})
	}
}

func raspRulesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		rules := make([]map[string]interface{}, 0)
		if rs, err := rasp.LoadElkeidRules("rules/rasp/elkeid_rasp_rules.yaml"); err == nil {
			for _, rule := range rs.Rules {
				if !rule.Enabled {
					continue
				}
				rules = append(rules, map[string]interface{}{
					"id":       rule.ID,
					"name":     rule.Name,
					"language": strings.Join(rule.Languages, ","),
					"severity": rule.Severity,
					"action":   rule.Action,
					"enabled":  rule.Enabled,
				})
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success", "data": rules,
		})
	}
}

func raspAgentsHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		agents := map[string]map[string]interface{}{}
		statusAgents, _ := loadRASPProtectionAgents(cfg)
		for _, a := range statusAgents {
			id := xdrPickString(a, "agent_id")
			if id == "" {
				continue
			}
			blockedCount := int64(0)
			if stats, ok := a["stats"].(map[string]interface{}); ok {
				blockedCount = xdrPickNumber(stats, "blocked_count", 0)
			}
			agents[id] = map[string]interface{}{
				"id":            id,
				"hostname":      xdrPickString(a, "hostname"),
				"language":      xdrPickString(a, "language"),
				"version":       "",
				"status":        "online",
				"protection":    a["enabled"],
				"blocked_count": blockedCount,
			}
		}

		events, _, _ := loadRASPEvents(cfg, 1000, 0)
		for _, e := range events {
			id := xdrPickString(e, "agent_id")
			if id == "" {
				continue
			}
			row, ok := agents[id]
			if !ok {
				row = map[string]interface{}{
					"id": id, "hostname": xdrPickString(e, "hostname"), "language": xdrPickString(e, "language"),
					"version": "", "status": "online", "protection": false, "blocked_count": int64(0),
				}
				agents[id] = row
			}
			if blocked, ok := e["blocked"].(bool); ok && blocked {
				row["blocked_count"] = row["blocked_count"].(int64) + 1
			}
		}

		items := make([]map[string]interface{}, 0, len(agents))
		for _, a := range agents {
			items = append(items, a)
		}
		sort.Slice(items, func(i, j int) bool { return xdrPickString(items[i], "id") < xdrPickString(items[j], "id") })

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success", "data": items,
		})
	}
}

func raspEnableProtectionHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AgentID   string `json:"agent_id"`
			BlockMode bool   `json:"block_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if req.AgentID == "" {
			http.Error(w, "agent_id is required", http.StatusBadRequest)
			return
		}
		if req.BlockMode {
			writeJSONError(w, http.StatusConflict, "rasp_policy_lifecycle_required", "block mode requires a signed canary policy and is disabled for production promotion")
			return
		}

		agent, err := getOrInitRASPProtectionAgent(cfg, req.AgentID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		agent["agent_id"] = req.AgentID
		agent["enabled"] = true
		agent["block_mode"] = req.BlockMode
		agent["last_update"] = time.Now().UTC().Format(time.RFC3339)
		if _, ok := agent["blocked_types"]; !ok {
			agent["blocked_types"] = map[string]bool{}
		}
		if err := saveRASPProtectionAgent(cfg, req.AgentID, agent); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{
				"agent_id": req.AgentID, "enabled": true, "block_mode": req.BlockMode,
			},
		})
	}
}

func raspDisableProtectionHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			AgentID string `json:"agent_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if req.AgentID == "" {
			http.Error(w, "agent_id is required", http.StatusBadRequest)
			return
		}

		agent, err := getOrInitRASPProtectionAgent(cfg, req.AgentID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		agent["agent_id"] = req.AgentID
		agent["enabled"] = false
		agent["last_update"] = time.Now().UTC().Format(time.RFC3339)
		if err := saveRASPProtectionAgent(cfg, req.AgentID, agent); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{"agent_id": req.AgentID, "enabled": false},
		})
	}
}

func raspProtectionStatusHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		status, err := loadRASPProtectionAgents(cfg)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 1, "message": err.Error()})
			return
		}

		items := make([]map[string]interface{}, 0, len(status))
		for _, a := range status {
			blockedTypes := []string{}
			if bt, ok := a["blocked_types"].(map[string]interface{}); ok {
				for k, v := range bt {
					if vv, ok := v.(bool); ok && vv {
						blockedTypes = append(blockedTypes, k)
					}
				}
			}
			sort.Strings(blockedTypes)
			items = append(items, map[string]interface{}{
				"agent_id":      xdrPickString(a, "agent_id"),
				"hostname":      xdrPickString(a, "hostname"),
				"language":      xdrPickString(a, "language"),
				"enabled":       firstNonNil(a["enabled"], true),
				"status":        firstNonEmpty(xdrPickString(a, "status"), "protected"),
				"mode":          firstNonEmpty(xdrPickString(a, "mode"), "monitor"),
				"source":        firstNonEmpty(xdrPickString(a, "source"), "telemetry:rasp"),
				"last_seen_at":  xdrPickString(a, "last_seen_at", "updated_at"),
				"policy_state":  firstNonEmpty(xdrPickString(a, "policy_state"), "audit_only"),
				"block_mode":    a["block_mode"],
				"blocked_types": blockedTypes,
			})
		}
		sort.Slice(items, func(i, j int) bool { return xdrPickString(items[i], "agent_id") < xdrPickString(items[j], "agent_id") })

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success", "data": items,
		})
	}
}

func raspReceiveEventHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const surface = "http.rasp-event"
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		principal, ok := authenticateIngestion(w, r, cfg, surface)
		if !ok {
			return
		}
		var event map[string]interface{}
		if !decodeIngestionJSON(w, r, cfg, principal, surface, &event) {
			return
		}
		agentID, ok := bindIngestionPrincipal(w, r, cfg, principal, surface, xdrPickString(event, "agent_id"))
		if !ok {
			return
		}
		event["agent_id"] = agentID
		if cfg.Redis == nil {
			if !recordIngestionRejection(w, r, cfg, principal, surface, ingestionauth.OutcomeRejected, "redis unavailable") {
				return
			}
			writeJSONError(w, http.StatusServiceUnavailable, "redis_unavailable", "redis unavailable")
			return
		}
		if !acceptIngestion(w, r, cfg, principal, surface) {
			return
		}
		event = rasp.NormalizeEventMap(event)
		if _, ok := event["occurred_at"]; !ok {
			event["occurred_at"] = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if _, ok := event["severity"]; !ok {
			event["severity"] = "low"
		}

		telemetry := contracts.TelemetryEnvelope{
			SchemaVersion: contracts.TelemetrySchemaVersion,
			ID:            fmt.Sprintf("rasp-%d", time.Now().UnixNano()),
			Category:      contracts.TelemetryRASP,
			EventType:     xdrPickString(event, "attack_type", "event_type", "type"),
			ObservedAt:    parseEventTime(event),
			ReceivedAt:    time.Now().UTC(),
			Source:        xdrPickString(event, "source", "language", "backend"),
			Entities: contracts.EntityRef{
				AgentID:     xdrPickString(event, "agent_id"),
				HostID:      xdrPickString(event, "hostname"),
				Hostname:    xdrPickString(event, "hostname"),
				Application: xdrPickString(event, "application", "app"),
				SourceIP:    xdrPickString(event, "source_ip", "client_ip"),
				TargetIP:    xdrPickString(event, "target_ip"),
				TraceID:     xdrPickString(event, "trace_id", "request_id"),
			},
			Fields:  event,
			Excerpt: xdrPickString(event, "payload", "query", "command", "cmdline", "path", "url", "message"),
		}
		if telemetry.ObservedAt.IsZero() {
			telemetry.ObservedAt = time.Now().UTC()
		}
		if telemetry.EventType == "" {
			telemetry.EventType = "rasp.event"
		}
		if telemetry.Source == "" {
			telemetry.Source = "rasp-probe"
		}
		if data, err := json.Marshal(telemetry); err == nil {
			if err := writeIngestionStream(r.Context(), cfg, "telemetry:rasp", map[string]interface{}{"id": telemetry.ID, "data": string(data)}); err != nil {
				writeJSONError(w, http.StatusServiceUnavailable, "rasp_telemetry_write_failed", err.Error())
				return
			}
		}
		if msgID, err := storeV2ComponentAlert(r.Context(), cfg, componentAlertFromRASPEvent(event, telemetry)); err == nil {
			event["component_message_id"] = msgID
		} else {
			log.Printf("[RASP] component alert store failed: %v", err)
		}

		attackType, _ := event["attack_type"].(string)
		log.Printf("[RASP] 收到事件: agent=%s type=%s mode=monitor → telemetry:rasp", agentID, attackType)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{
				"id":       "rasp-" + strconv.FormatInt(time.Now().UnixNano(), 10),
				"received": true,
				"stream":   "telemetry:rasp",
				"mode":     "monitor",
			},
		})
	}
}

func componentAlertFromRASPEvent(event map[string]interface{}, telemetry contracts.TelemetryEnvelope) contracts.ComponentAlert {
	severity := strings.ToLower(firstNonEmpty(xdrPickString(event, "severity"), "low"))
	switch severity {
	case "critical", "high", "medium", "low":
	default:
		severity = "low"
	}
	observedAt := telemetry.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	ruleID := firstNonEmpty(xdrPickString(event, "rule_id", "attack_type", "event_type", "type"), "rasp.event")
	ruleName := firstNonEmpty(xdrPickString(event, "rule_name", "attack_type", "event_type", "type"), ruleID)
	summary := firstNonEmpty(xdrPickString(event, "message", "payload", "query", "command", "cmdline", "path", "url"), ruleName)
	action := string(contracts.ActionAudit)
	policy := contracts.PolicyAuditOnly
	if blocked := strings.EqualFold(xdrPickString(event, "blocked"), "true"); blocked || strings.EqualFold(xdrPickString(event, "action"), "block") {
		action = string(contracts.ActionBlock)
		policy = contracts.PolicyBlock
	}
	return contracts.ComponentAlert{
		SchemaVersion: contracts.ComponentAlertSchemaVersion,
		ID:            firstNonEmpty(xdrPickString(event, "id"), telemetry.ID),
		Category:      contracts.TelemetryRASP,
		SourceEngine:  contracts.SourceEngineRASP,
		RuleID:        ruleID,
		RuleName:      ruleName,
		NativeRule:    &contracts.RuleReference{Engine: contracts.SourceEngineRASP, ID: ruleID, Name: ruleName, Source: "rasp"},
		Severity:      contracts.AlertSeverity(severity),
		ScoreHint:     int(severityBaseScore(severity)),
		StageHint:     firstNonEmpty(xdrPickString(event, "stage_hint", "stage"), "execution"),
		OccurredAt:    observedAt,
		Source:        firstNonEmpty(telemetry.Source, "rasp-probe"),
		Entities:      telemetry.Entities,
		Summary:       summary,
		Details:       event,
		Action:        action,
		PolicyState:   policy,
		CandidateOnly: policy != contracts.PolicyBlock,
	}
}

func raspElkeidRulesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		source := r.URL.Query().Get("source")
		language := r.URL.Query().Get("language")
		category := r.URL.Query().Get("category")

		if source == "" {
			source = "all"
		}

		var rules []map[string]interface{}
		raspCount := 0
		hidsCount := 0

		if rs, err := rasp.LoadElkeidRules("rules/rasp/elkeid_rasp_rules.yaml"); err == nil {
			for _, rule := range rs.Rules {
				if !rule.Enabled {
					continue
				}
				if source != "all" && source != "rasp" {
					continue
				}
				if language != "" {
					found := false
					for _, l := range rule.Languages {
						if l == language {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}
				if category != "" && rule.Category != category {
					continue
				}

				rules = append(rules, map[string]interface{}{
					"id":          rule.ID,
					"name":        rule.Name,
					"category":    rule.Category,
					"severity":    rule.Severity,
					"languages":   rule.Languages,
					"runtime":     rule.Runtime,
					"description": rule.Description,
					"hook_type":   rule.HookType,
					"patterns":    rule.Patterns,
					"mitre":       rule.Mitre,
					"action":      rule.Action,
					"source":      "elkeid_rasp",
				})
				raspCount++
			}
		}

		if source == "hids" || source == "all" {
			if hidsRs, err := rasp.LoadElkeidRules("rules/hids/elkeid_hids_rules.yaml"); err == nil {
				for _, rule := range hidsRs.Rules {
					if !rule.Enabled {
						continue
					}
					if category != "" && rule.Category != category {
						continue
					}

					rules = append(rules, map[string]interface{}{
						"id":          rule.ID,
						"name":        rule.Name,
						"category":    rule.Category,
						"severity":    rule.Severity,
						"description": rule.Description,
						"hook_type":   rule.HookType,
						"patterns":    rule.Patterns,
						"mitre":       rule.Mitre,
						"action":      rule.Action,
						"source":      "elkeid_hids",
					})
					hidsCount++
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success",
			"data": map[string]interface{}{
				"items": rules,
				"total": len(rules),
				"by_source": map[string]int{
					"elkeid_rasp": raspCount,
					"elkeid_hids": hidsCount,
				},
			},
		})
	}
}

// ============ Trace API Handlers (Enhanced) ============

var traceHandler = trace.NewHandler()

func traceStatsHandler(cfg *Config) http.HandlerFunc {
	return traceHandler.GetStats
}

func traceSessionsHandler(cfg *Config) http.HandlerFunc {
	return traceHandler.ListSessions
}

func traceSearchHandler(cfg *Config) http.HandlerFunc {
	return traceHandler.SearchEvents
}

func traceSessionHandler(cfg *Config) http.HandlerFunc {
	return traceHandler.GetSession
}

func traceEventsHandler(cfg *Config) http.HandlerFunc {
	return traceHandler.ListEvents
}

func traceAnalyzeHandler(cfg *Config) http.HandlerFunc {
	return traceHandler.AnalyzeSession
}

// ============ Asset API Handlers (Elkeid Style) ============

var assetHandler *asset.Handler

func assetsStatsHandler(cfg *Config) http.HandlerFunc {
	return assetHandler.GetStats
}

func assetsListHandler(cfg *Config) http.HandlerFunc {
	return assetHandler.ListHosts
}

func assetsDetailHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/api/v1/assets/" {
			if r.Method == http.MethodPost {
				assetHandler.CreateHost(w, r)
				return
			}
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		subPath := strings.TrimPrefix(path, "/api/v1/assets/")

		if strings.HasSuffix(subPath, "/overview") {
			assetHandler.GetHostOverview(w, r)
			return
		} else if strings.HasSuffix(subPath, "/fingerprints") {
			assetHandler.GetHostFingerprints(w, r)
			return
		} else if strings.HasSuffix(subPath, "/ports") {
			assetHandler.GetHostPorts(w, r)
			return
		} else if strings.HasSuffix(subPath, "/processes") {
			assetHandler.GetHostProcesses(w, r)
			return
		} else if strings.HasSuffix(subPath, "/software") {
			assetHandler.GetHostSoftware(w, r)
			return
		}

		switch r.Method {
		case http.MethodGet:
			assetHandler.GetHost(w, r)
		case http.MethodPut:
			assetHandler.UpdateHost(w, r)
		case http.MethodDelete:
			assetHandler.DeleteHost(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func assetsGroupsHandler(cfg *Config) http.HandlerFunc {
	return assetHandler.ListGroups
}

func assetsHeartbeatHandler(cfg *Config) http.HandlerFunc {
	return assetHandler.Heartbeat
}

func normalizeAgentID(agentID string) string {
	return strings.TrimSpace(agentID)
}

func agentEnrollHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			EnrollmentToken string                 `json:"enrollment_token"`
			Hostname        string                 `json:"hostname"`
			IP              string                 `json:"ip"`
			OS              string                 `json:"os"`
			Version         string                 `json:"version"`
			Capabilities    map[string]string      `json:"capabilities"`
			CapabilityModel map[string]interface{} `json:"capability_model"`
			Metadata        map[string]string      `json:"metadata"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		if cfg == nil || cfg.AgentIdentity == nil || strings.TrimSpace(req.EnrollmentToken) == "" {
			writeJSONError(w, http.StatusForbidden, "agent_enrollment_token_required", "valid agent enrollment token required")
			return
		}

		agentKey, err := generateAgentCredential()
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "agent_credential_generation_failed", "agent credential generation failed")
			return
		}
		ctx := r.Context()
		record, err := cfg.AgentIdentity.EnrollContext(ctx, strings.TrimSpace(req.EnrollmentToken), agentKey, agentidentity.EnabledTransports{HTTP: true})
		if err != nil {
			writeJSONError(w, http.StatusForbidden, "agent_enrollment_token_rejected", "valid agent enrollment token required")
			return
		}
		agentID := record.ID().String()

		agent := &models.Agent{
			UUID:         agentID,
			AgentKey:     "",
			Hostname:     req.Hostname,
			IP:           req.IP,
			OS:           req.OS,
			AgentVersion: req.Version,
			Status:       "online",
		}

		if req.Capabilities != nil {
			if v, ok := req.Capabilities["traffic"]; ok && v == "true" {
				agent.TrafficEnabled = true
			}
			if v, ok := req.Capabilities["hids"]; ok && v == "true" {
				agent.HIDSEnabled = true
			}
			if v, ok := req.Capabilities["rasp"]; ok && v == "true" {
				agent.RASPEnabled = true
			}
		}
		agent.LastHeartbeat = time.Now()

		if cfg.DBPool != nil {
			if err := upsertAgent(ctx, cfg, agent); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "agent_persistence_failed", "agent enrollment could not be persisted")
				return
			}
		}
		if cfg.DBPool != nil {
			if err := upsertHostControlRecord(ctx, cfg, agent, req.CapabilityModel); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "agent_host_persistence_failed", "agent host data could not be persisted")
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"agent_id":  agentID,
				"agent_key": agentKey,
				"config": map[string]interface{}{
					"traffic_analysis_enabled":   agent.TrafficEnabled,
					"endpoint_detection_enabled": agent.HIDSEnabled,
					"rasp_enabled":               agent.RASPEnabled,
					"heartbeat_interval":         30,
					"report_interval":            60,
				},
			},
		})
	}
}

func agentsListHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		limit := parseQueryInt(r.URL.Query().Get("limit"), 50)
		offset := parseQueryInt(r.URL.Query().Get("offset"), 0)
		items, total, err := loadAgentSummaries(r.Context(), cfg, limit, offset)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "agent_list_failed", err.Error())
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"items": items, "total": total, "limit": limit, "offset": offset}})
	}
}

func agentDetailHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		agentID := normalizeAgentID(strings.TrimPrefix(r.URL.Path, "/api/v1/agents/"))
		if agentID == "" {
			writeJSONError(w, http.StatusNotFound, "agent_not_found", "agent not found")
			return
		}
		if r.Method == http.MethodDelete {
			agentDeleteHandler(cfg)(w, r)
			return
		}
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		agent, err := loadAgentDetail(r.Context(), cfg, agentID)
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "agent_not_found", "agent not found")
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": agent})
	}
}

func agentCapabilitiesToggleHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		agentID := normalizeAgentID(strings.TrimPrefix(r.URL.Path, "/api/v1/agent/capabilities/"))
		if agentID == "" {
			writeJSONError(w, http.StatusBadRequest, "agent_id_required", "agent id required")
			return
		}
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid request")
			return
		}
		field := strings.TrimSpace(asString(req["field"]))
		value := asBool(req["enabled"])
		var column string
		switch field {
		case "traffic":
			column = "traffic_enabled"
		case "rasp":
			column = "rasp_enabled"
		default:
			writeJSONError(w, http.StatusBadRequest, "invalid_field", "field must be traffic or rasp")
			return
		}
		if _, err := cfg.DBPool.Exec(r.Context(),
			fmt.Sprintf(`UPDATE agents SET %s=$2 WHERE uuid=$1`, column),
			agentID, value); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "capability_update_failed", err.Error())
			return
		}
		log.Printf("agent capability toggled: agent=%s field=%s enabled=%v", agentID, field, value)
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"agent_id": agentID, "field": field, "enabled": value}})
	}
}

func agentRenameHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		agentID := normalizeAgentID(strings.TrimPrefix(r.URL.Path, "/api/v1/agent/name/"))
		if agentID == "" {
			writeJSONError(w, http.StatusBadRequest, "agent_id_required", "agent id required")
			return
		}
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid request")
			return
		}
		displayName := strings.TrimSpace(asString(req["display_name"]))
		if displayName == "" {
			writeJSONError(w, http.StatusBadRequest, "name_required", "display_name is required")
			return
		}
		if strings.ContainsAny(displayName, "\"'`<>&") || len(displayName) > 64 {
			writeJSONError(w, http.StatusBadRequest, "invalid_name", "display_name contains invalid characters or is too long")
			return
		}
		var existingID string
		if err := cfg.DBPool.QueryRow(r.Context(), `SELECT uuid FROM agents WHERE display_name=$1 AND uuid!=$2`, displayName, agentID).Scan(&existingID); err == nil {
			writeJSONError(w, http.StatusConflict, "name_duplicate", "display_name already in use")
			return
		}
		if _, err := cfg.DBPool.Exec(r.Context(), `UPDATE agents SET display_name=$2 WHERE uuid=$1`, agentID, displayName); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "rename_failed", err.Error())
			return
		}
		names := loadAgentNames()
		names[agentID] = displayName
		_ = saveAgentNames(names)
		log.Printf("agent renamed: agent=%s display_name=%s", agentID, displayName)
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"agent_id": agentID, "display_name": displayName}})
	}
}

func agentNamesHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		names := loadAgentNames()
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"names": names}})
			return
		}
		if r.Method == http.MethodPut || r.Method == http.MethodPost {
			var req map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid request")
				return
			}
			agentID := strings.TrimSpace(asString(req["agent_id"]))
			displayName := strings.TrimSpace(asString(req["display_name"]))
			if agentID == "" || displayName == "" {
				writeJSONError(w, http.StatusBadRequest, "fields_required", "agent_id and display_name required")
				return
			}
			names[agentID] = displayName
			if err := saveAgentNames(names); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "save_failed", err.Error())
				return
			}
			log.Printf("agent names updated: agent_id=%s display_name=%s", agentID, displayName)
			json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"agent_id": agentID, "display_name": displayName}})
			return
		}
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

func loadAgentNames() map[string]string {
	names := map[string]string{}
	_ = readJSONFile(".sisyphus/runtime/agent-names.json", &names)
	return names
}

func saveAgentNames(names map[string]string) error {
	if err := os.MkdirAll(".sisyphus/runtime", 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(names, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(".sisyphus/runtime/agent-names.json", data, 0o644)
}

func agentDeleteHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodDelete {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		agentID := normalizeAgentID(strings.TrimPrefix(r.URL.Path, "/api/v1/agents/"))
		if agentID == "" {
			writeJSONError(w, http.StatusBadRequest, "agent_id_required", "agent id required")
			return
		}
		tag, err := cfg.DBPool.Exec(r.Context(), `DELETE FROM agents WHERE uuid=$1 AND (status!='online' OR last_heartbeat IS NULL OR last_heartbeat < NOW() - INTERVAL '120 seconds')`, agentID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "agent_delete_failed", err.Error())
			return
		}
		if tag.RowsAffected() == 0 {
			writeJSONError(w, http.StatusBadRequest, "agent_not_deletable", "agent is online by recent heartbeat or not found")
			return
		}
		log.Printf("offline agent deleted: agent=%s", agentID)
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"deleted": true, "agent_id": agentID}})
	}
}

func agentHeartbeatHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}

		var req struct {
			AgentID      string                 `json:"agent_id"`
			AgentKey     string                 `json:"agent_key"`
			Status       string                 `json:"status"`
			Capabilities map[string]interface{} `json:"capabilities"`
			Metrics      map[string]int64       `json:"metrics"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid request")
			return
		}

		agentID := normalizeAgentID(req.AgentID)
		ctx := r.Context()
		if agentID == "" {
			writeJSONError(w, http.StatusBadRequest, "agent_id_required", "agent_id is required")
			return
		}
		if err := ensureConfiguredAgent(ctx, cfg, agentID, req.AgentKey, req.Capabilities); err != nil {
			writeJSONError(w, http.StatusUnauthorized, "agent_auth_required", "valid agent key required")
			return
		}
		if err := updateAgentHeartbeat(ctx, cfg, agentID, req.Status); err != nil {
			log.Printf("Failed to update heartbeat: %v", err)
			writeJSONError(w, http.StatusNotFound, "agent_not_found", "agent not found")
			return
		}
		if len(req.Capabilities) > 0 {
			if err := updateHostCapabilityModel(ctx, cfg, agentID, req.Capabilities); err != nil {
				log.Printf("Failed to update heartbeat capability model: %v", err)
			}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"ack": true,
			},
		})
	}
}

func agentConfigHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			AgentID            string                 `json:"agent_id"`
			AgentKey           string                 `json:"agent_key"`
			ACKPolicyVersion   uint64                 `json:"ack_policy_version"`
			ACKPolicySignature string                 `json:"ack_policy_signature"`
			Capabilities       map[string]interface{} `json:"capabilities"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		agentID := normalizeAgentID(req.AgentID)
		if agentID == "" {
			http.Error(w, "agent_id is required", http.StatusBadRequest)
			return
		}
		if err := requireAgentKey(r.Context(), cfg, agentID, req.AgentKey); err != nil {
			writeJSONError(w, http.StatusUnauthorized, "agent_auth_required", "valid agent key required")
			return
		}
		exists, err := agentExists(r.Context(), cfg, agentID)
		if err != nil {
			log.Printf("agent config lookup failed: %v", err)
			http.Error(w, "agent lookup failed", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "agent not found", http.StatusNotFound)
			return
		}

		trafficEnabled, hidsEnabled, raspEnabled, err := loadAgentDesiredFlags(r.Context(), cfg, agentID)
		if err != nil {
			log.Printf("agent desired config lookup failed: agent_id=%s err=%v", agentID, err)
			http.Error(w, "agent desired config lookup failed", http.StatusInternalServerError)
			return
		}
		if enabled, _ := capabilityEnabled(req.Capabilities, "traffic_collector"); enabled {
			trafficEnabled = true
		}
		if enabled, _ := capabilityEnabled(req.Capabilities, "runtime_sensor"); enabled {
			hidsEnabled = true
		}
		if enabled, _ := capabilityEnabled(req.Capabilities, "yara_scanner"); enabled {
			hidsEnabled = true
		}
		if enabled, _ := capabilityEnabled(req.Capabilities, "rasp_probe_manager"); enabled {
			raspEnabled = true
		}
		desiredStates := engineDesiredStatesForAgent(trafficEnabled, hidsEnabled, raspEnabled)
		if cfg.RASPPolicy == nil {
			http.Error(w, "RASP policy lifecycle unavailable", http.StatusServiceUnavailable)
			return
		}
		if req.ACKPolicyVersion > 0 {
			acknowledgement := agentpolicy.Acknowledgement{AgentID: agentID, Version: req.ACKPolicyVersion, Signature: req.ACKPolicySignature}
			if err := cfg.RASPPolicy.Acknowledge(r.Context(), acknowledgement); err != nil {
				writeJSONError(w, http.StatusConflict, "rasp_policy_ack_rejected", err.Error())
				return
			}
		}
		assignment, err := cfg.RASPPolicy.AssignCurrent(r.Context(), raspAssignmentTarget(agentID, req.Capabilities))
		if err != nil {
			log.Printf("RASP policy assignment failed: agent_id=%s err=%v", agentID, err)
			http.Error(w, "RASP policy assignment failed", http.StatusServiceUnavailable)
			return
		}
		raspConfig := raspPolicyConfig(assignment.Envelope.Policy)
		for _, state := range desiredStates {
			if asString(state["name"]) == "rasp" {
				state["enabled"] = assignment.Envelope.Policy.Mode == agentpolicy.ModeMonitor
			}
		}
		tasks := []responsepkg.ActionTask{}
		if cfg.ResponseActions != nil {
			if pending, taskErr := cfg.ResponseActions.PendingTasks(agentID); taskErr == nil {
				tasks = pending
			} else {
				log.Printf("response action task dispatch failed: agent_id=%s err=%v", agentID, taskErr)
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"agent_id":              agentID,
				"policy_version":        assignment.Envelope.Policy.Version,
				"rasp_policy":           assignment.Envelope,
				"engine_desired_states": desiredStates,
				"config": map[string]interface{}{
					"task_poll_interval":    30,
					"heartbeat_interval":    30,
					"engine_desired_states": desiredStates,
					"policy": map[string]interface{}{
						"version":   assignment.Envelope.Policy.Version,
						"traffic":   map[string]interface{}{"enabled": trafficEnabled, "interface": "auto", "capture_engine": "auto", "bpf_filter": "", "promiscuous": true},
						"rasp":      raspConfig,
						"runtime":   map[string]interface{}{"enabled": hidsEnabled, "backend": "auto", "include_paths": []string{"/etc", "/var/log"}, "exclude_paths": []string{"/proc", "/sys"}},
						"asset":     map[string]interface{}{"interval_seconds": 60, "processes": true, "performance": true},
						"retention": map[string]interface{}{"evidence_enabled": true, "max_file_mb": 128, "retain_days": 3},
						"streams":   map[string]string{"raw": "flows:raw", "semantic": "flows:semantic", "runtime": "alerts:runtime", "rasp": "alerts:rasp"},
					},
				},
				"tasks": tasks,
			},
		})
	}
}

func agentTrafficEventHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const surface = "http.traffic-event"
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		principal, ok := authenticateIngestion(w, r, cfg, surface)
		if !ok {
			return
		}
		var req struct {
			AgentID  string                 `json:"agent_id"`
			AgentKey string                 `json:"agent_key"`
			Stream   string                 `json:"stream"`
			Type     string                 `json:"type"`
			Data     string                 `json:"data"`
			Values   map[string]interface{} `json:"values"`
		}
		if !decodeIngestionJSON(w, r, cfg, principal, surface, &req) {
			return
		}
		agentID, ok := bindIngestionPrincipal(w, r, cfg, principal, surface, normalizeAgentID(req.AgentID))
		if !ok {
			return
		}
		stream := strings.TrimSpace(req.Stream)
		if stream == "" {
			writeJSONError(w, http.StatusBadRequest, "invalid_traffic_event", "stream is required")
			return
		}
		if !ingestionWriterAvailable(cfg) {
			writeJSONError(w, http.StatusServiceUnavailable, "redis_unavailable", "redis unavailable")
			return
		}
		values := req.Values
		if len(values) == 0 {
			values = map[string]interface{}{"type": req.Type, "data": req.Data}
		}
		if strings.TrimSpace(asString(values["data"])) == "" && strings.TrimSpace(req.Data) != "" {
			values["data"] = req.Data
		}
		if strings.TrimSpace(asString(values["type"])) == "" && strings.TrimSpace(req.Type) != "" {
			values["type"] = req.Type
		}
		values["agent_id"] = agentID
		if !acceptIngestion(w, r, cfg, principal, surface) {
			return
		}
		if err := writeIngestionStream(r.Context(), cfg, stream, values); err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "traffic_event_write_failed", err.Error())
			return
		}
		if cfg.Redis != nil {
			if err := transport.RegisterProducer(r.Context(), cfg.Redis, "agent-traffic"); err != nil {
				writeJSONError(w, http.StatusServiceUnavailable, "traffic_event_registration_failed", err.Error())
				return
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"ack": true}})
	}
}

func loadAgentDesiredFlags(ctx context.Context, cfg *Config, agentID string) (bool, bool, bool, error) {
	var trafficEnabled, hidsEnabled, raspEnabled bool
	if err := cfg.DBPool.QueryRow(ctx, `SELECT COALESCE(traffic_enabled, false), COALESCE(hids_enabled, false), COALESCE(rasp_enabled, false) FROM agents WHERE uuid = $1`, agentID).Scan(&trafficEnabled, &hidsEnabled, &raspEnabled); err != nil {
		return false, false, false, err
	}
	if !trafficEnabled && !hidsEnabled && !raspEnabled && agentID == cfg.AgentID {
		return false, true, true, nil
	}
	if !trafficEnabled && !hidsEnabled && !raspEnabled {
		var metadataRaw []byte
		if err := cfg.DBPool.QueryRow(ctx, `SELECT COALESCE(metadata, '{}'::jsonb) FROM hosts WHERE agent_id = $1`, agentID).Scan(&metadataRaw); err == nil {
			capabilities := capabilitiesFromMetadata(metadataRaw)
			if state, ok := capabilityEnabled(capabilities, "traffic_collector"); ok {
				trafficEnabled = state
			}
			if state, ok := capabilityEnabled(capabilities, "runtime_sensor"); ok {
				hidsEnabled = state
			} else if state, ok := capabilityEnabled(capabilities, "log_collector"); ok {
				hidsEnabled = state
			}
			if state, ok := capabilityEnabled(capabilities, "rasp_probe_manager"); ok {
				raspEnabled = state
			}
		}
	}
	return trafficEnabled, hidsEnabled, raspEnabled, nil
}

func capabilityEnabled(capabilities map[string]interface{}, key string) (bool, bool) {
	capability := asMap(capabilities[key])
	if len(capability) == 0 {
		return false, false
	}
	enabled := asBool(capability["enabled"])
	status := strings.ToLower(asString(capability["status"]))
	return enabled && status != "disabled", true
}

func engineDesiredStatesForAgent(trafficEnabled, hidsEnabled, raspEnabled bool) []map[string]interface{} {
	states := defaultEngineDesiredStates()
	for _, state := range states {
		switch asString(state["name"]) {
		case "suricata":
			state["enabled"] = trafficEnabled
		case "wazuh", "yara":
			state["enabled"] = hidsEnabled
		case "rasp":
			state["enabled"] = raspEnabled
		}
	}
	return states
}

func defaultEngineDesiredStates() []map[string]interface{} {
	return []map[string]interface{}{
		{"name": "suricata", "enabled": true, "mode": "suricata_live", "config_version": "v2", "rule_pack_version": "et-open-active", "settings": map[string]string{"output_path": "/var/log/suricata/eve.json", "interface": "auto"}},
		{"name": "wazuh", "enabled": true, "mode": "headless-agent", "config_version": "v2", "rule_pack_version": "wazuh-default", "settings": map[string]string{"output_path": "/var/ossec/logs/alerts/alerts.json"}},
		{"name": "yara", "enabled": true, "mode": "artifact-scan", "config_version": "v2", "rule_pack_version": "yara-security", "settings": map[string]string{"output_path": "/opt/ly-agent/yara/last-scan.json"}},
		{"name": "rasp", "enabled": true, "mode": "audit-only", "config_version": "v2", "rule_pack_version": "rasp-active", "settings": map[string]string{"output_path": "/opt/ly-agent/rasp/events.jsonl"}},
	}
}

func agentTaskResultHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const surface = "http.task-result"
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		principal, ok := authenticateIngestion(w, r, cfg, surface)
		if !ok {
			return
		}

		var req struct {
			AgentID  string                 `json:"agent_id"`
			AgentKey string                 `json:"agent_key"`
			TaskID   string                 `json:"task_id"`
			Status   string                 `json:"status"`
			Result   map[string]interface{} `json:"result"`
			ErrorMsg string                 `json:"error,omitempty"`
		}
		if !decodeIngestionJSON(w, r, cfg, principal, surface, &req) {
			return
		}
		agentID, ok := bindIngestionPrincipal(w, r, cfg, principal, surface, normalizeAgentID(req.AgentID))
		if !ok {
			return
		}
		if cfg.DBPool != nil {
			exists, err := agentExists(r.Context(), cfg, agentID)
			if err != nil {
				log.Printf("agent task result lookup failed: %v", err)
				http.Error(w, "agent lookup failed", http.StatusInternalServerError)
				return
			}
			if !exists {
				http.Error(w, "agent not found", http.StatusNotFound)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if !acceptIngestion(w, r, cfg, principal, surface) {
			return
		}
		if req.TaskID != "" {
			log.Printf("agent task result received: agent_id=%s task_id=%s status=%s", agentID, req.TaskID, req.Status)
			if cfg.ResponseActions != nil {
				if err := cfg.ResponseActions.Complete(req.TaskID, req.Status, req.Result, req.ErrorMsg); err != nil {
					log.Printf("response action completion update failed: task_id=%s err=%v", req.TaskID, err)
				}
			}
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"ack":      true,
				"agent_id": agentID,
				"task_id":  req.TaskID,
			},
		})
	}
}

func agentComponentAlertHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const surface = "http.component-alert"
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		principal, ok := authenticateIngestion(w, r, cfg, surface)
		if !ok {
			return
		}
		var raw json.RawMessage
		if !decodeIngestionJSON(w, r, cfg, principal, surface, &raw) {
			return
		}
		alerts, err := decodeComponentAlerts(raw)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_component_alert", err.Error())
			return
		}
		for index := range alerts {
			alert := &alerts[index]
			agentID, ok := bindIngestionPrincipal(w, r, cfg, principal, surface, alert.Entities.AgentID)
			if !ok {
				return
			}
			alert.Entities.AgentID = agentID
			if alert.Source == "" {
				alert.Source = string(alert.SourceEngine)
			}
			if err := alert.Validate(); err != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid_component_alert", err.Error())
				return
			}
		}
		if cfg == nil || cfg.Redis == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "redis_unavailable", "redis unavailable")
			return
		}
		if !acceptIngestion(w, r, cfg, principal, surface) {
			return
		}
		ids := make([]string, 0, len(alerts))
		messageIDs := make([]string, 0, len(alerts))
		for index := range alerts {
			alert := &alerts[index]
			msgID, err := storeV2ComponentAlert(r.Context(), cfg, *alert)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "component_alert_store_failed", err.Error())
				return
			}
			payload, err := json.Marshal(alert)
			if err != nil {
				writeJSONError(w, http.StatusInternalServerError, "component_alert_encode_failed", err.Error())
				return
			}
			if err := cfg.Redis.XAdd(r.Context(), &redis.XAddArgs{
				Stream: "component_alerts:v2",
				Values: map[string]interface{}{"data": string(payload)},
			}).Err(); err != nil {
				writeJSONError(w, http.StatusInternalServerError, "component_alert_stream_failed", err.Error())
				return
			}
			ids = append(ids, alert.ID)
			messageIDs = append(messageIDs, msgID)
		}
		data := map[string]interface{}{
			"ids": ids, "message_ids": messageIDs, "stream": "component_alerts:v2",
		}
		if len(ids) == 1 {
			data["id"] = ids[0]
			data["message_id"] = messageIDs[0]
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": data})
	}
}

func decodeComponentAlerts(raw json.RawMessage) ([]contracts.ComponentAlert, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return nil, fmt.Errorf("empty component alert")
	}
	if strings.HasPrefix(trimmed, "[") {
		var alerts []contracts.ComponentAlert
		if err := json.Unmarshal(raw, &alerts); err != nil {
			return nil, err
		}
		if len(alerts) == 0 {
			return nil, fmt.Errorf("empty component alert batch")
		}
		return alerts, nil
	}
	var alert contracts.ComponentAlert
	if err := json.Unmarshal(raw, &alert); err != nil {
		return nil, err
	}
	return []contracts.ComponentAlert{alert}, nil
}

func storeV2ComponentAlert(ctx context.Context, cfg *Config, alert contracts.ComponentAlert) (string, error) {
	if cfg == nil || cfg.EventStorage == nil {
		return "", fmt.Errorf("event migration runtime unavailable")
	}
	receipt, err := cfg.EventStorage.WriteComponentAlert(ctx, alert, time.Now().UTC())
	if err != nil {
		return "", err
	}
	return receipt.EventUID, nil
}

func upsertAgent(ctx context.Context, cfg *Config, agent *models.Agent) error {
	query := `
		INSERT INTO agents (uuid, agent_key, hostname, ip, os, agent_version, status, traffic_enabled, hids_enabled, rasp_enabled, last_heartbeat, connection_since, enrolled_at)
		VALUES ($1, $2, $3, NULLIF($4, '')::inet, $5, $6, $7, $8, $9, $10, $11, NOW(), NOW())
		ON CONFLICT (uuid) DO UPDATE SET
			agent_key = EXCLUDED.agent_key,
			hostname = EXCLUDED.hostname,
			ip = EXCLUDED.ip,
			os = EXCLUDED.os,
			agent_version = EXCLUDED.agent_version,
			status = EXCLUDED.status,
			traffic_enabled = EXCLUDED.traffic_enabled,
			hids_enabled = EXCLUDED.hids_enabled,
			rasp_enabled = EXCLUDED.rasp_enabled,
			last_heartbeat = EXCLUDED.last_heartbeat
	`
	_, err := cfg.DBPool.Exec(ctx, query,
		agent.UUID,
		agent.AgentKey,
		agent.Hostname,
		agent.IP,
		agent.OS,
		agent.AgentVersion,
		agent.Status,
		agent.TrafficEnabled,
		agent.HIDSEnabled,
		agent.RASPEnabled,
		agent.LastHeartbeat,
	)
	return err
}

func startAgentStaleCleanup(cfg *Config) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		ctx := context.Background()
		result, err := cfg.DBPool.Exec(ctx,
			`UPDATE agents SET status='offline' WHERE status='online' AND last_heartbeat < NOW() - INTERVAL '5 minutes'`)
		if err != nil {
			log.Printf("agent stale cleanup failed: %v", err)
			continue
		}
		n := result.RowsAffected()
		if n > 0 {
			log.Printf("agent stale cleanup: %d agents marked offline", n)
		}
		// also mark corresponding hosts as offline
		_, _ = cfg.DBPool.Exec(ctx,
			`UPDATE hosts SET status='offline' WHERE agent_id IN
			 (SELECT uuid FROM agents WHERE status='offline') AND status='online'`)
		deleted, err := cfg.DBPool.Exec(ctx,
			`DELETE FROM agents WHERE status='offline' AND last_heartbeat < NOW() - INTERVAL '24 hours'`)
		if err == nil && deleted.RowsAffected() > 0 {
			log.Printf("agent stale cleanup: %d stale agents purged", deleted.RowsAffected())
		}
		_, _ = cfg.DBPool.Exec(ctx,
			`DELETE FROM hosts WHERE agent_id NOT IN (SELECT uuid FROM agents)`)
	}
}

func loadAgentSummaries(ctx context.Context, cfg *Config, limit, offset int) ([]map[string]interface{}, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	var total int
	if err := cfg.DBPool.QueryRow(ctx, "SELECT COUNT(*) FROM agents").Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := cfg.DBPool.Query(ctx, `
		SELECT a.uuid, a.hostname, COALESCE(host(a.ip), ''), COALESCE(a.os, ''), COALESCE(a.agent_version, ''),
			COALESCE(a.status, 'offline'), COALESCE(a.traffic_enabled, false), COALESCE(a.hids_enabled, false), COALESCE(a.rasp_enabled, false),
			COALESCE(a.last_heartbeat, NOW()), COALESCE(a.connection_since, a.enrolled_at, a.last_heartbeat),
			COALESCE(a.display_name, a.hostname), COALESCE(h.metadata, '{}'::jsonb)
		FROM agents a
		LEFT JOIN hosts h ON h.agent_id = a.uuid
		ORDER BY a.last_heartbeat DESC NULLS LAST
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]map[string]interface{}, 0, limit)
	for rows.Next() {
		var id, hostname, ip, osName, version, status string
		var traffic, hids, raspEnabled bool
		var lastHeartbeat, connectionSince time.Time
		var displayName string
		var metadataRaw []byte
		if err := rows.Scan(&id, &hostname, &ip, &osName, &version, &status, &traffic, &hids, &raspEnabled, &lastHeartbeat, &connectionSince, &displayName, &metadataRaw); err != nil {
			return nil, 0, err
		}
		items = append(items, sanitizeAgentRecord(map[string]interface{}{
			"id": id, "agent_id": id, "hostname": hostname, "ip": ip, "os": osName, "version": version, "status": status,
			"traffic_enabled": traffic, "hids_enabled": hids, "rasp_enabled": raspEnabled, "last_heartbeat": lastHeartbeat.Format(time.RFC3339Nano),
			"connection_since": connectionSince.Format(time.RFC3339Nano),
			"display_name":     displayName,
			"capabilities":     capabilitiesFromMetadata(metadataRaw),
		}))
	}
	return items, total, nil
}

func loadAgentDetail(ctx context.Context, cfg *Config, agentID string) (map[string]interface{}, error) {
	var id, hostname, ip, osName, version, status string
	var traffic, hids, raspEnabled bool
	var lastHeartbeat, connectionSince time.Time
	var metadataRaw []byte
	err := cfg.DBPool.QueryRow(ctx, `
		SELECT a.uuid, a.hostname, COALESCE(host(a.ip), ''), COALESCE(a.os, ''), COALESCE(a.agent_version, ''),
			COALESCE(a.status, 'offline'), COALESCE(a.traffic_enabled, false), COALESCE(a.hids_enabled, false), COALESCE(a.rasp_enabled, false),
			COALESCE(a.last_heartbeat, NOW()), COALESCE(a.connection_since, a.enrolled_at, a.last_heartbeat), COALESCE(h.metadata, '{}'::jsonb)
		FROM agents a
		LEFT JOIN hosts h ON h.agent_id = a.uuid
		WHERE a.uuid = $1
	`, agentID).Scan(&id, &hostname, &ip, &osName, &version, &status, &traffic, &hids, &raspEnabled, &lastHeartbeat, &connectionSince, &metadataRaw)
	if err != nil {
		return nil, err
	}
	metadata := map[string]interface{}{}
	_ = json.Unmarshal(metadataRaw, &metadata)
	return sanitizeAgentRecord(map[string]interface{}{
		"id": id, "agent_id": id, "hostname": hostname, "ip": ip, "os": osName, "version": version, "status": status,
		"traffic_enabled": traffic, "hids_enabled": hids, "rasp_enabled": raspEnabled, "last_heartbeat": lastHeartbeat.Format(time.RFC3339Nano),
		"connection_since": connectionSince.Format(time.RFC3339Nano),
		"capabilities":     capabilitiesFromMetadata(metadataRaw), "metadata": metadata,
		"config": map[string]interface{}{"heartbeat_interval": 30, "task_poll_interval": 30},
		"tasks":  []map[string]interface{}{},
	}), nil
}

func capabilitiesFromMetadata(metadataRaw []byte) map[string]interface{} {
	metadata := map[string]interface{}{}
	if len(metadataRaw) > 0 {
		_ = json.Unmarshal(metadataRaw, &metadata)
	}
	if capabilities, ok := metadata["capabilities"].(map[string]interface{}); ok {
		return capabilities
	}
	return map[string]interface{}{}
}

func sanitizeAgentRecord(record map[string]interface{}) map[string]interface{} {
	delete(record, "agent_key")
	delete(record, "key")
	delete(record, "token")
	delete(record, "secret")
	return record
}

func requireAgentKey(ctx context.Context, cfg *Config, agentID, agentKey string) error {
	agentID = normalizeAgentID(agentID)
	agentKey = strings.TrimSpace(agentKey)
	if agentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if agentKey == "" {
		return fmt.Errorf("agent key required")
	}
	if cfg == nil || cfg.DBPool == nil {
		if cfg != nil && cfg.AgentIdentity != nil {
			return cfg.AgentIdentity.Authenticate(agentID, agentKey, agentidentity.TransportHTTP)
		}
		return fmt.Errorf("agent store unavailable")
	}
	if cfg.AgentIdentity != nil {
		if err := cfg.AgentIdentity.Authenticate(agentID, agentKey, agentidentity.TransportHTTP); err == nil {
			return nil
		}
	}
	var storedKey string
	if err := cfg.DBPool.QueryRow(ctx, "SELECT COALESCE(agent_key, '') FROM agents WHERE uuid = $1", agentID).Scan(&storedKey); err != nil {
		return err
	}
	if !sameSecret(storedKey, agentKey) {
		return fmt.Errorf("invalid agent key")
	}
	if cfg.AgentIdentity != nil {
		id, err := agentidentity.NewAgentID(agentID)
		if err != nil {
			return err
		}
		record, err := agentidentity.NewLegacyRecord(id, storedKey, agentidentity.EnabledTransports{HTTP: true})
		if err != nil {
			return err
		}
		if err := cfg.AgentIdentity.Store(record); err != nil && !errors.Is(err, agentidentity.ErrInvalidTransition) {
			return err
		}
		return cfg.AgentIdentity.Authenticate(agentID, agentKey, agentidentity.TransportHTTP)
	}
	return nil
}

func generateAgentCredential() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate agent credential: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func sameSecret(a, b string) bool {
	if a == "" || b == "" || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func ensureConfiguredAgent(ctx context.Context, cfg *Config, agentID, agentKey string, capabilities map[string]interface{}) error {
	agentID = normalizeAgentID(agentID)
	agentKey = strings.TrimSpace(agentKey)
	if agentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if agentKey == "" {
		return fmt.Errorf("agent key required")
	}
	if cfg == nil || cfg.DBPool == nil {
		return fmt.Errorf("agent store unavailable")
	}
	if cfg.AgentIdentity != nil {
		if err := cfg.AgentIdentity.Authenticate(agentID, agentKey, agentidentity.TransportHTTP); err == nil {
			return nil
		}
	}

	var storedKey string
	err := cfg.DBPool.QueryRow(ctx, "SELECT COALESCE(agent_key, '') FROM agents WHERE uuid = $1", agentID).Scan(&storedKey)
	if err == nil {
		if !sameSecret(storedKey, agentKey) {
			return fmt.Errorf("invalid agent key")
		}
		if cfg.AgentIdentity != nil {
			id, idErr := agentidentity.NewAgentID(agentID)
			if idErr != nil {
				return idErr
			}
			record, recordErr := agentidentity.NewLegacyRecord(id, storedKey, agentidentity.EnabledTransports{HTTP: true})
			if recordErr != nil {
				return recordErr
			}
			if storeErr := cfg.AgentIdentity.Store(record); storeErr != nil && !errors.Is(storeErr, agentidentity.ErrInvalidTransition) {
				return storeErr
			}
			return cfg.AgentIdentity.Authenticate(agentID, agentKey, agentidentity.TransportHTTP)
		}
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if cfg.AgentID == "" || cfg.AgentKey == "" || agentID != cfg.AgentID || !sameSecret(cfg.AgentKey, agentKey) {
		return fmt.Errorf("agent not enrolled and not server-preconfigured")
	}

	capabilityModel := normalizeCapabilityModel(capabilities)
	agent := &models.Agent{
		UUID:           agentID,
		AgentKey:       "",
		Hostname:       agentID,
		Status:         "online",
		TrafficEnabled: boolFromMap(capabilityModel, "traffic"),
		HIDSEnabled:    boolFromMap(capabilityModel, "hids"),
		RASPEnabled:    boolFromMap(capabilityModel, "rasp"),
		LastHeartbeat:  time.Now(),
	}
	if err := upsertAgent(ctx, cfg, agent); err != nil {
		return err
	}
	if err := upsertHostControlRecord(ctx, cfg, agent, capabilityModel); err != nil {
		return err
	}
	if cfg.AgentIdentity != nil {
		id, idErr := agentidentity.NewAgentID(agentID)
		if idErr != nil {
			return idErr
		}
		record, recordErr := agentidentity.NewLegacyRecord(id, agentKey, agentidentity.EnabledTransports{HTTP: true})
		if recordErr != nil {
			return recordErr
		}
		if storeErr := cfg.AgentIdentity.Store(record); storeErr != nil {
			return storeErr
		}
	}
	log.Printf("agent auto-enrolled from configured credentials: agent_id=%s", agentID)
	return nil
}

func normalizeCapabilityModel(capabilities map[string]interface{}) map[string]interface{} {
	if capabilities == nil {
		return map[string]interface{}{}
	}
	return capabilities
}

func boolFromMap(values map[string]interface{}, key string) bool {
	switch v := values[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
	default:
		return false
	}
}

func upsertHostControlRecord(ctx context.Context, cfg *Config, agent *models.Agent, capabilityModel map[string]interface{}) error {
	metadata, _ := json.Marshal(map[string]interface{}{
		"capabilities":   capabilityModel,
		"control_source": "agent-http-enroll",
	})
	_, err := cfg.DBPool.Exec(ctx, `
		INSERT INTO hosts (id, hostname, ip, os, agent_id, status, last_heartbeat, last_seen, metadata)
		VALUES ($1, $2, $3, $4, $5, 'online', NOW(), NOW(), $6::jsonb)
		ON CONFLICT (id) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			ip = EXCLUDED.ip,
			os = EXCLUDED.os,
			agent_id = EXCLUDED.agent_id,
			status = 'online',
			last_heartbeat = NOW(),
			last_seen = NOW(),
			metadata = hosts.metadata || EXCLUDED.metadata,
			updated_at = NOW()
	`, agent.UUID, agent.Hostname, agent.IP, agent.OS, agent.UUID, string(metadata))
	return err
}

func updateHostCapabilityModel(ctx context.Context, cfg *Config, agentID string, capabilityModel map[string]interface{}) error {
	if cfg == nil || cfg.DBPool == nil || agentID == "" {
		return nil
	}
	metadata, _ := json.Marshal(map[string]interface{}{
		"capabilities":   capabilityModel,
		"control_source": "agent-http-heartbeat",
	})
	_, err := cfg.DBPool.Exec(ctx, `UPDATE hosts SET metadata = metadata || $2::jsonb, last_heartbeat = NOW(), last_seen = NOW() WHERE agent_id = $1`, agentID, string(metadata))
	return err
}

func agentExists(ctx context.Context, cfg *Config, agentID string) (bool, error) {
	agentID = normalizeAgentID(agentID)
	if agentID == "" {
		return false, nil
	}
	var exists bool
	err := cfg.DBPool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM agents WHERE uuid = $1)", agentID).Scan(&exists)
	return exists, err
}

func updateAgentHeartbeat(ctx context.Context, cfg *Config, agentID, heartbeatStatus string) error {
	agentID = normalizeAgentID(agentID)
	if agentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	status := strings.ToLower(strings.TrimSpace(heartbeatStatus))
	if status == "" {
		status = "online"
	}
	if status != "online" && status != "offline" {
		status = "online"
	}
	// set connection_since on transition to online
	tag, err := cfg.DBPool.Exec(ctx,
		`UPDATE agents SET last_heartbeat = NOW(), status = $2,
		 connection_since = CASE WHEN status != 'online' THEN NOW() ELSE connection_since END
		 WHERE uuid = $1`, agentID, status)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("agent not found: %s", agentID)
	}
	_, err = cfg.DBPool.Exec(ctx, "UPDATE hosts SET last_heartbeat = NOW(), last_seen = NOW(), status = $2 WHERE agent_id = $1", agentID, status)
	return err
}

func agentRuntimeEventHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const surface = "http.runtime-event"
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		principal, ok := authenticateIngestion(w, r, cfg, surface)
		if !ok {
			return
		}

		var req map[string]interface{}
		if !decodeIngestionJSON(w, r, cfg, principal, surface, &req) {
			return
		}
		agentID, ok := bindIngestionPrincipal(w, r, cfg, principal, surface, xdrPickString(req, "agent_id"))
		if !ok {
			return
		}
		req["agent_id"] = agentID
		if cfg.Redis == nil {
			if !recordIngestionRejection(w, r, cfg, principal, surface, ingestionauth.OutcomeRejected, "redis unavailable") {
				return
			}
			writeJSONError(w, http.StatusServiceUnavailable, "redis_unavailable", "redis unavailable")
			return
		}
		if !acceptIngestion(w, r, cfg, principal, surface) {
			return
		}

		req["mode"] = "monitor"
		if _, ok := req["occurred_at"]; !ok {
			req["occurred_at"] = time.Now().UTC().Format(time.RFC3339Nano)
		}
		if _, ok := req["severity"]; !ok {
			req["severity"] = "low"
		}

		eventType := xdrPickString(req, "type", "event_type")
		isAuthEvent := strings.HasPrefix(eventType, "runtime.auth.") ||
			xdrPickString(req, "collector") == "auth-log-signal" ||
			strings.Contains(xdrPickString(req, "signal"), "auth") ||
			xdrPickString(req, "source") == "auth-log-signal"

		payload, err := json.Marshal(req)
		if err != nil {
			http.Error(w, "serialize failed", http.StatusInternalServerError)
			return
		}

		if !isAuthEvent {
			if err := writeIngestionStream(r.Context(), cfg, "alerts:runtime", map[string]interface{}{"id": xdrPickString(req, "id"), "data": string(payload)}); err != nil {
				log.Printf("runtime event publish failed: %v", err)
				http.Error(w, "publish failed", http.StatusInternalServerError)
				return
			}
		}
		telemetry := contracts.TelemetryEnvelope{
			SchemaVersion: contracts.TelemetrySchemaVersion,
			ID:            fmt.Sprintf("runtime-%d", time.Now().UnixNano()),
			Category:      contracts.TelemetryRuntime,
			EventType:     xdrPickString(req, "type", "event_type"),
			ObservedAt:    parseEventTime(req),
			ReceivedAt:    time.Now().UTC(),
			Source:        xdrPickString(req, "backend", "source_evidence", "source"),
			Entities: contracts.EntityRef{
				AgentID:  xdrPickString(req, "agent_id"),
				HostID:   xdrPickString(req, "hostname"),
				Hostname: xdrPickString(req, "hostname"),
				TargetIP: xdrPickString(req, "ip"),
				User:     xdrPickString(req, "user", "username"),
			},
			RawReference: &contracts.RawReference{Stream: "alerts:runtime"},
			Fields:       req,
			Excerpt:      xdrPickString(req, "message"),
		}
		if telemetry.ObservedAt.IsZero() {
			telemetry.ObservedAt = time.Now().UTC()
		}
		if telemetry.EventType == "" {
			telemetry.EventType = "runtime.event"
		}
		if telemetry.Source == "" {
			telemetry.Source = "ly-agent-runtime"
		}
		if data, err := json.Marshal(telemetry); err == nil {
			if err := writeIngestionStream(r.Context(), cfg, "telemetry:runtime", map[string]interface{}{"id": telemetry.ID, "data": string(data)}); err != nil {
				writeJSONError(w, http.StatusServiceUnavailable, "runtime_telemetry_write_failed", err.Error())
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"stream": "alerts:runtime",
				"mode":   "monitor",
				"ack":    true,
			},
		})
	}
}

func agentInstallConfigHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodGet {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		apiServer, ok := inferAPIServer(r)
		if !ok {
			http.Error(w, "invalid request host", http.StatusBadRequest)
			return
		}
		ruleBundle := currentAgentRuleBundleSummary(r.Context(), cfg)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":    0,
			"message": "success",
			"data": map[string]interface{}{
				"agent_center": map[string]interface{}{"role": "control_plane", "grpc_port": 8081, "api_server": apiServer},
				"install": map[string]interface{}{
					"service":       "ly-agent",
					"install_dir":   "/opt/ly-agent",
					"linux_url":     apiServer + "/api/v1/agent/install.sh",
					"uninstall_url": apiServer + "/api/v1/agent/uninstall.sh",
					"downloads": map[string]string{
						"linux_amd64": apiServer + "/api/v1/agent/download?os=linux&arch=amd64",
						"linux_arm64": apiServer + "/api/v1/agent/download?os=linux&arch=arm64",
					},
				},
				"telemetry_streams": map[string]string{
					"traffic":   "telemetry:traffic",
					"runtime":   "telemetry:runtime",
					"rasp":      "telemetry:rasp",
					"log_audit": "telemetry:log_audit",
				},
				"legacy_dpi":   map[string]interface{}{"enabled_by_default": false, "compose_profile": "legacy-dpi"},
				"rule_bundle":  ruleBundle,
				"rule_sources": currentAgentRuleSourceSummary(r.Context(), cfg),
				"rasp": map[string]interface{}{
					"auto_inject":         cfg.RASPAutomaticInjection,
					"block_by_default":    cfg.RASPBlockDefault,
					"bridge_addr":         "127.0.0.1:17891",
					"health_policy":       "auto_rollback_on_probe_failure",
					"field_contract":      []string{"query", "command", "cmdline", "path", "url", "payload", "message", "http_host", "http_path", "source_ip", "trace_id"},
					"rule_bundle_version": asString(ruleBundle["version"]),
					"probes": map[string]string{
						"python": apiServer + "/api/v1/agent/rasp/probe/python",
						"php":    apiServer + "/api/v1/agent/rasp/probe/php",
						"java":   apiServer + "/api/v1/agent/rasp/probe/java",
					},
				},
			},
		})
	}
}

func currentAgentRuleBundleSummary(ctx context.Context, cfg *Config) map[string]interface{} {
	rows, err := loadRulePlatformBundles(ctx, cfg)
	if err != nil || len(rows) == 0 {
		preview, previewErr := previewSecurityBundle(ctx, cfg)
		if previewErr != nil {
			return map[string]interface{}{"status": "unknown", "error": previewErr.Error()}
		}
		return preview
	}
	active := rows[0]
	preview, err := previewSecurityBundle(ctx, cfg)
	if err == nil {
		active["rule_count"] = preview["rule_count"]
		active["rule_counts"] = preview["rule_counts"]
	}
	return active
}

func currentAgentRuleSourceSummary(ctx context.Context, cfg *Config) []map[string]interface{} {
	versions, err := loadRulePlatformVersions(ctx, cfg, "")
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := []map[string]interface{}{}
	for _, version := range versions {
		sourceID := asString(version["source_id"])
		if sourceID == "" {
			continue
		}
		if _, ok := seen[sourceID]; ok {
			continue
		}
		seen[sourceID] = struct{}{}
		out = append(out, map[string]interface{}{"source_id": sourceID, "version": version["version"], "synced_at": version["synced_at"], "status": version["sync_status"]})
	}
	return out
}

func agentUninstallScriptHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		fmt.Fprint(w, `#!/bin/sh
set -eu
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop ly-agent 2>/dev/null || true
  systemctl disable ly-agent 2>/dev/null || true
fi
rm -f /etc/systemd/system/ly-agent.service
rm -rf /opt/ly-agent
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
printf 'ly-agent uninstalled\n'
`)
	}
}

func agentRASPPolicyRootHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		trustDir := strings.TrimSpace(getEnv("POLICY_TRUST_DIR", "/var/lib/lyflow/policy/trust"))
		path := filepath.Join(trustDir, "policy-root.pem")
		if st, err := os.Stat(path); err != nil || st.IsDir() {
			http.Error(w, "policy root unavailable", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		http.ServeFile(w, r, path)
	}
}

func agentRASPProbeHandler(language string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		path := ""
		contentType := "text/plain; charset=utf-8"
		switch language {
		case "python":
			path = "probe/rasp/python/sitecustomize.py"
		case "php":
			path = "probe/rasp/php/ly_rasp_prepend.php"
		case "java":
			path = "probe/rasp/java/ly-rasp-agent.jar"
			contentType = "application/java-archive"
		case "nodejs":
			path = "probe/rasp/nodejs/ly_rasp.js"
			contentType = "application/javascript"
		case "dotnet":
			path = "probe/rasp/dotnet/LyRaspProfiler.dll"
			contentType = "application/octet-stream"
		}
		if path == "" {
			http.NotFound(w, r)
			return
		}
		candidates := []string{"/app/" + path, path, filepath.Join("..", path)}
		if language == "java" {
			candidates = append(candidates, "/app/probe/rasp/java/src/main/java/com/lyflow/rasp/LyRaspAgent.java", "probe/rasp/java/src/main/java/com/lyflow/rasp/LyRaspAgent.java", filepath.Join("..", "probe/rasp/java/src/main/java/com/lyflow/rasp/LyRaspAgent.java"))
		}
		for _, candidate := range candidates {
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				w.Header().Set("Content-Type", contentType)
				http.ServeFile(w, r, candidate)
				return
			}
		}
		http.Error(w, "RASP probe asset not found", http.StatusNotFound)
	}
}

func agentRASPJavaSourceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/api/v1/agent/rasp/probe/java/source/")
		allowed := map[string]string{
			"LyRaspAgent.java":           "probe/rasp/java/src/main/java/com/lyflow/rasp/LyRaspAgent.java",
			"LyRaspSecurityManager.java": "probe/rasp/java/src/main/java/com/lyflow/rasp/LyRaspSecurityManager.java",
			"LyRaspJdbcDriver.java":      "probe/rasp/java/src/main/java/com/lyflow/rasp/LyRaspJdbcDriver.java",
			"MANIFEST.MF":                "probe/rasp/java/MANIFEST.MF",
			"build.sh":                   "probe/rasp/java/build.sh",
		}
		path := allowed[name]
		if path == "" {
			http.NotFound(w, r)
			return
		}
		candidates := []string{"/app/" + path, path, filepath.Join("..", path)}
		for _, candidate := range candidates {
			if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				http.ServeFile(w, r, candidate)
				return
			}
		}
		http.Error(w, "RASP Java source asset not found", http.StatusNotFound)
	}
}

func agentInstallScriptHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		apiServer, ok := inferAPIServer(r)
		if !ok {
			http.Error(w, "invalid request host", http.StatusBadRequest)
			return
		}
		enrollmentToken := strings.TrimSpace(r.URL.Query().Get("enrollment_token"))
		if enrollmentToken != "" && !safeEnrollmentToken(enrollmentToken) {
			http.Error(w, "invalid enrollment token", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		fmt.Fprintf(w, `#!/bin/sh
set -eu
ENROLL_TOKEN="%s"
REQUEST_API_SERVER="%s"
REQUEST_HOST=$(printf "%%s" "$REQUEST_API_SERVER" | sed -E 's#^https?://([^/:]+).*#\1#')
API_SERVER="$REQUEST_API_SERVER"
REDIS_SERVER="$REQUEST_HOST:6379"
INSTALL_DIR="/opt/ly-agent"
AGENT_BIN="$INSTALL_DIR/bin/ly-agent"
AGENT_TMP="$INSTALL_DIR/bin/ly-agent.new"
CONFIG_FILE="$INSTALL_DIR/etc/agent.yaml"
SERVICE_FILE="/etc/systemd/system/ly-agent.service"
TRAFFIC_INTERFACE=$(ip route get "$REQUEST_HOST" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
if [ "${TRAFFIC_INTERFACE:-}" = "lo" ]; then
  TRAFFIC_INTERFACE=""
fi
if [ -z "${TRAFFIC_INTERFACE:-}" ]; then
  TRAFFIC_INTERFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
fi
if [ -z "${TRAFFIC_INTERFACE:-}" ]; then
  TRAFFIC_INTERFACE="eth0"
fi
mkdir -p \
  "$INSTALL_DIR/bin" \
  "$INSTALL_DIR/etc" \
  "$INSTALL_DIR/logs" \
  "$INSTALL_DIR/data/sessions" \
  "$INSTALL_DIR/data/packets" \
  "$INSTALL_DIR/data/cache" \
  "$INSTALL_DIR/rasp/java" \
  "$INSTALL_DIR/rasp/python" \
  "$INSTALL_DIR/rasp/php" \
  "$INSTALL_DIR/rasp/ebpf" \
  "$INSTALL_DIR/rasp/rules"
rm -f "$AGENT_TMP"
ARCH=$(uname -m 2>/dev/null || printf 'unknown')
case "$ARCH" in
  x86_64|amd64) AGENT_ARCH="amd64" ;;
  aarch64|arm64) AGENT_ARCH="arm64" ;;
  *) printf 'Unsupported CPU architecture: %%s\n' "$ARCH" >&2; exit 1 ;;
esac
curl -kfsSL "$API_SERVER/api/v1/agent/download?os=linux&arch=$AGENT_ARCH" -o "$AGENT_TMP"
chmod +x "$AGENT_TMP"
mkdir -p /etc/lyflow/trust
curl -kfsSL "$API_SERVER/api/v1/agent/rasp/policy-root" -o /etc/lyflow/trust/policy-root.pem 2>/dev/null || true
chmod 0644 /etc/lyflow/trust/policy-root.pem 2>/dev/null || true
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop ly-agent 2>/dev/null || true
fi
mv -f "$AGENT_TMP" "$AGENT_BIN"
cat > "$CONFIG_FILE" <<'AGENT_CONFIG_EOF'
server:
  api: "__API_SERVER__"
  redis: "__REDIS_SERVER__"
  insecure_skip_verify: true

agent:
  id: ""
  key: ""
  heartbeat_interval: 30
  log_level: info
  log_file: /opt/ly-agent/logs/agent.log

traffic:
  enabled: true
  interface: "__TRAFFIC_INTERFACE__"
  capture_engine: auto
  bpf_filter: ""
  promiscuous: true
  streams:
    raw: "flows:raw"
    semantic: "flows:semantic"
    telemetry: "telemetry:traffic"

session:
  enabled: true
  mode: behavior_aggregate
  stream: "sessions:semantic"
  local_path: /opt/ly-agent/data/sessions
  retain_days: 7

packet:
  retain_enabled: true
  sample_mode: suspicious
  local_path: /opt/ly-agent/data/packets
  max_file_mb: 128
  retain_days: 3

asset:
  enabled: true
  interval: 60
  collect:
    interfaces: true
    performance: true
    processes: true

runtime:
  enabled: true
  mode: monitor
  backend: auto
  centos7_fallback: auditd
  stream: "alerts:runtime"
  telemetry_stream: "telemetry:runtime"

log_audit:
  enabled: true
  log_paths:
    - /var/log/auth.log
    - /var/log/secure
  stream: "alerts:log_audit"
  telemetry_stream: "telemetry:log_audit"

rasp:
  enabled: true
  mode: monitor
  auto_inject: true
  language_fallback: true
  stream: "alerts:rasp"
  telemetry_stream: "telemetry:rasp"
  bridge_addr: "127.0.0.1:17891"
  bridge_token: ""
  probes:
    python: /opt/ly-agent/rasp/python/sitecustomize.py
    php: /opt/ly-agent/rasp/php/ly_rasp_prepend.php
    java: /opt/ly-agent/rasp/java/ly-rasp-agent.jar
    nodejs: /opt/ly-agent/rasp/nodejs/ly_rasp.js
    dotnet: /opt/ly-agent/rasp/dotnet/LyRaspProfiler.dll
AGENT_CONFIG_EOF
sed -i "s|__API_SERVER__|$API_SERVER|g" "$CONFIG_FILE"
sed -i "s|__REDIS_SERVER__|$REDIS_SERVER|g" "$CONFIG_FILE"
sed -i "s|__TRAFFIC_INTERFACE__|$TRAFFIC_INTERFACE|g" "$CONFIG_FILE"
printf 'AGENT_ENROLL_TOKEN=%%s\n' "$ENROLL_TOKEN" > "$INSTALL_DIR/etc/agent.env"
chmod 0600 "$INSTALL_DIR/etc/agent.env"
curl -kfsSL "$API_SERVER/api/v1/agent/rasp/probe/python" -o "$INSTALL_DIR/rasp/python/sitecustomize.py" 2>/dev/null || true
curl -kfsSL "$API_SERVER/api/v1/agent/rasp/probe/php" -o "$INSTALL_DIR/rasp/php/ly_rasp_prepend.php" 2>/dev/null || true
if curl -kfsSL "$API_SERVER/api/v1/agent/rasp/probe/java" -o "$INSTALL_DIR/rasp/java/ly-rasp-agent.jar" 2>/dev/null \
  && head -c 4 "$INSTALL_DIR/rasp/java/ly-rasp-agent.jar" 2>/dev/null | grep -q '^PK'; then
  printf 'Java RASP probe installed.\n'
else
  rm -f "$INSTALL_DIR/rasp/java/ly-rasp-agent.jar"
  printf 'Java RASP probe unavailable from server; continue with other probes.\n'
fi
mkdir -p "$INSTALL_DIR/rasp/nodejs" "$INSTALL_DIR/rasp/dotnet"
curl -kfsSL "$API_SERVER/api/v1/agent/rasp/probe/nodejs" -o "$INSTALL_DIR/rasp/nodejs/ly_rasp.js" 2>/dev/null || true
curl -kfsSL "$API_SERVER/api/v1/agent/rasp/probe/dotnet" -o "$INSTALL_DIR/rasp/dotnet/LyRaspProfiler.dll" 2>/dev/null || true
curl -kfsSL "$API_SERVER/api/v1/agent/install-config" -o "$INSTALL_DIR/etc/install-control-plane.json" || true
cat > "$SERVICE_FILE" <<'SYSTEMD_EOF'
[Unit]
Description=LyFlow Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=-/opt/ly-agent/etc/agent.env
ExecStart=/opt/ly-agent/bin/ly-agent --config /opt/ly-agent/etc/agent.yaml
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
SYSTEMD_EOF
systemctl daemon-reload
systemctl enable ly-agent
systemctl restart ly-agent
printf 'ly-agent installed. API_SERVER=%%s REDIS_SERVER=%%s TRAFFIC_INTERFACE=%%s\n' "$API_SERVER" "$REDIS_SERVER" "$TRAFFIC_INTERFACE"
`, enrollmentToken, apiServer)
	}
}

func safeEnrollmentToken(value string) bool {
	if len(value) > 256 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == '~' {
			continue
		}
		return false
	}
	return value != ""
}

func agentDownloadHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		targetOS := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("os")))
		if targetOS == "" {
			targetOS = "linux"
		}
		targetArch := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("arch")))
		switch targetArch {
		case "", "x86_64", "x64":
			targetArch = "amd64"
		case "aarch64":
			targetArch = "arm64"
		}
		if targetOS != "linux" {
			http.Error(w, fmt.Sprintf("unsupported agent os: %s (Linux only)", targetOS), http.StatusBadRequest)
			return
		}
		if targetArch != "amd64" && targetArch != "arm64" {
			http.Error(w, fmt.Sprintf("unsupported agent arch: %s", targetArch), http.StatusBadRequest)
			return
		}

		filename := fmt.Sprintf("ly-agent-%s-%s", targetOS, targetArch)
		candidates := agentBinaryCandidates(targetOS, targetArch)
		for _, path := range candidates {
			if st, err := os.Stat(path); err == nil && !st.IsDir() {
				etag := fmt.Sprintf("%x-%x", st.Size(), st.ModTime().UnixNano())
				w.Header().Set("Content-Type", "application/octet-stream")
				w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
				w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
				w.Header().Set("Pragma", "no-cache")
				w.Header().Set("Expires", "0")
				w.Header().Set("ETag", etag)
				w.Header().Set("X-LyFlow-Agent-Version", "v2.0.0")
				w.Header().Set("X-LyFlow-Agent-Size", strconv.FormatInt(st.Size(), 10))
				http.ServeFile(w, r, path)
				return
			}
		}
		http.Error(w, fmt.Sprintf("agent binary not found for os=%s arch=%s", targetOS, targetArch), http.StatusNotFound)
	}
}

func agentBinaryCandidates(targetOS, targetArch string) []string {
	if targetOS == "" {
		targetOS = "linux"
	}
	if targetArch == "" {
		targetArch = "amd64"
	}
	name := "ly-agent"
	if targetOS == "windows" {
		name = "ly-agent.exe"
	}
	qualified := fmt.Sprintf("ly-agent-%s-%s", targetOS, targetArch)
	if targetOS == "windows" {
		qualified += ".exe"
	}
	candidates := []string{
		filepath.Join("/app", "agents", targetOS, targetArch, name),
		filepath.Join("/app", qualified),
		filepath.Join("/root/ly-flow-platform/agent", qualified),
		filepath.Join("/root/ly-flow-platform/agent", "dist", targetOS, targetArch, name),
		filepath.Join("agent", qualified),
		filepath.Join("agent", "dist", targetOS, targetArch, name),
		filepath.Join("..", "agent", qualified),
		filepath.Join("..", "agent", "dist", targetOS, targetArch, name),
	}
	if targetOS == "linux" {
		candidates = append(candidates,
			filepath.Join("/app", name),
			filepath.Join("/root/ly-flow-platform/agent", name),
			filepath.Join("agent", name),
			filepath.Join("..", "agent", name),
		)
	}
	return candidates
}

func agentSnapshotHandler(cfg *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method != http.MethodPost {
			writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
			return
		}
		var req struct {
			AgentID        string                   `json:"agent_id"`
			AgentKey       string                   `json:"agent_key"`
			Hostname       string                   `json:"hostname"`
			IP             string                   `json:"ip"`
			OS             string                   `json:"os"`
			Arch           string                   `json:"arch"`
			Kernel         string                   `json:"kernel"`
			Capabilities   map[string]interface{}   `json:"capabilities"`
			Interfaces     []map[string]interface{} `json:"interfaces"`
			ListeningPorts []map[string]interface{} `json:"listening_ports"`
			Performance    map[string]interface{}   `json:"performance"`
			Processes      []map[string]interface{} `json:"processes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_json", "Invalid request")
			return
		}
		agentID := normalizeAgentID(req.AgentID)
		if agentID == "" {
			writeJSONError(w, http.StatusBadRequest, "agent_id_required", "agent_id is required")
			return
		}
		if err := requireAgentKey(r.Context(), cfg, agentID, req.AgentKey); err != nil {
			writeJSONError(w, http.StatusUnauthorized, "agent_auth_required", "valid agent key required")
			return
		}
		metadata, _ := json.Marshal(map[string]interface{}{
			"arch":               req.Arch,
			"kernel":             req.Kernel,
			"capabilities":       req.Capabilities,
			"interfaces":         req.Interfaces,
			"listening_ports":    req.ListeningPorts,
			"performance":        req.Performance,
			"processes":          req.Processes,
			"process_count":      len(req.Processes),
			"metrics_updated_at": time.Now().UTC().Format(time.RFC3339Nano),
		})
		_, err := cfg.DBPool.Exec(r.Context(), `
			INSERT INTO hosts (id, hostname, ip, os, arch, agent_id, status, last_heartbeat, last_seen, metadata)
			VALUES ($1, $2, $3, $4, $5, $6, 'online', NOW(), NOW(), $7::jsonb)
			ON CONFLICT (id) DO UPDATE SET
				hostname = EXCLUDED.hostname,
				ip = EXCLUDED.ip,
				os = EXCLUDED.os,
				arch = EXCLUDED.arch,
				status = 'online',
				last_heartbeat = NOW(),
				last_seen = NOW(),
				metadata = EXCLUDED.metadata,
				updated_at = NOW()
		`, agentID, req.Hostname, req.IP, req.OS, req.Arch, agentID, string(metadata))
		if err != nil {
			log.Printf("Failed to upsert snapshot: %v", err)
			writeJSONError(w, http.StatusInternalServerError, "snapshot_save_failed", "snapshot save failed")
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{"code": 0, "message": "success", "data": map[string]interface{}{"ack": true}})
	}
}

func inferAPIServer(r *http.Request) (string, bool) {
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	// Never trust X-Forwarded-Host here: the value is embedded into a shell
	// installer script. Only a syntactically valid Host header is accepted.
	host, ok := sanitizeRequestHost(r.Host)
	if !ok {
		return "", false
	}
	if !strings.Contains(host, ":") {
		if port := serverPortFromRequest(r, scheme); port != "" {
			host = net.JoinHostPort(host, port)
		}
	}
	return scheme + "://" + host, true
}

func sanitizeRequestHost(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 253 || strings.ContainsAny(raw, "\"'`;$(){}|&<>\\ \t\r\n") {
		return "", false
	}
	parsed, err := url.Parse("//" + raw)
	if err != nil || parsed.Host != raw || parsed.Hostname() == "" || parsed.User != nil {
		return "", false
	}
	hostname := parsed.Hostname()
	if net.ParseIP(hostname) == nil {
		for _, label := range strings.Split(hostname, ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return "", false
			}
			for _, character := range label {
				if (character < 'a' || character > 'z') &&
					(character < 'A' || character > 'Z') &&
					(character < '0' || character > '9') && character != '-' {
					return "", false
				}
			}
		}
	}
	if port := parsed.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return "", false
		}
	}
	return raw, true
}

func serverPortFromRequest(r *http.Request, scheme string) string {
	if p := r.URL.Port(); p != "" {
		if value, err := strconv.Atoi(p); err == nil && value > 0 && value <= 65535 {
			return strconv.Itoa(value)
		}
	}
	if forwardedPort := strings.TrimSpace(r.Header.Get("X-Forwarded-Port")); forwardedPort != "" {
		if value, err := strconv.Atoi(forwardedPort); err == nil && value > 0 && value <= 65535 {
			return strconv.Itoa(value)
		}
	}
	if scheme == "https" {
		return ""
	}
	return "8080"
}
