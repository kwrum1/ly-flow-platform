package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentcenter/pb"
	"github.com/lyflow/ly-flow-platform/server/agentidentity"
	"github.com/lyflow/ly-flow-platform/server/ingestionauth"
	"github.com/lyflow/ly-flow-platform/server/internal/redisconfig"
	"github.com/lyflow/ly-flow-platform/server/models"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	enrollmentTokenMetadata = "x-agent-enrollment-token"
	authorizationMetadata   = "authorization"
	agentIDMetadata         = "x-lyflow-agent-id"
	maxGRPCMessageBytes     = 1 << 20
)

type Config struct {
	GRPCPort    int
	DBHost      string
	DBPort      int
	DBUser      string
	DBPassword  string
	DBName      string
	RedisAddr   string
	AgentID     string
	EnrollToken string
}

type AgentServer struct {
	pb.UnimplementedAgentServiceServer
	config     *Config
	grpcServer *grpc.Server
	redis      *redis.Client
	db         agentDB
	identity   *agentidentity.Manager
	authn      *ingestionauth.Authenticator
	authOnce   sync.Once
	agentsMu   sync.RWMutex
	agents     map[string]*AgentSession
}

type agentDB interface {
	CreateAgent(context.Context, *models.Agent) error
	UpdateAgentHeartbeat(context.Context, string) error
	GetAgentByUUID(context.Context, string) (*models.Agent, error)
}

type AgentSession struct {
	ID       string
	Hostname string
	IP       string
	LastSeen time.Time
	Config   *pb.AgentConfig
}

func main() {
	// 加载配置
	config := loadConfig()

	// 初始化
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", config.DBUser, config.DBPassword, config.DBHost, config.DBPort, config.DBName)
	db, err := models.NewDB(context.Background(), dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close(context.Background())

	redisClient := redis.NewClient(redisconfig.Options(config.RedisAddr, 0))
	defer redisClient.Close()
	identityStore := agentidentity.NewPostgresStore(db.Pool())
	if err := identityStore.EnsureSchema(context.Background()); err != nil {
		log.Fatalf("Failed to initialize Agent identity schema: %v", err)
	}
	ingestionAudit := ingestionauth.NewPostgresAudit(db.Pool())
	if err := ingestionAudit.EnsureSchema(context.Background()); err != nil {
		log.Fatalf("Failed to initialize Agent ingestion audit schema: %v", err)
	}

	server := &AgentServer{
		config:   config,
		redis:    redisClient,
		db:       db,
		identity: agentidentity.NewPersistentManager(identityStore, identityStore, time.Now),
		agents:   make(map[string]*AgentSession),
	}
	server.authn = newGRPCAuthenticator(server.identity, ingestionAudit)
	if config.AgentID != "" && config.EnrollToken != "" {
		if err := server.identity.RegisterEnrollmentToken(config.AgentID, config.EnrollToken, 15*time.Minute); err != nil {
			log.Fatalf("Invalid agent enrollment token configuration: %v", err)
		}
	}

	// 创建 gRPC 服务器
	server.grpcServer = grpc.NewServer(grpc.MaxRecvMsgSize(maxGRPCMessageBytes), grpc.MaxSendMsgSize(maxGRPCMessageBytes))
	pb.RegisterAgentServiceServer(server.grpcServer, server)

	// 监听
	addr := fmt.Sprintf(":%d", config.GRPCPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("AgentCenter listening on %s", addr)

	// 优雅关闭
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("Shutting down...")
		server.grpcServer.GracefulStop()
	}()

	// 启动 gRPC 服务
	if err := server.grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

// Enroll Agent 注册
func (s *AgentServer) Enroll(ctx context.Context, req *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	log.Printf("Agent enroll: hostname=%s, ip=%s, os=%s", req.Hostname, req.Ip, req.Os)
	if s.identity == nil {
		return nil, status.Error(codes.FailedPrecondition, "agent identity service unavailable")
	}
	token, err := incomingMetadataValue(ctx, enrollmentTokenMetadata)
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "valid enrollment token required")
	}
	agentKey, err := generateAgentKey(rand.Reader)
	if err != nil {
		return nil, status.Error(codes.Internal, "agent credential generation failed")
	}
	record, err := s.identity.EnrollContext(ctx, token, agentKey, agentidentity.EnabledTransports{GRPC: true})
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, "valid enrollment token required")
	}
	agentID := record.ID().String()

	// 存储到数据库
	agent := &models.Agent{
		UUID:         agentID,
		Hostname:     req.Hostname,
		IP:           req.Ip,
		OS:           req.Os,
		AgentVersion: req.Version,
		Status:       "online",
	}

	if s.db != nil {
		if err := s.db.CreateAgent(ctx, agent); err != nil {
			return nil, status.Errorf(codes.Internal, "Failed to create agent: %v", err)
		}
	}

	defaultConfig := defaultAgentConfig()
	s.agentsMu.Lock()
	s.agents[agentID] = &AgentSession{
		ID:       agentID,
		Hostname: req.Hostname,
		IP:       req.Ip,
		LastSeen: time.Now(),
		Config:   defaultConfig,
	}
	s.agentsMu.Unlock()

	return &pb.EnrollResponse{
		AgentId:  agentID,
		AgentKey: agentKey,
		Config:   defaultConfig,
	}, nil
}

// Heartbeat Agent 心跳
func (s *AgentServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	principal, err := s.authenticate(ctx, "grpc.heartbeat")
	if err != nil {
		return nil, err
	}
	agentID, err := bindGRPCPrincipal(principal, req.AgentId)
	if err != nil {
		if auditErr := s.authenticator().RecordIdentityMismatch(ctx, principal, "grpc.heartbeat"); auditErr != nil {
			return nil, status.Error(codes.Unavailable, "agent ingestion lifecycle audit unavailable")
		}
		return nil, err
	}
	session, err := s.sessionFor(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if err := s.authenticator().Record(ctx, principal, "grpc.heartbeat", ingestionauth.OutcomeAccepted, ""); err != nil {
		return nil, status.Error(codes.Unavailable, "agent ingestion lifecycle audit unavailable")
	}
	s.agentsMu.Lock()
	session.LastSeen = time.Now()
	s.agents[agentID] = session
	config := session.Config
	s.agentsMu.Unlock()

	// 更新数据库状态
	if s.db != nil {
		if err := s.db.UpdateAgentHeartbeat(ctx, agentID); err != nil {
			log.Printf("Failed to update heartbeat: %v", err)
		}
	}

	// 获取待执行任务
	pendingTasks, err := s.getPendingTasks(ctx, agentID)
	if err != nil {
		log.Printf("Failed to get pending tasks: %v", err)
	}

	response := &pb.HeartbeatResponse{
		Ack:          true,
		PendingTasks: pendingTasks,
		ConfigUpdate: config,
	}
	return response, nil
}

// GetConfig 获取配置
func (s *AgentServer) GetConfig(ctx context.Context, req *pb.GetConfigRequest) (*pb.GetConfigResponse, error) {
	principal, err := s.authenticate(ctx, "grpc.config")
	if err != nil {
		return nil, err
	}
	agentID, err := bindGRPCPrincipal(principal, req.AgentId)
	if err != nil {
		if auditErr := s.authenticator().RecordIdentityMismatch(ctx, principal, "grpc.config"); auditErr != nil {
			return nil, status.Error(codes.Unavailable, "agent ingestion lifecycle audit unavailable")
		}
		return nil, err
	}
	session, err := s.sessionFor(ctx, agentID)
	if err != nil {
		return nil, err
	}
	if err := s.authenticator().Record(ctx, principal, "grpc.config", ingestionauth.OutcomeAccepted, ""); err != nil {
		return nil, status.Error(codes.Unavailable, "agent ingestion lifecycle audit unavailable")
	}

	response := &pb.GetConfigResponse{
		Config: session.Config,
	}
	return response, nil
}

// ReportTaskResult 上报任务结果
func (s *AgentServer) ReportTaskResult(ctx context.Context, req *pb.TaskResultRequest) (*pb.TaskResultResponse, error) {
	principal, err := s.authenticate(ctx, "grpc.task-result")
	if err != nil {
		return nil, err
	}
	agentID, err := bindGRPCPrincipal(principal, req.AgentId)
	if err != nil {
		if auditErr := s.authenticator().RecordIdentityMismatch(ctx, principal, "grpc.task-result"); auditErr != nil {
			return nil, status.Error(codes.Unavailable, "agent ingestion lifecycle audit unavailable")
		}
		return nil, err
	}
	if _, err := s.sessionFor(ctx, agentID); err != nil {
		return nil, err
	}
	if err := s.authenticator().Record(ctx, principal, "grpc.task-result", ingestionauth.OutcomeAccepted, ""); err != nil {
		return nil, status.Error(codes.Unavailable, "agent ingestion lifecycle audit unavailable")
	}
	log.Printf("Task result: agent=%s, task=%s, success=%v", agentID, req.TaskId, req.Success)

	// Task persistence is not wired in the current DB model; acknowledge receipt so
	// agent control-plane builds until the task store is implemented.

	return &pb.TaskResultResponse{Ack: true}, nil
}

// getPendingTasks 获取待执行任务
func (s *AgentServer) getPendingTasks(ctx context.Context, agentID string) ([]*pb.Task, error) {
	return []*pb.Task{}, nil
}

func generateAgentKey(reader io.Reader) (string, error) {
	raw := make([]byte, 32)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return "", fmt.Errorf("read credential entropy: %w", err)
	}
	return "key-" + hex.EncodeToString(raw), nil
}

func (s *AgentServer) authenticate(ctx context.Context, surface string) (ingestionauth.Principal, error) {
	authenticator := s.authenticator()
	authorization, err := incomingMetadataValue(ctx, authorizationMetadata)
	if err != nil || !strings.HasPrefix(authorization, "Bearer ") {
		if _, auditErr := authenticator.Authenticate(ctx, "", "", agentidentity.TransportGRPC, surface); ingestionauth.IsAuditUnavailable(auditErr) {
			return ingestionauth.Principal{}, status.Error(codes.Unavailable, "agent ingestion lifecycle audit unavailable")
		}
		return ingestionauth.Principal{}, status.Error(codes.Unauthenticated, "valid agent credential required")
	}
	agentID, err := incomingMetadataValue(ctx, agentIDMetadata)
	if err != nil {
		if _, auditErr := authenticator.Authenticate(ctx, "", "", agentidentity.TransportGRPC, surface); ingestionauth.IsAuditUnavailable(auditErr) {
			return ingestionauth.Principal{}, status.Error(codes.Unavailable, "agent ingestion lifecycle audit unavailable")
		}
		return ingestionauth.Principal{}, status.Error(codes.Unauthenticated, "valid agent credential required")
	}
	credential := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
	principal, err := authenticator.Authenticate(ctx, agentID, credential, agentidentity.TransportGRPC, surface)
	if ingestionauth.IsAuditUnavailable(err) {
		return ingestionauth.Principal{}, status.Error(codes.Unavailable, "agent ingestion lifecycle audit unavailable")
	}
	if ingestionauth.IsRateLimited(err) {
		return ingestionauth.Principal{}, status.Error(codes.ResourceExhausted, "agent rate limit exceeded")
	}
	if err != nil {
		return ingestionauth.Principal{}, status.Error(codes.Unauthenticated, "valid agent credential required")
	}
	return principal, nil
}

func (s *AgentServer) authenticator() *ingestionauth.Authenticator {
	s.authOnce.Do(func() {
		if s.authn == nil {
			s.authn = newGRPCAuthenticator(s.identity, ingestionauth.NewMemoryAudit())
		}
	})
	return s.authn
}

func bindGRPCPrincipal(principal ingestionauth.Principal, payloadAgentID string) (string, error) {
	agentID, err := principal.BindPayloadAgentID(payloadAgentID)
	if err != nil {
		return "", status.Error(codes.PermissionDenied, "payload Agent identity conflicts with authenticated principal")
	}
	return agentID, nil
}

func newGRPCAuthenticator(manager *agentidentity.Manager, audit ingestionauth.Audit) *ingestionauth.Authenticator {
	return ingestionauth.New(manager, audit, time.Now, 120, time.Minute)
}

func newAgentServerForTest(manager *agentidentity.Manager, agents map[string]*AgentSession) *AgentServer {
	return &AgentServer{identity: manager, authn: newGRPCAuthenticator(manager, ingestionauth.NewMemoryAudit()), agents: agents}
}

func incomingMetadataValue(ctx context.Context, key string) (string, error) {
	values := metadata.ValueFromIncomingContext(ctx, key)
	if len(values) != 1 || strings.TrimSpace(values[0]) == "" {
		return "", fmt.Errorf("metadata %s required", key)
	}
	return strings.TrimSpace(values[0]), nil
}

func (s *AgentServer) sessionFor(ctx context.Context, agentID string) (*AgentSession, error) {
	s.agentsMu.RLock()
	session, ok := s.agents[agentID]
	s.agentsMu.RUnlock()
	if ok {
		return session, nil
	}
	if s.db == nil {
		return nil, status.Error(codes.NotFound, "Agent not found")
	}
	agent, err := s.db.GetAgentByUUID(ctx, agentID)
	if err != nil {
		return nil, status.Error(codes.NotFound, "Agent not found")
	}
	session = &AgentSession{
		ID:       agent.UUID,
		Hostname: agent.Hostname,
		IP:       agent.IP,
		LastSeen: agent.LastHeartbeat,
		Config:   defaultAgentConfig(),
	}
	return session, nil
}

func defaultAgentConfig() *pb.AgentConfig {
	return &pb.AgentConfig{
		TrafficAnalysisEnabled:   true,
		LogAuditEnabled:          true,
		EndpointDetectionEnabled: true,
		RaspEnabled:              true,
		HeartbeatInterval:        30,
		ReportInterval:           60,
	}
}

func loadConfig() *Config {
	viper.SetDefault("grpc_port", 8081)
	viper.SetDefault("db_host", "postgres")
	viper.SetDefault("db_port", 5432)
	viper.SetDefault("db_user", "lyflow")
	viper.SetDefault("db_password", "lyflow_secret_password")
	viper.SetDefault("db_name", "lyflow")
	viper.SetDefault("redis_addr", "redis:6379")

	viper.AutomaticEnv()

	return &Config{
		GRPCPort:    viper.GetInt("grpc_port"),
		DBHost:      viper.GetString("db_host"),
		DBPort:      viper.GetInt("db_port"),
		DBUser:      viper.GetString("db_user"),
		DBPassword:  viper.GetString("db_password"),
		DBName:      viper.GetString("db_name"),
		RedisAddr:   viper.GetString("redis_addr"),
		AgentID:     viper.GetString("agent_id"),
		EnrollToken: viper.GetString("agent_enroll_token"),
	}
}
