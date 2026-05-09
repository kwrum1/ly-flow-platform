package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ly-flow-platform/server/agentcenter/pb"
	"ly-flow-platform/server/models"

	"github.com/redis/go-redis/v9"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type Config struct {
	GRPCPort    int
	DBHost      string
	DBPort      int
	DBUser      string
	DBPassword  string
	DBName      string
	RedisAddr   string
	RedisPass   string
}

type AgentServer struct {
	pb.UnimplementedAgentServiceServer
	config     *Config
	grpcServer *grpc.Server
	redis      *redis.Client
	db         *models.DB
	agents     map[string]*AgentSession
}

type AgentSession struct {
	ID        string
	Key       string
	Hostname  string
	IP        string
	LastSeen  time.Time
	Config    *pb.AgentConfig
}

func main() {
	// 加载配置
	config := loadConfig()

	// 初始化
	db, err := models.NewDB(config.DBHost, config.DBPort, config.DBUser, config.DBPassword, config.DBName)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	redisClient := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPass,
	})
	defer redisClient.Close()

	server := &AgentServer{
		config:  config,
		redis:  redisClient,
		db:     db,
		agents: make(map[string]*AgentSession),
	}

	// 创建 gRPC 服务器
	server.grpcServer = grpc.NewServer()
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

	// 生成 Agent ID 和 Key
	agentID := generateAgentID()
	agentKey := generateAgentKey()

	// 存储到数据库
	agent := &models.Agent{
		UUID:     agentID,
		Hostname: req.Hostname,
		IP:       req.Ip,
		OS:       req.Os,
		Version:  req.Version,
		Status:   "online",
	}

	if err := s.db.CreateAgent(ctx, agent); err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to create agent: %v", err)
	}

	// 存储到内存
	s.agents[agentID] = &AgentSession{
		ID:       agentID,
		Key:      agentKey,
		Hostname: req.Hostname,
		IP:       req.Ip,
		LastSeen: time.Now(),
	}

	// 默认配置
	defaultConfig := &pb.AgentConfig{
		TrafficAnalysisEnabled:   true,
		LogAuditEnabled:          true,
		EndpointDetectionEnabled: true,
		RaspEnabled:              false,
		HeartbeatInterval:        30,
		ReportInterval:           60,
	}

	return &pb.EnrollResponse{
		AgentId:   agentID,
		AgentKey:  agentKey,
		Config:    defaultConfig,
	}, nil
}

// Heartbeat Agent 心跳
func (s *AgentServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	session, ok := s.agents[req.AgentId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Agent not found")
	}

	session.LastSeen = time.Now()

	// 更新数据库状态
	if err := s.db.UpdateAgentHeartbeat(ctx, req.AgentId); err != nil {
		log.Printf("Failed to update heartbeat: %v", err)
	}

	// 获取待执行任务
	pendingTasks, err := s.getPendingTasks(ctx, req.AgentId)
	if err != nil {
		log.Printf("Failed to get pending tasks: %v", err)
	}

	return &pb.HeartbeatResponse{
		Ack:          true,
		PendingTasks:  pendingTasks,
		ConfigUpdate:  session.Config,
	}, nil
}

// GetConfig 获取配置
func (s *AgentServer) GetConfig(ctx context.Context, req *pb.GetConfigRequest) (*pb.GetConfigResponse, error) {
	session, ok := s.agents[req.AgentId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "Agent not found")
	}

	return &pb.GetConfigResponse{
		Config: session.Config,
	}, nil
}

// ReportTaskResult 上报任务结果
func (s *AgentServer) ReportTaskResult(ctx context.Context, req *pb.TaskResultRequest) (*pb.TaskResultResponse, error) {
	log.Printf("Task result: agent=%s, task=%s, success=%v", req.AgentId, req.TaskId, req.Success)

	// 更新任务状态
	if err := s.db.UpdateTaskResult(ctx, req.AgentId, req.TaskId, req.Success, req.Result, req.Error); err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to update task result: %v", err)
	}

	return &pb.TaskResultResponse{Ack: true}, nil
}

// getPendingTasks 获取待执行任务
func (s *AgentServer) getPendingTasks(ctx context.Context, agentID string) ([]*pb.Task, error) {
	tasks, err := s.db.GetPendingTasks(ctx, agentID)
	if err != nil {
		return nil, err
	}

	result := make([]*pb.Task, len(tasks))
	for i, task := range tasks {
		result[i] = &pb.Task{
			TaskId:   task.TaskID,
			TaskType: task.TaskType,
			Params:   task.Params,
			Deadline: task.Deadline,
		}
	}

	return result, nil
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
		GRPCPort:   viper.GetInt("grpc_port"),
		DBHost:     viper.GetString("db_host"),
		DBPort:     viper.GetInt("db_port"),
		DBUser:     viper.GetString("db_user"),
		DBPassword: viper.GetString("db_password"),
		DBName:     viper.GetString("db_name"),
		RedisAddr:  viper.GetString("redis_addr"),
		RedisPass:  viper.GetString("redis_password"),
	}
}
