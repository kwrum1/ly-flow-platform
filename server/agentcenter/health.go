package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentcenter/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	defaultAgentCenterGRPCPort = 8081
	healthcheckTimeout         = 3 * time.Second
)

type agentCenterGRPCServer struct {
	grpcServer   *grpc.Server
	healthServer *health.Server
	shutdownOnce sync.Once
}

func newAgentCenterGRPCServer(agentServer *AgentServer) *agentCenterGRPCServer {
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(maxGRPCMessageBytes),
		grpc.MaxSendMsgSize(maxGRPCMessageBytes),
	)
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_NOT_SERVING)
	healthServer.SetServingStatus(pb.AgentService_ServiceDesc.ServiceName, healthgrpc.HealthCheckResponse_NOT_SERVING)
	pb.RegisterAgentServiceServer(grpcServer, agentServer)
	healthgrpc.RegisterHealthServer(grpcServer, healthServer)
	agentServer.grpcServer = grpcServer

	return &agentCenterGRPCServer{
		grpcServer:   grpcServer,
		healthServer: healthServer,
	}
}

func (s *agentCenterGRPCServer) Serve(listener net.Listener) error {
	s.healthServer.SetServingStatus("", healthgrpc.HealthCheckResponse_SERVING)
	s.healthServer.SetServingStatus(pb.AgentService_ServiceDesc.ServiceName, healthgrpc.HealthCheckResponse_SERVING)
	return s.grpcServer.Serve(listener)
}

func (s *agentCenterGRPCServer) Shutdown() {
	s.shutdownOnce.Do(func() {
		s.healthServer.Shutdown()
		s.grpcServer.GracefulStop()
	})
}

func agentCenterHealthcheckAddress() (string, error) {
	port := defaultAgentCenterGRPCPort
	if rawPort, configured := os.LookupEnv("GRPC_PORT"); configured {
		parsedPort, err := strconv.Atoi(rawPort)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return "", fmt.Errorf("healthcheck GRPC_PORT %q is invalid", rawPort)
		}
		port = parsedPort
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
}

func checkAgentCenterHealth(ctx context.Context, address string) error {
	checkContext, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()

	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("create AgentCenter health client: %w", err)
	}

	response, err := healthgrpc.NewHealthClient(connection).Check(checkContext, &healthgrpc.HealthCheckRequest{})
	closeErr := connection.Close()
	if err != nil {
		return errors.Join(fmt.Errorf("check AgentCenter health: %w", err), closeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close AgentCenter health client: %w", closeErr)
	}
	if response.GetStatus() != healthgrpc.HealthCheckResponse_SERVING {
		return fmt.Errorf("AgentCenter health status is %s", response.GetStatus())
	}
	return nil
}
