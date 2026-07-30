package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lyflow/ly-flow-platform/server/agentcenter/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

const (
	healthcheckHelperEnv = "LYFLOW_AGENTCENTER_HEALTHCHECK_HELPER"
	healthTestTimeout    = 5 * time.Second
)

func TestAgentCenterHealth_servesStandardCheck(t *testing.T) {
	client, shutdown := startAgentCenterHealthServer(t)
	t.Cleanup(func() {
		if err := shutdown(); err != nil {
			t.Errorf("shutdown AgentCenter health server: %v", err)
		}
	})

	services := []struct {
		name    string
		service string
	}{
		{name: "overall", service: ""},
		{name: "AgentService", service: pb.AgentService_ServiceDesc.ServiceName},
	}
	for _, service := range services {
		t.Run(service.name, func(t *testing.T) {
			// Given
			ctx, cancel := context.WithTimeout(t.Context(), healthTestTimeout)
			defer cancel()

			// When
			response, err := client.Check(ctx, &healthgrpc.HealthCheckRequest{Service: service.service})

			// Then
			if err != nil {
				t.Fatalf("standard health Check(%q): %v", service.service, err)
			}
			if response.GetStatus() != healthgrpc.HealthCheckResponse_SERVING {
				t.Fatalf("standard health Check(%q) status = %s, want SERVING", service.service, response.GetStatus())
			}
		})
	}
}

func TestAgentCenterHealth_reportsUnknownService(t *testing.T) {
	// Given
	client, shutdown := startAgentCenterHealthServer(t)
	t.Cleanup(func() {
		if err := shutdown(); err != nil {
			t.Errorf("shutdown AgentCenter health server: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), healthTestTimeout)
	defer cancel()

	// When
	_, err := client.Check(ctx, &healthgrpc.HealthCheckRequest{Service: "lyflow.agent.v1.UnknownService"})

	// Then
	if status.Code(err) != codes.NotFound {
		t.Fatalf("unknown service status = %s, error = %v, want NotFound", status.Code(err), err)
	}
}

func TestAgentCenterHealth_shutdownInvalidatesServing(t *testing.T) {
	// Given
	client, shutdown := startAgentCenterHealthServer(t)
	t.Cleanup(func() {
		if err := shutdown(); err != nil {
			t.Errorf("shutdown AgentCenter health server: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), healthTestTimeout)
	defer cancel()
	stream, err := client.Watch(ctx, &healthgrpc.HealthCheckRequest{Service: pb.AgentService_ServiceDesc.ServiceName})
	if err != nil {
		t.Fatalf("start standard health Watch: %v", err)
	}
	initial, err := stream.Recv()
	if err != nil {
		t.Fatalf("receive initial standard health status: %v", err)
	}
	if initial.GetStatus() != healthgrpc.HealthCheckResponse_SERVING {
		t.Fatalf("initial health status = %s, want SERVING", initial.GetStatus())
	}
	shutdownDone := make(chan error, 1)

	// When
	go func() {
		shutdownDone <- shutdown()
	}()
	invalidated, err := stream.Recv()

	// Then
	if err != nil {
		t.Fatalf("receive shutdown health status: %v", err)
	}
	if invalidated.GetStatus() != healthgrpc.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("shutdown health status = %s, want NOT_SERVING", invalidated.GetStatus())
	}
	cancel()
	select {
	case shutdownErr := <-shutdownDone:
		if shutdownErr != nil {
			t.Fatalf("shutdown AgentCenter health server: %v", shutdownErr)
		}
	case <-time.After(healthTestTimeout):
		t.Fatal("AgentCenter shutdown remained blocked after health Watch cancellation")
	}
}

func TestAgentCenterHealth_checkerIsBoundedWhenEndpointUnavailable(t *testing.T) {
	if os.Getenv(healthcheckHelperEnv) == "1" {
		os.Args = []string{os.Args[0], "healthcheck"}
		main()
		return
	}

	// Given
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve unavailable health endpoint: %v", err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close unavailable health endpoint: %v", err)
		}
	})
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split unavailable health endpoint: %v", err)
	}

	// When
	output, runErr := runAgentCenterHealthcheck(t, portText)

	// Then
	if runErr == nil {
		t.Fatal("in-binary healthcheck succeeded against unavailable endpoint")
	}
	lowerOutput := strings.ToLower(string(output))
	if !strings.Contains(lowerOutput, "health") || strings.Contains(lowerOutput, "database") {
		t.Fatalf("in-binary healthcheck did not use the standard health endpoint; output: %q", string(output))
	}
}

func TestAgentCenterHealth_checkerRejectsNotServing(t *testing.T) {
	if os.Getenv(healthcheckHelperEnv) == "1" {
		os.Args = []string{os.Args[0], "healthcheck"}
		main()
		return
	}

	// Given
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for standard health server: %v", err)
	}
	server := grpc.NewServer()
	service := health.NewServer()
	service.SetServingStatus("", healthgrpc.HealthCheckResponse_NOT_SERVING)
	healthgrpc.RegisterHealthServer(server, service)
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Errorf("close standard health listener: %v", err)
		}
		if err := <-serveDone; err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			t.Errorf("serve standard health endpoint: %v", err)
		}
	})
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split standard health endpoint: %v", err)
	}

	// When
	output, runErr := runAgentCenterHealthcheck(t, portText)

	// Then
	if runErr == nil {
		t.Fatal("in-binary healthcheck accepted NOT_SERVING")
	}
	lowerOutput := strings.ToLower(string(output))
	if !strings.Contains(lowerOutput, "health") || strings.Contains(lowerOutput, "database") {
		t.Fatalf("in-binary healthcheck did not reject the standard health status; output: %q", string(output))
	}
}

func runAgentCenterHealthcheck(t *testing.T, port string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), healthTestTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAgentCenterHealth_checker")
	command.Env = []string{healthcheckHelperEnv + "=1", "GRPC_PORT=" + port}
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("in-binary healthcheck exceeded %s: %v", healthTestTimeout, ctx.Err())
	}
	return output, err
}

func startAgentCenterHealthServer(t *testing.T) (healthgrpc.HealthClient, func() error) {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	runtime := newAgentCenterGRPCServer(&AgentServer{agents: make(map[string]*AgentSession)})
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- runtime.Serve(listener)
	}()

	connection, err := grpc.NewClient(
		"passthrough:///agentcenter",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("create standard health client: %v", err)
	}
	shutdown := sync.OnceValue(func() error {
		runtime.Shutdown()
		connectionErr := connection.Close()
		listenerErr := listener.Close()
		serveErr := <-serveDone
		if errors.Is(serveErr, grpc.ErrServerStopped) || errors.Is(serveErr, net.ErrClosed) {
			serveErr = nil
		}
		return errors.Join(connectionErr, listenerErr, serveErr)
	})
	return healthgrpc.NewHealthClient(connection), shutdown
}
