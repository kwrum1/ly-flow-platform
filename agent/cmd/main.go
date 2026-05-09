package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"ly-flow-platform/agent/agentcenter/pb"
)

var (
	version = "v1.0.0"
	commit  = "dev"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("ly-agent %s (%s) starting...", version, commit)

	agentID := os.Getenv("AGENT_ID")
	agentKey := os.Getenv("AGENT_KEY")
	agentCenterAddr := os.Getenv("AGENT_CENTER_ADDR")
	if agentCenterAddr == "" {
		agentCenterAddr = "agentcenter:50051"
	}

	hostname, _ := os.Hostname()
	addrs, _ := net.LookupHost(hostname)
	var ip string
	if len(addrs) > 0 {
		ip = addrs[0]
	} else {
		ifaces, _ := net.Interfaces()
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback == 0 {
				continue
			}
			addrs, _ := iface.Addrs()
			for _, addr := range addrs {
				if v4, ok := addr.(*net.IPNet); ok && v4.IP.To4() != nil {
					ip = v4.IP.String()
					break
				}
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn, err := grpc.Dial(agentCenterAddr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
	if err != nil {
		log.Fatalf("Failed to connect to AgentCenter at %s: %v", agentCenterAddr, err)
	}
	defer conn.Close()

	client := pb.NewAgentServiceClient(conn)

	if agentID == "" || agentKey == "" {
		// Enroll
		log.Printf("[agent] Enrolling with AgentCenter at %s", agentCenterAddr)
		enrollResp, err := client.Enroll(ctx, &pb.EnrollRequest{
			Hostname: hostname,
			Ip:       ip,
			Os:       runtime.GOOS,
			Version:  version,
			Capabilities: map[string]string{
				"rasp":      "true",
				"ebpf":      "true",
				"collector": "true",
			},
			Metadata: map[string]string{
				"commit": commit,
			},
		})
		if err != nil {
			log.Fatalf("[agent] Enroll failed: %v", err)
		}
		agentID = enrollResp.AgentId
		agentKey = enrollResp.AgentKey
		log.Printf("[agent] Enrolled: agent_id=%s", agentID)
		log.Printf("[agent] Store these credentials: AGENT_ID=%s AGENT_KEY=%s", agentID, agentKey)
	} else {
		log.Printf("[agent] Resuming with agent_id=%s", agentID)
	}

	// Start heartbeat loop
	go heartbeatLoop(ctx, client, agentID, agentKey)

	// Block until signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	log.Println("[agent] Shutdown signal received")
	cancel()
}

func heartbeatLoop(ctx context.Context, client pb.AgentServiceClient, agentID, agentKey string) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			heartbeatResp, err := client.Heartbeat(ctx, &pb.HeartbeatRequest{
				AgentId: agentID,
				Status:  "running",
				Metrics: &pb.AgentMetrics{
					CpuPercent:    0,
					MemoryBytes:   0,
					NetworkRxBytes: 0,
					NetworkTxBytes: 0,
					EventsSent:    0,
					EventsDropped: 0,
				},
				EventIds: []string{},
			})
			if err != nil {
				log.Printf("[agent] Heartbeat failed: %v", err)
				continue
			}
			log.Printf("[agent] Heartbeat ack=%v, pending_tasks=%d", heartbeatResp.Ack, len(heartbeatResp.PendingTasks))
			if heartbeatResp.ConfigUpdate != nil {
				log.Printf("[agent] Config update received")
			}
		}
	}
}