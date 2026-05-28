package main

import (
	"context"
	"testing"

	"github.com/lyflow/ly-flow-platform/server/agentcenter/pb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestReportTaskResultRejectsUnknownAgent(t *testing.T) {
	server := &AgentServer{agents: map[string]*AgentSession{}}
	_, err := server.ReportTaskResult(context.Background(), &pb.TaskResultRequest{AgentId: "missing", TaskId: "task-1"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound for unknown agent, got %v", err)
	}
}

func TestReportTaskResultAcceptsKnownAgent(t *testing.T) {
	server := &AgentServer{agents: map[string]*AgentSession{"agent-1": {ID: "agent-1"}}}
	resp, err := server.ReportTaskResult(context.Background(), &pb.TaskResultRequest{AgentId: "agent-1", TaskId: "task-1", Success: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil || !resp.Ack {
		t.Fatalf("expected ack response, got %#v", resp)
	}
}
