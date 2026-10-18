package agentfacade

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeProvider struct {
	name   string
	agents []Agent
	err    error
}

func (provider fakeProvider) Name() string { return provider.name }

func (provider fakeProvider) List(context.Context) ([]Agent, error) {
	return provider.agents, provider.err
}

func TestListMergesAndSorts(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	facade := New(
		fakeProvider{name: "wazuh", agents: []Agent{{SourceID: "w1", Name: "win-1", LastSeen: now.Add(-time.Minute), Status: "online"}}},
		fakeProvider{name: "elkeid", agents: []Agent{{SourceID: "e1", Name: "linux-1", LastSeen: now, Status: "online"}}},
	)
	agents, err := facade.List(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(agents) != 2 || agents[0].Provider != "elkeid" || agents[0].ID != "elkeid:e1" {
		t.Fatalf("agents = %+v", agents)
	}
}

func TestListReturnsPartialOnProviderFailure(t *testing.T) {
	facade := New(
		fakeProvider{name: "wazuh", agents: []Agent{{SourceID: "w1"}}},
		fakeProvider{name: "elkeid", err: errors.New("down")},
	)
	agents, err := facade.List(context.Background())
	if err == nil || len(agents) != 1 {
		t.Fatalf("agents=%+v err=%v", agents, err)
	}
}

func TestFilter(t *testing.T) {
	agents := []Agent{
		{ID: "wazuh:w1", Provider: "wazuh", Name: "win-1", Status: "online", Platform: "windows"},
		{ID: "elkeid:e1", Provider: "elkeid", Name: "linux-1", Status: "offline", Platform: "linux"},
	}
	if got := Filter(agents, "linux", "", ""); len(got) != 1 || got[0].ID != "elkeid:e1" {
		t.Fatalf("query filter = %+v", got)
	}
	if got := Filter(agents, "", "online", "wazuh"); len(got) != 1 || got[0].ID != "wazuh:w1" {
		t.Fatalf("status/provider filter = %+v", got)
	}
}

func TestPage(t *testing.T) {
	agents := []Agent{{ID: "1"}, {ID: "2"}, {ID: "3"}}
	if got := Page(agents, 1, 1); len(got) != 1 || got[0].ID != "2" {
		t.Fatalf("page = %+v", got)
	}
	if got := Page(agents, 10, 1); len(got) != 0 {
		t.Fatalf("out of range = %+v", got)
	}
	if got := Page(agents, -1, 0); len(got) != 3 {
		t.Fatalf("defaults = %+v", got)
	}
}
