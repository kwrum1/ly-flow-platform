// Package graph builds an in-memory entity graph from canonical v2 events.
// It is intentionally small and dependency-free; persistence and long-window
// lookups stay in ClickHouse/Postgres.
package graph

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lyflow/ly-flow-platform/contracts"
)

type NodeType string

const (
	NodeAsset   NodeType = "asset"
	NodeUser    NodeType = "user"
	NodeProcess NodeType = "process"
	NodeFile    NodeType = "file"
	NodeIP      NodeType = "ip"
	NodeDomain  NodeType = "domain"
)

type EdgeType string

const (
	EdgeSpawn   EdgeType = "spawn"
	EdgeWrite   EdgeType = "write"
	EdgeConnect EdgeType = "connect"
	EdgeLogin   EdgeType = "login"
	EdgeResolve EdgeType = "resolve"
)

type Node struct {
	ID    string
	Type  NodeType
	Label string
	At    time.Time
}

type Edge struct {
	From     string
	To       string
	Type     EdgeType
	EventUID string
	At       time.Time
}

type Graph struct {
	mu        sync.RWMutex
	nodes     map[string]Node
	edges     []Edge
	adjacency map[string][]Edge
	seen      map[string]struct{}
}

func New() *Graph {
	return &Graph{
		nodes:     map[string]Node{},
		adjacency: map[string][]Edge{},
		seen:      map[string]struct{}{},
	}
}

func (graph *Graph) AddEvent(event contracts.EventV2) {
	if graph == nil {
		return
	}
	graph.mu.Lock()
	defer graph.mu.Unlock()
	graph.init()

	assetID := ""
	if event.Entities.Asset != nil {
		assetID = nodeID(NodeAsset, event.Entities.Asset.ID)
		graph.addNode(Node{ID: assetID, Type: NodeAsset, Label: event.Entities.Asset.Hostname, At: event.Timestamps.EventAt})
	}
	userID := ""
	if event.Entities.User != nil {
		userID = nodeID(NodeUser, event.Entities.User.ID)
		graph.addNode(Node{ID: userID, Type: NodeUser, Label: event.Entities.User.Name, At: event.Timestamps.EventAt})
		if assetID != "" {
			graph.addEdge(Edge{From: userID, To: assetID, Type: EdgeLogin, EventUID: event.EventUID, At: event.Timestamps.EventAt})
		}
	}
	processID := ""
	if event.Entities.Process != nil {
		label := event.Entities.Process.Exe
		if label == "" {
			label = event.Entities.Process.Cmdline
		}
		key := fmt.Sprintf("%s:%d:%s", assetID, event.Entities.Process.PID, label)
		processID = nodeID(NodeProcess, key)
		graph.addNode(Node{ID: processID, Type: NodeProcess, Label: label, At: event.Timestamps.EventAt})
		if assetID != "" {
			graph.addEdge(Edge{From: assetID, To: processID, Type: EdgeSpawn, EventUID: event.EventUID, At: event.Timestamps.EventAt})
		}
	}
	if event.Entities.File != nil {
		fileKey := event.Entities.File.Hash
		if fileKey == "" {
			fileKey = event.Entities.File.Path
		}
		if fileKey != "" {
			fileID := nodeID(NodeFile, fileKey)
			graph.addNode(Node{ID: fileID, Type: NodeFile, Label: event.Entities.File.Path, At: event.Timestamps.EventAt})
			if processID != "" {
				graph.addEdge(Edge{From: processID, To: fileID, Type: EdgeWrite, EventUID: event.EventUID, At: event.Timestamps.EventAt})
			} else if assetID != "" {
				graph.addEdge(Edge{From: assetID, To: fileID, Type: EdgeWrite, EventUID: event.EventUID, At: event.Timestamps.EventAt})
			}
		}
	}
	if event.Entities.Network != nil {
		src := event.Entities.Network.SrcIP
		dst := event.Entities.Network.DstIP
		if src != "" {
			srcID := nodeID(NodeIP, src)
			graph.addNode(Node{ID: srcID, Type: NodeIP, Label: src, At: event.Timestamps.EventAt})
			if assetID != "" {
				graph.addEdge(Edge{From: assetID, To: srcID, Type: EdgeConnect, EventUID: event.EventUID, At: event.Timestamps.EventAt})
			}
		}
		if dst != "" {
			dstID := nodeID(NodeIP, dst)
			graph.addNode(Node{ID: dstID, Type: NodeIP, Label: dst, At: event.Timestamps.EventAt})
			if assetID != "" {
				graph.addEdge(Edge{From: assetID, To: dstID, Type: EdgeConnect, EventUID: event.EventUID, At: event.Timestamps.EventAt})
			}
		}
		if event.Entities.App != nil && event.Entities.App.Host != "" && dst != "" {
			domainID := nodeID(NodeDomain, event.Entities.App.Host)
			graph.addNode(Node{ID: domainID, Type: NodeDomain, Label: event.Entities.App.Host, At: event.Timestamps.EventAt})
			graph.addEdge(Edge{From: domainID, To: nodeID(NodeIP, dst), Type: EdgeResolve, EventUID: event.EventUID, At: event.Timestamps.EventAt})
		}
	}
}

func (graph *Graph) Neighbors(id string) []Edge {
	graph.mu.RLock()
	defer graph.mu.RUnlock()
	return append([]Edge(nil), graph.adjacency[id]...)
}

func (graph *Graph) Nodes() []Node {
	graph.mu.RLock()
	defer graph.mu.RUnlock()
	result := make([]Node, 0, len(graph.nodes))
	for _, node := range graph.nodes {
		result = append(result, node)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result
}

// FindPath returns a shortest edge path between two node IDs using BFS.
func (graph *Graph) FindPath(from, to string, maxDepth int) ([]Edge, bool) {
	graph.mu.RLock()
	defer graph.mu.RUnlock()
	if from == to {
		return nil, true
	}
	if maxDepth <= 0 {
		maxDepth = 6
	}
	type step struct {
		node string
		path []Edge
	}
	queue := []step{{node: from}}
	visited := map[string]struct{}{from: {}}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if len(current.path) >= maxDepth {
			continue
		}
		for _, edge := range graph.adjacency[current.node] {
			if _, exists := visited[edge.To]; exists {
				continue
			}
			nextPath := append(append([]Edge(nil), current.path...), edge)
			if edge.To == to {
				return nextPath, true
			}
			visited[edge.To] = struct{}{}
			queue = append(queue, step{node: edge.To, path: nextPath})
		}
	}
	return nil, false
}

func (graph *Graph) Components() [][]string {
	graph.mu.RLock()
	defer graph.mu.RUnlock()
	visited := map[string]struct{}{}
	components := make([][]string, 0)
	for id := range graph.nodes {
		if _, exists := visited[id]; exists {
			continue
		}
		component := []string{}
		stack := []string{id}
		visited[id] = struct{}{}
		for len(stack) > 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			component = append(component, current)
			for _, edge := range graph.adjacency[current] {
				if _, exists := visited[edge.To]; exists {
					continue
				}
				visited[edge.To] = struct{}{}
				stack = append(stack, edge.To)
			}
		}
		sort.Strings(component)
		components = append(components, component)
	}
	sort.Slice(components, func(left, right int) bool { return components[left][0] < components[right][0] })
	return components
}

func (graph *Graph) EdgeCount() int {
	graph.mu.RLock()
	defer graph.mu.RUnlock()
	return len(graph.edges)
}

func (graph *Graph) init() {
	if graph.nodes == nil {
		graph.nodes = map[string]Node{}
	}
	if graph.adjacency == nil {
		graph.adjacency = map[string][]Edge{}
	}
	if graph.seen == nil {
		graph.seen = map[string]struct{}{}
	}
}

func (graph *Graph) addNode(node Node) {
	if node.ID == "" {
		return
	}
	if _, exists := graph.nodes[node.ID]; exists {
		return
	}
	graph.nodes[node.ID] = node
}

func (graph *Graph) addEdge(edge Edge) {
	if edge.From == "" || edge.To == "" || edge.From == edge.To {
		return
	}
	key := strings.Join([]string{edge.From, edge.To, string(edge.Type), edge.EventUID}, "\x00")
	if _, exists := graph.seen[key]; exists {
		return
	}
	graph.seen[key] = struct{}{}
	graph.edges = append(graph.edges, edge)
	graph.adjacency[edge.From] = append(graph.adjacency[edge.From], edge)
}

func nodeID(nodeType NodeType, id string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	return string(nodeType) + ":" + id
}
