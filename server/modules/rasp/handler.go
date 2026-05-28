package rasp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Handler struct {
	pm     *ProtectionManager
	mu     sync.RWMutex
	events []map[string]interface{}
}

func NewHandler() *Handler {
	return &Handler{events: make([]map[string]interface{}, 0, 64)}
}

func NewHandlerWithProtection(pm *ProtectionManager) *Handler {
	return &Handler{pm: pm, events: make([]map[string]interface{}, 0, 64)}
}

type HandlerStats struct {
	TotalEvents int64            `json:"total_events"`
	TodayEvents int64            `json:"today_events"`
	Blocked     int64            `json:"blocked"`
	Allowed     int64            `json:"allowed"`
	ByLanguage  map[string]int64 `json:"by_language"`
	ByAttack    map[string]int64 `json:"by_attack_type"`
	Critical    int64            `json:"critical"`
	High        int64            `json:"high"`
	Medium      int64            `json:"medium"`
	Low         int64            `json:"low"`
}

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	stats := &HandlerStats{
		ByLanguage: map[string]int64{},
		ByAttack:   map[string]int64{},
	}
	today := time.Now().Format("2006-01-02")
	for _, event := range h.events {
		stats.TotalEvents++
		if blocked, ok := event["blocked"].(bool); ok && blocked {
			stats.Blocked++
		} else {
			stats.Allowed++
		}
		severity := strings.ToLower(toString(event["severity"]))
		switch severity {
		case "critical":
			stats.Critical++
		case "high":
			stats.High++
		case "medium":
			stats.Medium++
		default:
			stats.Low++
		}
		lang := toString(event["language"])
		if lang != "" {
			stats.ByLanguage[lang]++
		}
		attack := toString(event["attack_type"])
		if attack != "" {
			stats.ByAttack[attack]++
		}
		if ts := toString(event["occurred_at"]); strings.HasPrefix(ts, today) {
			stats.TodayEvents++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": stats,
	})
}

func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 50
	}
	if limit < 0 {
		limit = 0
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if offset < 0 {
		offset = 0
	}

	h.mu.RLock()
	total := len(h.events)
	items := make([]map[string]interface{}, 0, limit)
	for i := offset; i < total && len(items) < limit; i++ {
		items = append(items, cloneEvent(h.events[i]))
	}
	h.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{"items": items, "total": total, "limit": limit, "offset": offset},
	})
}

func (h *Handler) GetEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Path[len("/api/v1/rasp/"):]
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, event := range h.events {
		if toString(event["id"]) == id {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 0, "message": "success", "data": cloneEvent(event),
			})
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code":    0,
		"message": "success",
		"data":    nil,
	})
}

func (h *Handler) GetRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rules := make([]map[string]interface{}, 0)
	if rs, err := LoadElkeidRules("rules/rasp/elkeid_rasp_rules.yaml"); err == nil {
		for _, rule := range rs.Rules {
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": rules,
	})
}

func (h *Handler) UpdateRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID      int    `json:"id"`
		Enabled bool   `json:"enabled"`
		Action  string `json:"action"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{"id": req.ID, "enabled": req.Enabled, "action": req.Action},
	})
}

func (h *Handler) GetAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agents := make([]map[string]interface{}, 0)
	if h.pm != nil {
		for _, agent := range h.pm.ListAgents() {
			blockedCount := int64(0)
			if agent.Stats != nil {
				blockedCount = agent.Stats.BlockedCount
			}
			agents = append(agents, map[string]interface{}{
				"id":         agent.AgentID,
				"hostname":   agent.Hostname,
				"language":   agent.Language,
				"version":    "",
				"status":     "online",
				"protection": agent.Enabled,
				"blocked":    blockedCount,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": agents,
	})
}

func (h *Handler) EnableProtection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID   string `json:"agent_id"`
		BlockMode bool   `json:"block_mode"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if h.pm != nil {
		h.pm.EnableProtection(req.AgentID, req.BlockMode)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{
			"agent_id": req.AgentID, "enabled": true, "block_mode": req.BlockMode,
		},
	})
}

func (h *Handler) DisableProtection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID string `json:"agent_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if h.pm != nil {
		h.pm.DisableProtection(req.AgentID)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{"agent_id": req.AgentID, "enabled": false},
	})
}

func (h *Handler) SetBlockType(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentID    string `json:"agent_id"`
		AttackType string `json:"attack_type"`
		Blocked    bool   `json:"blocked"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if h.pm != nil {
		h.pm.SetBlockType(req.AgentID, req.AttackType, req.Blocked)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
	})
}

func (h *Handler) GetProtectionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if h.pm != nil {
		agents := h.pm.ListAgents()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code": 0, "message": "success", "data": agents,
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": []map[string]interface{}{},
	})
}

func (h *Handler) ReceiveEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var event map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	event = NormalizeEventMap(event)

	eventID := fmt.Sprintf("rasp-%d", time.Now().UnixNano())
	event["id"] = eventID
	if _, ok := event["occurred_at"]; !ok {
		event["occurred_at"] = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, ok := event["mode"]; !ok {
		event["mode"] = "monitor"
	}
	if _, ok := event["severity"]; !ok {
		event["severity"] = "low"
	}
	if _, ok := event["blocked"]; !ok {
		event["blocked"] = false
	}

	attackType, _ := event["attack_type"].(string)
	agentID, _ := event["agent_id"].(string)

	if h.pm != nil && agentID != "" && attackType != "" {
		if blocked, _ := h.pm.ShouldBlock(agentID, attackType); blocked {
			event["blocked"] = true
			fmt.Printf("[RASP] Agent %s blocked %s\n", agentID, attackType)
		}
	}

	h.mu.Lock()
	h.events = append([]map[string]interface{}{cloneEvent(event)}, h.events...)
	if len(h.events) > 2000 {
		h.events = h.events[:2000]
	}
	h.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{"id": eventID, "received": true},
	})
}

func (h *Handler) GetElkeidRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Source   string `json:"source"`
		Language string `json:"language"`
		Category string `json:"category"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Source == "" {
		req.Source = "all"
	}

	var rules []map[string]interface{}
	var total int

	rs, err := LoadElkeidRules("rules/rasp/elkeid_rasp_rules.yaml")
	if err == nil {
		for _, r := range rs.Rules {
			if !r.Enabled {
				continue
			}
			if req.Source == "hids" {
				continue
			}
			if req.Language != "" {
				found := false
				for _, l := range r.Languages {
					if l == req.Language {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			if req.Category != "" && r.Category != req.Category {
				continue
			}

			rules = append(rules, map[string]interface{}{
				"id":          r.ID,
				"name":        r.Name,
				"category":    r.Category,
				"severity":    r.Severity,
				"languages":   r.Languages,
				"runtime":     r.Runtime,
				"description": r.Description,
				"hook_type":   r.HookType,
				"patterns":    r.Patterns,
				"mitre":       r.Mitre,
				"action":      r.Action,
				"source":      "elkeid_rasp",
			})
			total++
		}
	}

	raspCount := total
	rsHIDS, err := LoadElkeidRules("rules/hids/elkeid_hids_rules.yaml")
	if err == nil {
		for _, r := range rsHIDS.Rules {
			if !r.Enabled {
				continue
			}
			if req.Source == "hids" || req.Source == "all" {
				if req.Category != "" && r.Category != req.Category {
					continue
				}

				rules = append(rules, map[string]interface{}{
					"id":          r.ID,
					"name":        r.Name,
					"category":    r.Category,
					"severity":    r.Severity,
					"description": r.Description,
					"hook_type":   r.HookType,
					"patterns":    r.Patterns,
					"mitre":       r.Mitre,
					"action":      r.Action,
					"source":      "elkeid_hids",
				})
				total++
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{
			"items": rules,
			"total": total,
			"by_source": map[string]int{
				"elkeid_rasp": raspCount,
				"elkeid_hids": total - raspCount,
			},
		},
	})
}

func toString(v interface{}) string {
	s, _ := v.(string)
	return s
}

func cloneEvent(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
