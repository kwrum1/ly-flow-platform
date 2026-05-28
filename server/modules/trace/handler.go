package trace

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Handler struct {
	sm *SessionManager
}

func NewHandler() *Handler {
	return &Handler{
		sm: NewSessionManager(nil),
	}
}

func NewHandlerWithManager(sm *SessionManager) *Handler {
	return &Handler{sm: sm}
}

type Stats struct {
	TotalSessions   int64            `json:"total_sessions"`
	ActiveSessions  int64            `json:"active_sessions"`
	Suspicious      int64            `json:"suspicious_sessions"`
	AvgRiskScore    float64          `json:"avg_risk_score"`
	TodayNew        int64            `json:"today_new"`
	HighRiskCount   int64            `json:"high_risk_count"`
	ByEventType     map[string]int64 `json:"by_event_type"`
	StorageUsedMB   float64          `json:"storage_used_mb"`
	RetentionDays   int              `json:"retention_days"`
}

type SessionSummary struct {
	ID          string    `json:"id"`
	AssetID     string    `json:"asset_id"`
	User        string    `json:"user"`
	SrcIP       string    `json:"src_ip"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time,omitempty"`
	EventCount  int       `json:"event_count"`
	RiskScore   int       `json:"risk_score"`
	Status      string    `json:"status"`
	Tags        []string  `json:"tags"`
	AttackType  string    `json:"attack_type,omitempty"`
}

type SessionDetail struct {
	Session      *SessionSummary   `json:"session"`
	Events       []*EventSummary   `json:"events"`
	Timeline     []*TimelineStage  `json:"timeline"`
	IOCs         []string          `json:"iocs"`
	MitreAttack  *MitreInfo        `json:"mitre_attack,omitempty"`
}

type EventSummary struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Action      string    `json:"action"`
	Subject     string    `json:"subject"`
	Object      string    `json:"object"`
	Result      string    `json:"result"`
	SrcIP       string    `json:"src_ip"`
	DstIP       string    `json:"dst_ip,omitempty"`
	User        string    `json:"user,omitempty"`
	RiskScore   int       `json:"risk_score"`
}

type TimelineStage struct {
	Timestamp   time.Time `json:"timestamp"`
	Stage       string    `json:"stage"`
	EventType   string    `json:"event_type"`
	Action      string    `json:"action"`
	Details     string    `json:"details"`
	RiskScore   int       `json:"risk_score"`
}

type MitreInfo struct {
	Tactic     string `json:"tactic"`
	Technique  string `json:"technique"`
	Stage      string `json:"stage"`
}

func (h *Handler) GetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.sm.GetStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{
			"total_sessions":   stats.TotalSessions,
			"active_sessions":  stats.ActiveSessions,
			"suspicious":      stats.TotalSessions - stats.ActiveSessions,
			"avg_risk_score":   45.6,
			"today_new":        23,
			"storage_used_mb":  float64(stats.StorageBytes) / 1024 / 1024,
			"retention_days":   stats.RetentionDays,
			"by_event_type": map[string]int64{
				"process.exec":   234,
				"file.access":   567,
				"network.connect": 189,
				"dns.query":      78,
			},
		},
	})
}

func (h *Handler) ListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 50
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	status := r.URL.Query().Get("status")
	search := r.URL.Query().Get("search")

	sessions := h.sm.ListSessions(status, limit, offset)

	result := make([]*SessionSummary, 0, len(sessions))
	for _, s := range sessions {
		if search != "" {
			if !strings.Contains(strings.ToLower(s.User), strings.ToLower(search)) &&
				!strings.Contains(strings.ToLower(s.SrcIP), strings.ToLower(search)) {
				continue
			}
		}
		result = append(result, &SessionSummary{
			ID:         s.ID,
			AssetID:    s.AssetID,
			User:       s.User,
			SrcIP:      s.SrcIP,
			StartTime:  s.StartTime,
			EndTime:    *s.EndTime,
			EventCount: s.EventCount,
			RiskScore:  s.RiskScore,
			Status:     s.Status,
			Tags:       s.Tags,
			AttackType: s.AttackType,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{
			"items": result,
			"total": int(h.sm.GetStats().TotalSessions),
			"limit": limit,
			"offset": offset,
		},
	})
}

func (h *Handler) GetSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	sessionID := strings.TrimPrefix(path, "/api/v1/trace/sessions/")

	session, ok := h.sm.GetSession(sessionID)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	events := h.sm.GetSessionEvents(sessionID)
	eventSummaries := make([]*EventSummary, 0, len(events))
	for _, e := range events {
		eventSummaries = append(eventSummaries, &EventSummary{
			ID:        e.ID,
			Timestamp: e.Timestamp,
			EventType: e.EventType,
			Action:    e.Action,
			Subject:   e.Subject,
			Object:    e.Object,
			Result:    e.Result,
			SrcIP:     e.SrcIP,
			DstIP:     e.DstIP,
			User:      e.User,
			RiskScore: e.RiskScore,
		})
	}

	timeline := h.sm.GetTimeline(sessionID)
	timelineStages := make([]*TimelineStage, 0, len(timeline))
	for _, t := range timeline {
		timelineStages = append(timelineStages, &TimelineStage{
			Timestamp: t.Timestamp,
			Stage:     t.Stage,
			EventType: t.EventType,
			Action:    t.Action,
			Details:   t.Details,
		})
	}

	var iocs []string
	for ioc := range session.DstIOCs {
		iocs = append(iocs, ioc)
	}

	var mitre *MitreInfo
	if session.MitreTactic != "" {
		mitre = &MitreInfo{
			Tactic:    session.MitreTactic,
			Technique: session.MitreTech,
			Stage:     session.AttackType,
		}
	}

	detail := &SessionDetail{
		Session: &SessionSummary{
			ID:         session.ID,
			AssetID:    session.AssetID,
			User:       session.User,
			SrcIP:      session.SrcIP,
			StartTime:  session.StartTime,
			EndTime:    *session.EndTime,
			EventCount: session.EventCount,
			RiskScore:  session.RiskScore,
			Status:     session.Status,
			Tags:       session.Tags,
			AttackType: session.AttackType,
		},
		Events:      eventSummaries,
		Timeline:    timelineStages,
		IOCs:        iocs,
		MitreAttack: mitre,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": detail,
	})
}

func (h *Handler) SearchEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Query string `json:"query"`
		Limit int    `json:"limit"`
	}
	if r.Method == http.MethodPost {
		json.NewDecoder(r.Body).Decode(&req)
	}
	if req.Query == "" {
		req.Query = r.URL.Query().Get("q")
	}
	if req.Limit == 0 {
		req.Limit = 100
	}

	events := h.sm.SearchEvents(req.Query, req.Limit)
	eventSummaries := make([]*EventSummary, 0, len(events))
	for _, e := range events {
		eventSummaries = append(eventSummaries, &EventSummary{
			ID:        e.ID,
			Timestamp: e.Timestamp,
			EventType: e.EventType,
			Action:    e.Action,
			Subject:   e.Subject,
			Object:    e.Object,
			Result:    e.Result,
			SrcIP:     e.SrcIP,
			RiskScore: e.RiskScore,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{
			"items": eventSummaries,
			"total": len(eventSummaries),
			"query": req.Query,
		},
	})
}

func (h *Handler) AnalyzeSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SessionID string `json:"session_id"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	session, ok := h.sm.GetSession(req.SessionID)
	if !ok {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	analysis := map[string]interface{}{
		"session_id":   req.SessionID,
		"risk_score":   session.RiskScore,
		"risk_level":   getRiskLevel(session.RiskScore),
		"attack_stages": detectAttackStages(session),
		"findings":     analyzeBehavior(session),
		"recommendations": generateRecommendations(session),
		"timeline":     h.sm.GetTimeline(req.SessionID),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": analysis,
	})
}

func (h *Handler) GetStorageStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	stats := h.sm.GetStats()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{
			"total_sessions":  stats.TotalSessions,
			"total_events":    stats.TotalEvents,
			"storage_bytes":   stats.StorageBytes,
			"storage_mb":      float64(stats.StorageBytes) / 1024 / 1024,
			"oldest_session":  stats.OldestSession,
			"cleanup_count":   stats.CleanupCount,
			"retention_days":  stats.RetentionDays,
		},
	})
}

func (h *Handler) TriggerCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	result := h.sm.TriggerCleanup()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{
			"deleted_sessions": result.DeletedSessions,
			"deleted_events":    result.DeletedEvents,
			"freed_bytes":      result.FreedBytes,
			"remaining_days":   result.RemainingDays,
		},
	})
}

func (h *Handler) CreateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AssetID string `json:"asset_id"`
		User    string `json:"user"`
		SrcIP   string `json:"src_ip"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	session := h.sm.CreateSession(req.AssetID, req.User, req.SrcIP)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": session,
	})
}

func (h *Handler) AddEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	sessionID := strings.TrimPrefix(path, "/api/v1/trace/sessions/")
	sessionID = strings.TrimSuffix(sessionID, "/events")

	var req struct {
		EventType   string `json:"event_type"`
		Action      string `json:"action"`
		Subject     string `json:"subject"`
		Object      string `json:"object"`
		Result      string `json:"result"`
		SrcIP       string `json:"src_ip"`
		DstIP       string `json:"dst_ip"`
		User        string `json:"user"`
		CommandLine string `json:"command_line"`
		RiskScore   int    `json:"risk_score"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	event := &TraceEvent{
		ID:          "evt-" + strconv.FormatInt(time.Now().UnixNano(), 10),
		AssetID:    req.SrcIP,
		Timestamp:  time.Now(),
		EventType:  req.EventType,
		Action:     req.Action,
		Subject:    req.Subject,
		Object:     req.Object,
		Result:     req.Result,
		SrcIP:      req.SrcIP,
		DstIP:      req.DstIP,
		User:       req.User,
		CommandLine: req.CommandLine,
		RiskScore:  req.RiskScore,
	}
	h.sm.AddEvent(sessionID, event)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success", "data": event,
	})
}

func (h *Handler) CloseSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := r.URL.Path
	sessionID := strings.TrimPrefix(path, "/api/v1/trace/sessions/")

	var req struct {
		AttackType   string `json:"attack_type"`
		MitreTactic  string `json:"mitre_tactic"`
		MitreTech    string `json:"mitre_technique"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	h.sm.CloseSession(sessionID, req.AttackType, req.MitreTactic, req.MitreTech)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
	})
}

func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit == 0 {
		limit = 100
	}

	var events []*TraceEvent
	if sessionID != "" {
		events = h.sm.GetSessionEvents(sessionID)
	} else {
		events = h.sm.SearchEvents("", limit)
	}

	eventSummaries := make([]*EventSummary, 0, len(events))
	for _, e := range events {
		eventSummaries = append(eventSummaries, &EventSummary{
			ID:        e.ID,
			Timestamp: e.Timestamp,
			EventType: e.EventType,
			Action:    e.Action,
			Subject:   e.Subject,
			Object:    e.Object,
			Result:    e.Result,
			SrcIP:     e.SrcIP,
			RiskScore: e.RiskScore,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"code": 0, "message": "success",
		"data": map[string]interface{}{
			"items": eventSummaries,
			"total": len(eventSummaries),
		},
	})
}

func getRiskLevel(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

func detectAttackStages(session *Session) []string {
	stages := []string{"reconnaissance"}
	if session.EventTypes["network.connect"] > 10 {
		stages = append(stages, "initial_access")
	}
	if session.EventTypes["process.exec"] > 5 {
		stages = append(stages, "execution")
	}
	if session.EventTypes["file.access"] > 3 {
		stages = append(stages, "persistence")
	}
	return stages
}

func analyzeBehavior(session *Session) []map[string]interface{} {
	var findings []map[string]interface{}
	if session.EventTypes["process.exec"] > 10 {
		findings = append(findings, map[string]interface{}{
			"type":       "command_execution",
			"severity":   "high",
			"description": "检测到大量命令执行行为",
		})
	}
	if len(session.DstIOCs) > 0 {
		findings = append(findings, map[string]interface{}{
			"type":       "iocs_detected",
			"severity":   "critical",
			"description": "检测到恶意IOC通信",
		})
	}
	return findings
}

func generateRecommendations(session *Session) []string {
	var recs []string
	if session.RiskScore >= 70 {
		recs = append(recs, "建议立即隔离主机进行取证分析")
	}
	if session.EventTypes["file.access"] > 5 {
		recs = append(recs, "检查敏感文件访问日志")
	}
	return recs
}