package trace

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type SessionManager struct {
	sessions   map[string]*Session
	events     map[string][]*TraceEvent
	sequences  map[string]*AttackSequence
	mu         sync.RWMutex
	cfg        *SessionConfig
}

type SessionConfig struct {
	RetentionDays      int
	MaxRetentionDays   int
	CleanupThreshold   float64
	HighRiskHours      int
	HighRiskMinScore   int
}

type Session struct {
	ID           string
	AssetID      string
	User         string
	SrcIP        string
	DstIPs       []string
	StartTime    time.Time
	EndTime      *time.Time
	EventCount   int
	RiskScore    int
	Status       string
	AttackType   string
	MitreTactic  string
	MitreTech    string
	Tags         []string
	FirstEvent   *TraceEvent
	LastEvent    *TraceEvent
	EventTypes   map[string]int
	SrcIPs       map[string]int
	DstIOCs      map[string]bool
	Metadata     map[string]interface{}
}

type TraceEvent struct {
	ID             string
	SessionID      string
	AssetID        string
	Timestamp      time.Time
	OrderNum       int
	EventType      string
	Action         string
	Subject        string
	Object         string
	Result         string
	SrcIP          string
	DstIP          string
	DstPort        int
	User           string
	ParentProc     string
	CommandLine    string
	RiskScore      int
	RelatedIOCs    []string
	AlertID        string
	Raw            string
}

type AttackSequence struct {
	ID           string
	SessionID    string
	AttackType   string
	MitreTactic  string
	MitreTech    string
	RiskScore    int
	Stages       []*SequenceStage
	Evidence     []string
	Status       string
	CreatedAt    time.Time
}

type SequenceStage struct {
	Timestamp   time.Time
	Stage       string
	EventType   string
	Action      string
	Details     string
}

type StorageStats struct {
	TotalSessions    int64
	ActiveSessions   int64
	TotalEvents      int64
	StorageBytes     int64
	OldestSession    time.Time
	CleanupCount     int
	CleanupBytes     int64
	RetentionDays    int
}

type CleanupConfig struct {
	RetentionDays      int
	MaxRetentionDays   int
	CleanupThreshold   float64
	HighRiskHours      int
	HighRiskMinScore   int
	Enabled            bool
}

type CleanupResult struct {
	DeletedSessions   int
	DeletedEvents     int64
	FreedBytes        int64
	RemainingDays     int
}

func NewSessionManager(cfg *SessionConfig) *SessionManager {
	if cfg == nil {
		cfg = &SessionConfig{
			RetentionDays:    7,
			MaxRetentionDays: 180,
			CleanupThreshold: 70.0,
			HighRiskHours:    24,
			HighRiskMinScore: 70,
		}
	}
	return &SessionManager{
		sessions:   make(map[string]*Session),
		events:     make(map[string][]*TraceEvent),
		sequences:  make(map[string]*AttackSequence),
		cfg:        cfg,
	}
}

func (sm *SessionManager) CreateSession(assetID, user, srcIP string) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	session := &Session{
		ID:        fmt.Sprintf("sess-%d", time.Now().UnixNano()),
		AssetID:   assetID,
		User:      user,
		SrcIP:     srcIP,
		StartTime: time.Now(),
		Status:    "active",
		Tags:      []string{},
		EventTypes: make(map[string]int),
		SrcIPs:    make(map[string]int),
		DstIOCs:   make(map[string]bool),
		DstIPs:    []string{},
		Metadata:  make(map[string]interface{}),
	}
	sm.sessions[session.ID] = session
	return session
}

func (sm *SessionManager) AddEvent(sessionID string, event *TraceEvent) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	event.SessionID = sessionID
	if session, ok := sm.sessions[sessionID]; ok {
		session.EventCount++
		session.EventTypes[event.EventType]++
		if event.SrcIP != "" {
			session.SrcIPs[event.SrcIP]++
		}
		session.RiskScore += event.RiskScore
		session.LastEvent = event
		if session.FirstEvent == nil {
			session.FirstEvent = event
		}
	}
	sm.events[sessionID] = append(sm.events[sessionID], event)
}

func (sm *SessionManager) CloseSession(sessionID string, attackType, mitreTactic, mitreTech string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, ok := sm.sessions[sessionID]; ok {
		now := time.Now()
		session.EndTime = &now
		session.Status = "closed"
		session.AttackType = attackType
		session.MitreTactic = mitreTactic
		session.MitreTech = mitreTech

		if session.RiskScore >= sm.cfg.HighRiskMinScore {
			session.Tags = append(session.Tags, "high_risk")
		}
	}
}

func (sm *SessionManager) GetSession(sessionID string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[sessionID]
	return session, ok
}

func (sm *SessionManager) ListSessions(status string, limit, offset int) []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var result []*Session
	for _, session := range sm.sessions {
		if status != "" && session.Status != status {
			continue
		}
		result = append(result, session)
	}

	if offset > len(result) {
		offset = len(result)
	}
	if limit > 0 && offset+limit < len(result) {
		result = result[offset : offset+limit]
	} else if offset > 0 {
		result = result[offset:]
	}

	return result
}

func (sm *SessionManager) GetSessionEvents(sessionID string) []*TraceEvent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.events[sessionID]
}

func (sm *SessionManager) GetStats() *StorageStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := &StorageStats{
		TotalSessions:  int64(len(sm.sessions)),
		RetentionDays:  sm.cfg.RetentionDays,
	}

	var oldestTime time.Time
	for _, session := range sm.sessions {
		if session.Status == "active" {
			stats.ActiveSessions++
		}
		stats.TotalEvents += int64(len(sm.events[session.ID]))
		if oldestTime.IsZero() || session.StartTime.Before(oldestTime) {
			oldestTime = session.StartTime
		}
	}
	stats.OldestSession = oldestTime

	return stats
}

func (sm *SessionManager) TriggerCleanup() *CleanupResult {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	result := &CleanupResult{}
	threshold := sm.cfg.HighRiskHours
	minScore := sm.cfg.HighRiskMinScore

	for id, session := range sm.sessions {
		if session.Status == "closed" {
			hours := time.Since(session.StartTime).Hours()
			isHighRisk := session.RiskScore >= minScore

			if isHighRisk && hours < float64(threshold) {
				continue
			}

			delete(sm.sessions, id)
			delete(sm.events, id)
			result.DeletedSessions++
			result.FreedBytes += int64(session.EventCount * 500)
		}
	}

	return result
}

func (sm *SessionManager) MarkIOC(sessionID, ioc string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if session, ok := sm.sessions[sessionID]; ok {
		session.DstIOCs[ioc] = true
	}
}

func (sm *SessionManager) SearchEvents(query string, limit int) []*TraceEvent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var results []*TraceEvent
	for _, events := range sm.events {
		for _, event := range events {
			if containsIgnoreCase(event.CommandLine, query) ||
				containsIgnoreCase(event.Subject, query) ||
				containsIgnoreCase(event.Object, query) {
				results = append(results, event)
				if limit > 0 && len(results) >= limit {
					return results
				}
			}
		}
	}
	return results
}

func (sm *SessionManager) GetTimeline(sessionID string) []*SequenceStage {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var stages []*SequenceStage
	events := sm.events[sessionID]
	for i, event := range events {
		stage := &SequenceStage{
			Timestamp: event.Timestamp,
			Stage:     fmt.Sprintf("Stage %d", i+1),
			EventType: event.EventType,
			Action:    event.Action,
			Details:   fmt.Sprintf("%s -> %s", event.Subject, event.Object),
		}
		stages = append(stages, stage)
	}
	return stages
}

func (sm *SessionManager) ExportToJSON(sessionID string) ([]byte, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session not found")
	}

	data := map[string]interface{}{
		"session": session,
		"events":  sm.events[sessionID],
	}
	return json.Marshal(data)
}

func containsIgnoreCase(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFold(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}