package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"ly-flow-platform/pkg/model"
)

// Analyzer provides AI-powered alert analysis using DeepSeek
type Analyzer struct {
	client *DeepSeekClient
}

// AnalysisResult represents the result of an alert analysis
type AnalysisResult struct {
	IsFalsePositive bool    `json:"is_false_positive"`
	Confidence       float64 `json:"confidence"`
	Category         string  `json:"category"`
	Summary          string  `json:"summary"`
	Recommendation   string  `json:"recommendation"`
}

// ChainAnalysisResult represents the result of an attack chain analysis
type ChainAnalysisResult struct {
	AttackType   string  `json:"attack_type"`
	Confidence   float64 `json:"confidence"`
	AttackStage  string  `json:"attack_stage"`
	Summary      string  `json:"summary"`
	Recommendation string  `json:"recommendation"`
}

// alertAnalysisResponse is the JSON structure expected from the API
type alertAnalysisResponse struct {
	IsFalsePositive bool    `json:"is_false_positive"`
	Confidence      float64 `json:"confidence"`
	Category        string  `json:"category"`
	Summary         string  `json:"summary"`
	Recommendation  string  `json:"recommendation"`
}

// chainAnalysisResponse is the JSON structure expected for chain analysis
type chainAnalysisResponse struct {
	AttackType     string  `json:"attack_type"`
	Confidence     float64 `json:"confidence"`
	AttackStage    string  `json:"attack_stage"`
	Summary        string  `json:"summary"`
	Recommendation string  `json:"recommendation"`
}

// NewAnalyzer creates a new alert analyzer with the given API key
func NewAnalyzer(apiKey string) *Analyzer {
	return &Analyzer{
		client: NewClient(apiKey),
	}
}

// AnalyzeAlert analyzes a single alert to determine if it's a false positive
func (a *Analyzer) AnalyzeAlert(ctx context.Context, alert *model.Alert) (*AnalysisResult, error) {
	prompt := fmt.Sprintf(
		AlertAnalysisPrompt,
		alert.Type,
		SeverityLevel(alert.Severity),
		alert.SrcIP,
		alert.DstIP,
		alert.Domain,
		alert.Signature,
	)

	response, err := a.client.Chat([]ChatMessage{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		return nil, err
	}

	return parseAlertAnalysisResponse(response)
}

// AnalyzeChain analyzes multiple alerts as an attack chain
func (a *Analyzer) AnalyzeChain(ctx context.Context, alerts []*model.Alert) (*ChainAnalysisResult, error) {
	alertList := buildAlertList(alerts)
	prompt := fmt.Sprintf(ChainAnalysisPrompt, alertList)

	response, err := a.client.Chat([]ChatMessage{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		return nil, err
	}

	return parseChainAnalysisResponse(response)
}

// buildAlertList formats alerts for the prompt
func buildAlertList(alerts []*model.Alert) string {
	var list string
	for i, alert := range alerts {
		list += fmt.Sprintf("\n%d. [%s] %s | %s -> %s | 签名: %s",
			i+1,
			SeverityLevel(alert.Severity),
			alert.Type,
			alert.SrcIP,
			alert.DstIP,
			alert.Signature,
		)
	}
	return list
}

// parseAlertAnalysisResponse parses the API response into an AnalysisResult
func parseAlertAnalysisResponse(response string) (*AnalysisResult, error) {
	var resp alertAnalysisResponse
	if err := json.Unmarshal([]byte(response), &resp); err != nil {
		return &AnalysisResult{
			IsFalsePositive: false,
			Confidence:      0.5,
			Category:        "解析失败",
			Summary:         response,
			Recommendation:  "请人工确认",
		}, nil
	}

	return &AnalysisResult{
		IsFalsePositive: resp.IsFalsePositive,
		Confidence:      resp.Confidence,
		Category:        resp.Category,
		Summary:         resp.Summary,
		Recommendation:  resp.Recommendation,
	}, nil
}

// parseChainAnalysisResponse parses the API response into a ChainAnalysisResult
func parseChainAnalysisResponse(response string) (*ChainAnalysisResult, error) {
	var resp chainAnalysisResponse
	if err := json.Unmarshal([]byte(response), &resp); err != nil {
		return &ChainAnalysisResult{
			AttackType:     "未知",
			Confidence:     0.5,
			AttackStage:    "未知",
			Summary:        response,
			Recommendation: "请人工确认",
		}, nil
	}

	return &ChainAnalysisResult{
		AttackType:     resp.AttackType,
		Confidence:     resp.Confidence,
		AttackStage:    resp.AttackStage,
		Summary:        resp.Summary,
		Recommendation: resp.Recommendation,
	}, nil
}
