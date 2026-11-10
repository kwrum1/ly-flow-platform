package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/lyflow/ly-flow-platform/model"
	"github.com/lyflow/ly-flow-platform/server/webhook"
)

// Webhook notification runtime wiring.
//
// The server/webhook package already implements DingTalk / WeCom / Feishu
// message formatting plus daily report rendering, but nothing in the server
// binary used it. This file only wires environment configuration to that
// package: if no channel is configured, no manager is created and no goroutine
// is started.
const (
	webhookEnvDingTalkURL = "WEBHOOK_DINGTALK_URL"
	webhookEnvWeComURL    = "WEBHOOK_WECOM_URL"
	webhookEnvFeishuURL   = "WEBHOOK_FEISHU_URL"

	webhookEnvDailyReportEnabled = "WEBHOOK_DAILY_REPORT_ENABLED"
	webhookEnvDailyReportTime    = "WEBHOOK_DAILY_REPORT_TIME"
	webhookEnvAlertNotifyEnabled = "WEBHOOK_ALERT_NOTIFY_ENABLED"

	defaultWebhookDailyReportTime = "08:00"

	// webhookAlertStream is the Redis stream that already carries XDR alerts.
	webhookAlertStream = "alerts:xdr"

	// webhookDailyReportAlertLimit bounds how many alerts are pulled per report
	// so a busy day cannot exhaust memory during aggregation.
	webhookDailyReportAlertLimit = 5000
)

// webhookChannel is one configured notification channel. URLs are never logged.
type webhookChannel struct {
	Type string
	ID   string
	URL  string
}

// webhookRuntimeConfig is the resolved, validated runtime configuration.
type webhookRuntimeConfig struct {
	Channels           []webhookChannel
	AlertNotifyEnabled bool
	DailyReportEnabled bool
	ReportHour         int
	ReportMinute       int
}

// webhookRuntime owns the webhook manager and the scheduler parameters.
type webhookRuntime struct {
	manager            *webhook.Manager
	channels           []webhookChannel
	alertNotifyEnabled bool
	dailyReportEnabled bool
	reportHour         int
	reportMinute       int
}

// Enabled reports whether the runtime has at least one configured channel.
func (r *webhookRuntime) Enabled() bool {
	return r != nil && len(r.channels) > 0
}

// Channels returns the configured channels (metadata only).
func (r *webhookRuntime) Channels() []webhookChannel {
	if r == nil {
		return nil
	}
	out := make([]webhookChannel, len(r.channels))
	copy(out, r.channels)
	return out
}

// dailyReportTime returns the configured report schedule as "HH:MM".
func (r *webhookRuntime) dailyReportTime() string {
	if r == nil {
		return defaultWebhookDailyReportTime
	}
	return fmt.Sprintf("%02d:%02d", r.reportHour, r.reportMinute)
}

// webhookChannelEnvValues collects every non-empty channel variable. It is the
// very first check in the startup path: with no channel configured the runtime
// returns before validating anything else, without logging and without
// starting a goroutine. The channel list is only allocated once a variable is
// actually set, so the disabled path performs no heap allocation.
func webhookChannelEnvValues(getenv func(string) string) []webhookChannel {
	if getenv == nil {
		return nil
	}
	var channels []webhookChannel
	add := func(raw, id, kind string) {
		if raw == "" {
			return
		}
		channels = append(channels, webhookChannel{Type: kind, ID: id, URL: raw})
	}
	add(getenv(webhookEnvDingTalkURL), "dingtalk", "dingtalk")
	add(getenv(webhookEnvWeComURL), "wecom", "wecom")
	add(getenv(webhookEnvFeishuURL), "feishu", "feishu")
	return channels
}

// validateWebhookURL rejects empty, relative and non-HTTP(S) webhook URLs.
func validateWebhookURL(name, raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", name, err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%s must use http or https, got %q", name, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s must include a host", name)
	}
	return nil
}

// loadWebhookRuntimeConfig validates channel URLs and resolves scheduler
// settings. channels must contain at least one entry.
func loadWebhookRuntimeConfig(getenv func(string) string, channels []webhookChannel) (webhookRuntimeConfig, error) {
	var cfg webhookRuntimeConfig

	channelVars := map[string]string{
		"dingtalk": webhookEnvDingTalkURL,
		"wecom":    webhookEnvWeComURL,
		"feishu":   webhookEnvFeishuURL,
	}
	for _, channel := range channels {
		if err := validateWebhookURL(channelVars[channel.Type], channel.URL); err != nil {
			return webhookRuntimeConfig{}, err
		}
		channel.URL = strings.TrimSpace(channel.URL)
		cfg.Channels = append(cfg.Channels, channel)
	}

	alertNotify, err := webhookEnvBool(getenv, webhookEnvAlertNotifyEnabled, true)
	if err != nil {
		return webhookRuntimeConfig{}, err
	}
	cfg.AlertNotifyEnabled = alertNotify

	dailyReport, err := webhookEnvBool(getenv, webhookEnvDailyReportEnabled, true)
	if err != nil {
		return webhookRuntimeConfig{}, err
	}
	cfg.DailyReportEnabled = dailyReport

	// The report time is only relevant (and only validated) when the daily
	// report is actually enabled.
	cfg.ReportHour, cfg.ReportMinute = 8, 0
	if cfg.DailyReportEnabled {
		hour, minute, err := parseWebhookReportTime(getenv(webhookEnvDailyReportTime))
		if err != nil {
			return webhookRuntimeConfig{}, err
		}
		cfg.ReportHour, cfg.ReportMinute = hour, minute
	}

	return cfg, nil
}

func webhookEnvBool(getenv func(string) string, name string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be true or false, got %q", name, raw)
	}
	return value, nil
}

// parseWebhookReportTime parses a 24-hour "HH:MM" schedule. An empty value
// falls back to the default 08:00.
func parseWebhookReportTime(value string) (int, int, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		trimmed = defaultWebhookDailyReportTime
	}
	parts := strings.Split(trimmed, ":")
	if len(parts) != 2 || !webhookAllDigits(parts[0]) || !webhookAllDigits(parts[1]) || len(parts[0]) > 2 || len(parts[1]) > 2 {
		return 0, 0, fmt.Errorf("%s must use 24-hour HH:MM, got %q", webhookEnvDailyReportTime, value)
	}
	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("%s must use 24-hour HH:MM, got %q", webhookEnvDailyReportTime, value)
	}
	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("%s must use 24-hour HH:MM, got %q", webhookEnvDailyReportTime, value)
	}
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, fmt.Errorf("%s must be a valid 24-hour HH:MM time between 00:00 and 23:59, got %q", webhookEnvDailyReportTime, value)
	}
	return hour, minute, nil
}

func webhookAllDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

// nextWebhookReportTime returns the next occurrence of hour:minute strictly
// after now (same timezone).
func nextWebhookReportTime(now time.Time, hour, minute int) time.Time {
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
	if !next.After(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// startWebhookRuntime is the single startup entry point used by main().
// When nothing is configured it returns immediately: no manager, no goroutine,
// no error log.
func startWebhookRuntime(ctx context.Context, cfg *Config) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := startWebhookRuntimeWithLauncher(ctx, cfg, os.Getenv, nil); err != nil {
		log.Printf("[webhook] disabled: %v", err)
	}
}

// startWebhookRuntimeWithLauncher is the testable startup path. launch lets
// tests observe whether any background goroutine would be started.
func startWebhookRuntimeWithLauncher(ctx context.Context, cfg *Config, getenv func(string) string, launch func(func())) (*webhookRuntime, error) {
	channels := webhookChannelEnvValues(getenv)
	if len(channels) == 0 {
		return nil, nil
	}

	runtimeConfig, err := loadWebhookRuntimeConfig(getenv, channels)
	if err != nil {
		return nil, err
	}

	manager := webhook.NewManager()
	for _, channel := range runtimeConfig.Channels {
		if err := manager.AddWebhook(&webhook.WebhookConfig{
			ID:      channel.ID,
			Name:    channel.Type,
			Type:    channel.Type,
			URL:     channel.URL,
			Enabled: true,
		}); err != nil {
			return nil, fmt.Errorf("%s webhook rejected: %w", channel.Type, err)
		}
	}

	runtime := &webhookRuntime{
		manager:            manager,
		channels:           runtimeConfig.Channels,
		alertNotifyEnabled: runtimeConfig.AlertNotifyEnabled,
		dailyReportEnabled: runtimeConfig.DailyReportEnabled,
		reportHour:         runtimeConfig.ReportHour,
		reportMinute:       runtimeConfig.ReportMinute,
	}

	if launch == nil {
		launch = func(fn func()) { go fn() }
	}
	if ctx == nil {
		ctx = context.Background()
	}

	kinds := make([]string, 0, len(runtime.channels))
	for _, channel := range runtime.channels {
		kinds = append(kinds, channel.Type)
	}
	// Channel types and schedule only: webhook URLs embed tokens and must never
	// be written to logs.
	if runtime.alertNotifyEnabled {
		launch(func() { runtime.runAlertNotifications(ctx, cfg) })
	}
	if runtime.dailyReportEnabled {
		launch(func() { runtime.runDailyReports(ctx, cfg) })
	}
	log.Printf("[webhook] enabled channels=%s alert_notify=%t daily_report=%t report_time=%02d:%02d",
		strings.Join(kinds, ","), runtime.alertNotifyEnabled, runtime.dailyReportEnabled, runtime.reportHour, runtime.reportMinute)

	return runtime, nil
}

// runAlertNotifications forwards new alerts from the Redis alert stream.
func (r *webhookRuntime) runAlertNotifications(ctx context.Context, cfg *Config) {
	if r == nil || r.manager == nil || cfg == nil || cfg.Redis == nil {
		return
	}
	lastID := "$"
	for {
		if ctx.Err() != nil {
			return
		}
		streams, err := cfg.Redis.XRead(ctx, &redis.XReadArgs{
			Streams: []string{webhookAlertStream, lastID},
			Count:   32,
			Block:   30 * time.Second,
		}).Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, redis.Nil) {
				continue
			}
			log.Printf("[webhook] alert stream read failed: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			continue
		}
		for _, stream := range streams {
			for _, message := range stream.Messages {
				lastID = message.ID
				alert := webhookAlertFromStream(message)
				if alert == nil {
					continue
				}
				if err := r.manager.SendAlert(alert); err != nil {
					log.Printf("[webhook] alert notification failed: %v", err)
				}
			}
		}
	}
}

// runDailyReports pushes an aggregated report for the previous day at the
// configured local time.
func (r *webhookRuntime) runDailyReports(ctx context.Context, cfg *Config) {
	if r == nil || r.manager == nil {
		return
	}
	for {
		next := nextWebhookReportTime(time.Now(), r.reportHour, r.reportMinute)
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := r.deliverDailyReport(ctx, cfg, time.Now().AddDate(0, 0, -1)); err != nil {
			log.Printf("[webhook] daily report failed: %v", err)
		}
	}
}

func (r *webhookRuntime) deliverDailyReport(ctx context.Context, cfg *Config, day time.Time) error {
	if r == nil || r.manager == nil {
		return nil
	}
	report, err := loadWebhookDailyReport(ctx, cfg, day)
	if err != nil {
		return err
	}
	return r.manager.SendDailyReport(report)
}

// loadWebhookDailyReport aggregates one day of threat_events into the report
// shape already produced by the webhook package.
func loadWebhookDailyReport(ctx context.Context, cfg *Config, day time.Time) (*webhook.DailyReport, error) {
	if cfg == nil || cfg.DBPool == nil {
		return webhook.GenerateDailyReport(nil, day), nil
	}
	start := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, day.Location())
	end := start.AddDate(0, 0, 1)

	rows, err := cfg.DBPool.Query(ctx, `
		SELECT severity, src_ip, dst_ip, category, message, observed_at
		FROM threat_events
		WHERE observed_at >= $1 AND observed_at < $2
		ORDER BY observed_at DESC
		LIMIT $3`, start, end, webhookDailyReportAlertLimit)
	if err != nil {
		return nil, fmt.Errorf("query daily report alerts: %w", err)
	}
	defer rows.Close()

	alerts := make([]*model.Alert, 0, 64)
	for rows.Next() {
		var severity, srcIP, dstIP, category, message string
		var observedAt time.Time
		if err := rows.Scan(&severity, &srcIP, &dstIP, &category, &message, &observedAt); err != nil {
			return nil, fmt.Errorf("scan daily report alert: %w", err)
		}
		alerts = append(alerts, &model.Alert{
			Timestamp: observedAt,
			SrcIP:     srcIP,
			DstIP:     dstIP,
			Category:  category,
			Signature: message,
			Severity:  webhookSeverityUint8(severity),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read daily report alerts: %w", err)
	}

	return webhook.GenerateDailyReport(alerts, day), nil
}

// webhookAlertFromStream converts one Redis alert message into the package's
// alert model. Informational events are skipped.
func webhookAlertFromStream(message redis.XMessage) *model.Alert {
	payload := map[string]interface{}{}
	if raw := streamDataString(message.Values); raw != "" {
		_ = json.Unmarshal([]byte(raw), &payload)
	}
	if len(payload) == 0 {
		return nil
	}
	severity := strings.ToLower(xdrPickString(payload, "severity"))
	if severity == "" || severity == "info" || severity == "informational" {
		return nil
	}
	observedAt := parseEventTime(payload)
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	return &model.Alert{
		Timestamp: observedAt,
		SrcIP:     xdrPickString(payload, "src_ip", "source_ip", "entities.source_ip"),
		DstIP:     xdrPickString(payload, "dst_ip", "dest_ip", "destination_ip", "entities.target_ip"),
		Protocol:  xdrPickString(payload, "protocol", "proto"),
		Signature: xdrPickString(payload, "message", "signature", "rule_name"),
		Category:  xdrPickString(payload, "category", "event_type", "type"),
		Severity:  webhookSeverityUint8(severity),
		Status:    xdrPickString(payload, "status"),
		SensorID:  xdrPickString(payload, "sensor_id", "agent_id"),
		Domain:    xdrPickString(payload, "domain"),
	}
}

// webhookSeverityUint8 maps severity names to the model.Alert scale.
func webhookSeverityUint8(severity string) uint8 {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return model.AlertSeverityCritical
	case "high":
		return model.AlertSeverityHigh
	case "medium":
		return model.AlertSeverityMedium
	default:
		return model.AlertSeverityLow
	}
}
