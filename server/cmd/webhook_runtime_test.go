package main

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisMessage builds an alert stream message in the same shape the consumer
// receives (a JSON document under the "data" field).
func redisMessage(payload map[string]interface{}) redis.XMessage {
	raw, _ := json.Marshal(payload)
	return redis.XMessage{ID: "1-1", Values: map[string]interface{}{"data": string(raw)}}
}

// fakeEnv returns an environment lookup over a fixed map.
func fakeEnv(values map[string]string) func(string) string {
	return func(key string) string {
		return values[key]
	}
}

// TestStartWebhookRuntimeNoChannelsConfigured asserts that an empty
// configuration starts nothing and returns no error.
func TestStartWebhookRuntimeNoChannelsConfigured(t *testing.T) {
	launched := 0
	runtime, err := startWebhookRuntimeWithLauncher(context.Background(), &Config{}, fakeEnv(map[string]string{}), func(func()) {
		launched++
	})
	if err != nil {
		t.Fatalf("expected no error without configuration, got %v", err)
	}
	if runtime != nil {
		t.Fatalf("expected nil runtime without configuration, got %#v", runtime)
	}
	if launched != 0 {
		t.Fatalf("expected zero launched goroutines, got %d", launched)
	}
}

// TestStartWebhookRuntimeNoChannelsDoesNoExtraWork proves the disabled path is
// a single pass over the three channel variables: no schedule parsing, no
// boolean parsing, no manager construction.
func TestStartWebhookRuntimeNoChannelsDoesNoExtraWork(t *testing.T) {
	var probed []string
	runtime, err := startWebhookRuntimeWithLauncher(context.Background(), &Config{}, func(key string) string {
		probed = append(probed, key)
		return ""
	}, func(func()) {
		t.Fatalf("must not launch workers without configuration")
	})
	if err != nil || runtime != nil {
		t.Fatalf("expected disabled runtime, got runtime=%v err=%v", runtime, err)
	}
	if len(probed) != 3 {
		t.Fatalf("expected exactly the 3 channel variables to be read, got %v", probed)
	}
	for _, key := range probed {
		switch key {
		case webhookEnvDingTalkURL, webhookEnvWeComURL, webhookEnvFeishuURL:
		default:
			t.Fatalf("disabled path read unexpected variable %q", key)
		}
	}
}

// TestStartWebhookRuntimeWhitespaceOnlyURLIsRejected keeps URL validation
// strict: a configured-but-blank value is an error, not silent disabling.
func TestStartWebhookRuntimeWhitespaceOnlyURLIsRejected(t *testing.T) {
	launched := 0
	runtime, err := startWebhookRuntimeWithLauncher(context.Background(), &Config{}, fakeEnv(map[string]string{
		webhookEnvDingTalkURL: "   ",
	}), func(func()) { launched++ })
	if err == nil || !strings.Contains(err.Error(), "must not be empty") {
		t.Fatalf("expected empty-URL validation error, got %v", err)
	}
	if runtime != nil || launched != 0 {
		t.Fatalf("expected disabled runtime, got runtime=%v launched=%d", runtime, launched)
	}
}

func TestStartWebhookRuntimeSingleChannelEnabled(t *testing.T) {
	var mu sync.Mutex
	var launched int
	runtime, err := startWebhookRuntimeWithLauncher(context.Background(), &Config{}, fakeEnv(map[string]string{
		webhookEnvDingTalkURL: "https://example.invalid/hook",
	}), func(func()) {
		mu.Lock()
		launched++
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runtime == nil || !runtime.Enabled() {
		t.Fatalf("expected enabled runtime, got %#v", runtime)
	}
	channels := runtime.Channels()
	if len(channels) != 1 || channels[0].Type != "dingtalk" {
		t.Fatalf("expected only dingtalk channel, got %#v", channels)
	}
	if channels[0].URL != "https://example.invalid/hook" {
		t.Fatalf("expected channel URL to be retained, got %q", channels[0].URL)
	}
	// Defaults: alert notifications and the daily report are both enabled.
	mu.Lock()
	defer mu.Unlock()
	if launched != 2 {
		t.Fatalf("expected 2 launched workers (alert + daily report), got %d", launched)
	}
	if !runtime.alertNotifyEnabled || !runtime.dailyReportEnabled {
		t.Fatalf("expected both workers enabled by default: %#v", runtime)
	}
	if runtime.reportHour != 8 || runtime.reportMinute != 0 {
		t.Fatalf("expected default report time 08:00, got %02d:%02d", runtime.reportHour, runtime.reportMinute)
	}
}

func TestStartWebhookRuntimeAllChannelsEnabled(t *testing.T) {
	runtime, err := startWebhookRuntimeWithLauncher(context.Background(), &Config{}, fakeEnv(map[string]string{
		webhookEnvDingTalkURL: "https://example.invalid/dingtalk",
		webhookEnvWeComURL:    "https://example.invalid/wecom",
		webhookEnvFeishuURL:   "http://example.invalid/feishu",
	}), func(func()) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := len(runtime.Channels()); got != 3 {
		t.Fatalf("expected 3 channels, got %d", got)
	}
}

func TestStartWebhookRuntimeRejectsInvalidURLs(t *testing.T) {
	cases := []struct {
		name    string
		env     map[string]string
		wantSub string
	}{
		{
			name:    "blank value is not treated as configured",
			env:     map[string]string{webhookEnvWeComURL: ""},
			wantSub: "",
		},
		{
			name:    "relative url",
			env:     map[string]string{webhookEnvFeishuURL: "/hook"},
			wantSub: "must use http or https",
		},
		{
			name:    "ftp scheme",
			env:     map[string]string{webhookEnvDingTalkURL: "ftp://example.invalid/hook"},
			wantSub: "must use http or https",
		},
		{
			name:    "missing host",
			env:     map[string]string{webhookEnvDingTalkURL: "https:///hook"},
			wantSub: "must include a host",
		},
		{
			name:    "control character",
			env:     map[string]string{webhookEnvWeComURL: "https://example.invalid/\x7f"},
			wantSub: "not a valid URL",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime, err := startWebhookRuntimeWithLauncher(context.Background(), &Config{}, fakeEnv(tc.env), func(func()) {
				t.Fatalf("must not launch workers for invalid configuration")
			})
			if tc.wantSub == "" {
				if err != nil || runtime != nil {
					t.Fatalf("expected no runtime and no error, got runtime=%v err=%v", runtime, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("expected error containing %q, got %q", tc.wantSub, err.Error())
			}
			if runtime != nil {
				t.Fatalf("expected no runtime on validation failure, got %#v", runtime)
			}
		})
	}
}

func TestParseWebhookReportTime(t *testing.T) {
	valid := []struct {
		in     string
		hour   int
		minute int
	}{
		{"08:00", 8, 0},
		{"00:00", 0, 0},
		{"23:59", 23, 59},
		{"7:05", 7, 5},
		{"", 8, 0}, // default
	}
	for _, tc := range valid {
		hour, minute, err := parseWebhookReportTime(tc.in)
		if err != nil {
			t.Fatalf("parseWebhookReportTime(%q) unexpected error: %v", tc.in, err)
		}
		if hour != tc.hour || minute != tc.minute {
			t.Fatalf("parseWebhookReportTime(%q) = %02d:%02d, want %02d:%02d", tc.in, hour, minute, tc.hour, tc.minute)
		}
	}

	invalid := []string{"24:00", "08:60", "8", "08-00", "08:00:00", "aa:bb", "-1:00", "08:"}
	for _, in := range invalid {
		if _, _, err := parseWebhookReportTime(in); err == nil {
			t.Fatalf("parseWebhookReportTime(%q) expected error, got nil", in)
		}
	}
}

func TestLoadWebhookRuntimeConfigRejectsInvalidReportTime(t *testing.T) {
	_, err := startWebhookRuntimeWithLauncher(context.Background(), &Config{}, fakeEnv(map[string]string{
		webhookEnvDingTalkURL:     "https://example.invalid/hook",
		webhookEnvDailyReportTime: "25:00",
	}), func(func()) {
		t.Fatalf("must not launch workers with an invalid report time")
	})
	if err == nil || !strings.Contains(err.Error(), "HH:MM") {
		t.Fatalf("expected HH:MM validation error, got %v", err)
	}
}

func TestLoadWebhookRuntimeConfigDailyReportCanBeDisabled(t *testing.T) {
	runtime, err := startWebhookRuntimeWithLauncher(context.Background(), &Config{}, fakeEnv(map[string]string{
		webhookEnvDingTalkURL:        "https://example.invalid/hook",
		webhookEnvDailyReportEnabled: "false",
		webhookEnvAlertNotifyEnabled: "false",
		webhookEnvDailyReportTime:    "not-a-time", // ignored when disabled
	}), func(func()) {
		t.Fatalf("both workers disabled, must not launch anything")
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runtime == nil || !runtime.Enabled() {
		t.Fatalf("expected enabled runtime, got %#v", runtime)
	}
	if runtime.dailyReportEnabled || runtime.alertNotifyEnabled {
		t.Fatalf("expected both workers disabled, got %#v", runtime)
	}
	if got := runtime.dailyReportTime(); got != defaultWebhookDailyReportTime {
		t.Fatalf("expected default report time %s, got %s", defaultWebhookDailyReportTime, got)
	}
}

func TestNextWebhookReportTime(t *testing.T) {
	now := time.Date(2026, 11, 10, 7, 30, 0, 0, time.UTC)
	next := nextWebhookReportTime(now, 8, 0)
	if want := time.Date(2026, 11, 10, 8, 0, 0, 0, time.UTC); !next.Equal(want) {
		t.Fatalf("nextWebhookReportTime = %s, want %s", next, want)
	}

	after := time.Date(2026, 11, 10, 9, 30, 0, 0, time.UTC)
	nextDay := nextWebhookReportTime(after, 8, 0)
	if want := time.Date(2026, 11, 11, 8, 0, 0, 0, time.UTC); !nextDay.Equal(want) {
		t.Fatalf("nextWebhookReportTime = %s, want %s", nextDay, want)
	}
}

// TestWebhookRuntimeWiresManager confirms the reused webhook.Manager receives
// the configured channel instead of a locally reimplemented sender.
func TestWebhookRuntimeWiresManager(t *testing.T) {
	runtime, err := startWebhookRuntimeWithLauncher(context.Background(), &Config{}, fakeEnv(map[string]string{
		webhookEnvFeishuURL: "https://example.invalid/hook",
	}), func(func()) {})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	configs := runtime.manager.ListWebhooks()
	if len(configs) != 1 {
		t.Fatalf("expected 1 manager webhook, got %d", len(configs))
	}
	if configs[0].Type != "feishu" || !configs[0].Enabled {
		t.Fatalf("unexpected manager config: %#v", configs[0])
	}
	if configs[0].URL != "https://example.invalid/hook" {
		t.Fatalf("unexpected manager URL: %q", configs[0].URL)
	}
}

// TestWebhookAlertFromStreamSkipsInformational verifies stream conversion and
// that info-level noise never reaches a channel.
func TestWebhookAlertFromStreamSkipsInformational(t *testing.T) {
	if alert := webhookAlertFromStream(redisMessage(map[string]interface{}{"severity": "info"})); alert != nil {
		t.Fatalf("expected informational event to be skipped, got %#v", alert)
	}
	alert := webhookAlertFromStream(redisMessage(map[string]interface{}{
		"severity": "critical",
		"src_ip":   "192.0.2.10",
		"dst_ip":   "192.0.2.20",
		"message":  "probe",
		"category": "malware",
	}))
	if alert == nil {
		t.Fatal("expected alert from critical event")
	}
	if alert.Severity != webhookSeverityUint8("critical") || alert.SrcIP != "192.0.2.10" {
		t.Fatalf("unexpected alert mapping: %#v", alert)
	}
}
