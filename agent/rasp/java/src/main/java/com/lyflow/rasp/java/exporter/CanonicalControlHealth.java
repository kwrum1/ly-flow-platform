package com.lyflow.rasp.java.exporter;

import com.google.gson.JsonObject;
import com.lyflow.rasp.java.config.RASPConfig;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

final class CanonicalControlHealth {
    private final RASPConfig config;
    private final String runtime;
    private final int queueCapacity;
    private final String status;
    private final String reason;
    private final Instant watchdogAt;
    private final ControlHealthPublication publication;

    CanonicalControlHealth(
            RASPConfig config,
            String runtime,
            int queueCapacity,
            String status,
            String reason,
            Instant watchdogAt,
            ControlHealthPublication publication) {
        this.config = config;
        this.runtime = runtime;
        this.queueCapacity = queueCapacity;
        this.status = status;
        this.reason = reason;
        this.watchdogAt = watchdogAt;
        this.publication = publication;
    }

    Map<String, Object> asMap() {
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("schema_version", "lyflow.control_health.v1");
        health.put("event_type", "control.health");
        health.put("runtime", runtime);
        health.put("status", status);
        health.put("reason", reason);
        health.put("prevention_enabled", config.isPreventionEnabled());
        health.put("fail_policy", Map.of(
                "observation", "fail_open",
                "integrity", "fail_closed",
                "authorization", "fail_closed"));
        health.put("limits", Map.of(
                "queue_capacity", queueCapacity,
                "read_bytes", config.getReadLimitBytes(),
                "cpu_budget_ms", config.getCpuBudgetMillis(),
                "memory_bytes", config.getMemoryBudgetBytes(),
                "restart_budget", config.getRestartBudget()));
        health.put("restart_count", config.getRestartCount());
        health.put("watchdog_at", watchdogAt);
        health.put("publication", publication.asMap());
        return health;
    }

    JsonObject asJson() {
        JsonObject event = new JsonObject();
        event.addProperty("schema_version", "lyflow.control_health.v1");
        event.addProperty("event_type", "control.health");
        event.addProperty("runtime", runtime);
        event.addProperty("status", status);
        event.addProperty("reason", reason);
        event.addProperty("prevention_enabled", config.isPreventionEnabled());
        JsonObject failPolicy = new JsonObject();
        failPolicy.addProperty("observation", "fail_open");
        failPolicy.addProperty("integrity", "fail_closed");
        failPolicy.addProperty("authorization", "fail_closed");
        event.add("fail_policy", failPolicy);
        JsonObject limits = new JsonObject();
        limits.addProperty("queue_capacity", queueCapacity);
        limits.addProperty("read_bytes", config.getReadLimitBytes());
        limits.addProperty("cpu_budget_ms", config.getCpuBudgetMillis());
        limits.addProperty("memory_bytes", config.getMemoryBudgetBytes());
        limits.addProperty("restart_budget", config.getRestartBudget());
        event.add("limits", limits);
        event.addProperty("restart_count", config.getRestartCount());
        event.addProperty("watchdog_at", watchdogAt.toString());
        event.add("publication", publication.asJson());
        return event;
    }
}
