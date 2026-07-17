package com.lyflow.rasp.java.exporter;

import com.google.gson.JsonObject;
import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.model.RASPEvent;
import java.time.Instant;
import java.util.Map;

final class CanonicalEventEncoder {
    JsonObject encode(RASPEvent event, RASPConfig config) {
        JsonObject payload = new JsonObject();
        payload.addProperty("schema_version", "lyflow.rasp_bridge_event.v1");
        payload.addProperty("event_id", event.getId());
        payload.addProperty("agent_id", config.getAgentID());
        payload.addProperty("policy_id", config.getPolicyID());
        payload.addProperty("policy_version", config.getPolicyVersion());
        payload.addProperty("language", "java");
        payload.addProperty("event_type", bridgeEventType(event.getType()));
        payload.addProperty("severity", event.getSeverity() == null ? "low" : event.getSeverity());
        payload.addProperty("observed_at", Instant.ofEpochMilli(event.getTimestamp()).toString());
        payload.addProperty("application", event.getAppName());
        payload.addProperty("rule_id", "java-monitor-" + event.getType());
        payload.addProperty("evidence", evidence(event));
        payload.addProperty("trace_id", "");
        return payload;
    }

    private static String evidence(RASPEvent event) {
        Map<String, Object> context = event.getContext();
        if (context == null || context.get("evidence") == null) {
            return event.getMethodName() == null ? event.getType() : event.getMethodName();
        }
        return String.valueOf(context.get("evidence"));
    }

    private static String bridgeEventType(String type) {
        if (RASPEvent.TYPE_SQL_INJECTION.equals(type)) return "rasp.sql";
        if (RASPEvent.TYPE_COMMAND_INJECTION.equals(type)) return "rasp.command";
        if (RASPEvent.TYPE_FILE_ACCESS.equals(type)) return "rasp.file";
        if (RASPEvent.TYPE_DESERIALIZATION.equals(type)) return "rasp.deserialization";
        return "rasp.unknown";
    }
}
