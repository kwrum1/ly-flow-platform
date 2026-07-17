package com.lyflow.rasp.java.exporter;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.model.RASPEvent;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

final class RuntimeControlFailureTest {
    private static final Set<String> CANONICAL_HEALTH_FIELDS = Set.of(
            "schema_version", "event_type", "runtime", "status", "reason",
            "prevention_enabled", "fail_policy", "limits", "restart_count", "watchdog_at", "publication");

    @TempDir
    Path temporary;

    @Test
    void authorizationFailureFailsClosedAndEmitsCanonicalHealth() throws Exception {
        // Given
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/rasp/config", exchange -> {
            exchange.sendResponseHeaders(401, -1);
            exchange.close();
        });
        server.start();
        RASPConfig config = bridgeConfig(server);
        OTLPExporter exporter = new OTLPExporter(config);

        try {
            // When
            exporter.exportSync(event());

            // Then
            Map<String, Object> health = exporter.getDeliveryHealth();
            assertEquals(CANONICAL_HEALTH_FIELDS, health.keySet());
            assertEquals("authorization_failed", health.get("reason"));
            assertFalse((Boolean) health.get("prevention_enabled"));
            assertEquals("off", config.getMode());
            assertCanonicalFallback("authorization_failed");
        } finally {
            exporter.shutdown();
            server.stop(0);
        }
    }

    @Test
    void oversizedConfigResponseEnforcesReadBudget() throws Exception {
        // Given
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/rasp/config", exchange -> {
            byte[] body = " ".repeat(2048).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        RASPConfig config = bridgeConfig(server);
        config.applyRuntimeLimits(8, 1024, 50, 1_048_576, 3);
        OTLPExporter exporter = new OTLPExporter(config);

        try {
            // When
            exporter.exportSync(event());

            // Then
            assertEquals("read_budget_exceeded", exporter.getDeliveryHealth().get("reason"));
            assertEquals("monitor", config.getMode());
        } finally {
            exporter.shutdown();
            server.stop(0);
        }
    }

    @Test
    void oversizedEventEnforcesMemoryBudget() {
        // Given
        RASPConfig config = new RASPConfig();
        config.setPolicyVersion(15);
        config.setEvidencePath(temporary.resolve("events.jsonl").toString());
        config.setFallbackPath(temporary.resolve("memory-fallback.jsonl").toString());
        config.applyRuntimeLimits(8, 65_536, 50, 1024, 3);
        OTLPExporter exporter = new OTLPExporter(config);
        RASPEvent oversized = RASPEvent.builder()
                .type(RASPEvent.TYPE_SQL_INJECTION)
                .severity(RASPEvent.SEVERITY_LOW)
                .context(Map.of("evidence", "x".repeat(2048)))
                .build();

        try {
            // When
            exporter.exportSync(oversized);

            // Then
            assertEquals("memory_budget_exceeded", exporter.getDeliveryHealth().get("reason"));
            assertEquals("monitor", config.getMode());
        } finally {
            exporter.shutdown();
        }
    }

    @Test
    void binaryIntegrityFailureEmitsCanonicalHealth() throws Exception {
        // Given
        Path binary = temporary.resolve("runtime.jar");
        Files.writeString(binary, "trusted", StandardCharsets.UTF_8);
        RASPConfig config = new RASPConfig();
        config.setEvidencePath(temporary.resolve("events.jsonl").toString());
        config.setFallbackPath(temporary.resolve("fallback.jsonl").toString());
        config.setBinaryPath(binary.toString());
        config.setBinarySha256(HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest("different".getBytes(StandardCharsets.UTF_8))));

        // When
        OTLPExporter exporter = new OTLPExporter(config);

        try {
            // Then
            assertEquals("off", config.getMode());
            assertCanonicalFallback("binary_integrity_failed");
        } finally {
            exporter.shutdown();
        }
    }

    private RASPConfig bridgeConfig(HttpServer server) {
        RASPConfig config = new RASPConfig();
        config.setServerAddr("http://127.0.0.1:" + server.getAddress().getPort());
        config.setAgentID("agent-java");
        config.setBridgeToken("bridge-secret");
        config.setPolicyID("todo15");
        config.setPolicyVersion(15);
        config.setFallbackPath(temporary.resolve("fallback.jsonl").toString());
        return config;
    }

    private static RASPEvent event() {
        return RASPEvent.builder()
                .type(RASPEvent.TYPE_SQL_INJECTION)
                .severity(RASPEvent.SEVERITY_LOW)
                .methodName("execute")
                .build();
    }

    private void assertCanonicalFallback(String reason) throws IOException {
        JsonObject record = JsonParser.parseString(Files.readString(
                temporary.resolve("fallback.jsonl"), StandardCharsets.UTF_8)).getAsJsonObject();
        JsonObject event = record.getAsJsonObject("event");
        assertEquals(CANONICAL_HEALTH_FIELDS, event.keySet());
        assertEquals(reason, event.get("reason").getAsString());
    }
}
