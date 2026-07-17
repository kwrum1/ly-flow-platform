package com.lyflow.rasp.java.exporter;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.model.RASPEvent;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class ExporterHealthTest {
    @TempDir
    Path temporary;

    @Test
    void controlHealthPublicationRetriesAndRecovers() throws Exception {
        // Given
        AtomicBoolean failing = new AtomicBoolean(true);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/rasp/config", ExporterHealthTest::sendConfig);
        server.createContext("/v1/rasp/events", exchange -> {
            exchange.sendResponseHeaders(failing.get() ? 503 : 202, -1);
            exchange.close();
        });
        server.createContext("/v1/rasp/health", exchange -> {
            exchange.sendResponseHeaders(failing.get() ? 503 : 202, -1);
            exchange.close();
        });
        server.start();
        RASPConfig config = bridgeConfig(server);
        OTLPExporter exporter = new OTLPExporter(config);

        try {
            // When
            exporter.exportSync(event());
            Map<String, Object> failed = exporter.getDeliveryHealth();
            assertTrue(exporter.getLastPublicationFailure() instanceof ControlHealthPublicationException);
            failing.set(false);
            exporter.exportSync(event());
            Map<String, Object> recovered = exporter.getDeliveryHealth();

            // Then
            assertEquals("degraded", ((Map<?, ?>) failed.get("publication")).get("status"));
            assertEquals(3L, ((Map<?, ?>) failed.get("publication")).get("retry_count"));
            assertEquals("healthy", ((Map<?, ?>) recovered.get("publication")).get("status"));
            assertEquals("", ((Map<?, ?>) recovered.get("publication")).get("last_error"));
            assertEquals(null, exporter.getLastPublicationFailure());
            assertEquals(true, recovered.get("prevention_enabled"));
        } finally {
            exporter.shutdown();
            server.stop(0);
        }
    }

    @Test
    void blockedTransportCannotGrowQueuePastCapacity() throws Exception {
        // Given
        CountDownLatch requestStarted = new CountDownLatch(1);
        CountDownLatch releaseRequest = new CountDownLatch(1);
        HttpServer server = bridgeServer(exchange -> {
            requestStarted.countDown();
            await(releaseRequest);
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
        });
        RASPConfig config = bridgeConfig(server);
        config.applyRuntimeLimits(2, 65_536, 50, 1_048_576, 3);
        config.setMaxEventsPerSecond(1000);
        OTLPExporter exporter = new OTLPExporter(config);

        try {
            // When
            exporter.export(event());
            assertTrue(requestStarted.await(5, TimeUnit.SECONDS));
            for (int index = 0; index < 300; index++) {
                exporter.export(event());
            }

            // Then
            Map<String, Object> health = exporter.getDeliveryHealth();
            assertTrue(exporter.getQueueSize() <= (Integer) ((Map<?, ?>) health.get("limits")).get("queue_capacity"));
            assertEquals(2, ((Map<?, ?>) health.get("limits")).get("queue_capacity"));
        } finally {
            releaseRequest.countDown();
            exporter.shutdown();
            server.stop(0);
        }
    }

    @Test
    void exporterOutageFallsBackAndReportsDegradedHealth() throws Exception {
        // Given
        HttpServer server = bridgeServer(exchange -> {
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
        });
        RASPConfig config = bridgeConfig(server);
        OTLPExporter exporter = new OTLPExporter(config);

        try {
            // When
            exporter.exportSync(event());

            // Then
            Map<String, Object> health = exporter.getDeliveryHealth();
            assertEquals("degraded", health.get("status"));
            assertEquals("exporter_unavailable", health.get("reason"));
            assertEquals(true, health.get("prevention_enabled"));
            assertEquals("degraded", ((Map<?, ?>) health.get("publication")).get("status"));
            assertEquals(3L, ((Map<?, ?>) health.get("publication")).get("retry_count"));
            assertTrue(Files.size(temporary.resolve("fallback.jsonl")) > 0);
        } finally {
            exporter.shutdown();
            server.stop(0);
        }
    }

    @Test
    void invalidConfigSignatureDisablesPreventionAndReportsCanonicalHealth() throws Exception {
        // Given
        HttpServer server = bridgeServer(exchange -> {
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
        });
        server.removeContext("/v1/rasp/config");
        server.createContext("/v1/rasp/config", exchange -> sendConfig(exchange, "0".repeat(64)));
        RASPConfig config = bridgeConfig(server);
        OTLPExporter exporter = new OTLPExporter(config);

        try {
            // When
            exporter.exportSync(event());

            // Then
            Map<String, Object> health = exporter.getDeliveryHealth();
            assertEquals("lyflow.control_health.v1", health.get("schema_version"));
            assertEquals("config_signature_invalid", health.get("reason"));
            assertEquals(false, health.get("prevention_enabled"));
            assertEquals("off", config.getMode());
        } finally {
            exporter.shutdown();
            server.stop(0);
        }
    }

    @Test
    void canonicalHealthMarshalsJavaInstantAsUtcString() {
        // Given
        RASPConfig config = new RASPConfig();
        config.setEvidencePath(temporary.resolve("events.jsonl").toString());
        OTLPExporter exporter = new OTLPExporter(config);

        try {
            // When
            String health = exporter.getDeliveryHealthJson();

            // Then
            assertTrue(health.matches(".*\\\"watchdog_at\\\":\\\"[^\\\"]+Z\\\".*"), health);
        } finally {
            exporter.shutdown();
        }
    }

    @Test
    void binaryIntegrityFailureDisablesRuntime() throws Exception {
        // Given
        Path binary = temporary.resolve("runtime.jar");
        Files.writeString(binary, "trusted", StandardCharsets.UTF_8);
        RASPConfig config = new RASPConfig();
        config.setEvidencePath(temporary.resolve("events.jsonl").toString());
        config.setBinaryPath(binary.toString());
        config.setBinarySha256(java.util.HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest("different".getBytes(StandardCharsets.UTF_8))));

        // When
        OTLPExporter exporter = new OTLPExporter(config);

        try {
            // Then
            assertEquals("binary_integrity_failed", exporter.getDeliveryHealth().get("reason"));
            assertEquals("off", config.getMode());
        } finally {
            exporter.shutdown();
        }
    }

    @Test
    void restartBudgetExhaustionReportsCanonicalDegradedHealth() {
        // Given
        RASPConfig config = new RASPConfig();
        config.setRestartBudget(1);
        config.setEvidencePath(temporary.resolve("events.jsonl").toString());
        OTLPExporter exporter = new OTLPExporter(config);

        try {
            // When
            assertTrue(config.recordWatchdogRestart());
            assertEquals(false, config.recordWatchdogRestart());

            // Then
            Map<String, Object> health = exporter.getDeliveryHealth();
            assertEquals("degraded", health.get("status"));
            assertEquals("restart_budget_exhausted", health.get("reason"));
            assertEquals("off", config.getMode());
        } finally {
            exporter.shutdown();
        }
    }

    @Test
    void cpuBudgetStopsExporterWorkAndFailsObservationOpen() {
        // Given
        RASPConfig config = new RASPConfig();
        config.setPolicyVersion(15);
        config.applyRuntimeLimits(128, 65536, 1, 1048576, 3);
        config.setEvidencePath(temporary.resolve("events.jsonl").toString());
        AtomicLong clock = new AtomicLong();
        OTLPExporter exporter = new OTLPExporter(config, () -> clock.getAndAdd(TimeUnit.MILLISECONDS.toNanos(2)));

        try {
            // When
            exporter.exportSync(event());

            // Then
            Map<String, Object> health = exporter.getDeliveryHealth();
            assertEquals("cpu_budget_exceeded", health.get("reason"));
            assertEquals(true, health.get("prevention_enabled"));
            assertEquals("monitor", config.getMode());
        } finally {
            exporter.shutdown();
        }
    }

    private HttpServer bridgeServer(EventHandler eventHandler) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/rasp/config", ExporterHealthTest::sendConfig);
        server.createContext("/v1/rasp/events", eventHandler::handle);
        server.start();
        return server;
    }

    private RASPConfig bridgeConfig(HttpServer server) {
        RASPConfig config = new RASPConfig();
        config.setServerAddr("http://127.0.0.1:" + server.getAddress().getPort());
        config.setAgentID("agent-java");
        config.setBridgeToken("bridge-secret");
        config.setPolicyID("todo14");
        config.setPolicyVersion(14);
        config.setFallbackPath(temporary.resolve("fallback.jsonl").toString());
        return config;
    }

    private static RASPEvent event() {
        return RASPEvent.builder()
                .type(RASPEvent.TYPE_SQL_INJECTION)
                .severity(RASPEvent.SEVERITY_LOW)
                .appName("todo14-fixture")
                .methodName("execute")
                .build();
    }

    private static void sendConfig(HttpExchange exchange) throws IOException {
        String unsigned = "{\"agent_id\":\"agent-java\",\"bridge_token\":\"bridge-secret\","
                + "\"expires_at\":\"2099-01-01T00:00:00Z\","
                + "\"limits\":{\"cpu_budget_ms\":50,\"memory_bytes\":1048576,\"queue_capacity\":128,\"read_bytes\":65536,\"restart_budget\":3},"
                + "\"policy_id\":\"todo14\",\"policy_mode\":\"monitor\",\"policy_version\":14,"
                + "\"schema_version\":\"lyflow.rasp_bridge_config.v1\"}";
        try {
            sendConfig(exchange, hmac(unsigned, "bridge-secret"));
        } catch (GeneralSecurityException error) {
            throw new IOException("sign fixture config", error);
        }
    }

    private static void sendConfig(HttpExchange exchange, String signature) throws IOException {
        byte[] body = ("{\"schema_version\":\"lyflow.rasp_bridge_config.v1\","
                + "\"agent_id\":\"agent-java\",\"policy_id\":\"todo14\","
                + "\"policy_version\":14,\"policy_mode\":\"monitor\","
                + "\"expires_at\":\"2099-01-01T00:00:00Z\",\"bridge_token\":\"bridge-secret\","
                + "\"limits\":{\"queue_capacity\":128,\"read_bytes\":65536,\"cpu_budget_ms\":50,\"memory_bytes\":1048576,\"restart_budget\":3},"
                + "\"config_signature\":\"" + signature + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private static String hmac(String value, String secret) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return java.util.HexFormat.of().formatHex(mac.doFinal(value.getBytes(StandardCharsets.UTF_8)));
    }

    private static void await(CountDownLatch latch) throws IOException {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IOException("timed out waiting to release bridge request");
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new IOException("bridge request interrupted", error);
        }
    }

    @FunctionalInterface
    private interface EventHandler {
        void handle(HttpExchange exchange) throws IOException;
    }
}
