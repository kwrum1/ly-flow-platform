package com.lyflow.rasp.java.exporter;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.model.RASPEvent;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class OTLPExporterBridgeTest {
    @Test
    void bridgeDeliveryEmitsCanonicalPolicyBoundEvent() throws Exception {
        // Given
        AtomicReference<String> delivered = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/rasp/config", exchange -> handleConfig(exchange));
        server.createContext("/v1/rasp/events", exchange -> {
            requireAuthenticated(exchange);
            delivered.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(202, -1);
            exchange.close();
        });
        server.start();

        RASPConfig config = new RASPConfig();
        config.setServerAddr("http://127.0.0.1:" + server.getAddress().getPort());
        config.setAgentID("agent-java");
        config.setBridgeToken("bridge-secret");
        config.setPolicyID("policy-12");
        config.setPolicyVersion(12);
        OTLPExporter exporter = new OTLPExporter(config);
        try {
            RASPEvent event = RASPEvent.builder()
                    .type(RASPEvent.TYPE_COMMAND_INJECTION)
                    .severity(RASPEvent.SEVERITY_LOW)
                    .appName("todo12-java-fixture")
                    .methodName("inert")
                    .build();
            exporter.exportSync(event);
        } finally {
            exporter.shutdown();
            server.stop(0);
        }

        // Then
        String body = delivered.get();
        assertNotNull(body);
        assertTrue(body.contains("\"schema_version\":\"lyflow.rasp_bridge_event.v1\""));
        assertTrue(body.contains("\"agent_id\":\"agent-java\""));
        assertTrue(body.contains("\"policy_id\":\"policy-12\""));
        assertTrue(body.contains("\"policy_version\":12"));
        assertTrue(body.contains("\"event_type\":\"rasp.command\""));
    }

    private static void handleConfig(HttpExchange exchange) throws IOException {
        requireAuthenticated(exchange);
        String unsigned = "{\"agent_id\":\"agent-java\",\"bridge_token\":\"bridge-secret\","
                + "\"expires_at\":\"2099-01-01T00:00:00Z\","
                + "\"limits\":{\"cpu_budget_ms\":50,\"memory_bytes\":1048576,\"queue_capacity\":128,\"read_bytes\":65536,\"restart_budget\":3},"
                + "\"policy_id\":\"policy-12\",\"policy_mode\":\"monitor\",\"policy_version\":12,"
                + "\"schema_version\":\"lyflow.rasp_bridge_config.v1\"}";
        String signature;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec("bridge-secret".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            signature = HexFormat.of().formatHex(mac.doFinal(unsigned.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException error) {
            throw new IOException("sign bridge fixture", error);
        }
        byte[] body = ("{\"schema_version\":\"lyflow.rasp_bridge_config.v1\","
                + "\"agent_id\":\"agent-java\",\"policy_id\":\"policy-12\","
                + "\"policy_version\":12,\"policy_mode\":\"monitor\","
                + "\"expires_at\":\"2099-01-01T00:00:00Z\",\"bridge_token\":\"bridge-secret\","
                + "\"limits\":{\"queue_capacity\":128,\"read_bytes\":65536,\"cpu_budget_ms\":50,\"memory_bytes\":1048576,\"restart_budget\":3},"
                + "\"config_signature\":\"" + signature + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private static void requireAuthenticated(HttpExchange exchange) {
        if (!"bridge-secret".equals(exchange.getRequestHeaders().getFirst("X-Ly-RASP-Token"))
                || !"agent-java".equals(exchange.getRequestHeaders().getFirst("X-Lyflow-Agent-ID"))) {
            throw new AssertionError("bridge request was not authenticated");
        }
    }
}
