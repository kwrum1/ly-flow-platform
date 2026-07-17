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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class WatchdogSupervisorTest {
    @TempDir
    Path temporary;

    @Test
    void productionSupervisorExhaustsRestartBudgetWithInjectedClockCount10() throws Exception {
        HttpServer server = unavailableBridge();
        try {
            for (int iteration = 0; iteration < 10; iteration++) {
                // Given
                Path fallback = temporary.resolve("watchdog-" + iteration + ".jsonl");
                RASPConfig config = new RASPConfig();
                config.setServerAddr("http://127.0.0.1:" + server.getAddress().getPort());
                config.setBridgeToken("bridge-secret");
                config.setPolicyVersion(15);
                config.setRestartBudget(1);
                config.setFallbackPath(fallback.toString());
                ManualWatchdogClock clock = new ManualWatchdogClock();
                OTLPExporter exporter = new OTLPExporter(config, () -> 0L, clock);

                try {
                    // When
                    exporter.exportSync(event());
                    clock.advance(6, TimeUnit.SECONDS);
                    clock.advance(0, TimeUnit.NANOSECONDS);
                    exporter.exportSync(event());
                    clock.advance(6, TimeUnit.SECONDS);
                    assertTrue(exporter.awaitWatchdogStopped(1, TimeUnit.SECONDS));

                    // Then
                    Map<String, Object> health = exporter.getDeliveryHealth();
                    assertEquals("lyflow.control_health.v1", health.get("schema_version"));
                    assertEquals("restart_budget_exhausted", health.get("reason"));
                    assertEquals(1, health.get("restart_count"));
                    assertEquals("off", config.getMode());
                    assertEquals(false, health.get("prevention_enabled"));
                    assertTrue(emittedRestartExhaustion(fallback));
                } finally {
                    exporter.shutdown();
                    assertTrue(exporter.executorsTerminated());
                }
            }
        } finally {
            server.stop(0);
        }
    }

    private static HttpServer unavailableBridge() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
        });
        server.start();
        return server;
    }

    private static RASPEvent event() {
        return RASPEvent.builder()
                .type(RASPEvent.TYPE_SQL_INJECTION)
                .severity(RASPEvent.SEVERITY_LOW)
                .appName("todo15-watchdog")
                .methodName("execute")
                .build();
    }

    private static boolean emittedRestartExhaustion(Path fallback) throws IOException {
        List<String> records = Files.readAllLines(fallback, StandardCharsets.UTF_8);
        for (String record : records) {
            JsonObject event = JsonParser.parseString(record).getAsJsonObject().getAsJsonObject("event");
            if (event.has("schema_version")
                    && "lyflow.control_health.v1".equals(event.get("schema_version").getAsString())
                    && "restart_budget_exhausted".equals(event.get("reason").getAsString())) {
                return true;
            }
        }
        return false;
    }

    private static final class ManualWatchdogClock implements OTLPExporter.WatchdogClock {
        private final SynchronousQueue<Long> advances = new SynchronousQueue<>();
        private long nanos;

        @Override
        public synchronized long nanoTime() {
            return nanos;
        }

        @Override
        public synchronized Instant now() {
            return Instant.parse("2026-07-15T00:00:00Z").plusNanos(nanos);
        }

        @Override
        public boolean await(CountDownLatch stopped, long timeoutNanos) throws InterruptedException {
            if (stopped.getCount() == 0) {
                return true;
            }
            Long delta = advances.take();
            synchronized (this) {
                nanos += delta;
            }
            return stopped.getCount() == 0;
        }

        void advance(long value, TimeUnit unit) throws InterruptedException {
            advances.put(unit.toNanos(value));
        }
    }
}
