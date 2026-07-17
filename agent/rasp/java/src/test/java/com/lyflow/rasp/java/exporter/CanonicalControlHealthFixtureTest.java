package com.lyflow.rasp.java.exporter;

import com.lyflow.rasp.java.config.RASPConfig;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class CanonicalControlHealthFixtureTest {
    @Test
    void generatedHealthMatchesSharedCanonicalFixtureBytes() throws Exception {
        // Given
        RASPConfig config = new RASPConfig();
        config.setPolicyVersion(15);
        config.applyRuntimeLimits(128, 1 << 20, 100, 256 << 10, 3);
        assertTrue(config.recordWatchdogRestart());
        assertTrue(config.recordWatchdogRestart());
        CanonicalControlHealth health = new CanonicalControlHealth(
                config,
                "fixture-runtime",
                128,
                "degraded",
                "control_health_delivery_unavailable",
                Instant.parse("2026-07-15T00:00:00Z"),
                new ControlHealthPublication("degraded", 3, "fixture publication unavailable"));
        Path fixture = Path.of("..", "..", "..", "contracts", "control-health", "v1", "fixture.json");

        // When
        String generated = health.asJson().toString();

        // Then
        assertEquals(Files.readString(fixture, StandardCharsets.UTF_8).trim(), generated);
    }
}
