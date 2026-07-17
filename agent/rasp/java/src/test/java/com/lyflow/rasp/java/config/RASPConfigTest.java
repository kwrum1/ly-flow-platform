package com.lyflow.rasp.java.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class RASPConfigTest {
    @Test
    void expiredPolicyUsesConfiguredFailBehavior() {
        // Given
        RASPConfig config = new RASPConfig();
        config.setMode("monitor");
        config.setExpiresAtEpochSecond(100);
        config.setFailBehavior("disable");

        // When / Then
        assertEquals("off", config.effectiveMode(101));
        config.setFailBehavior("monitor");
        assertEquals("monitor", config.effectiveMode(101));
    }

    @Test
    void eventRateLimitIsBoundedPerSecond() {
        // Given
        RASPConfig config = new RASPConfig();
        config.setMaxEventsPerSecond(2);

        // When
        boolean first = config.allowEvent(200);
        boolean second = config.allowEvent(200);
        boolean third = config.allowEvent(200);

        // Then
        assertTrue(first);
        assertTrue(second);
        assertFalse(third);
    }

    @Test
    void monitorConfigurationNeverActivatesBlocking() {
        // Given
        RASPConfig config = new RASPConfig();
        config.setMode("monitor");

        // When / Then
        assertFalse(config.shouldBlock());
    }

    @Test
    void restartLoopIsBoundedAndDisablesPrevention() {
        // Given
        RASPConfig config = new RASPConfig();
        config.setRestartBudget(2);

        // When
        boolean first = config.recordWatchdogRestart();
        boolean second = config.recordWatchdogRestart();
        boolean third = config.recordWatchdogRestart();

        // Then
        assertTrue(first);
        assertTrue(second);
        assertFalse(third);
        assertEquals("off", config.getMode());
    }
}
