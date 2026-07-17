package com.lyflow.rasp.java.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class InstrumentationScopeTest {
    @Test
    void explicitApplicationPackagesAreNormalized() {
        // Given
        InstrumentationScope scope = InstrumentationScope.parse("com.example.app;org.example.worker");

        // When / Then
        assertTrue(scope.matches("com/example/app/Service"));
        assertTrue(scope.matches("org/example/worker/Job"));
        assertFalse(scope.matches("org/example/other/Job"));
    }

    @Test
    void systemAndAgentPackagesAreRejected() {
        // Given / When / Then
        assertThrows(IllegalArgumentException.class, () -> InstrumentationScope.parse("java.lang"));
        assertThrows(IllegalArgumentException.class, () -> InstrumentationScope.parse("com.lyflow.rasp.java"));
    }
}
