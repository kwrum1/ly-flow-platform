package com.lyflow.rasp.java;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

final class AgentIT {
    @Test
    void monitorAgentPreservesFixtureResultsAndEmitsFourCanonicalContracts() throws Exception {
        // Given
        Path temporary = Files.createTempDirectory("java-rasp-it-");
        Path evidence = temporary.resolve("events.jsonl");
        Path fallback = temporary.resolve("fallback.jsonl");

        // When
        ProcessResult baseline = runFixture(null);
        String options = "mode=monitor,policyVersion=14,policyId=todo14,agentId=java-fixture,"
                + "app=todo14-fixture,packages=com.lyflow.rasp.fixture,evidence=" + evidence
                + ",fallback=" + fallback;
        ProcessResult monitored = runFixture(options);

        // Then
        assertEquals(0, baseline.exitCode());
        assertEquals(0, monitored.exitCode());
        assertEquals(baseline.stdout(), monitored.stdout());
        assertEquals(
                "sql:true\ncommand:0\nfile:file-ok\ndeserialize:deserialize-ok\n",
                monitored.stdout());
        assertCanonicalContracts(evidence);
        deleteTree(temporary);
    }

    private static ProcessResult runFixture(String agentOptions) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        ProcessBuilder builder;
        if (agentOptions == null) {
            builder = new ProcessBuilder(java, "-cp", "target/test-classes", "com.lyflow.rasp.fixture.FixtureMain");
        } else {
            builder = new ProcessBuilder(
                    java,
                    "-javaagent:target/ly-rasp-java-1.0.0.jar=" + agentOptions,
                    "-cp",
                    "target/test-classes",
                    "com.lyflow.rasp.fixture.FixtureMain");
        }
        builder.redirectError(ProcessBuilder.Redirect.INHERIT);
        Process process = builder.start();
        boolean completed = process.waitFor(Duration.ofSeconds(20).toMillis(), TimeUnit.MILLISECONDS);
        assertTrue(completed, "fixture process timed out");
        String stdout = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        return new ProcessResult(process.exitValue(), stdout);
    }

    private static void assertCanonicalContracts(Path evidence) throws IOException {
        List<String> lines = Files.readAllLines(evidence, StandardCharsets.UTF_8);
        Set<String> types = new HashSet<>();
        for (String line : lines) {
            JsonObject event = JsonParser.parseString(line).getAsJsonObject();
            assertEquals("lyflow.rasp_bridge_event.v1", event.get("schema_version").getAsString());
            assertEquals(14, event.get("policy_version").getAsInt());
            types.add(event.get("event_type").getAsString());
        }
        assertEquals(Set.of("rasp.sql", "rasp.command", "rasp.file", "rasp.deserialization"), types);
    }

    private static void deleteTree(Path root) throws IOException {
        try (var paths = Files.walk(root)) {
            paths.sorted((left, right) -> right.compareTo(left)).forEach(path -> {
                try {
                    Files.delete(path);
                } catch (IOException error) {
                    throw new IllegalStateException(error);
                }
            });
        }
    }

    private record ProcessResult(int exitCode, String stdout) {
    }
}
