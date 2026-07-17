package com.lyflow.rasp.java.exporter;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.lyflow.rasp.java.config.RASPConfig;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.security.GeneralSecurityException;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class RASPBridgeTransport {
    private static final long CONFIG_REFRESH_NANOS = TimeUnit.SECONDS.toNanos(30);

    private final RASPConfig config;
    private volatile long lastConfigPullNanos = Long.MIN_VALUE;

    RASPBridgeTransport(RASPConfig config) {
        this.config = config;
        validateLocalEndpoint(config.getServerAddr());
    }

    void refreshConfig() throws IOException {
        long now = System.nanoTime();
        if (lastConfigPullNanos != Long.MIN_VALUE && now - lastConfigPullNanos < CONFIG_REFRESH_NANOS) {
            return;
        }
        HttpURLConnection connection = openConnection("/v1/rasp/config", "GET");
        try {
            int status = connection.getResponseCode();
            if (status == HttpURLConnection.HTTP_UNAUTHORIZED || status == HttpURLConnection.HTTP_FORBIDDEN) {
                throw new ControlAuthorizationException();
            }
            if (status != HttpURLConnection.HTTP_OK) {
                throw new IOException("RASP config pull returned " + status);
            }
            JsonObject response;
            try {
                response = JsonParser.parseString(
                        readBounded(connection.getInputStream(), config.getReadLimitBytes())).getAsJsonObject();
            } catch (RuntimeException error) {
                throw new ConfigIntegrityException("config_payload_invalid", error);
            }
            try {
                if (!"lyflow.rasp_bridge_config.v1".equals(response.get("schema_version").getAsString())
                        || !config.getAgentID().equals(response.get("agent_id").getAsString())) {
                    throw new ConfigIntegrityException("config_binding_invalid");
                }
                verifySignature(response);
                JsonObject limits = response.getAsJsonObject("limits");
                config.applyRuntimeLimits(
                        positiveInt(limits, "queue_capacity"),
                        positiveInt(limits, "read_bytes"),
                        positiveInt(limits, "cpu_budget_ms"),
                        positiveInt(limits, "memory_bytes"),
                        positiveInt(limits, "restart_budget"));
                config.setPolicyID(response.get("policy_id").getAsString());
                config.setPolicyVersion(response.get("policy_version").getAsLong());
                config.setBridgeToken(response.get("bridge_token").getAsString());
                config.setMode(response.get("policy_mode").getAsString());
                config.setExpiresAtEpochSecond(Instant.parse(response.get("expires_at").getAsString()).getEpochSecond());
                lastConfigPullNanos = now;
            } catch (RuntimeException error) {
                throw new ConfigIntegrityException("config_payload_invalid", error);
            }
        } finally {
            connection.disconnect();
        }
    }

    private void verifySignature(JsonObject response) throws IOException {
        if (!response.has("config_signature") || !response.has("limits")) {
            throw new ConfigIntegrityException("config_signature_invalid");
        }
        JsonObject signed = new JsonObject();
        signed.addProperty("agent_id", response.get("agent_id").getAsString());
        signed.addProperty("bridge_token", response.get("bridge_token").getAsString());
        signed.addProperty("expires_at", response.get("expires_at").getAsString());
        JsonObject sourceLimits = response.getAsJsonObject("limits");
        JsonObject limits = new JsonObject();
        limits.addProperty("cpu_budget_ms", positiveInt(sourceLimits, "cpu_budget_ms"));
        limits.addProperty("memory_bytes", positiveInt(sourceLimits, "memory_bytes"));
        limits.addProperty("queue_capacity", positiveInt(sourceLimits, "queue_capacity"));
        limits.addProperty("read_bytes", positiveInt(sourceLimits, "read_bytes"));
        limits.addProperty("restart_budget", positiveInt(sourceLimits, "restart_budget"));
        signed.add("limits", limits);
        signed.addProperty("policy_id", response.get("policy_id").getAsString());
        signed.addProperty("policy_mode", response.get("policy_mode").getAsString());
        signed.addProperty("policy_version", response.get("policy_version").getAsLong());
        signed.addProperty("schema_version", response.get("schema_version").getAsString());
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(config.getBridgeToken().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String expected = HexFormat.of().formatHex(mac.doFinal(signed.toString().getBytes(StandardCharsets.UTF_8)));
            if (!java.security.MessageDigest.isEqual(
                    expected.getBytes(StandardCharsets.US_ASCII),
                    response.get("config_signature").getAsString().getBytes(StandardCharsets.US_ASCII))) {
                throw new ConfigIntegrityException("config_signature_invalid");
            }
        } catch (GeneralSecurityException error) {
            throw new ConfigIntegrityException("config_signature_invalid", error);
        }
    }

    private static int positiveInt(JsonObject values, String name) throws ConfigIntegrityException {
        if (!values.has(name)) {
            throw new ConfigIntegrityException("config_limits_invalid");
        }
        int value = values.get(name).getAsInt();
        if (value <= 0) {
            throw new ConfigIntegrityException("config_limits_invalid");
        }
        return value;
    }

    void send(JsonObject payload, Gson gson) throws IOException {
        HttpURLConnection connection = openConnection("/v1/rasp/events", "POST");
        connection.setDoOutput(true);
        byte[] encoded = gson.toJson(payload).getBytes(StandardCharsets.UTF_8);
        try {
            try (OutputStream output = connection.getOutputStream()) {
                output.write(encoded);
            }
            int status = connection.getResponseCode();
            if (status == HttpURLConnection.HTTP_UNAUTHORIZED || status == HttpURLConnection.HTTP_FORBIDDEN) {
                throw new ControlAuthorizationException();
            }
            if (status != 202) {
                throw new IOException("RASP bridge returned " + status);
            }
        } finally {
            connection.disconnect();
        }
    }

    void sendControlHealth(JsonObject payload, Gson gson) throws IOException {
        HttpURLConnection connection = openConnection("/v1/rasp/health", "POST");
        connection.setDoOutput(true);
        byte[] encoded = gson.toJson(payload).getBytes(StandardCharsets.UTF_8);
        try {
            try (OutputStream output = connection.getOutputStream()) {
                output.write(encoded);
            }
            int status = connection.getResponseCode();
            if (status != 202) {
                throw new IOException("RASP control health bridge returned " + status);
            }
        } finally {
            connection.disconnect();
        }
    }

    private HttpURLConnection openConnection(String path, String method) throws IOException {
        URL url = new URL(config.getServerAddr().replaceAll("/+$", "") + path);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method);
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setRequestProperty("X-Ly-RASP-Token", config.getBridgeToken());
        connection.setRequestProperty("X-Lyflow-Agent-ID", config.getAgentID());
        connection.setConnectTimeout(2000);
        connection.setReadTimeout(2000);
        return connection;
    }

    private static void validateLocalEndpoint(String endpoint) {
        try {
            URI uri = URI.create(endpoint);
            String host = uri.getHost();
            boolean loopback = "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host) || "::1".equals(host);
            if (!"http".equalsIgnoreCase(uri.getScheme()) || !loopback || uri.getUserInfo() != null || uri.getQuery() != null || uri.getFragment() != null) {
                throw new IllegalArgumentException("RASP bridge endpoint must be loopback HTTP");
            }
        } catch (RuntimeException error) {
            throw new IllegalArgumentException("RASP bridge endpoint invalid", error);
        }
    }

    private static String readBounded(InputStream input, int limit) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int total = 0;
        int read;
        while ((read = input.read(buffer)) != -1) {
            total += read;
            if (total > limit) {
                throw new RuntimeBudgetException("read_budget_exceeded");
            }
            output.write(buffer, 0, read);
        }
        return output.toString(StandardCharsets.UTF_8.name());
    }
}
