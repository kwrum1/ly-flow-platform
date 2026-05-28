package com.lyflow.rasp;

import java.io.OutputStream;
import java.lang.instrument.Instrumentation;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.sql.DriverManager;
import java.time.Instant;

public final class LyRaspAgent {
    private static volatile boolean started;
    private static final ThreadLocal<Boolean> EMITTING = new ThreadLocal<Boolean>();

    private LyRaspAgent() {}

    public static void premain(String args, Instrumentation inst) {
        start("premain");
    }

    public static void agentmain(String args, Instrumentation inst) {
        start("agentmain");
    }

    public static synchronized void start(String mode) {
        if (started) {
            installJdbcHook();
            return;
        }
        started = true;
        installSecurityHooks();
        installJdbcHook();
        emit("rasp.lifecycle", "java", "jvm", "LyFlow Java RASP attached via " + mode, "agent.lifecycle");
    }

    private static void installSecurityHooks() {
        if (!Boolean.parseBoolean(System.getProperty("ly.rasp.security_manager", "true"))) return;
        try {
            SecurityManager current = System.getSecurityManager();
            if (!(current instanceof LyRaspSecurityManager)) {
                System.setSecurityManager(new LyRaspSecurityManager(current));
            }
        } catch (Throwable t) {
            emit("rasp.hook_error", "java", "jvm", "security manager hook failed: " + t.getClass().getName(), "agent.security_manager");
        }
    }

    private static void installJdbcHook() {
        if (!Boolean.parseBoolean(System.getProperty("ly.rasp.jdbc_driver", "true"))) return;
        try {
            LyRaspJdbcDriver.install();
        } catch (Throwable t) {
            emit("rasp.hook_error", "java", "sql", "JDBC driver hook failed: " + t.getClass().getName() + ": " + String.valueOf(t.getMessage()), "agent.jdbc_driver");
        }
    }

    public static void emit(String eventType, String language, String hookType, String payload) {
        emit(eventType, language, hookType, payload, "java.runtime");
    }

    public static void emit(String eventType, String language, String hookType, String payload, String sink) {
        if (Boolean.TRUE.equals(EMITTING.get())) return;
        EMITTING.set(Boolean.TRUE);
        try {
            String bridge = System.getenv().getOrDefault("LY_RASP_BRIDGE", "http://127.0.0.1:17891/v1/rasp/events");
            String token = System.getenv().getOrDefault("LY_RASP_TOKEN", "");
            String app = System.getenv().getOrDefault("LY_APP_NAME", System.getProperty("ly.app.name", "java-app"));
            String query = fieldForHook(hookType, "sql", payload);
            String command = fieldForHook(hookType, "command", payload);
            String path = fieldForHook(hookType, "file", payload);
            String url = fieldForHook(hookType, "ssrf", payload);
            String body = "{"
                + "\"event_type\":\"" + escape(eventType) + "\","
                + "\"language\":\"" + escape(language) + "\","
                + "\"runtime\":\"jvm\","
                + "\"application\":\"" + escape(app) + "\","
                + "\"hook_type\":\"" + escape(hookType) + "\","
                + "\"sink\":\"" + escape(sink) + "\","
                + "\"payload\":\"" + escape(payload) + "\","
                + "\"message\":\"" + escape(payload) + "\","
                + "\"query\":\"" + escape(query) + "\","
                + "\"command\":\"" + escape(command) + "\","
                + "\"cmdline\":\"" + escape(command) + "\","
                + "\"path\":\"" + escape(path) + "\","
                + "\"url\":\"" + escape(url) + "\","
                + "\"rule_field_contract\":[\"query\",\"command\",\"cmdline\",\"path\",\"url\",\"payload\",\"message\"],"
                + "\"observed_at\":\"" + Instant.now().toString() + "\""
                + "}";
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(bridge).openConnection();
                conn.setRequestMethod("POST");
                conn.setConnectTimeout(500);
                conn.setReadTimeout(500);
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/json");
                if (!token.isEmpty()) conn.setRequestProperty("X-Ly-RASP-Token", token);
                try (OutputStream out = conn.getOutputStream()) {
                    out.write(body.getBytes(StandardCharsets.UTF_8));
                }
                conn.getInputStream().close();
            } catch (Exception ignored) {
            }
        } finally {
            EMITTING.remove();
        }
    }

    static boolean isEmitting() {
        return Boolean.TRUE.equals(EMITTING.get());
    }

    public static boolean suspiciousSql(String sql) {
        String value = lower(sql);
        return value.contains("union select") || value.contains(" or 1=1") || value.contains("sleep(") || value.contains("information_schema") || value.contains("load_file(");
    }

    public static boolean sensitivePath(String path) {
        String value = lower(path);
        return value.contains("../") || value.contains("/etc/passwd") || value.contains("/etc/shadow") || value.contains("/proc/self/environ") || value.contains("id_rsa");
    }

    public static boolean sensitiveUrl(String url) {
        String value = lower(url);
        return value.contains("127.0.0.1") || value.contains("localhost") || value.contains("169.254.169.254") || value.startsWith("file:") || value.startsWith("gopher:");
    }

    static String lower(String value) {
        return value == null ? "" : value.toLowerCase();
    }

    private static String fieldForHook(String hookType, String expected, String payload) {
        if (hookType == null) return "";
        String hook = hookType.toLowerCase();
        if (hook.contains(expected)) return payload == null ? "" : payload;
        if (expected.equals("command") && (hook.contains("exec") || hook.contains("process"))) return payload == null ? "" : payload;
        if (expected.equals("file") && (hook.contains("read") || hook.contains("write") || hook.contains("include"))) return payload == null ? "" : payload;
        if (expected.equals("ssrf") && (hook.contains("http") || hook.contains("url") || hook.contains("network"))) return payload == null ? "" : payload;
        return "";
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }
}
