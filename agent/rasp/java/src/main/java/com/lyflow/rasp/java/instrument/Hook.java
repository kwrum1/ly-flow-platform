package com.lyflow.rasp.java.instrument;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.exporter.Exporter;
import com.lyflow.rasp.java.model.RASPEvent;
import java.io.File;
import java.lang.reflect.Array;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Hook {
    private static final int MAX_EVIDENCE_CHARS = 512;
    private static final int MAX_ARRAY_ITEMS = 16;
    private static volatile Exporter exporter;
    private static volatile RASPConfig config;

    private Hook() {
    }

    public static void install(Exporter installedExporter, RASPConfig installedConfig) {
        exporter = installedExporter;
        config = installedConfig;
    }

    public static void disable() {
        exporter = null;
        config = null;
    }

    public static void observe(Object evidence, String eventType, String owner, String method) {
        try {
            Exporter activeExporter = exporter;
            RASPConfig activeConfig = config;
            if (activeExporter == null || activeConfig == null || "off".equals(activeConfig.getMode())) {
                return;
            }
            Map<String, Object> context = new LinkedHashMap<>();
            context.put("owner", owner);
            context.put("method", method);
            context.put("evidence", boundedEvidence(evidence));
            activeExporter.export(RASPEvent.builder()
                    .type(eventType)
                    .severity(RASPEvent.SEVERITY_LOW)
                    .appName(activeConfig.getAppName())
                    .className(owner)
                    .methodName(method)
                    .context(context)
                    .build());
        } catch (Throwable ignored) {
            return;
        }
    }

    private static String boundedEvidence(Object value) {
        if (value == null) {
            return "";
        }
        if (value instanceof ProcessBuilder) {
            return truncate(String.join(" ", ((ProcessBuilder) value).command()));
        }
        if (!value.getClass().isArray()) {
            boolean textual = value instanceof CharSequence || value instanceof Path || value instanceof File;
            return truncate(textual ? value.toString() : value.getClass().getName());
        }
        StringBuilder result = new StringBuilder();
        int count = Math.min(Array.getLength(value), MAX_ARRAY_ITEMS);
        for (int index = 0; index < count; index++) {
            if (index > 0) {
                result.append(' ');
            }
            result.append(String.valueOf(Array.get(value, index)));
            if (result.length() >= MAX_EVIDENCE_CHARS) {
                break;
            }
        }
        return truncate(result.toString());
    }

    private static String truncate(String value) {
        String normalized = value.replace('\n', ' ').replace('\r', ' ');
        return normalized.length() <= MAX_EVIDENCE_CHARS
                ? normalized
                : normalized.substring(0, MAX_EVIDENCE_CHARS);
    }
}
