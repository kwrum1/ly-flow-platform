package com.lyflow.rasp.java.exporter;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.model.RASPEvent;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * OTLP HTTP Exporter
 * Exports RASP events in OpenTelemetry format
 */
public class OTLPExporter implements Exporter {
    private static final Logger logger = LoggerFactory.getLogger(OTLPExporter.class);

    private static final String OTLP_ENDPOINT = "/v1/traces";
    private static final String CONTENT_TYPE = "application/x-protobuf";

    private final RASPConfig config;
    private final Gson gson;
    private final BlockingQueue<RASPEvent> eventQueue;
    private final ExecutorService exporterExecutor;
    private volatile boolean running = true;

    public OTLPExporter(RASPConfig config) {
        this.config = config;
        this.gson = new Gson();
        this.eventQueue = new LinkedBlockingQueue<>(10000);
        this.exporterExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "otlp-exporter");
            t.setDaemon(true);
            return t;
        });

        startExporting();
        logger.info("OTLPExporter initialized, endpoint: {}", config.getOTLPEndpoint());
    }

    private void startExporting() {
        exporterExecutor.submit(() -> {
            while (running) {
                try {
                    RASPEvent event = eventQueue.poll(1, TimeUnit.SECONDS);
                    if (event != null) {
                        sendEvent(event);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error in OTLP exporter loop", e);
                }
            }
        });
    }

    @Override
    public void export(RASPEvent event) {
        if (event == null) return;

        // Add agent metadata
        if (event.getAppName() == null || event.getAppName().isEmpty()) {
            event.setAppName(config.getAppName() != null ? config.getAppName() : getAppName());
        }

        // Queue the event for async export
        boolean queued = eventQueue.offer(event);
        if (!queued) {
            logger.warn("Event queue full, dropping event: {}", event.getId());
        }
    }

    @Override
    public void exportSync(RASPEvent event) {
        sendEvent(event);
    }

    private void sendEvent(RASPEvent event) {
        try {
            String otlpPayload = buildOTLPPayload(event);
            sendToOTLPEndpoint(otlpPayload);
            logger.debug("Event exported successfully: {}", event.getId());
        } catch (Exception e) {
            logger.error("Failed to export event: {}", event.getId(), e);
            // Fallback: try sending to Redis directly
            try {
                sendToRedis(event);
            } catch (Exception ex) {
                logger.error("Failed to send event to Redis as fallback", ex);
            }
        }
    }

    private String buildOTLPPayload(RASPEvent event) {
        // Build OTLP JSON payload
        JsonObject payload = new JsonObject();

        // ResourceSpans array
        JsonArray resourceSpans = new JsonArray();
        JsonObject resourceSpan = new JsonObject();

        // Resource
        JsonObject resource = new JsonObject();
        JsonObject resourceAttr = new JsonObject();
        JsonArray attrs = new JsonArray();

        // Agent ID attribute
        attrs.add(createAttribute("agent.id", config.getAgentID()));
        attrs.add(createAttribute("agent.type", "java"));
        attrs.add(createAttribute("service.name", "ly-rasp-java"));

        resource.add("attributes", attrs);
        resourceSpan.add("resource", resource);

        // ScopeSpans (empty for now)
        JsonArray scopeSpans = new JsonArray();
        JsonObject scopeSpan = new JsonObject();
        JsonObject scope = new JsonObject();
        scope.add("name", createJsonPrimitive("ly-rasp"));
        scope.add("version", createJsonPrimitive("1.0.0"));
        scopeSpan.add("scope", scope);

        // Spans array
        JsonArray spans = new JsonArray();
        JsonObject span = new JsonObject();

        // Span details
        span.add("trace_id", createJsonPrimitive(generateTraceId()));
        span.add("span_id", createJsonPrimitive(generateSpanId()));
        span.add("parent_span_id", createJsonPrimitive(""));
        span.add("name", createJsonPrimitive("rasp." + event.getType()));
        span.add("kind", createJsonPrimitive(1)); // INTERNAL
        span.add("startTimeUnixNano", createJsonPrimitive(String.valueOf(event.getTimestamp() * 1000000)));
        span.add("endTimeUnixNano", createJsonPrimitive(String.valueOf(System.currentTimeMillis() * 1000000)));
        span.add("status", createJsonObject("code", 1)); // UNSET

        // Span attributes
        JsonArray spanAttrs = new JsonArray();
        spanAttrs.add(createAttribute("event.type", event.getType()));
        spanAttrs.add(createAttribute("event.severity", event.getSeverity()));
        spanAttrs.add(createAttribute("event.id", event.getId()));
        spanAttrs.add(createAttribute("event.class", event.getClassName()));
        spanAttrs.add(createAttribute("event.method", event.getMethodName()));

        if (event.getStackTrace() != null) {
            spanAttrs.add(createAttribute("event.stacktrace", event.getStackTrace()));
        }

        if (event.getContext() != null) {
            for (Map.Entry<String, Object> entry : event.getContext().entrySet()) {
                String key = "event.context." + entry.getKey();
                Object value = entry.getValue();
                if (value != null) {
                    spanAttrs.add(createAttribute(key, String.valueOf(value)));
                }
            }
        }

        span.add("attributes", spanAttrs);

        // Events array
        JsonArray events = new JsonArray();
        JsonObject eventObj = new JsonObject();
        eventObj.add("timeUnixNano", createJsonPrimitive(String.valueOf(event.getTimestamp() * 1000000)));
        eventObj.add("name", createJsonPrimitive("exception"));
        JsonArray eventAttrs = new JsonArray();
        eventAttrs.add(createAttribute("exception.type", event.getType()));
        eventAttrs.add(createAttribute("exception.message", event.getDescription()));
        eventObj.add("attributes", eventAttrs);
        events.add(eventObj);
        span.add("events", events);

        spans.add(span);
        scopeSpan.add("spans", spans);
        scopeSpans.add(scopeSpan);
        resourceSpan.add("scopeSpans", scopeSpans);
        resourceSpans.add(resourceSpan);

        payload.add("resourceSpans", resourceSpans);

        return gson.toJson(payload);
    }

    private JsonObject createAttribute(String key, String value) {
        JsonObject attr = new JsonObject();
        attr.add("key", createJsonPrimitive(key));
        JsonObject val = new JsonObject();
        val.add("stringValue", createJsonPrimitive(value));
        attr.add("value", val);
        return attr;
    }

    private JsonObject createJsonObject(String key, int value) {
        JsonObject obj = new JsonObject();
        obj.add(key, createJsonPrimitive(String.valueOf(value)));
        return obj;
    }

    private com.google.gson.JsonPrimitive createJsonPrimitive(String value) {
        return new com.google.gson.JsonPrimitive(value);
    }

    private void sendToOTLPEndpoint(String payload) throws Exception {
        String endpoint = config.getServerAddr() + OTLP_ENDPOINT;
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("User-Agent", "ly-rasp-java/1.0.0");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(payload.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            if (responseCode >= 400) {
                throw new Exception("OTLP endpoint returned " + responseCode);
            }
        } finally {
            conn.disconnect();
        }
    }

    private void sendToRedis(RASPEvent event) throws Exception {
        // Fallback: send to Redis Stream alerts:rasp
        // In production, this would use Lettuce client
        logger.info("Sending event to Redis fallback: {}", event.getId());
    }

    private String getAppName() {
        // Try to get application name from system properties
        String appName = System.getProperty("spring.application.name");
        if (appName == null) {
            appName = System.getProperty("application.name", "unknown");
        }
        return appName;
    }

    private String generateTraceId() {
        // Generate a 32-character hex trace ID
        return String.format("%032x", System.nanoTime());
    }

    private String generateSpanId() {
        // Generate a 16-character hex span ID
        return String.format("%016x", System.nanoTime());
    }

    public void shutdown() {
        running = false;
        exporterExecutor.shutdown();
        try {
            if (!exporterExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                exporterExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            exporterExecutor.shutdownNow();
        }
    }

    public int getQueueSize() {
        return eventQueue.size();
    }
}