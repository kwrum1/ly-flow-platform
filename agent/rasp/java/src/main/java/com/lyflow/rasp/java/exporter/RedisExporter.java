package com.lyflow.rasp.java.exporter;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.model.RASPEvent;
import com.google.gson.Gson;
import io.lettuce.core.RedisClient;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.sync.RedisCommands;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Redis Stream Exporter
 * Exports RASP events to Redis Stream
 */
public class RedisExporter implements Exporter {
    private static final Logger logger = LoggerFactory.getLogger(RedisExporter.class);

    private static final String STREAM_KEY = "alerts:rasp";
    private static final String STREAM_KEY_ALT = "alerts:endpoint";

    private final RASPConfig config;
    private final Gson gson;
    private final BlockingQueue<RASPEvent> eventQueue;
    private final ExecutorService exporterExecutor;
    private final RedisClient redisClient;
    private volatile StatefulRedisConnection<String, String> connection;
    private volatile boolean running = true;
    private volatile boolean connected = false;

    public RedisExporter(RASPConfig config) {
        this.config = config;
        this.gson = new Gson();
        this.eventQueue = new LinkedBlockingQueue<>(10000);

        // Initialize Redis client if address is provided
        if (config.getServerAddr() != null && !config.getServerAddr().isEmpty()) {
            String redisUrl = convertToRedisUrl(config.getServerAddr());
            this.redisClient = RedisClient.create(redisUrl);
            try {
                this.connection = redisClient.connect();
                this.connected = true;
                logger.info("Redis connection established: {}", redisUrl);
            } catch (Exception e) {
                logger.warn("Failed to connect to Redis, will retry: {}", e.getMessage());
                this.redisClient = null;
            }
        } else {
            this.redisClient = null;
        }

        this.exporterExecutor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "redis-exporter");
            t.setDaemon(true);
            return t;
        });

        startExporting();
        logger.info("RedisExporter initialized");
    }

    private String convertToRedisUrl(String serverAddr) {
        // Convert HTTP URL to Redis URL
        // e.g., http://localhost:8080 -> redis://localhost:6379
        if (serverAddr.startsWith("http://")) {
            serverAddr = serverAddr.substring(7);
        } else if (serverAddr.startsWith("https://")) {
            serverAddr = serverAddr.substring(8);
        }

        // Extract host and port
        String[] parts = serverAddr.split(":");
        String host = parts[0];
        int port = parts.length > 1 ? Integer.parseInt(parts[1].split("/")[0]) : 6379;

        return "redis://" + host + ":" + port;
    }

    private void startExporting() {
        exporterExecutor.submit(() -> {
            while (running) {
                try {
                    RASPEvent event = eventQueue.poll(1, TimeUnit.SECONDS);
                    if (event != null) {
                        sendEvent(event);
                    }

                    // Try to reconnect if disconnected
                    if (!connected && redisClient != null) {
                        tryReconnect();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.error("Error in Redis exporter loop", e);
                }
            }
        });
    }

    private void tryReconnect() {
        try {
            if (redisClient != null && connection == null) {
                connection = redisClient.connect();
                connected = true;
                logger.info("Redis reconnected successfully");
            }
        } catch (Exception e) {
            logger.debug("Redis reconnect failed: {}", e.getMessage());
        }
    }

    @Override
    public void export(RASPEvent event) {
        if (event == null) return;

        // Add agent metadata
        if (event.getAppName() == null || event.getAppName().isEmpty()) {
            event.setAppName(config.getAppName() != null ? config.getAppName() : getAppName());
        }

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
            if (!connected || connection == null) {
                logger.debug("Redis not connected, skipping event: {}", event.getId());
                return;
            }

            RedisCommands<String, String> commands = connection.sync();

            // Build event as Redis Hash fields
            java.util.Map<String, String> fields = new java.util.HashMap<>();
            fields.put("id", event.getId());
            fields.put("timestamp", String.valueOf(event.getTimestamp()));
            fields.put("type", event.getType());
            fields.put("severity", event.getSeverity());
            fields.put("agent_id", config.getAgentID());
            fields.put("class_name", event.getClassName() != null ? event.getClassName() : "");
            fields.put("method_name", event.getMethodName() != null ? event.getMethodName() : "");
            fields.put("stack_trace", event.getStackTrace() != null ? event.getStackTrace() : "");

            if (event.getContext() != null) {
                fields.put("context", gson.toJson(event.getContext()));
            }

            // Add to Redis Stream
            String streamKey = event.getType().contains("sql") ? STREAM_KEY : STREAM_KEY_ALT;
            commands.xadd(streamKey, io.lettuce.core.XAddArgs.Builder.maxlen(10000).approximate(), fields);

            logger.debug("Event exported to Redis: {}", event.getId());

        } catch (Exception e) {
            logger.error("Failed to export event to Redis: {}", event.getId(), e);
            connected = false;
        }
    }

    private String getAppName() {
        String appName = System.getProperty("spring.application.name");
        if (appName == null) {
            appName = System.getProperty("application.name", "unknown");
        }
        return appName;
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

        if (connection != null) {
            try {
                connection.close();
            } catch (Exception e) {
                logger.warn("Error closing Redis connection", e);
            }
        }

        if (redisClient != null) {
            try {
                redisClient.shutdown();
            } catch (Exception e) {
                logger.warn("Error shutting down Redis client", e);
            }
        }
    }

    public int getQueueSize() {
        return eventQueue.size();
    }

    public boolean isConnected() {
        return connected;
    }
}