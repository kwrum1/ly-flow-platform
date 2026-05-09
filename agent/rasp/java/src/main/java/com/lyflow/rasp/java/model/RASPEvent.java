package com.lyflow.rasp.java.model;

import java.util.Map;
import java.util.UUID;

/**
 * RASP Security Event Model
 */
public class RASPEvent {
    private String id;
    private long timestamp;
    private String type;
    private String severity;
    private String appName;
    private String className;
    private String methodName;
    private String stackTrace;
    private Map<String, Object> context;

    public RASPEvent() {
        this.id = UUID.randomUUID().toString();
        this.timestamp = System.currentTimeMillis();
    }

    public RASPEvent(String type, String severity) {
        this();
        this.type = type;
        this.severity = severity;
    }

    // Builder pattern for convenient construction
    public static Builder builder() {
        return new Builder();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public String getMethodName() {
        return methodName;
    }

    public void setMethodName(String methodName) {
        this.methodName = methodName;
    }

    public String getStackTrace() {
        return stackTrace;
    }

    public void setStackTrace(String stackTrace) {
        this.stackTrace = stackTrace;
    }

    public Map<String, Object> getContext() {
        return context;
    }

    public void setContext(Map<String, Object> context) {
        this.context = context;
    }

    // Event type constants
    public static final String TYPE_SQL_INJECTION = "sql_injection";
    public static final String TYPE_COMMAND_INJECTION = "command_injection";
    public static final String TYPE_FILE_ACCESS = "file_access";
    public static final String TYPE_DESERIALIZATION = "deserialization";

    // Severity constants
    public static final String SEVERITY_CRITICAL = "critical";
    public static final String SEVERITY_HIGH = "high";
    public static final String SEVERITY_MEDIUM = "medium";
    public static final String SEVERITY_LOW = "low";

    public static class Builder {
        private final RASPEvent event = new RASPEvent();

        public Builder type(String type) {
            event.setType(type);
            return this;
        }

        public Builder severity(String severity) {
            event.setSeverity(severity);
            return this;
        }

        public Builder appName(String appName) {
            event.setAppName(appName);
            return this;
        }

        public Builder className(String className) {
            event.setClassName(className);
            return this;
        }

        public Builder methodName(String methodName) {
            event.setMethodName(methodName);
            return this;
        }

        public Builder stackTrace(String stackTrace) {
            event.setStackTrace(stackTrace);
            return this;
        }

        public Builder context(Map<String, Object> context) {
            event.setContext(context);
            return this;
        }

        public RASPEvent build() {
            return event;
        }
    }
}