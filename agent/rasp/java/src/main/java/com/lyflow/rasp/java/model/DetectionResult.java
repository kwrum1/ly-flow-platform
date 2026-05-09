package com.lyflow.rasp.java.model;

/**
 * Detection Result Model
 */
public class DetectionResult {
    private boolean blocked;
    private String vulnerabilityType;
    private String severity;
    private String stackTrace;
    private String description;
    private Object payload;

    public DetectionResult() {
    }

    public DetectionResult(boolean blocked, String vulnerabilityType, String severity) {
        this.blocked = blocked;
        this.vulnerabilityType = vulnerabilityType;
        this.severity = severity;
    }

    public static Builder builder() {
        return new Builder();
    }

    public boolean isBlocked() {
        return blocked;
    }

    public void setBlocked(boolean blocked) {
        this.blocked = blocked;
    }

    public String getVulnerabilityType() {
        return vulnerabilityType;
    }

    public void setVulnerabilityType(String vulnerabilityType) {
        this.vulnerabilityType = vulnerabilityType;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getStackTrace() {
        return stackTrace;
    }

    public void setStackTrace(String stackTrace) {
        this.stackTrace = stackTrace;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Object getPayload() {
        return payload;
    }

    public void setPayload(Object payload) {
        this.payload = payload;
    }

    public static class Builder {
        private boolean blocked = false;
        private String vulnerabilityType;
        private String severity = RASPEvent.SEVERITY_MEDIUM;
        private String stackTrace;
        private String description;
        private Object payload;

        public Builder blocked(boolean blocked) {
            this.blocked = blocked;
            return this;
        }

        public Builder vulnerabilityType(String vulnerabilityType) {
            this.vulnerabilityType = vulnerabilityType;
            return this;
        }

        public Builder severity(String severity) {
            this.severity = severity;
            return this;
        }

        public Builder stackTrace(String stackTrace) {
            this.stackTrace = stackTrace;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        public Builder payload(Object payload) {
            this.payload = payload;
            return this;
        }

        public DetectionResult build() {
            DetectionResult result = new DetectionResult(blocked, vulnerabilityType, severity);
            result.setStackTrace(stackTrace);
            result.setDescription(description);
            result.setPayload(payload);
            return result;
        }
    }
}