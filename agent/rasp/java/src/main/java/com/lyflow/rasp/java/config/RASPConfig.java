package com.lyflow.rasp.java.config;

public final class RASPConfig {
    private static final String DEFAULT_FALLBACK = "/var/lib/lyflow/rasp/java-fallback.jsonl";

    private String serverAddr = valueOrDefault(System.getenv("LY_RASP_BRIDGE_URL"), "http://127.0.0.1:17891");
    private String agentID = "java-agent-default";
    private String bridgeToken = valueOrEmpty(System.getenv("LY_RASP_TOKEN"));
    private String policyID = valueOrEmpty(System.getenv("RASP_POLICY_ID"));
    private String fallbackPath = valueOrDefault(System.getenv("LY_RASP_FALLBACK_PATH"), DEFAULT_FALLBACK);
    private String evidencePath = "";
    private String appName = "unknown";
    private String mode = "monitor";
    private String failBehavior = "disable";
    private long policyVersion = nonnegativeLong(System.getenv("RASP_POLICY_VERSION"));
    private long expiresAtEpochSecond = Long.MAX_VALUE;
    private int maxEventsPerSecond = 100;
    private int queueCapacity = 128;
    private int readLimitBytes = 65_536;
    private int cpuBudgetMillis = 50;
    private int memoryBudgetBytes = 1_048_576;
    private int restartBudget = 3;
    private int restartCount;
    private String runtimeHealthReason = "";
    private String binaryPath = valueOrEmpty(System.getenv("LY_RASP_BINARY_PATH"));
    private String binarySha256 = valueOrEmpty(System.getenv("LY_RASP_BINARY_SHA256"));
    private long eventWindowEpochSecond = Long.MIN_VALUE;
    private int eventCount;
    private InstrumentationScope instrumentationScope = InstrumentationScope.fixtureOnly();

    public String getServerAddr() { return serverAddr; }
    public void setServerAddr(String value) { serverAddr = valueOrDefault(value, "http://127.0.0.1:17891"); }
    public String getAgentID() { return agentID; }
    public void setAgentID(String value) { agentID = valueOrDefault(value, "java-agent-default"); }
    public String getBridgeToken() { return bridgeToken; }
    public void setBridgeToken(String value) { bridgeToken = valueOrEmpty(value); }
    public String getPolicyID() { return policyID; }
    public void setPolicyID(String value) { policyID = valueOrEmpty(value); }
    public String getFallbackPath() { return fallbackPath; }
    public void setFallbackPath(String value) { fallbackPath = valueOrDefault(value, DEFAULT_FALLBACK); }
    public String getEvidencePath() { return evidencePath; }
    public void setEvidencePath(String value) { evidencePath = valueOrEmpty(value); }
    public String getAppName() { return appName; }
    public void setAppName(String value) { appName = valueOrDefault(value, "unknown"); }
    public String getMode() { return mode; }
    public void setMode(String value) { mode = "off".equalsIgnoreCase(value) ? "off" : "monitor"; }
    public long getPolicyVersion() { return policyVersion; }
    public void setPolicyVersion(long value) { policyVersion = Math.max(0, value); }
    public void setExpiresAtEpochSecond(long value) { expiresAtEpochSecond = Math.max(0, value); }
    public void setFailBehavior(String value) {
        failBehavior = "monitor".equalsIgnoreCase(value) ? "monitor" : "disable";
    }
    public String getFailBehavior() { return failBehavior; }
    public void setMaxEventsPerSecond(int value) { maxEventsPerSecond = Math.max(1, Math.min(1000, value)); }
    public InstrumentationScope getInstrumentationScope() { return instrumentationScope; }
    public void setInstrumentationPackages(String value) { instrumentationScope = InstrumentationScope.parse(value); }
    public int getQueueCapacity() { return queueCapacity; }
    public int getReadLimitBytes() { return readLimitBytes; }
    public int getCpuBudgetMillis() { return cpuBudgetMillis; }
    public int getMemoryBudgetBytes() { return memoryBudgetBytes; }
    public int getRestartBudget() { return restartBudget; }
    public int getRestartCount() { return restartCount; }
    public String getRuntimeHealthReason() { return runtimeHealthReason; }
    public String getBinaryPath() { return binaryPath; }
    public void setBinaryPath(String value) { binaryPath = valueOrEmpty(value); }
    public String getBinarySha256() { return binarySha256; }
    public void setBinarySha256(String value) { binarySha256 = valueOrEmpty(value).trim().toLowerCase(java.util.Locale.ROOT); }
    public void setRestartBudget(int value) { restartBudget = Math.max(1, Math.min(10, value)); }
    public void applyRuntimeLimits(int queue, int read, int cpu, int memory, int restarts) {
        queueCapacity = Math.max(1, Math.min(1024, queue));
        readLimitBytes = Math.max(1024, Math.min(1_048_576, read));
        cpuBudgetMillis = Math.max(1, Math.min(5000, cpu));
        memoryBudgetBytes = Math.max(1024, Math.min(16_777_216, memory));
        setRestartBudget(restarts);
    }
    public synchronized boolean recordWatchdogRestart() {
        if (restartCount >= restartBudget) {
            mode = "off";
            runtimeHealthReason = "restart_budget_exhausted";
            return false;
        }
        restartCount++;
        return true;
    }
    public void disablePrevention() { mode = "off"; }
    public boolean isPreventionEnabled() {
        return policyVersion > 0 && !"off".equals(effectiveMode(System.currentTimeMillis() / 1000));
    }
    public long getMaxLogBytes() { return 1_048_576L; }
    public boolean shouldBlock() { return false; }

    public String effectiveMode(long nowEpochSecond) {
        if (nowEpochSecond < expiresAtEpochSecond) {
            return mode;
        }
        return "monitor".equals(failBehavior) ? "monitor" : "off";
    }

    public synchronized boolean allowEvent(long nowEpochSecond) {
        if (nowEpochSecond != eventWindowEpochSecond) {
            eventWindowEpochSecond = nowEpochSecond;
            eventCount = 0;
        }
        if (eventCount >= maxEventsPerSecond) {
            return false;
        }
        eventCount++;
        return true;
    }

    public boolean shouldExportNow() {
        long nowEpochSecond = System.currentTimeMillis() / 1000;
        return policyVersion > 0 && !"off".equals(effectiveMode(nowEpochSecond)) && allowEvent(nowEpochSecond);
    }

    private static String valueOrEmpty(String value) { return value == null ? "" : value; }
    private static String valueOrDefault(String value, String fallback) {
        return value == null || value.isEmpty() ? fallback : value;
    }
    private static long nonnegativeLong(String value) {
        try {
            return value == null ? 0 : Math.max(0, Long.parseLong(value));
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }
}
