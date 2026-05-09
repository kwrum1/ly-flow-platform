package com.lyflow.rasp.java.config;

/**
 * RASP Configuration
 */
public class RASPConfig {
    private String serverAddr = "http://localhost:8080";
    private String agentID = "java-agent-default";
    private boolean sqlInjectionEnabled = true;
    private boolean commandInjectionEnabled = true;
    private boolean fileAccessEnabled = true;
    private boolean deserializeEnabled = true;
    private String appName;
    private int maxStackTraceDepth = 10;

    public RASPConfig() {
        // 默认启用所有检测
    }

    public String getServerAddr() {
        return serverAddr;
    }

    public void setServerAddr(String serverAddr) {
        this.serverAddr = serverAddr;
    }

    public String getAgentID() {
        return agentID;
    }

    public void setAgentID(String agentID) {
        this.agentID = agentID;
    }

    public boolean isSqlInjectionEnabled() {
        return sqlInjectionEnabled;
    }

    public void setSqlInjectionEnabled(boolean sqlInjectionEnabled) {
        this.sqlInjectionEnabled = sqlInjectionEnabled;
    }

    public boolean isCommandInjectionEnabled() {
        return commandInjectionEnabled;
    }

    public void setCommandInjectionEnabled(boolean commandInjectionEnabled) {
        this.commandInjectionEnabled = commandInjectionEnabled;
    }

    public boolean isFileAccessEnabled() {
        return fileAccessEnabled;
    }

    public void setFileAccessEnabled(boolean fileAccessEnabled) {
        this.fileAccessEnabled = fileAccessEnabled;
    }

    public boolean isDeserializeEnabled() {
        return deserializeEnabled;
    }

    public void setDeserializeEnabled(boolean deserializeEnabled) {
        this.deserializeEnabled = deserializeEnabled;
    }

    public String getAppName() {
        return appName;
    }

    public void setAppName(String appName) {
        this.appName = appName;
    }

    public int getMaxStackTraceDepth() {
        return maxStackTraceDepth;
    }

    public void setMaxStackTraceDepth(int maxStackTraceDepth) {
        this.maxStackTraceDepth = maxStackTraceDepth;
    }

    public String getOTLPEndpoint() {
        return serverAddr + "/v1/traces";
    }
}