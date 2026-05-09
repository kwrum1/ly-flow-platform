package com.lyflow.rasp.java.model;

import java.util.Map;

/**
 * Invocation Context for security checks
 */
public class InvocationContext {
    private String className;
    private String methodName;
    private String methodDesc;
    private Object target;
    private Object[] args;
    private Map<String, Object> metadata;

    public InvocationContext() {
    }

    public InvocationContext(String className, String methodName, String methodDesc, Object target, Object[] args) {
        this.className = className;
        this.methodName = methodName;
        this.methodDesc = methodDesc;
        this.target = target;
        this.args = args;
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

    public String getMethodDesc() {
        return methodDesc;
    }

    public void setMethodDesc(String methodDesc) {
        this.methodDesc = methodDesc;
    }

    public Object getTarget() {
        return target;
    }

    public void setTarget(Object target) {
        this.target = target;
    }

    public Object[] getArgs() {
        return args;
    }

    public void setArgs(Object[] args) {
        this.args = args;
    }

    public Map<String, Object> getMetadata() {
        return metadata;
    }

    public void setMetadata(Map<String, Object> metadata) {
        this.metadata = metadata;
    }

    public String getFullMethodName() {
        return className + "." + methodName;
    }
}