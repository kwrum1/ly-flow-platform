package com.lyflow.rasp.java.detector;

import com.lyflow.rasp.java.model.DetectionResult;
import com.lyflow.rasp.java.model.InvocationContext;

/**
 * Security Detector Interface
 */
public interface Detector {
    /**
     * Detect security threats in the given invocation context
     *
     * @param context The invocation context containing method info and arguments
     * @return DetectionResult with threat information
     */
    DetectionResult detect(InvocationContext context);

    /**
     * Get the detector name
     */
    String getName();

    /**
     * Check if this detector is enabled
     */
    boolean isEnabled();
}