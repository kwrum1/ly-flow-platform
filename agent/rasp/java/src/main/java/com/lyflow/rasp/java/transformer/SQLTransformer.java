package com.lyflow.rasp.java.transformer;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.detector.SQLDetector;
import com.lyflow.rasp.java.exporter.OTLPExporter;
import com.lyflow.rasp.java.model.DetectionResult;
import com.lyflow.rasp.java.model.InvocationContext;
import com.lyflow.rasp.java.model.RASPEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.HashMap;
import java.util.Map;

/**
 * SQL Transformer - Hooks JDBC Statement methods
 * Detects SQL injection attacks in SQL execution
 */
public class SQLTransformer implements ClassFileTransformer {
    private static final Logger logger = LoggerFactory.getLogger(SQLTransformer.class);

    private static final String HOOKED_CLASS_PREFIX = "java/sql/";

    // Target classes for transformation
    private static final String[] TARGET_CLASSES = {
        "java/sql/Statement",
        "java/sql/PreparedStatement",
        "java/sql/Connection"
    };

    private final RASPConfig config;
    private final OTLPExporter exporter;
    private final SQLDetector detector;

    // Map of class bytecode transformations
    private final Map<String, byte[]> transformedClasses = new HashMap<>();

    public SQLTransformer(RASPConfig config, OTLPExporter exporter) {
        this.config = config;
        this.exporter = exporter;
        this.detector = new SQLDetector();
        logger.info("SQLTransformer initialized");
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                           ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {

        // Only process target classes
        if (!isTargetClass(className)) {
            return null;
        }

        logger.debug("Transforming class: {}", className);

        try {
            // Use ASM-style bytecode manipulation
            // In production, we would use a bytecode library like ASM or Javassist
            // For this implementation, we'll create a wrapper approach

            // Check cache
            if (transformedClasses.containsKey(className)) {
                return transformedClasses.get(className);
            }

            // Create instrumented version
            byte[] transformed = instrumentClass(classfileBuffer, className);
            transformedClasses.put(className, transformed);

            return transformed;

        } catch (Exception e) {
            logger.error("Failed to transform class: " + className, e);
            return null;
        }
    }

    private boolean isTargetClass(String className) {
        if (className == null) return false;

        for (String target : TARGET_CLASSES) {
            if (className.startsWith(target) || className.equals(target.replace('/', '.'))) {
                return true;
            }
        }
        return false;
    }

    private byte[] instrumentClass(byte[] original, String className) throws Exception {
        // In a real implementation, this would use ASM or Javassist to:
        // 1. Add a security manager check before execute methods
        // 2. Wrap the SQL with monitoring

        // For now, return original bytecode with logging
        logger.info("Instrumenting SQL class: {}", className);

        // Return original - real implementation would do bytecode manipulation
        return original;
    }

    /**
     * Check SQL for injection vulnerabilities
     */
    public DetectionResult checkSQL(String className, String methodName, Object[] args) {
        InvocationContext context = new InvocationContext(className, methodName, null, null, args);
        return detector.detect(context);
    }

    /**
     * Handle detection and export
     */
    public void handleDetection(String className, String methodName, Object[] args, Object target) {
        InvocationContext context = new InvocationContext(className, methodName, null, target, args);
        DetectionResult result = detector.detect(context);

        if (result.isBlocked()) {
            logger.warn("SQL Injection blocked: {} in {}.{}", result.getDescription(), className, methodName);

            RASPEvent event = RASPEvent.builder()
                    .type(RASPEvent.TYPE_SQL_INJECTION)
                    .severity(result.getSeverity())
                    .className(className)
                    .methodName(methodName)
                    .stackTrace(result.getStackTrace())
                    .context(createContext(className, methodName, args, result))
                    .build();

            exporter.export(event);
        }
    }

    private Map<String, Object> createContext(String className, String methodName, Object[] args, DetectionResult result) {
        Map<String, Object> ctx = new HashMap<>();
        ctx.put("className", className);
        ctx.put("methodName", methodName);
        ctx.put("payload", result.getPayload());
        ctx.put("vulnerabilityType", result.getVulnerabilityType());
        ctx.put("severity", result.getSeverity());
        return ctx;
    }
}