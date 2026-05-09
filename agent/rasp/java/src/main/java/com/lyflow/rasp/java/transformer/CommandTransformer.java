package com.lyflow.rasp.java.transformer;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.detector.CommandDetector;
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
 * Command Transformer - Hooks Runtime.exec() and ProcessBuilder
 * Detects command injection attacks
 */
public class CommandTransformer implements ClassFileTransformer {
    private static final Logger logger = LoggerFactory.getLogger(CommandTransformer.class);

    // Target classes for command execution
    private static final String[] TARGET_CLASSES = {
        "java/lang/Runtime",
        "java/lang/ProcessBuilder"
    };

    private final RASPConfig config;
    private final OTLPExporter exporter;
    private final CommandDetector detector;

    // Map of class bytecode transformations
    private final Map<String, byte[]> transformedClasses = new HashMap<>();

    public CommandTransformer(RASPConfig config, OTLPExporter exporter) {
        this.config = config;
        this.exporter = exporter;
        this.detector = new CommandDetector();
        logger.info("CommandTransformer initialized");
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
        logger.info("Instrumenting command execution class: {}", className);

        // In a real implementation, we would use ASM/Javassist to:
        // 1. Hook Runtime.exec()
        // 2. Hook ProcessBuilder.<init>() and start()

        // Return original - real implementation would do bytecode manipulation
        return original;
    }

    /**
     * Check command for injection vulnerabilities
     */
    public DetectionResult checkCommand(String className, String methodName, Object[] args) {
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
            logger.warn("Command Injection blocked: {} in {}.{}", result.getDescription(), className, methodName);

            RASPEvent event = RASPEvent.builder()
                    .type(RASPEvent.TYPE_COMMAND_INJECTION)
                    .severity(result.getSeverity())
                    .className(className)
                    .methodName(methodName)
                    .stackTrace(result.getStackTrace())
                    .context(createContext(className, methodName, args, result))
                    .build();

            exporter.export(event);

            // In production, we would throw an exception to block the execution
            // throw new SecurityException("Command injection blocked: " + result.getDescription());
        }
    }

    private Map<String, Object> createContext(String className, String methodName, Object[] args, DetectionResult result) {
        Map<String, Object> ctx = new HashMap<>();
        ctx.put("className", className);
        ctx.put("methodName", methodName);
        ctx.put("payload", result.getPayload());
        ctx.put("vulnerabilityType", result.getVulnerabilityType());
        ctx.put("severity", result.getSeverity());

        // Extract command details
        if (args != null && args.length > 0) {
            if (args[0] instanceof String) {
                ctx.put("command", args[0]);
            } else if (args[0] instanceof String[]) {
                ctx.put("commandArray", args[0]);
            }
        }

        return ctx;
    }
}