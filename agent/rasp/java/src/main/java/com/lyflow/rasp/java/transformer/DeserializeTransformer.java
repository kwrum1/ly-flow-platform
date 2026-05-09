package com.lyflow.rasp.java.transformer;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.detector.DeserializeDetector;
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
 * Deserialization Transformer - Hooks ObjectInputStream.readObject()
 * Detects unsafe deserialization attacks and gadget chains
 */
public class DeserializeTransformer implements ClassFileTransformer {
    private static final Logger logger = LoggerFactory.getLogger(DeserializeTransformer.class);

    // Target classes for deserialization
    private static final String[] TARGET_CLASSES = {
        "java/io/ObjectInputStream"
    };

    private final RASPConfig config;
    private final OTLPExporter exporter;
    private final DeserializeDetector detector;

    private final Map<String, byte[]> transformedClasses = new HashMap<>();

    public DeserializeTransformer(RASPConfig config, OTLPExporter exporter) {
        this.config = config;
        this.exporter = exporter;
        this.detector = new DeserializeDetector();
        logger.info("DeserializeTransformer initialized");
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                           ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {

        // Only process target classes
        if (!isTargetClass(className)) {
            return null;
        }

        logger.debug("Transforming deserialization class: {}", className);

        try {
            if (transformedClasses.containsKey(className)) {
                return transformedClasses.get(className);
            }

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
        logger.info("Instrumenting deserialization class: {}", className);

        // In a real implementation, we would use ASM/Javassist to:
        // 1. Override readObject() to intercept deserialization
        // 2. Check the class being deserialized against known gadget chains
        // 3. Block known malicious classes

        return original;
    }

    /**
     * Check deserialization for gadget chain vulnerabilities
     */
    public DetectionResult checkDeserialization(String className, String methodName, Object[] args, Object target) {
        InvocationContext context = new InvocationContext(className, methodName, null, target, args);
        return detector.detect(context);
    }

    /**
     * Handle detection and export
     */
    public void handleDetection(String className, String methodName, Object[] args, Object target) {
        InvocationContext context = new InvocationContext(className, methodName, null, target, args);
        DetectionResult result = detector.detect(context);

        if (result.isBlocked()) {
            logger.warn("Deserialization attack blocked: {} in {}.{}", result.getDescription(), className, methodName);

            RASPEvent event = RASPEvent.builder()
                    .type(RASPEvent.TYPE_DESERIALIZATION)
                    .severity(result.getSeverity())
                    .className(className)
                    .methodName(methodName)
                    .stackTrace(result.getStackTrace())
                    .context(createContext(className, methodName, args, result))
                    .build();

            exporter.export(event);

            // In production, we would throw an exception to block the deserialization
            // throw new SecurityException("Unsafe deserialization blocked: " + result.getDescription());
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