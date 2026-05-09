package com.lyflow.rasp.java.transformer;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.exporter.OTLPExporter;
import com.lyflow.rasp.java.model.RASPEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;

/**
 * File Transformer - Hooks file I/O operations
 * Monitors access to sensitive file paths
 */
public class FileTransformer implements ClassFileTransformer {
    private static final Logger logger = LoggerFactory.getLogger(FileTransformer.class);

    // Target classes for file operations
    private static final String[] TARGET_CLASSES = {
        "java/io/FileInputStream",
        "java/io/FileOutputStream",
        "java/io/File",
        "java/nio/file/Files"
    };

    // Sensitive paths that should be monitored
    private static final Set<String> SENSITIVE_PATHS = new HashSet<>();

    static {
        // System directories
        SENSITIVE_PATHS.add("/etc/");
        SENSITIVE_PATHS.add("/proc/");
        SENSITIVE_PATHS.add("/sys/");
        SENSITIVE_PATHS.add("/root/");
        SENSITIVE_PATHS.add("/boot/");
        SENSITIVE_PATHS.add("/dev/");

        // Configuration files
        SENSITIVE_PATHS.add("/etc/passwd");
        SENSITIVE_PATHS.add("/etc/shadow");
        SENSITIVE_PATHS.add("/etc/sudoers");
        SENSITIVE_PATHS.add("/etc/group");
        SENSITIVE_PATHS.add("/etc/hosts");

        // Log files
        SENSITIVE_PATHS.add("/var/log/");
        SENSITIVE_PATHS.add("/var/spool/");

        // SSH keys
        SENSITIVE_PATHS.add("/.ssh/");

        // Windows-specific
        SENSITIVE_PATHS.add("C:\\Windows\\");
        SENSITIVE_PATHS.add("C:\\Program Files\\");
        SENSITIVE_PATHS.add("C:\\Users\\");
        SENSITIVE_PATHS.add("C:\\Windows\\System32\\config\\");
        SENSITIVE_PATHS.add("C:\\Windows\\System32\\drivers\\");
    }

    // Paths that should be blocked
    private static final Set<String> BLOCKED_PATHS = new HashSet<>();

    static {
        BLOCKED_PATHS.add("/etc/passwd");
        BLOCKED_PATHS.add("/etc/shadow");
        BLOCKED_PATHS.add("/.ssh/");
        BLOCKED_PATHS.add("C:\\Windows\\System32\\config\\");
    }

    private final RASPConfig config;
    private final OTLPExporter exporter;

    private final Map<String, byte[]> transformedClasses = new HashMap<>();

    public FileTransformer(RASPConfig config, OTLPExporter exporter) {
        this.config = config;
        this.exporter = exporter;
        logger.info("FileTransformer initialized with {} sensitive paths", SENSITIVE_PATHS.size());
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                           ProtectionDomain protectionDomain, byte[] classfileBuffer) throws IllegalClassFormatException {

        // Only process target classes
        if (!isTargetClass(className)) {
            return null;
        }

        logger.debug("Transforming file class: {}", className);

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
        logger.info("Instrumenting file I/O class: {}", className);

        // In a real implementation, we would:
        // 1. Hook FileInputStream.<init>(File)
        // 2. Hook FileOutputStream.<init>(File)
        // 3. Hook Files.newInputStream()

        return original;
    }

    /**
     * Check file path for sensitive access
     */
    public DetectionResult checkFileAccess(String className, String methodName, Object[] args, Object target) {
        String filePath = extractFilePath(className, methodName, args, target);

        if (filePath == null) {
            return new DetectionResult(false, "none", RASPEvent.SEVERITY_LOW);
        }

        logger.debug("Checking file access: {}", filePath);

        // Check if it's a blocked path
        for (String blocked : BLOCKED_PATHS) {
            if (filePath.startsWith(blocked) || filePath.equals(blocked)) {
                return DetectionResult.builder()
                        .blocked(true)
                        .vulnerabilityType(RASPEvent.TYPE_FILE_ACCESS)
                        .severity(RASPEvent.SEVERITY_CRITICAL)
                        .description("Access to sensitive path blocked: " + filePath)
                        .payload(filePath)
                        .build();
            }
        }

        // Check if it's a monitored sensitive path
        for (String sensitive : SENSITIVE_PATHS) {
            if (filePath.startsWith(sensitive)) {
                return DetectionResult.builder()
                        .blocked(false)  // Log but don't block
                        .vulnerabilityType(RASPEvent.TYPE_FILE_ACCESS)
                        .severity(RASPEvent.SEVERITY_MEDIUM)
                        .description("Access to sensitive path detected: " + filePath)
                        .payload(filePath)
                        .build();
            }
        }

        return DetectionResult.builder()
                .blocked(false)
                .vulnerabilityType("none")
                .severity(RASPEvent.SEVERITY_LOW)
                .build();
    }

    private String extractFilePath(String className, String methodName, Object[] args, Object target) {
        if (args == null || args.length == 0) {
            return null;
        }

        // Extract from FileInputStream/FileOutputStream constructor
        for (Object arg : args) {
            if (arg instanceof String) {
                return (String) arg;
            }
            if (arg instanceof java.io.File) {
                return ((java.io.File) arg).getPath();
            }
        }

        // For File class methods
        if (className != null && className.contains("File")) {
            if (target instanceof java.io.File) {
                return ((java.io.File) target).getPath();
            }
        }

        return null;
    }

    /**
     * Handle detection and export
     */
    public void handleDetection(String className, String methodName, Object[] args, Object target) {
        DetectionResult result = checkFileAccess(className, methodName, args, target);

        if (result.isBlocked() || !result.getVulnerabilityType().equals("none")) {
            logger.warn("File access detected: {} for {}.{}", result.getDescription(), className, methodName);

            RASPEvent event = RASPEvent.builder()
                    .type(RASPEvent.TYPE_FILE_ACCESS)
                    .severity(result.getSeverity())
                    .className(className)
                    .methodName(methodName)
                    .stackTrace(getStackTrace())
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
        ctx.put("blocked", result.isBlocked());
        return ctx;
    }

    private String getStackTrace() {
        StringBuilder sb = new StringBuilder();
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        int depth = Math.min(stackTrace.length, 10);

        for (int i = 2; i < depth && i < stackTrace.length; i++) {
            if (i > 2) sb.append("\n");
            sb.append(stackTrace[i].toString());
        }

        return sb.toString();
    }

    // Inner class for detection result
    private static class DetectionResult {
        private final boolean blocked;
        private final String vulnerabilityType;
        private final String severity;
        private final String description;
        private final Object payload;

        public DetectionResult(boolean blocked, String vulnerabilityType, String severity) {
            this.blocked = blocked;
            this.vulnerabilityType = vulnerabilityType;
            this.severity = severity;
            this.description = null;
            this.payload = null;
        }

        public boolean isBlocked() { return blocked; }
        public String getVulnerabilityType() { return vulnerabilityType; }
        public String getSeverity() { return severity; }
        public String getDescription() { return description; }
        public Object getPayload() { return payload; }
    }
}