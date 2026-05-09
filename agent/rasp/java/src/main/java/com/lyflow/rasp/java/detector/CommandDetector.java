package com.lyflow.rasp.java.detector;

import com.lyflow.rasp.java.model.DetectionResult;
import com.lyflow.rasp.java.model.InvocationContext;
import com.lyflow.rasp.java.model.RASPEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Command Injection Detector
 * Detects command injection attacks in Runtime.exec() and ProcessBuilder
 */
public class CommandDetector implements Detector {
    private static final Logger logger = LoggerFactory.getLogger(CommandDetector.class);

    // Command injection patterns
    private static final Pattern[] COMMAND_INJECTION_PATTERNS = {
        // Shell metacharacters for chaining
        Pattern.compile(";"),
        Pattern.compile("\\|"),
        Pattern.compile("&"),
        Pattern.compile("\\$\\("),
        Pattern.compile("`"),
        // Command substitution
        Pattern.compile("\\$\\{[^}]+\\}"),
        // Newlines for multi-line injection
        Pattern.compile("\\n"),
        Pattern.compile("\\r"),
        // Variable expansion
        Pattern.compile("\\$[A-Za-z_][A-Za-z0-9_]*"),
        // Parentheses for subshell
        Pattern.compile("\\([^)]+\\)"),
        // redirection operators
        Pattern.compile(">"),
        Pattern.compile("<"),
        // Heredoc
        Pattern.compile("<<"),
        // Environment variable injection
        Pattern.compile("env\\s+"),
        Pattern.compile("export\\s+")
    };

    // Dangerous commands that should never be executed
    private static final Set<String> DANGEROUS_COMMANDS = new HashSet<>(Arrays.asList(
        "rm", "rmrf", "del", "format", "shutdown", "reboot",
        "mkfs", "fdisk", "dd", "wget", "curl", "nc", "netcat",
        "bash", "sh", "cmd", "powershell", "python", "perl", "ruby",
        "chmod", "chown", "useradd", "userdel", "passwd"
    ));

    // Patterns for URL download attempts
    private static final Pattern URL_DOWNLOAD_PATTERN = Pattern.compile(
        "(?i)(wget|curl|nc).*(https?|ftp)://"
    );

    // Patterns for reverse shell attempts
    private static final Pattern REVERSE_SHELL_PATTERN = Pattern.compile(
        "(?i)/dev/tcp/|nc\\s+-e|/bin/sh\\s+-i"
    );

    private boolean enabled = true;

    @Override
    public DetectionResult detect(InvocationContext context) {
        if (!enabled || context == null) {
            return DetectionResult.builder()
                    .blocked(false)
                    .vulnerabilityType("none")
                    .severity(RASPEvent.SEVERITY_LOW)
                    .build();
        }

        // Extract command from context
        String command = extractCommand(context);

        if (command == null || command.isEmpty()) {
            return DetectionResult.builder()
                    .blocked(false)
                    .vulnerabilityType("none")
                    .severity(RASPEvent.SEVERITY_LOW)
                    .build();
        }

        logger.debug("Checking command: {}", truncateForLog(command));

        // Check for reverse shell patterns (CRITICAL)
        if (REVERSE_SHELL_PATTERN.matcher(command).find()) {
            return DetectionResult.builder()
                    .blocked(true)
                    .vulnerabilityType(RASPEvent.TYPE_COMMAND_INJECTION)
                    .severity(RASPEvent.SEVERITY_CRITICAL)
                    .description("Reverse shell attempt detected")
                    .payload(command)
                    .stackTrace(getStackTrace())
                    .build();
        }

        // Check for URL download patterns (HIGH)
        if (URL_DOWNLOAD_PATTERN.matcher(command).find()) {
            return DetectionResult.builder()
                    .blocked(true)
                    .vulnerabilityType(RASPEvent.TYPE_COMMAND_INJECTION)
                    .severity(RASPEvent.SEVERITY_HIGH)
                    .description("Remote command download attempt detected")
                    .payload(command)
                    .stackTrace(getStackTrace())
                    .build();
        }

        // Check for command injection patterns
        int patternMatchCount = 0;
        String matchedPatterns = "";

        for (Pattern pattern : COMMAND_INJECTION_PATTERNS) {
            if (pattern.matcher(command).find()) {
                patternMatchCount++;
                matchedPatterns += pattern.pattern() + ", ";
            }
        }

        if (patternMatchCount >= 2) {
            String severity = determineSeverity(command);
            return DetectionResult.builder()
                    .blocked(true)
                    .vulnerabilityType(RASPEvent.TYPE_COMMAND_INJECTION)
                    .severity(severity)
                    .description("Command injection pattern detected: " + matchedPatterns)
                    .payload(command)
                    .stackTrace(getStackTrace())
                    .build();
        }

        // Check for dangerous commands
        String lowerCommand = command.toLowerCase();
        for (String dangerous : DANGEROUS_COMMANDS) {
            if (lowerCommand.contains(dangerous)) {
                return DetectionResult.builder()
                        .blocked(true)
                        .vulnerabilityType(RASPEvent.TYPE_COMMAND_INJECTION)
                        .severity(RASPEvent.SEVERITY_HIGH)
                        .description("Dangerous command detected: " + dangerous)
                        .payload(command)
                        .stackTrace(getStackTrace())
                        .build();
            }
        }

        return DetectionResult.builder()
                .blocked(false)
                .vulnerabilityType("none")
                .severity(RASPEvent.SEVERITY_LOW)
                .build();
    }

    private String extractCommand(InvocationContext context) {
        Object[] args = context.getArgs();

        if (args == null || args.length == 0) {
            return null;
        }

        // For Runtime.exec(String)
        if (args.length >= 1 && args[0] instanceof String) {
            return (String) args[0];
        }

        // For Runtime.exec(String[]) - combine all args
        if (args.length >= 1 && args[0] instanceof String[]) {
            StringBuilder sb = new StringBuilder();
            for (String arg : (String[]) args[0]) {
                if (sb.length() > 0) sb.append(" ");
                sb.append(arg);
            }
            return sb.toString();
        }

        // For ProcessBuilder constructor with List<String>
        // Note: actual implementation would need to handle List<String> constructor

        return null;
    }

    private String determineSeverity(String command) {
        String lower = command.toLowerCase();

        if (REVERSE_SHELL_PATTERN.matcher(command).find()) {
            return RASPEvent.SEVERITY_CRITICAL;
        }

        if (lower.contains("rm") || lower.contains("dd") || lower.contains("mkfs")) {
            return RASPEvent.SEVERITY_CRITICAL;
        }

        if (lower.contains("wget") || lower.contains("curl") || lower.contains("nc")) {
            return RASPEvent.SEVERITY_HIGH;
        }

        return RASPEvent.SEVERITY_MEDIUM;
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

    private String truncateForLog(String cmd) {
        if (cmd == null) return null;
        if (cmd.length() <= 100) return cmd;
        return cmd.substring(0, 100) + "...[truncated]";
    }

    @Override
    public String getName() {
        return "CommandDetector";
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}