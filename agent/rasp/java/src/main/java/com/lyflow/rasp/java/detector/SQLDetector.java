package com.lyflow.rasp.java.detector;

import com.lyflow.rasp.java.model.DetectionResult;
import com.lyflow.rasp.java.model.InvocationContext;
import com.lyflow.rasp.java.model.RASPEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.regex.Pattern;

/**
 * SQL Injection Detector
 * Detects SQL injection attacks in JDBC operations
 */
public class SQLDetector implements Detector {
    private static final Logger logger = LoggerFactory.getLogger(SQLDetector.class);

    // SQL injection patterns
    private static final Pattern[] SQL_INJECTION_PATTERNS = {
        // UNION-based injection
        Pattern.compile("(?i)\\bUNION\\b.*\\bSELECT\\b", Pattern.CASE_INSENSITIVE),
        // Comment-based attacks
        Pattern.compile("(?i)--"),
        Pattern.compile("/\\*.*\\*/"),
        // Stacked queries
        Pattern.compile(";"),
        // OR-based injection (e.g., ' OR '1'='1)
        Pattern.compile("(?i)'\\s*OR\\s*'", Pattern.CASE_INSENSITIVE),
        // AND-based injection
        Pattern.compile("(?i)'\\s*AND\\s*'", Pattern.CASE_INSENSITIVE),
        // EXEC/EXECUTE for stored procedure injection
        Pattern.compile("(?i)\\bEXEC\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)\\bEXECUTE\\b", Pattern.CASE_INSENSITIVE),
        // DROP/DELETE/TRUNCATE for DDL attacks
        Pattern.compile("(?i)\\bDROP\\b", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)\\bDELETE\\b.*\\bFROM\\b", Pattern.CASE_INSENSITIVE),
        // SLEEP/BENCHMARK for time-based blind injection
        Pattern.compile("(?i)\\bSLEEP\\s*\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(?i)\\bBENCHMARK\\s*\\(", Pattern.CASE_INSENSITIVE),
        // WAITFOR for time-based blind injection (MSSQL)
        Pattern.compile("(?i)\\bWAITFOR\\s+DELAY\\b", Pattern.CASE_INSENSITIVE)
    };

    // High-risk SQL keywords
    private static final String[] HIGH_RISK_KEYWORDS = {
        "UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC", "EXECUTE"
    };

    private boolean enabled = true;

    @Override
    public DetectionResult detect(InvocationContext context) {
        if (!enabled || context == null || context.getArgs() == null) {
            return DetectionResult.builder()
                    .blocked(false)
                    .vulnerabilityType("none")
                    .severity(RASPEvent.SEVERITY_LOW)
                    .build();
        }

        // Extract SQL from arguments
        String sql = extractSQL(context);

        if (sql == null || sql.isEmpty()) {
            return DetectionResult.builder()
                    .blocked(false)
                    .vulnerabilityType("none")
                    .severity(RASPEvent.SEVERITY_LOW)
                    .build();
        }

        logger.debug("Checking SQL: {}", truncateForLog(sql));

        // Check for SQL injection patterns
        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            if (pattern.matcher(sql).find()) {
                String severity = determineSeverity(sql);
                return DetectionResult.builder()
                        .blocked(true)
                        .vulnerabilityType(RASPEvent.TYPE_SQL_INJECTION)
                        .severity(severity)
                        .description("SQL injection pattern detected: " + pattern.pattern())
                        .payload(sql)
                        .stackTrace(getStackTrace())
                        .build();
            }
        }

        // Check for high-risk keywords
        String upperSql = sql.toUpperCase();
        for (String keyword : HIGH_RISK_KEYWORDS) {
            if (upperSql.contains(keyword) && containsSuspiciousChars(sql)) {
                return DetectionResult.builder()
                        .blocked(true)
                        .vulnerabilityType(RASPEvent.TYPE_SQL_INJECTION)
                        .severity(RASPEvent.SEVERITY_HIGH)
                        .description("High-risk SQL keyword with suspicious characters: " + keyword)
                        .payload(sql)
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

    private String extractSQL(InvocationContext context) {
        Object[] args = context.getArgs();

        if (args == null || args.length == 0) {
            return null;
        }

        // For Statement.execute(String), PreparedStatement.execute()
        if (args.length >= 1 && args[0] instanceof String) {
            return (String) args[0];
        }

        // For PreparedStatement.setXxx() methods, check the SQL
        // Note: In real implementation, we would need to track the SQL from prepareStatement

        return null;
    }

    private String determineSeverity(String sql) {
        String upper = sql.toUpperCase();

        if (upper.contains("UNION") || upper.contains("DROP") || upper.contains("DELETE")) {
            return RASPEvent.SEVERITY_CRITICAL;
        }

        if (upper.contains("SELECT") || upper.contains("EXEC")) {
            return RASPEvent.SEVERITY_HIGH;
        }

        return RASPEvent.SEVERITY_MEDIUM;
    }

    private boolean containsSuspiciousChars(String sql) {
        // Check for common injection characters
        return sql.contains("'") || sql.contains("\"") ||
               sql.contains(";") || sql.contains("--") ||
               sql.contains("/*") || sql.contains("*/");
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

    private String truncateForLog(String sql) {
        if (sql == null) return null;
        if (sql.length() <= 200) return sql;
        return sql.substring(0, 200) + "...[truncated]";
    }

    @Override
    public String getName() {
        return "SQLDetector";
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}