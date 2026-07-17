package com.lyflow.rasp.java.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class InstrumentationScope {
    private static final int MAX_PACKAGES = 16;
    private static final int MAX_PACKAGE_LENGTH = 160;
    private static final String FIXTURE_PACKAGE = "com/lyflow/rasp/fixture/";
    private final List<String> prefixes;

    private InstrumentationScope(List<String> prefixes) {
        this.prefixes = Collections.unmodifiableList(prefixes);
    }

    public static InstrumentationScope fixtureOnly() {
        return new InstrumentationScope(Collections.singletonList(FIXTURE_PACKAGE));
    }

    public static InstrumentationScope parse(String value) {
        if (value == null || value.trim().isEmpty()) {
            return fixtureOnly();
        }
        List<String> parsed = new ArrayList<>();
        for (String item : value.split(";")) {
            String prefix = normalize(item);
            if (!parsed.contains(prefix)) {
                parsed.add(prefix);
            }
            if (parsed.size() > MAX_PACKAGES) {
                throw new IllegalArgumentException("too many instrumentation packages");
            }
        }
        return new InstrumentationScope(parsed);
    }

    private static String normalize(String value) {
        String prefix = value.trim().replace('.', '/');
        while (prefix.startsWith("/")) {
            prefix = prefix.substring(1);
        }
        if (!prefix.endsWith("/")) {
            prefix += "/";
        }
        if (prefix.length() > MAX_PACKAGE_LENGTH || isSystemPrefix(prefix) || prefix.contains("..")) {
            throw new IllegalArgumentException("unsafe instrumentation package");
        }
        return prefix;
    }

    private static boolean isSystemPrefix(String prefix) {
        return prefix.startsWith("java/")
                || prefix.startsWith("javax/")
                || prefix.startsWith("jdk/")
                || prefix.startsWith("sun/")
                || prefix.startsWith("com/sun/")
                || prefix.startsWith("com/lyflow/rasp/java/");
    }

    public boolean matches(String className) {
        if (className == null) {
            return false;
        }
        for (String prefix : prefixes) {
            if (className.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    public List<String> prefixes() {
        return prefixes;
    }
}
