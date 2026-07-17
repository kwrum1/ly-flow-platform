package com.lyflow.rasp.java;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.exporter.OTLPExporter;
import com.lyflow.rasp.java.instrument.ApplicationTransformer;
import com.lyflow.rasp.java.instrument.Hook;
import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public final class Agent {
    private static final AtomicBoolean INITIALIZED = new AtomicBoolean();
    private static volatile OTLPExporter exporter;

    private Agent() {
    }

    public static void premain(String arguments, Instrumentation instrumentation) {
        initialize(arguments, instrumentation);
    }

    public static void agentmain(String arguments, Instrumentation instrumentation) {
        initialize(arguments, instrumentation);
    }

    private static void initialize(String arguments, Instrumentation instrumentation) {
        if (!INITIALIZED.compareAndSet(false, true)) {
            return;
        }
        OTLPExporter installedExporter = null;
        try {
            RASPConfig config = parseConfig(arguments);
            if ("off".equals(config.getMode())) {
                return;
            }
            installedExporter = new OTLPExporter(config);
            exporter = installedExporter;
            Hook.install(installedExporter, config);
            ApplicationTransformer transformer = new ApplicationTransformer(config.getInstrumentationScope());
            instrumentation.addTransformer(transformer, true);
            retransformAllowedClasses(instrumentation, config, transformer);
            OTLPExporter shutdownExporter = installedExporter;
            Runtime.getRuntime().addShutdownHook(new Thread(shutdownExporter::shutdown, "rasp-exporter-shutdown"));
        } catch (Throwable error) {
            Hook.disable();
            if (installedExporter != null) {
                installedExporter.shutdown();
            }
            System.err.println("lyflow.rasp.control_health initialization_failed " + error.getClass().getSimpleName());
        }
    }

    static RASPConfig parseConfig(String arguments) {
        RASPConfig config = new RASPConfig();
        if (arguments == null || arguments.trim().isEmpty()) {
            return config;
        }
        for (String pair : arguments.split(",")) {
            String[] entry = pair.split("=", 2);
            if (entry.length == 2) {
                apply(config, entry[0].trim(), entry[1].trim());
            }
        }
        return config;
    }

    private static void apply(RASPConfig config, String key, String value) {
        switch (key) {
            case "server": config.setServerAddr(value); break;
            case "agentId": config.setAgentID(value); break;
            case "token": config.setBridgeToken(value); break;
            case "policyId": config.setPolicyID(value); break;
            case "policyVersion": config.setPolicyVersion(parseLong(value)); break;
            case "mode": config.setMode(value); break;
            case "app": config.setAppName(value); break;
            case "packages": config.setInstrumentationPackages(value); break;
            case "evidence": config.setEvidencePath(value); break;
            case "fallback": config.setFallbackPath(value); break;
            case "binary": config.setBinaryPath(value); break;
            case "binarySha256": config.setBinarySha256(value); break;
            default: break;
        }
    }

    private static long parseLong(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException ignored) {
            return 0;
        }
    }

    private static void retransformAllowedClasses(
            Instrumentation instrumentation,
            RASPConfig config,
            ApplicationTransformer transformer) {
        List<Class<?>> candidates = new ArrayList<>();
        for (Class<?> loaded : instrumentation.getAllLoadedClasses()) {
            if (instrumentation.isModifiableClass(loaded)
                    && transformer.supports(loaded.getName().replace('.', '/'))
                    && config.getInstrumentationScope().matches(loaded.getName().replace('.', '/'))) {
                candidates.add(loaded);
            }
        }
        if (candidates.isEmpty()) {
            return;
        }
        try {
            instrumentation.retransformClasses(candidates.toArray(new Class<?>[0]));
        } catch (Throwable error) {
            candidates.clear();
            System.err.println("lyflow.rasp.control_health retransform_failed " + error.getClass().getSimpleName());
        }
    }

    public static OTLPExporter getExporter() {
        return exporter;
    }
}
