package com.lyflow.rasp.java;

import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.detector.*;
import com.lyflow.rasp.java.exporter.OTLPExporter;
import com.lyflow.rasp.java.transformer.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.instrument.Instrumentation;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * RASP Java Agent Main Class
 * Supports both premain (JVM startup) and agentmain (dynamic attach)
 */
public class Agent {
    private static final Logger logger = LoggerFactory.getLogger(Agent.class);
    private static final AtomicBoolean initialized = new AtomicBoolean(false);
    private static RASPConfig config;
    private static OTLPExporter exporter;

    /**
     * JVM启动时加载
     * java -javaagent:ly-rasp-java.jar=server=http://server:8080 -jar application.jar
     */
    public static void premain(String args, Instrumentation inst) {
        logger.info("RASP Java Agent premain starting...");
        try {
            initialize(args, inst);
            logger.info("RASP Java Agent premain initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize RASP Java Agent", e);
        }
    }

    /**
     * JVM运行时动态加载
     * 通过Attach API动态注入
     */
    public static void agentmain(String args, Instrumentation inst) {
        logger.info("RASP Java Agent agentmain starting...");
        try {
            if (initialized.get()) {
                logger.info("RASP Java Agent already initialized");
                return;
            }
            initialize(args, inst);
            logger.info("RASP Java Agent agentmain initialized successfully");
        } catch (Exception e) {
            logger.error("Failed to initialize RASP Java Agent", e);
        }
    }

    private static void initialize(String args, Instrumentation inst) throws Exception {
        if (!initialized.compareAndSet(false, true)) {
            return;
        }

        // 解析配置参数
        config = parseConfig(args);
        logger.info("RASP Config loaded: server={}, agentId={}, sqlInjection={}, commandInjection={}",
                config.getServerAddr(), config.getAgentID(), config.isSqlInjectionEnabled(), config.isCommandInjectionEnabled());

        // 初始化事件导出器
        exporter = new OTLPExporter(config);

        // 注册ClassFileTransformer
        List<ClassFileTransformer> transformers = createTransformers();

        for (ClassFileTransformer transformer : transformers) {
            inst.addTransformer(transformer, true);
            logger.info("Registered transformer: {}", transformer.getClass().getSimpleName());
        }

        // 尝试重新转换已加载的类
        retransformClasses(inst);
    }

    private static RASPConfig parseConfig(String args) {
        RASPConfig cfg = new RASPConfig();

        if (args == null || args.isEmpty()) {
            logger.warn("No configuration args provided, using defaults");
            return cfg;
        }

        // 解析 key=value 格式的参数
        String[] pairs = args.split(",");
        for (String pair : pairs) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                String key = kv[0].trim();
                String value = kv[1].trim();

                switch (key) {
                    case "server":
                        cfg.setServerAddr(value);
                        break;
                    case "agentId":
                        cfg.setAgentID(value);
                        break;
                    case "sqlInjection":
                        cfg.setSqlInjectionEnabled(Boolean.parseBoolean(value));
                        break;
                    case "commandInjection":
                        cfg.setCommandInjectionEnabled(Boolean.parseBoolean(value));
                        break;
                    case "fileAccess":
                        cfg.setFileAccessEnabled(Boolean.parseBoolean(value));
                        break;
                    case "deserialize":
                        cfg.setDeserializeEnabled(Boolean.parseBoolean(value));
                        break;
                }
            }
        }

        return cfg;
    }

    private static List<ClassFileTransformer> createTransformers() {
        List<ClassFileTransformer> transformers = new ArrayList<>();

        if (config.isSqlInjectionEnabled()) {
            transformers.add(new SQLTransformer(config, exporter));
        }

        if (config.isCommandInjectionEnabled()) {
            transformers.add(new CommandTransformer(config, exporter));
        }

        if (config.isFileAccessEnabled()) {
            transformers.add(new FileTransformer(config, exporter));
        }

        if (config.isDeserializeEnabled()) {
            transformers.add(new DeserializeTransformer(config, exporter));
        }

        return transformers;
    }

    private static void retransformClasses(Instrumentation inst) {
        // 获取所有已加载的类并重新转换
        Class<?>[] classes = inst.getAllLoadedClasses();
        List<Class<?>> targetClasses = new ArrayList<>();

        for (Class<?> clazz : classes) {
            if (isTargetClass(clazz)) {
                targetClasses.add(clazz);
            }
        }

        if (!targetClasses.isEmpty()) {
            try {
                inst.retransformClasses(targetClasses.toArray(new Class[0]));
                logger.info("Retransformed {} classes", targetClasses.size());
            } catch (Exception e) {
                logger.warn("Failed to retransform classes", e);
            }
        }
    }

    private static boolean isTargetClass(Class<?> clazz) {
        if (clazz == null || clazz.getName() == null) {
            return false;
        }

        String name = clazz.getName().replace('.', '/');

        // SQL相关
        if (config.isSqlInjectionEnabled()) {
            if (name.contains("java/sql/Statement") ||
                name.contains("java/sql/PreparedStatement") ||
                name.contains("java/sql/Connection")) {
                return true;
            }
        }

        // 命令注入相关
        if (config.isCommandInjectionEnabled()) {
            if (name.contains("java/lang/Runtime") ||
                name.contains("java/lang/ProcessBuilder")) {
                return true;
            }
        }

        // 文件操作相关
        if (config.isFileAccessEnabled()) {
            if (name.contains("java/io/FileInputStream") ||
                name.contains("java/io/FileOutputStream") ||
                name.contains("java/nio/file/Files")) {
                return true;
            }
        }

        // 反序列化相关
        if (config.isDeserializeEnabled()) {
            if (name.contains("java/io/ObjectInputStream")) {
                return true;
            }
        }

        return false;
    }

    public static RASPConfig getConfig() {
        return config;
    }

    public static OTLPExporter getExporter() {
        return exporter;
    }
}