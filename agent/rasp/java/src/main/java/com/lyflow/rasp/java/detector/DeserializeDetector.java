package com.lyflow.rasp.java.detector;

import com.lyflow.rasp.java.model.DetectionResult;
import com.lyflow.rasp.java.model.InvocationContext;
import com.lyflow.rasp.java.model.RASPEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Set;

/**
 * Deserialization Vulnerability Detector
 * Detects unsafe deserialization attacks
 */
public class DeserializeDetector implements Detector {
    private static final Logger logger = LoggerFactory.getLogger(DeserializeDetector.class);

    // Known dangerous classes for deserialization attacks
    private static final Set<String> DANGEROUS_CLASSES = new HashSet<>();

    static {
        // Apache Commons Collections gadget chain
        DANGEROUS_CLASSES.add("org.apache.commons.collections.Transformer");
        DANGEROUS_CLASSES.add("org.apache.commons.collections.functors.InvokerTransformer");
        DANGEROUS_CLASSES.add("org.apache.commons.collections.functors.ChainedTransformer");
        DANGEROUS_CLASSES.add("org.apache.commons.collections.functors.ConstantTransformer");
        DANGEROUS_CLASSES.add("org.apache.commons.collections.map.LazyMap");

        // Spring Framework gadget chain
        DANGEROUS_CLASSES.add("org.springframework.beans.factory.ObjectFactory");
        DANGEROUS_CLASSES.add("com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet");

        // C3P0 gadget chain
        DANGEROUS_CLASSES.add("com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase");

        // JBoss/WildFly gadget chain
        DANGEROUS_CLASSES.add("org.jboss.interceptor.proxy.InterceptorMethodHandler");

        // Groovy gadget chain
        DANGEROUS_CLASSES.add("org.codehaus.groovy.runtime.ConvertedClosure");
        DANGEROUS_CLASSES.add("org.codehaus.groovy.runtime.MethodClosure");

        // Various known gadget chains
        DANGEROUS_CLASSES.add("org.apache.axis2.databinding.utils.BeanUtil");
        DANGEROUS_CLASSES.add("sun.reflect.annotation.AnnotationInvocationHandler");
        DANGEROUS_CLASSES.add("java.util.TimerTask");
        DANGEROUS_CLASSES.add("java.lang.ProcessBuilder");
        DANGEROUS_CLASSES.add("java.lang.Runtime");
    }

    // Known unsafe base classes
    private static final Set<String> UNSAFE_BASE_CLASSES = new HashSet<>();

    static {
        UNSAFE_BASE_CLASSES.add("java.io.ObjectInputStream");
        UNSAFE_BASE_CLASSES.add("com.caucho.hessian.io.ObjectDeserializer");
        UNSAFE_BASE_CLASSES.add("flex.messaging.io.amf.ObjectInput");
    }

    private boolean enabled = true;
    private boolean checkGadgetChains = true;

    @Override
    public DetectionResult detect(InvocationContext context) {
        if (!enabled || context == null || context.getArgs() == null) {
            return DetectionResult.builder()
                    .blocked(false)
                    .vulnerabilityType("none")
                    .severity(RASPEvent.SEVERITY_LOW)
                    .build();
        }

        // Check if deserializing an object
        if (!isDeserializationCall(context)) {
            return DetectionResult.builder()
                    .blocked(false)
                    .vulnerabilityType("none")
                    .severity(RASPEvent.SEVERITY_LOW)
                    .build();
        }

        // Get the class being deserialized
        String className = getDeserializedClassName(context);

        if (className == null) {
            return DetectionResult.builder()
                    .blocked(false)
                    .vulnerabilityType("none")
                    .severity(RASPEvent.SEVERITY_LOW)
                    .build();
        }

        logger.debug("Checking deserialization of: {}", className);

        // Check against known dangerous classes
        if (DANGEROUS_CLASSES.contains(className)) {
            return DetectionResult.builder()
                    .blocked(true)
                    .vulnerabilityType(RASPEvent.TYPE_DESERIALIZATION)
                    .severity(RASPEvent.SEVERITY_CRITICAL)
                    .description("Known gadget chain class deserialized: " + className)
                    .payload(className)
                    .stackTrace(getStackTrace())
                    .build();
        }

        // Check for partial matches in dangerous packages
        if (checkGadgetChains && isDangerousPackage(className)) {
            return DetectionResult.builder()
                    .blocked(true)
                    .vulnerabilityType(RASPEvent.TYPE_DESERIALIZATION)
                    .severity(RASPEvent.SEVERITY_HIGH)
                    .description("Potentially dangerous deserialization from known gadget package: " + className)
                    .payload(className)
                    .stackTrace(getStackTrace())
                    .build();
        }

        return DetectionResult.builder()
                .blocked(false)
                .vulnerabilityType("none")
                .severity(RASPEvent.SEVERITY_LOW)
                .build();
    }

    private boolean isDeserializationCall(InvocationContext context) {
        String methodName = context.getMethodName();
        if (methodName == null) {
            return false;
        }

        // ObjectInputStream.readObject(), readUnshared()
        return "readObject".equals(methodName) || "readUnshared".equals(methodName);
    }

    private String getDeserializedClassName(InvocationContext context) {
        // When deserializing, we cannot easily get the class name without modifying behavior
        // This would require instrumentation to track what class is being read

        // In a real implementation, we would:
        // 1. Instrument readObject to capture the class being deserialized
        // 2. Check against known gadget chains

        // For now, return a placeholder - real implementation would need bytecode manipulation
        Object[] args = context.getArgs();
        if (args != null && args.length > 0) {
            // If we have a handle to the stream, we could potentially determine the class
            // This is a simplified approach
            return "ObjectInputStream.readObject()";
        }

        return null;
    }

    private boolean isDangerousPackage(String className) {
        if (className == null) {
            return false;
        }

        String[] dangerousPackages = {
            "org.apache.commons.collections",
            "org.apache.commons.beanutils",
            "org.apache.commons.configuration",
            "org.apache.axis2",
            "org.apache.struts",
            "org.springframework.",
            "com.sun.org.apache.xalan",
            "com.mchange.v2.c3p0",
            "org.jboss",
            "org.codehaus.groovy",
            "sun.reflect.annotation"
        };

        for (String pkg : dangerousPackages) {
            if (className.startsWith(pkg)) {
                return true;
            }
        }

        return false;
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

    @Override
    public String getName() {
        return "DeserializeDetector";
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public void setCheckGadgetChains(boolean checkGadgetChains) {
        this.checkGadgetChains = checkGadgetChains;
    }
}