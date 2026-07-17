package com.lyflow.rasp.java.instrument;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;

final class LoaderAwareClassWriter extends ClassWriter {
    private final ClassLoader loader;

    LoaderAwareClassWriter(ClassReader reader, int flags, ClassLoader loader) {
        super(reader, flags);
        this.loader = loader;
    }

    @Override
    protected String getCommonSuperClass(String leftName, String rightName) {
        try {
            ClassLoader effectiveLoader = loader == null ? ClassLoader.getSystemClassLoader() : loader;
            Class<?> left = Class.forName(leftName.replace('/', '.'), false, effectiveLoader);
            Class<?> right = Class.forName(rightName.replace('/', '.'), false, effectiveLoader);
            if (left.isAssignableFrom(right)) return leftName;
            if (right.isAssignableFrom(left)) return rightName;
            if (left.isInterface() || right.isInterface()) return "java/lang/Object";
            Class<?> parent = left;
            do {
                parent = parent.getSuperclass();
            } while (parent != null && !parent.isAssignableFrom(right));
            return parent == null ? "java/lang/Object" : parent.getName().replace('.', '/');
        } catch (ClassNotFoundException | LinkageError ignored) {
            return "java/lang/Object";
        }
    }
}
