package com.lyflow.rasp.java.instrument;

import com.lyflow.rasp.java.config.InstrumentationScope;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

public final class ApplicationTransformer implements ClassFileTransformer {
    private static final int MAX_CLASS_BYTES = 2 * 1024 * 1024;
    private final InstrumentationScope scope;

    public ApplicationTransformer(InstrumentationScope scope) {
        this.scope = scope;
    }

    public boolean supports(String className) {
        return scope.matches(className) && !className.startsWith("com/lyflow/rasp/java/");
    }

    @Override
    public byte[] transform(
            ClassLoader loader,
            String className,
            Class<?> classBeingRedefined,
            ProtectionDomain protectionDomain,
            byte[] classfileBuffer) {
        if (!supports(className)
                || classfileBuffer == null
                || classfileBuffer.length == 0
                || classfileBuffer.length > MAX_CLASS_BYTES) {
            return null;
        }
        try {
            ClassReader reader = new ClassReader(classfileBuffer);
            LoaderAwareClassWriter writer = new LoaderAwareClassWriter(
                    reader,
                    LoaderAwareClassWriter.COMPUTE_FRAMES | LoaderAwareClassWriter.COMPUTE_MAXS,
                    loader);
            TransformationState state = new TransformationState();
            ClassVisitor visitor = new ClassVisitor(Opcodes.ASM9, writer) {
                @Override
                public MethodVisitor visitMethod(
                        int access,
                        String name,
                        String descriptor,
                        String signature,
                        String[] exceptions) {
                    MethodVisitor method = super.visitMethod(access, name, descriptor, signature, exceptions);
                    return method == null ? null : new CallSiteAdapter(method, access, name, descriptor, state);
                }
            };
            reader.accept(visitor, ClassReader.SKIP_FRAMES);
            return state.changed() ? writer.toByteArray() : null;
        } catch (RuntimeException | LinkageError ignored) {
            return null;
        }
    }
}
