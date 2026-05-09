package com.lyflow.rasp.java.util;

import org.objectweb.asm.*;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.IllegalClassFormatException;
import java.security.ProtectionDomain;

/**
 * ASM Bytecode Hook Utility
 * Helper class for bytecode instrumentation using ASM
 */
public class ASMHookHelper {

    /**
     * Visit a method and add security checks
     */
    public static MethodVisitor addSecurityCheck(MethodVisitor mv, int access, String name, String desc,
                                                 String className, ClassFileTransformer transformer) {
        return new AdviceAdapter(Opcodes.ASM9, mv, access, name, desc) {
            @Override
            public void visitCode() {
                super.visitCode();
                // Add security check at method entry
                // This would be implemented with actual bytecode manipulation
            }

            @Override
            public void onMethodEnter() {
                super.onMethodEnter();
                // Insert security check bytecode
            }

            @Override
            public void onMethodExit(int opcode) {
                super.onMethodExit(opcode);
                // Add any post-method checks
            }
        };
    }

    /**
     * Create a ClassReader with error handling
     */
    public static ClassReader createClassReader(byte[] classfileBuffer) {
        try {
            return new ClassReader(classfileBuffer);
        } catch (Exception e) {
            throw new IllegalClassFormatException("Failed to create ClassReader: " + e.getMessage());
        }
    }

    /**
     * Get method descriptor for execute methods
     */
    public static boolean isExecuteMethod(String name) {
        return "execute".equals(name) ||
               "executeQuery".equals(name) ||
               "executeUpdate".equals(name) ||
               "executeLargeUpdate".equals(name);
    }

    /**
     * Get method descriptor for Runtime.exec
     */
    public static boolean isExecMethod(String name) {
        return "exec".equals(name);
    }

    /**
     * Get method descriptor for ProcessBuilder
     */
    public static boolean isProcessBuilderMethod(String name) {
        return "<init>".equals(name) || "start".equals(name);
    }

    /**
     * Get method descriptor for ObjectInputStream
     */
    public static boolean isReadObjectMethod(String name) {
        return "readObject".equals(name) || "readUnshared".equals(name);
    }

    /**
     * Extract SQL from PreparedStatement (simplified)
     */
    public static String extractSQLFromPreparedStatement(String className, Object[] args) {
        if (args == null || args.length == 0) {
            return null;
        }

        if (args[0] instanceof String) {
            return (String) args[0];
        }

        return null;
    }

    /**
     * Extract command from Runtime.exec args
     */
    public static String extractCommandFromArgs(Object[] args) {
        if (args == null || args.length == 0) {
            return null;
        }

        if (args[0] instanceof String) {
            return (String) args[0];
        }

        if (args[0] instanceof String[]) {
            StringBuilder sb = new StringBuilder();
            for (String arg : (String[]) args[0]) {
                if (sb.length() > 0) sb.append(" ");
                sb.append(arg);
            }
            return sb.toString();
        }

        return null;
    }
}