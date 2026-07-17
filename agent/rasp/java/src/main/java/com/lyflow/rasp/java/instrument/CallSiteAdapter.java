package com.lyflow.rasp.java.instrument;

import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

final class CallSiteAdapter extends AdviceAdapter {
    private static final Type HOOK_TYPE = Type.getType(Hook.class);
    private static final Method OBSERVE = new Method(
            "observe",
            "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V");
    private final TransformationState state;

    CallSiteAdapter(MethodVisitor visitor, int access, String name, String descriptor, TransformationState state) {
        super(Opcodes.ASM9, visitor, access, name, descriptor);
        this.state = state;
    }

    @Override
    public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
        ContractCall call = ContractCall.match(opcode, owner, name, descriptor);
        if (call == null) {
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
            return;
        }
        Type[] argumentTypes = Type.getArgumentTypes(descriptor);
        int[] argumentLocals = storeArguments(argumentTypes);
        int receiverLocal = storeReceiver(opcode, owner);
        loadEvidence(call, argumentTypes, argumentLocals, receiverLocal);
        push(call.eventType());
        push(owner.replace('/', '.'));
        push(name);
        invokeStatic(HOOK_TYPE, OBSERVE);
        reloadInvocation(opcode, owner, argumentTypes, argumentLocals, receiverLocal);
        state.markChanged();
        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
    }

    private int[] storeArguments(Type[] argumentTypes) {
        int[] locals = new int[argumentTypes.length];
        for (int index = argumentTypes.length - 1; index >= 0; index--) {
            locals[index] = newLocal(argumentTypes[index]);
            storeLocal(locals[index], argumentTypes[index]);
        }
        return locals;
    }

    private int storeReceiver(int opcode, String owner) {
        if (opcode == Opcodes.INVOKESTATIC) {
            return -1;
        }
        Type receiverType = Type.getObjectType(owner);
        int local = newLocal(receiverType);
        storeLocal(local, receiverType);
        return local;
    }

    private void loadEvidence(ContractCall call, Type[] types, int[] locals, int receiverLocal) {
        int argument = call.evidenceArgument();
        if (argument >= 0) {
            loadLocal(locals[argument], types[argument]);
            box(types[argument]);
            return;
        }
        if (receiverLocal >= 0) {
            loadLocal(receiverLocal);
        } else {
            visitInsn(Opcodes.ACONST_NULL);
        }
    }

    private void reloadInvocation(int opcode, String owner, Type[] types, int[] locals, int receiverLocal) {
        if (opcode != Opcodes.INVOKESTATIC) {
            loadLocal(receiverLocal, Type.getObjectType(owner));
        }
        for (int index = 0; index < types.length; index++) {
            loadLocal(locals[index], types[index]);
        }
    }
}
