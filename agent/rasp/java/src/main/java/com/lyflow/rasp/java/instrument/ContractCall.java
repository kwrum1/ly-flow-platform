package com.lyflow.rasp.java.instrument;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

final class ContractCall {
    private final String eventType;
    private final int evidenceArgument;

    private ContractCall(String eventType, int evidenceArgument) {
        this.eventType = eventType;
        this.evidenceArgument = evidenceArgument;
    }

    static ContractCall match(int opcode, String owner, String method, String descriptor) {
        if (opcode == Opcodes.INVOKESPECIAL || "<init>".equals(method)) {
            return null;
        }
        Type[] arguments = Type.getArgumentTypes(descriptor);
        if (isSql(owner, method)) {
            return new ContractCall("sql_injection", firstArgumentOrReceiver(arguments));
        }
        if (isCommand(owner, method)) {
            return new ContractCall("command_injection", firstArgumentOrReceiver(arguments));
        }
        if (isFile(owner, method)) {
            return new ContractCall("file_access", firstArgumentOrReceiver(arguments));
        }
        if ("java/io/ObjectInputStream".equals(owner)
                && ("readObject".equals(method) || "readUnshared".equals(method))) {
            return new ContractCall("deserialization", -1);
        }
        return null;
    }

    private static int firstArgumentOrReceiver(Type[] arguments) {
        return arguments.length == 0 ? -1 : 0;
    }

    private static boolean isSql(String owner, String method) {
        return ("java/sql/Statement".equals(owner) || "java/sql/PreparedStatement".equals(owner))
                && ("execute".equals(method)
                || "executeQuery".equals(method)
                || "executeUpdate".equals(method)
                || "executeLargeUpdate".equals(method)
                || "addBatch".equals(method));
    }

    private static boolean isCommand(String owner, String method) {
        return ("java/lang/Runtime".equals(owner) && "exec".equals(method))
                || ("java/lang/ProcessBuilder".equals(owner) && "start".equals(method));
    }

    private static boolean isFile(String owner, String method) {
        if ("java/nio/file/Files".equals(owner)) {
            return method.startsWith("read")
                    || method.startsWith("write")
                    || method.startsWith("newInput")
                    || method.startsWith("newOutput")
                    || "lines".equals(method)
                    || "list".equals(method)
                    || "walk".equals(method)
                    || "copy".equals(method)
                    || "move".equals(method)
                    || "delete".equals(method);
        }
        return "java/io/File".equals(owner)
                && ("delete".equals(method) || "list".equals(method) || "listFiles".equals(method));
    }

    String eventType() {
        return eventType;
    }

    int evidenceArgument() {
        return evidenceArgument;
    }
}
