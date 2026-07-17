package com.lyflow.rasp.fixture;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Statement;

public final class FixtureMain {
    private FixtureMain() {
    }

    public static void main(String[] arguments) throws Exception {
        System.out.println("sql:" + runSql());
        System.out.println("command:" + runCommand());
        System.out.println("file:" + runFile());
        System.out.println("deserialize:" + runDeserialization());
    }

    private static boolean runSql() throws Exception {
        Statement statement = (Statement) Proxy.newProxyInstance(
                FixtureMain.class.getClassLoader(),
                new Class<?>[]{Statement.class},
                (proxy, method, arguments) -> Boolean.TRUE);
        return statement.execute("SELECT 1");
    }

    private static int runCommand() throws Exception {
        Process process = Runtime.getRuntime().exec(new String[]{"/usr/bin/true"});
        return process.waitFor();
    }

    private static String runFile() throws Exception {
        Path path = Files.createTempFile("lyflow-java-rasp-", ".txt");
        try {
            Files.write(path, "file-ok".getBytes(StandardCharsets.UTF_8));
            return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        } finally {
            Files.delete(path);
        }
    }

    private static Object runDeserialization() throws Exception {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ObjectOutputStream output = new ObjectOutputStream(bytes)) {
            output.writeObject("deserialize-ok");
        }
        try (ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            return input.readObject();
        }
    }
}
