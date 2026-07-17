package com.lyflow.rasp.java.exporter;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.lyflow.rasp.java.config.RASPConfig;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.UUID;

final class BridgeFallbackLog {
    private final File path;
    private final long maxBytes;
    private final Gson gson = new Gson();
    private String previousHash;

    BridgeFallbackLog(RASPConfig config) {
        path = new File(config.getFallbackPath());
        maxBytes = config.getMaxLogBytes();
        try {
            previousHash = loadLastHash();
        } catch (IOException | NoSuchAlgorithmException error) {
            throw new IllegalStateException("cannot read RASP fallback integrity log", error);
        }
    }

    synchronized void append(JsonObject event, String reason, RASPConfig config) throws IOException, NoSuchAlgorithmException {
        JsonObject record = new JsonObject();
        record.addProperty("schema_version", "lyflow.rasp_fallback.v1");
        record.addProperty("recorded_at", Instant.now().toString());
        record.addProperty("reason", reason);
        record.addProperty("agent_id", config.getAgentID());
        record.addProperty("policy_id", config.getPolicyID());
        record.addProperty("policy_version", config.getPolicyVersion());
        record.addProperty("event_id", event.has("event_id")
                ? event.get("event_id").getAsString()
                : UUID.randomUUID().toString());
        record.addProperty("payload_sha256", sha256(gson.toJson(event)));
        record.addProperty("previous_record_sha256", previousHash);
        record.add("event", event);
        String recordHash = sha256(gson.toJson(record));
        record.addProperty("record_sha256", recordHash);
        byte[] encoded = (gson.toJson(record) + "\n").getBytes(StandardCharsets.UTF_8);
        if (path.length() + encoded.length > maxBytes) {
            throw new IOException("RASP fallback capacity reached");
        }
        File parent = path.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IllegalStateException("cannot create RASP fallback directory");
        }
        try (FileOutputStream output = new FileOutputStream(path, true);
             OutputStreamWriter writer = new OutputStreamWriter(output, StandardCharsets.UTF_8)) {
            writer.write(new String(encoded, StandardCharsets.UTF_8));
            writer.flush();
            output.getFD().sync();
        }
        previousHash = recordHash;
    }

    private String loadLastHash() throws IOException, NoSuchAlgorithmException {
        if (!path.isFile()) {
            return "";
        }
        if (path.length() > maxBytes) {
            throw new IOException("RASP fallback exceeds capacity");
        }
        String lastHash = "";
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.trim().isEmpty()) {
                    JsonObject record = JsonParser.parseString(line).getAsJsonObject();
                    String recordHash = record.remove("record_sha256").getAsString();
                    String previousRecordHash = record.get("previous_record_sha256").getAsString();
                    JsonObject event = record.getAsJsonObject("event");
                    String payloadHash = record.get("payload_sha256").getAsString();
                    if (!lastHash.equals(previousRecordHash)
                            || !payloadHash.equals(sha256(gson.toJson(event)))
                            || !recordHash.equals(sha256(gson.toJson(record)))) {
                        throw new IOException("RASP fallback integrity verification failed");
                    }
                    lastHash = recordHash;
                }
            }
        }
        return lastHash;
    }

    private static String sha256(String value) throws NoSuchAlgorithmException {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder encoded = new StringBuilder(digest.length * 2);
        for (byte item : digest) {
            encoded.append(String.format("%02x", item & 0xff));
        }
        return encoded.toString();
    }
}
