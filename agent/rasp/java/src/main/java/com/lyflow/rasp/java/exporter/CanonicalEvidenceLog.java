package com.lyflow.rasp.java.exporter;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

final class CanonicalEvidenceLog {
    private final File path;
    private final long maxBytes;
    private final Gson gson = new Gson();

    CanonicalEvidenceLog(String path, long maxBytes) {
        this.path = new File(path);
        this.maxBytes = maxBytes;
    }

    synchronized void append(JsonObject event) throws IOException {
        byte[] encoded = (gson.toJson(event) + "\n").getBytes(StandardCharsets.UTF_8);
        if (path.length() + encoded.length > maxBytes) {
            throw new IOException("canonical evidence capacity reached");
        }
        File parent = path.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("cannot create canonical evidence directory");
        }
        try (FileOutputStream output = new FileOutputStream(path, true);
             OutputStreamWriter writer = new OutputStreamWriter(output, StandardCharsets.UTF_8)) {
            writer.write(new String(encoded, StandardCharsets.UTF_8));
            writer.flush();
        }
    }
}
