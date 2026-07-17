package com.lyflow.rasp.java.exporter;

import com.lyflow.rasp.java.config.RASPConfig;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

final class BinaryIntegrityVerifier {
    boolean verify(RASPConfig config) {
        if (config.getBinarySha256().isEmpty()) {
            return true;
        }
        try {
            byte[] contents = Files.readAllBytes(Path.of(config.getBinaryPath()));
            String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(contents));
            return MessageDigest.isEqual(
                    actual.getBytes(StandardCharsets.US_ASCII),
                    config.getBinarySha256().getBytes(StandardCharsets.US_ASCII));
        } catch (IOException | NoSuchAlgorithmException | RuntimeException error) {
            return false;
        }
    }
}
