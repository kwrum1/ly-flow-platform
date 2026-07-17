package com.lyflow.rasp.java.exporter;

import java.io.IOException;

final class ControlHealthPublicationException extends IOException {
    private static final long serialVersionUID = 1L;
    private final int attempts;

    ControlHealthPublicationException(int attempts, String message) {
        super("control health publication exhausted after " + attempts + " attempts: " + message);
        this.attempts = attempts;
    }

    int attempts() {
        return attempts;
    }
}
