package com.lyflow.rasp.java.exporter;

import java.io.IOException;

final class ConfigIntegrityException extends IOException {
    private static final long serialVersionUID = 1L;

    ConfigIntegrityException(String message) {
        super(message);
    }

    ConfigIntegrityException(String message, Throwable cause) {
        super(message, cause);
    }
}
