package com.lyflow.rasp.java.exporter;

import java.io.IOException;

final class ControlAuthorizationException extends IOException {
    private static final long serialVersionUID = 1L;

    ControlAuthorizationException() {
        super("RASP bridge authorization failed");
    }
}
