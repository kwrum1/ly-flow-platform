package com.lyflow.rasp.java.exporter;

import java.io.IOException;

final class RuntimeBudgetException extends IOException {
    private static final long serialVersionUID = 1L;
    private final String reason;

    RuntimeBudgetException(String reason) {
        super(reason);
        this.reason = reason;
    }

    String reason() {
        return reason;
    }
}
