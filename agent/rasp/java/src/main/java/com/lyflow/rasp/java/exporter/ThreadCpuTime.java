package com.lyflow.rasp.java.exporter;

import java.lang.management.ManagementFactory;
import java.lang.management.ThreadMXBean;
import java.util.function.LongSupplier;

final class ThreadCpuTime {
    private ThreadCpuTime() {
    }

    static LongSupplier supplier() {
        ThreadMXBean bean = ManagementFactory.getThreadMXBean();
        if (!bean.isCurrentThreadCpuTimeSupported()) {
            return System::nanoTime;
        }
        if (!bean.isThreadCpuTimeEnabled()) {
            bean.setThreadCpuTimeEnabled(true);
        }
        return bean::getCurrentThreadCpuTime;
    }
}
