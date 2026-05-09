package com.lyflow.rasp.java.exporter;

import com.lyflow.rasp.java.model.RASPEvent;

/**
 * Exporter Interface
 * Implementations should export RASP events to various backends
 */
public interface Exporter {
    /**
     * Export a RASP event asynchronously
     *
     * @param event The RASP event to export
     */
    void export(RASPEvent event);

    /**
     * Export a RASP event synchronously
     *
     * @param event The RASP event to export
     */
    void exportSync(RASPEvent event);
}