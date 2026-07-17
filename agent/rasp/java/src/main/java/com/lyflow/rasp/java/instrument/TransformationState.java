package com.lyflow.rasp.java.instrument;

final class TransformationState {
    private boolean changed;

    void markChanged() {
        changed = true;
    }

    boolean changed() {
        return changed;
    }
}
