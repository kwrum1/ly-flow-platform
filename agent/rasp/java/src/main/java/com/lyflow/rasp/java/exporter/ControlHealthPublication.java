package com.lyflow.rasp.java.exporter;

import com.google.gson.JsonObject;
import java.util.LinkedHashMap;
import java.util.Map;

record ControlHealthPublication(String status, long retryCount, String lastError) {
    Map<String, Object> asMap() {
        Map<String, Object> publication = new LinkedHashMap<>();
        publication.put("status", status);
        publication.put("retry_count", retryCount);
        publication.put("last_error", lastError);
        return publication;
    }

    JsonObject asJson() {
        JsonObject publication = new JsonObject();
        publication.addProperty("status", status);
        publication.addProperty("retry_count", retryCount);
        publication.addProperty("last_error", lastError);
        return publication;
    }
}
