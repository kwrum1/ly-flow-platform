package com.lyflow.rasp.java.exporter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;
import com.lyflow.rasp.java.config.RASPConfig;
import com.lyflow.rasp.java.model.RASPEvent;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

// allow: SIZE_OK - this bounded exporter is one queue-owning supervised state machine.
public final class OTLPExporter implements Exporter {
    private static final long WATCHDOG_STALE_NANOS = TimeUnit.SECONDS.toNanos(5);
    private static final long WATCHDOG_CHECK_NANOS = TimeUnit.SECONDS.toNanos(1);
    private static final long WATCHDOG_BACKOFF_NANOS = TimeUnit.MILLISECONDS.toNanos(250);

    interface WatchdogClock {
        long nanoTime();
        Instant now();
        boolean await(CountDownLatch stopped, long timeoutNanos) throws InterruptedException;
    }

    private static final class SystemWatchdogClock implements WatchdogClock {
        @Override
        public long nanoTime() {
            return System.nanoTime();
        }

        @Override
        public Instant now() {
            return Instant.now();
        }

        @Override
        public boolean await(CountDownLatch stopped, long timeoutNanos) throws InterruptedException {
            return stopped.await(timeoutNanos, TimeUnit.NANOSECONDS);
        }
    }

    private final RASPConfig config;
    private final Gson gson = new GsonBuilder()
            .registerTypeAdapter(Instant.class, (JsonSerializer<Instant>)
                    (source, type, context) -> new JsonPrimitive(source.toString()))
            .create();
    private final CanonicalEventEncoder encoder = new CanonicalEventEncoder();
    private final BlockingQueue<RASPEvent> eventQueue;
    private final int physicalQueueCapacity;
    private final Object queueAdmissionLock = new Object();
    private final Object workerLifecycleLock = new Object();
    private final ExecutorService executor;
    private final ExecutorService watchdogExecutor;
    private final BridgeFallbackLog fallbackLog;
    private final RASPBridgeTransport transport;
    private final CanonicalEvidenceLog evidenceLog;
    private final LongSupplier nanoTime;
    private final WatchdogClock watchdogClock;
    private final CountDownLatch stopped = new CountDownLatch(1);
    private final CountDownLatch watchdogFinished = new CountDownLatch(1);
    private final AtomicLong delivered = new AtomicLong();
    private final AtomicLong rejected = new AtomicLong();
    private final AtomicLong failures = new AtomicLong();
    private final AtomicLong fallbackPersisted = new AtomicLong();
    private final AtomicLong publicationRetryCount = new AtomicLong();
    private volatile boolean running = true;
    private volatile boolean workerBusy;
    private volatile String lastError = "";
    private volatile Instant watchdogAt;
    private volatile long watchdogActivityNanos;
    private volatile long failureAtNanos;
    private volatile Future<?> workerTask;
    private volatile String publicationStatus = "healthy";
    private volatile String publicationLastError = "";
    private volatile String publicationReason = "";
    private volatile ControlHealthPublicationException lastPublicationFailure;

    public OTLPExporter(RASPConfig config) {
        this(config, ThreadCpuTime.supplier(), new SystemWatchdogClock());
    }

    OTLPExporter(RASPConfig config, LongSupplier nanoTime) {
        this(config, nanoTime, new SystemWatchdogClock());
    }

    OTLPExporter(RASPConfig config, LongSupplier nanoTime, WatchdogClock watchdogClock) {
        this.config = config;
        this.nanoTime = nanoTime;
        this.watchdogClock = watchdogClock;
        watchdogAt = watchdogClock.now();
        watchdogActivityNanos = watchdogClock.nanoTime();
        physicalQueueCapacity = config.getQueueCapacity();
        eventQueue = new ArrayBlockingQueue<>(physicalQueueCapacity);
        transport = config.getEvidencePath().isEmpty() ? new RASPBridgeTransport(config) : null;
        evidenceLog = config.getEvidencePath().isEmpty()
                ? null
                : new CanonicalEvidenceLog(config.getEvidencePath(), config.getMaxLogBytes());
        BridgeFallbackLog configuredFallback;
        try {
            configuredFallback = new BridgeFallbackLog(config);
        } catch (RuntimeException error) {
            configuredFallback = null;
            failures.incrementAndGet();
            lastError = "fallback_integrity_failed";
            config.disablePrevention();
        }
        fallbackLog = configuredFallback;
        if (!new BinaryIntegrityVerifier().verify(config)) {
            config.disablePrevention();
            failures.incrementAndGet();
            lastError = "binary_integrity_failed";
            reportControlHealth(lastError);
        }
        executor = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "rasp-bounded-exporter");
            thread.setDaemon(true);
            return thread;
        });
        watchdogExecutor = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task, "rasp-exporter-watchdog");
            thread.setDaemon(true);
            return thread;
        });
        workerTask = executor.submit(this::runExporter);
        watchdogExecutor.submit(this::runWatchdog);
    }

    @Override
    public void export(RASPEvent event) {
        if (!prepare(event)) {
            return;
        }
        synchronized (queueAdmissionLock) {
            if (eventQueue.size() >= effectiveQueueCapacity() || !eventQueue.offer(event)) {
                rejected.incrementAndGet();
                lastError = "queue_capacity_exceeded";
                reportControlHealth(lastError);
            }
        }
    }

    @Override
    public void exportSync(RASPEvent event) {
        if (prepare(event)) {
            sendEvent(event);
        }
    }

    private boolean prepare(RASPEvent event) {
        if (event == null || !running) {
            return false;
        }
        applyAppName(event);
        if (transport != null) {
            try {
                transport.refreshConfig();
            } catch (IOException | RuntimeException error) {
                recordFailure(event, error);
                return false;
            }
        }
        return config.shouldExportNow();
    }

    private void runExporter() {
        while (running || !eventQueue.isEmpty()) {
            touchWatchdog();
            try {
                RASPEvent event = eventQueue.poll(100, TimeUnit.MILLISECONDS);
                if (event != null) {
                    sendEvent(event);
                }
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void sendEvent(RASPEvent event) {
        workerBusy = true;
        touchWatchdog();
        try {
            long started = nanoTime.getAsLong();
            JsonObject payload = encoder.encode(event, config);
            if (gson.toJson(payload).getBytes(java.nio.charset.StandardCharsets.UTF_8).length > config.getMemoryBudgetBytes()) {
                failures.incrementAndGet();
                lastError = "memory_budget_exceeded";
                reportControlHealth(lastError);
                return;
            }
            if (nanoTime.getAsLong() - started > TimeUnit.MILLISECONDS.toNanos(config.getCpuBudgetMillis())) {
                failures.incrementAndGet();
                lastError = "cpu_budget_exceeded";
                reportControlHealth(lastError);
                return;
            }
            try {
                if (evidenceLog != null) {
                    evidenceLog.append(payload);
                } else {
                    transport.refreshConfig();
                    transport.send(payload, gson);
                }
                delivered.incrementAndGet();
                lastError = "";
                if ("degraded".equals(publicationStatus)) {
                    reportControlHealth("ready");
                }
            } catch (IOException | RuntimeException error) {
                recordFailure(event, error);
            }
        } finally {
            workerBusy = false;
            touchWatchdog();
        }
    }

    private void recordFailure(RASPEvent event, Exception error) {
        failures.incrementAndGet();
        failureAtNanos = watchdogClock.nanoTime();
        watchdogAt = watchdogClock.now();
        if (error instanceof ControlAuthorizationException) {
            config.disablePrevention();
            lastError = "authorization_failed";
            reportControlHealth(lastError);
            return;
        }
        if (error instanceof ConfigIntegrityException) {
            config.disablePrevention();
            lastError = error.getMessage();
            reportControlHealth(lastError);
            return;
        }
        if (error instanceof RuntimeBudgetException budgetError) {
            lastError = budgetError.reason();
            reportControlHealth(lastError);
            return;
        }
        lastError = "exporter_unavailable";
        persistFallback(encoder.encode(event, config), lastError);
        reportControlHealth(lastError);
    }

    private void runWatchdog() {
        long nextRestartAt = watchdogClock.nanoTime();
        try {
            while (running && !watchdogClock.await(stopped, WATCHDOG_CHECK_NANOS)) {
                long now = watchdogClock.nanoTime();
                boolean unavailable = "exporter_unavailable".equals(lastError);
                boolean staleWorker = workerBusy
                        && now - watchdogActivityNanos > WATCHDOG_STALE_NANOS;
                boolean staleExporter = unavailable
                        && now - failureAtNanos > WATCHDOG_STALE_NANOS;
                boolean stale = staleWorker || staleExporter;
                if (!stale || now < nextRestartAt || "off".equals(config.getMode())) {
                    continue;
                }
                lastError = "watchdog_stale";
                watchdogAt = watchdogClock.now();
                if (!config.recordWatchdogRestart()) {
                    lastError = config.getRuntimeHealthReason();
                    reportControlHealth(lastError);
                    return;
                }
                reportControlHealth(lastError);
                restartWorker();
                int shift = Math.min(config.getRestartCount() - 1, 20);
                nextRestartAt = now + (WATCHDOG_BACKOFF_NANOS << shift);
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        } finally {
            watchdogFinished.countDown();
        }
    }

    private void restartWorker() {
        synchronized (workerLifecycleLock) {
            if (!running) {
                return;
            }
            workerTask.cancel(true);
            workerTask = executor.submit(this::runExporter);
        }
    }

    private void touchWatchdog() {
        watchdogActivityNanos = watchdogClock.nanoTime();
        watchdogAt = watchdogClock.now();
    }

    private void persistFallback(JsonObject payload, String reason) {
        if (fallbackLog == null) {
            return;
        }
        try {
            fallbackLog.append(payload, reason, config);
            fallbackPersisted.incrementAndGet();
        } catch (IOException | NoSuchAlgorithmException | RuntimeException error) {
            lastError = error.getClass().getSimpleName();
        }
    }

    private void reportControlHealth(String reason) {
        if (transport == null) {
            persistFallback(controlHealth(reason), reason);
            return;
        }
        if ("degraded".equals(publicationStatus) && reason.equals(publicationReason)) {
            persistFallback(controlHealth(reason), reason);
            return;
        }
        ControlHealthPublicationException failure = publishControlHealth(reason);
        if (failure != null) {
            persistFallback(controlHealth(reason), reason);
        }
    }

    private ControlHealthPublicationException publishControlHealth(String reason) {
        if (transport == null) {
            publicationStatus = "healthy";
            publicationLastError = "";
            lastPublicationFailure = null;
            return null;
        }
        for (int attempt = 1; attempt <= 3; attempt++) {
            try {
                transport.sendControlHealth(controlHealth(reason), gson);
                publicationStatus = "healthy";
                publicationLastError = "";
                publicationReason = reason;
                lastPublicationFailure = null;
                return null;
            } catch (IOException | RuntimeException error) {
                publicationStatus = "degraded";
                publicationReason = reason;
                publicationRetryCount.incrementAndGet();
                publicationLastError = error.getClass().getSimpleName() + ": " + error.getMessage();
                if (attempt < 3 && !awaitPublicationBackoff(attempt)) {
                    break;
                }
            }
        }
        lastPublicationFailure = new ControlHealthPublicationException(3, publicationLastError);
        return lastPublicationFailure;
    }

    private boolean awaitPublicationBackoff(int attempt) {
        try {
            TimeUnit.MILLISECONDS.sleep(10L << (attempt - 1));
            return true;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            publicationLastError = "InterruptedException: control health retry interrupted";
            return false;
        }
    }

    private void applyAppName(RASPEvent event) {
        if (event.getAppName() == null || event.getAppName().isEmpty()) {
            event.setAppName(config.getAppName());
        }
    }

    public void shutdown() {
        synchronized (workerLifecycleLock) {
            running = false;
            stopped.countDown();
            executor.shutdown();
        }
        watchdogExecutor.shutdownNow();
        try {
            if (!watchdogExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                watchdogExecutor.shutdownNow();
                watchdogExecutor.awaitTermination(5, TimeUnit.SECONDS);
            }
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                eventQueue.clear();
                workerTask.cancel(true);
                executor.shutdownNow();
                executor.awaitTermination(5, TimeUnit.SECONDS);
            }
        } catch (InterruptedException ignored) {
            watchdogExecutor.shutdownNow();
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    boolean awaitWatchdogStopped(long timeout, TimeUnit unit) throws InterruptedException {
        return watchdogFinished.await(timeout, unit);
    }

    boolean executorsTerminated() {
        return executor.isTerminated() && watchdogExecutor.isTerminated();
    }

    public int getQueueSize() {
        return eventQueue.size();
    }

    private int effectiveQueueCapacity() {
        int configured = Math.min(physicalQueueCapacity, config.getQueueCapacity());
        return Math.max(eventQueue.size(), configured);
    }

    public Map<String, Object> getDeliveryHealth() {
        String configReason = config.getRuntimeHealthReason();
        String reason = lastError.isEmpty() ? configReason : lastError;
        String status = failures.get() > 0 || rejected.get() > 0 || !reason.isEmpty() ? "degraded" : "healthy";
        return new CanonicalControlHealth(
                config, "java-rasp", effectiveQueueCapacity(), status, reason, watchdogAt, publication()).asMap();
    }

    public String getDeliveryHealthJson() {
        return gson.toJson(getDeliveryHealth());
    }

    private JsonObject controlHealth(String reason) {
        return new CanonicalControlHealth(
                config, "java-rasp", effectiveQueueCapacity(), "degraded", reason, watchdogAt, publication()).asJson();
    }

    private ControlHealthPublication publication() {
        return new ControlHealthPublication(
                publicationStatus, publicationRetryCount.get(), publicationLastError);
    }

    ControlHealthPublicationException getLastPublicationFailure() {
        return lastPublicationFailure;
    }
}
