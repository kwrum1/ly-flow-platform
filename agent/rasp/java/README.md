# LyFlow Java RASP

This module provides bounded, monitor-only JVM call-site instrumentation for explicitly allowlisted fixture or application packages. It observes JDBC statement execution, command execution, selected file APIs, and Java object deserialization while preserving the original invocation and result.

The agent never instruments broad JDK packages. The default allowlist contains only `com.lyflow.rasp.fixture`; applications must pass their package roots with a semicolon-separated `packages` agent option. System, JDK, and agent packages are rejected. Unsupported classes and unsupported bytecode return the JVM no-transform result.

Build and test with the pinned OpenJDK 17.0.19 and Maven 3.9.9 toolchain:

```bash
mvn -q -Pexperimental-runtime clean verify
bash ../../../scripts/qa/run-java-rasp-conformance.sh --iterations 10
```

Example monitor attachment:

```text
-javaagent:ly-rasp-java-1.0.0.jar=mode=monitor,policyVersion=14,policyId=policy-id,agentId=agent-id,packages=com.example.app
```

The optional `experimental-runtime` Maven profile emits the reproducible `ly-rasp-java-1.0.0-experimental.jar`. Its conformance gate boots that artifact with `-javaagent` and runs watchdog exhaustion, binary tamper, publication outage/recovery, and canonical health checks. This profile is experimental verification only: the Java agent remains excluded from default and pilot production packages.
