# LyFlow Java RASP probe

Build:

```sh
./build.sh
```

Run with JVM monitor hooks:

```sh
java -javaagent:/opt/ly-agent/rasp/java/ly-rasp-agent.jar -jar app.jar
```

JDBC SQL monitoring is available through the wrapper URL prefix:

```text
jdbc:lyrasp:jdbc:mysql://127.0.0.1:3306/app
```

The agent installs monitor-mode hooks for:

- process execution via `SecurityManager.checkExec`
- sensitive file reads/writes via `SecurityManager.checkRead/checkWrite`
- loopback/metadata SSRF-style connections via `SecurityManager.checkConnect`
- SQL execution via the `jdbc:lyrasp:` driver wrapper

All events are sent to `LY_RASP_BRIDGE` and stay candidate-only in server response policy.
