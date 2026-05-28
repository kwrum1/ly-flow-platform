# LyFlow Java RASP Packaging

Java RASP is packaged as a JVM agent roadmap-compatible surface modeled after Elkeid `premain/agentmain` and OpenRASP-style hook/rule concepts.

Current production claim: **monitor-capability packaging contract only**. Protect/block mode must remain disabled unless an agent-executed QA run verifies blocking behavior for the target JVM and hook set.

Required manifest entry points for future implementation:

- `Premain-Class: com.lyflow.rasp.Agent`
- `Agent-Class: com.lyflow.rasp.Agent`
- `Can-Redefine-Classes: true`
- `Can-Retransform-Classes: true`

Policy mapping:

- `rasp.mode=off`: do not attach hooks.
- `rasp.mode=monitor`: attach hooks and report events without blocking.
- `rasp.mode=protect`: attach hooks and block only rules with verified block actions.
