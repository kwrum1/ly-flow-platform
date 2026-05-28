# LyFlow PHP RASP probe

The PHP RASP layer has two modes:

- `extension/`: native Zend internal-function hook for process execution, SQL, file, and SSRF sinks.
- `ly_rasp_prepend.php`: `auto_prepend_file` fallback and framework-friendly wrapper helpers.

Build the extension on a PHP host with development headers:

```sh
cd /opt/ly-agent/rasp/php/extension
phpize
./configure --enable-ly-rasp
make
make install
```

Enable monitor mode:

```ini
extension=ly_rasp.so
ly_rasp.bridge=http://127.0.0.1:17891/v1/rasp/events
ly_rasp.token=
ly_rasp.app=php-app
auto_prepend_file=/opt/ly-agent/rasp/php/ly_rasp_prepend.php
```

The extension does not block requests; it emits candidate-only telemetry to the local ly-agent RASP bridge.
