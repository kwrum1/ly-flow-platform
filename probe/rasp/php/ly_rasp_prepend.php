<?php
// LyFlow PHP RASP probe. Use with auto_prepend_file in monitor mode.
function ly_rasp_normalize_payload($hook_type, $payload) {
    if (isset($payload['sql']) && !isset($payload['query'])) $payload['query'] = $payload['sql'];
    if (isset($payload['cmd']) && !isset($payload['command'])) $payload['command'] = $payload['cmd'];
    if (isset($payload['command']) && !isset($payload['cmdline'])) $payload['cmdline'] = $payload['command'];
    if (isset($payload['cmdline']) && !isset($payload['command'])) $payload['command'] = $payload['cmdline'];
    if (isset($payload['file']) && !isset($payload['path'])) $payload['path'] = $payload['file'];
    if (isset($payload['uri']) && !isset($payload['url'])) $payload['url'] = $payload['uri'];
    foreach (array('query', 'command', 'cmdline', 'path', 'url') as $key) {
        if (isset($payload[$key]) && !isset($payload['payload'])) $payload['payload'] = (string)$payload[$key];
        if (isset($payload[$key]) && !isset($payload['message'])) $payload['message'] = (string)$payload[$key];
    }
    $payload['rule_field_contract'] = array('query', 'command', 'cmdline', 'path', 'url', 'payload', 'message');
    return $payload;
}

function ly_rasp_emit($hook_type, $payload) {
    $payload = ly_rasp_normalize_payload($hook_type, $payload);
    $bridge = getenv('LY_RASP_BRIDGE') ?: 'http://127.0.0.1:17891/v1/rasp/events';
    $token = getenv('LY_RASP_TOKEN') ?: '';
    $app = getenv('LY_APP_NAME') ?: 'php-app';
    $body = json_encode(array_merge(array(
        'event_type' => 'rasp.' . $hook_type,
        'language' => 'php',
        'runtime' => PHP_VERSION,
        'application' => $app,
        'hook_type' => $hook_type,
        'observed_at' => gmdate('c'),
        'source_ip' => $_SERVER['REMOTE_ADDR'] ?? '',
        'path' => $_SERVER['REQUEST_URI'] ?? '',
        'xff' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
    ), $payload), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    $headers = "Content-Type: application/json\r\n";
    if ($token !== '') $headers .= "X-Ly-RASP-Token: " . $token . "\r\n";
    @file_get_contents($bridge, false, stream_context_create(array('http' => array(
        'method' => 'POST',
        'header' => $headers,
        'content' => $body,
        'timeout' => 0.5,
    ))));
}

function ly_rasp_exec($command, $sink = 'ly_rasp_exec') {
    ly_rasp_emit('exec', array('command' => (string)$command, 'cmdline' => (string)$command, 'sink' => $sink));
    return shell_exec($command);
}

function ly_rasp_system($command, $sink = 'ly_rasp_system') {
    ly_rasp_emit('exec', array('command' => (string)$command, 'cmdline' => (string)$command, 'sink' => $sink));
    return system($command);
}

function ly_rasp_query($query, $sink = 'ly_rasp_query') {
    if (preg_match('/union\s+select|or\s+1=1|sleep\s*\(|information_schema|load_file\s*\(/i', (string)$query)) {
        ly_rasp_emit('sql', array('query' => (string)$query, 'sink' => $sink));
    }
    return $query;
}

function ly_rasp_file_path($path, $sink = 'ly_rasp_file_path') {
    if (preg_match('/\.\.\/|\/etc\/passwd|\/etc\/shadow|\/proc\/self\/environ|id_rsa/i', (string)$path)) {
        ly_rasp_emit('file', array('path' => (string)$path, 'sink' => $sink));
    }
    return $path;
}

function ly_rasp_url($url, $sink = 'ly_rasp_url') {
    if (preg_match('/127\.0\.0\.1|169\.254\.169\.254|localhost|file:\/\/|gopher:\/\//i', (string)$url)) {
        ly_rasp_emit('ssrf', array('url' => (string)$url, 'sink' => $sink));
    }
    return $url;
}

function ly_rasp_unserialize($payload, $allowed_classes = null, $sink = 'ly_rasp_unserialize') {
    if (preg_match('/(^|;)O:\d+:|__wakeup|__destruct|Serializable/i', (string)$payload)) {
        ly_rasp_emit('deserialization', array('payload' => (string)$payload, 'sink' => $sink));
    }
    if ($allowed_classes === null) {
        return unserialize($payload);
    }
    return unserialize($payload, array('allowed_classes' => $allowed_classes));
}

function ly_rasp_code_payload($payload, $sink = 'ly_rasp_code_payload') {
    if (preg_match('/eval\s*\(|assert\s*\(|base64_decode|shell_exec|passthru|proc_open|system\s*\(/i', (string)$payload)) {
        ly_rasp_emit('webshell', array('payload' => (string)$payload, 'sink' => $sink));
    }
    return $payload;
}

if (isset($_REQUEST['cmd'])) {
    ly_rasp_emit('exec.input', array('command' => (string)$_REQUEST['cmd'], 'sink' => 'request.cmd'));
}
if (isset($_REQUEST['q']) && preg_match('/union\s+select|or\s+1=1|sleep\s*\(/i', (string)$_REQUEST['q'])) {
    ly_rasp_emit('sql.input', array('query' => (string)$_REQUEST['q'], 'sink' => 'request.q'));
}
if (isset($_REQUEST['file']) && preg_match('/\.\.\/|\/etc\/passwd|\/proc\/self\/environ/i', (string)$_REQUEST['file'])) {
    ly_rasp_emit('file.input', array('path' => (string)$_REQUEST['file'], 'sink' => 'request.file'));
}
if (isset($_REQUEST['url']) && preg_match('/127\.0\.0\.1|169\.254\.169\.254|localhost|file:\/\/|gopher:\/\//i', (string)$_REQUEST['url'])) {
    ly_rasp_emit('ssrf.input', array('url' => (string)$_REQUEST['url'], 'sink' => 'request.url'));
}
if (isset($_REQUEST['serialized']) && preg_match('/(^|;)O:\d+:|__wakeup|__destruct|Serializable/i', (string)$_REQUEST['serialized'])) {
    ly_rasp_emit('deserialization.input', array('payload' => (string)$_REQUEST['serialized'], 'sink' => 'request.serialized'));
}
$request_payload = json_encode($_REQUEST, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
if ($request_payload !== false && preg_match('/eval\s*\(|assert\s*\(|base64_decode|Runtime\.getRuntime|ProcessBuilder/i', $request_payload)) {
    ly_rasp_emit('webshell.input', array('payload' => $request_payload, 'sink' => 'request.payload'));
}
?>
