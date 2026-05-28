#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "SAPI.h"
#include "Zend/zend_smart_str.h"
#include "Zend/zend_compile.h"
#include "php_ly_rasp.h"

static void (*original_execute_internal)(zend_execute_data *execute_data, zval *return_value);
static zend_op_array *(*original_compile_file)(zend_file_handle *file_handle, int type);
static zend_op_array *(*original_compile_string)(zend_string *source_string, const char *filename, zend_compile_position position);

static PHP_INI_MH(OnUpdateBridge)
{
    return OnUpdateString(entry, new_value, mh_arg1, mh_arg2, mh_arg3, stage);
}

ZEND_BEGIN_MODULE_GLOBALS(ly_rasp)
    char *bridge;
    char *token;
    char *app;
ZEND_END_MODULE_GLOBALS(ly_rasp)

ZEND_DECLARE_MODULE_GLOBALS(ly_rasp)

#define LY_RASP_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(ly_rasp, v)

PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("ly_rasp.bridge", "http://127.0.0.1:17891/v1/rasp/events", PHP_INI_ALL, OnUpdateBridge, bridge, zend_ly_rasp_globals, ly_rasp_globals)
    STD_PHP_INI_ENTRY("ly_rasp.token", "", PHP_INI_ALL, OnUpdateString, token, zend_ly_rasp_globals, ly_rasp_globals)
    STD_PHP_INI_ENTRY("ly_rasp.app", "php-app", PHP_INI_ALL, OnUpdateString, app, zend_ly_rasp_globals, ly_rasp_globals)
PHP_INI_END()

static void php_ly_rasp_init_globals(zend_ly_rasp_globals *globals)
{
    globals->bridge = NULL;
    globals->token = NULL;
    globals->app = NULL;
}

static int contains_case_insensitive(const char *haystack, const char *needle)
{
    size_t needle_len;
    const char *p;
    if (haystack == NULL || needle == NULL) return 0;
    needle_len = strlen(needle);
    if (needle_len == 0) return 0;
    for (p = haystack; *p; p++) {
        if (strncasecmp(p, needle, needle_len) == 0) return 1;
    }
    return 0;
}

static int sensitive_sql(const char *value)
{
    return contains_case_insensitive(value, "union select") || contains_case_insensitive(value, "sleep(") || contains_case_insensitive(value, " or 1=1") || contains_case_insensitive(value, "information_schema");
}

static int sensitive_path(const char *value)
{
    return contains_case_insensitive(value, "../") || contains_case_insensitive(value, "/etc/passwd") || contains_case_insensitive(value, "/etc/shadow") || contains_case_insensitive(value, "/proc/self/environ");
}

static int sensitive_url(const char *value)
{
    return contains_case_insensitive(value, "127.0.0.1") || contains_case_insensitive(value, "localhost") || contains_case_insensitive(value, "169.254.169.254") || contains_case_insensitive(value, "file://") || contains_case_insensitive(value, "gopher://");
}

static int sensitive_code(const char *value)
{
    return contains_case_insensitive(value, "eval(") || contains_case_insensitive(value, "assert(") || contains_case_insensitive(value, "base64_decode") || contains_case_insensitive(value, "shell_exec") || contains_case_insensitive(value, "passthru") || contains_case_insensitive(value, "system(") || contains_case_insensitive(value, "proc_open");
}

static zend_string *json_escape(const char *value)
{
    smart_str out = {0};
    const unsigned char *p;
    if (value == NULL) value = "";
    for (p = (const unsigned char *)value; *p; p++) {
        switch (*p) {
            case '\\': smart_str_appends(&out, "\\\\"); break;
            case '"': smart_str_appends(&out, "\\\""); break;
            case '\n': smart_str_appends(&out, "\\n"); break;
            case '\r': smart_str_appends(&out, "\\r"); break;
            case '\t': smart_str_appends(&out, "\\t"); break;
            default: smart_str_appendc(&out, *p); break;
        }
    }
    smart_str_0(&out);
    return out.s;
}

static void emit_rasp_event(const char *hook, const char *field, const char *value, const char *sink)
{
    php_stream_context *context;
    php_stream *stream;
    zval option;
    smart_str headers = {0};
    smart_str body = {0};
    zend_string *escaped_value = json_escape(value);
    const char *bridge = LY_RASP_G(bridge) != NULL ? LY_RASP_G(bridge) : "http://127.0.0.1:17891/v1/rasp/events";
    const char *app = LY_RASP_G(app) != NULL ? LY_RASP_G(app) : "php-app";

    smart_str_appends(&body, "{");
    smart_str_append_printf(&body, "\"event_type\":\"rasp.%s\",\"language\":\"php\",\"runtime\":\"php-extension\",\"application\":\"%s\",", hook, app);
    smart_str_append_printf(&body, "\"hook_type\":\"%s\",\"sink\":\"%s\",", hook, sink != NULL ? sink : "php.internal");
    if (SG(request_info).request_uri != NULL) smart_str_append_printf(&body, "\"path\":\"%s\",", SG(request_info).request_uri);
    if (SG(request_info).request_method != NULL) smart_str_append_printf(&body, "\"http_method\":\"%s\",", SG(request_info).request_method);
    smart_str_append_printf(&body, "\"%s\":\"%s\",\"payload\":\"%s\",\"message\":\"%s\",", field, ZSTR_VAL(escaped_value), ZSTR_VAL(escaped_value), ZSTR_VAL(escaped_value));
    if (strcmp(field, "command") == 0) smart_str_append_printf(&body, "\"cmdline\":\"%s\",", ZSTR_VAL(escaped_value));
    smart_str_appends(&body, "\"rule_field_contract\":[\"query\",\"command\",\"cmdline\",\"path\",\"url\",\"payload\",\"message\"]}");
    smart_str_0(&body);

    smart_str_appends(&headers, "Content-Type: application/json\r\n");
    if (LY_RASP_G(token) != NULL && LY_RASP_G(token)[0] != '\0') {
        smart_str_append_printf(&headers, "X-Ly-RASP-Token: %s\r\n", LY_RASP_G(token));
    }
    smart_str_0(&headers);

    context = php_stream_context_alloc();
    ZVAL_STRING(&option, "POST");
    php_stream_context_set_option(context, "http", "method", &option);
    zval_ptr_dtor(&option);
    ZVAL_STRINGL(&option, ZSTR_VAL(headers.s), ZSTR_LEN(headers.s));
    php_stream_context_set_option(context, "http", "header", &option);
    zval_ptr_dtor(&option);
    ZVAL_STRINGL(&option, ZSTR_VAL(body.s), ZSTR_LEN(body.s));
    php_stream_context_set_option(context, "http", "content", &option);
    zval_ptr_dtor(&option);
    ZVAL_DOUBLE(&option, 0.5);
    php_stream_context_set_option(context, "http", "timeout", &option);
    stream = php_stream_open_wrapper_ex((char *)bridge, "rb", 0, NULL, context);
    if (stream != NULL) php_stream_close(stream);

    smart_str_free(&headers);
    smart_str_free(&body);
    zend_string_release(escaped_value);
}

static const char *first_string_arg(zend_execute_data *execute_data)
{
    zval *arg;
    if (ZEND_CALL_NUM_ARGS(execute_data) < 1) return NULL;
    arg = ZEND_CALL_ARG(execute_data, 1);
    return Z_TYPE_P(arg) == IS_STRING ? Z_STRVAL_P(arg) : NULL;
}

static void ly_rasp_execute_internal(zend_execute_data *execute_data, zval *return_value)
{
    const char *arg = first_string_arg(execute_data);
    const char *name = execute_data->func != NULL && execute_data->func->common.function_name != NULL ? ZSTR_VAL(execute_data->func->common.function_name) : "";
    if (arg != NULL) {
        if (strcasecmp(name, "exec") == 0 || strcasecmp(name, "system") == 0 || strcasecmp(name, "shell_exec") == 0 || strcasecmp(name, "passthru") == 0 || strcasecmp(name, "proc_open") == 0 || strcasecmp(name, "popen") == 0) {
            emit_rasp_event("exec", "command", arg, name);
        } else if ((strcasecmp(name, "mysqli_query") == 0 || strcasecmp(name, "pg_query") == 0 || strcasecmp(name, "sqlite_query") == 0) && sensitive_sql(arg)) {
            emit_rasp_event("sql", "query", arg, name);
        } else if ((strcasecmp(name, "fopen") == 0 || strcasecmp(name, "file_get_contents") == 0 || strcasecmp(name, "readfile") == 0 || strcasecmp(name, "include") == 0 || strcasecmp(name, "require") == 0) && sensitive_path(arg)) {
            emit_rasp_event("file", "path", arg, name);
        } else if ((strcasecmp(name, "curl_init") == 0 || strcasecmp(name, "file_get_contents") == 0) && sensitive_url(arg)) {
            emit_rasp_event("ssrf", "url", arg, name);
        } else if ((strcasecmp(name, "unserialize") == 0) && contains_case_insensitive(arg, "O:")) {
            emit_rasp_event("deserialization", "payload", arg, name);
        } else if ((strcasecmp(name, "assert") == 0 || strcasecmp(name, "create_function") == 0) && sensitive_code(arg)) {
            emit_rasp_event("webshell", "payload", arg, name);
        }
    }
    if (original_execute_internal != NULL) {
        original_execute_internal(execute_data, return_value);
        return;
    }
    execute_internal(execute_data, return_value);
}

static zend_op_array *ly_rasp_compile_file(zend_file_handle *file_handle, int type)
{
    if (file_handle != NULL && file_handle->filename != NULL) {
        const char *filename = ZSTR_VAL(file_handle->filename);
        if (sensitive_path(filename) || sensitive_url(filename)) {
            emit_rasp_event("file", "path", filename, "zend_compile_file");
        }
    }
    return original_compile_file(file_handle, type);
}

static zend_op_array *ly_rasp_compile_string(zend_string *source_string, const char *filename, zend_compile_position position)
{
    if (source_string != NULL && sensitive_code(ZSTR_VAL(source_string))) {
        emit_rasp_event("webshell", "payload", ZSTR_VAL(source_string), filename != NULL ? filename : "zend_compile_string");
    }
    return original_compile_string(source_string, filename, position);
}

PHP_MINIT_FUNCTION(ly_rasp)
{
    ZEND_INIT_MODULE_GLOBALS(ly_rasp, php_ly_rasp_init_globals, NULL);
    REGISTER_INI_ENTRIES();
    original_execute_internal = zend_execute_internal;
    zend_execute_internal = ly_rasp_execute_internal;
    original_compile_file = zend_compile_file;
    zend_compile_file = ly_rasp_compile_file;
    original_compile_string = zend_compile_string;
    zend_compile_string = ly_rasp_compile_string;
    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(ly_rasp)
{
    zend_execute_internal = original_execute_internal;
    zend_compile_file = original_compile_file;
    zend_compile_string = original_compile_string;
    UNREGISTER_INI_ENTRIES();
    return SUCCESS;
}

PHP_MINFO_FUNCTION(ly_rasp)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "LyFlow RASP", "enabled");
    php_info_print_table_row(2, "Version", PHP_LY_RASP_VERSION);
    php_info_print_table_end();
}

zend_module_entry ly_rasp_module_entry = {
    STANDARD_MODULE_HEADER,
    "ly_rasp",
    NULL,
    PHP_MINIT(ly_rasp),
    PHP_MSHUTDOWN(ly_rasp),
    NULL,
    NULL,
    PHP_MINFO(ly_rasp),
    PHP_LY_RASP_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_LY_RASP
ZEND_GET_MODULE(ly_rasp)
#endif
