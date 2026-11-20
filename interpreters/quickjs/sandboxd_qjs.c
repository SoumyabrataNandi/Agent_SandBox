/*
 * sandboxd_qjs.c: QuickJS-ng for WASI as a *reactor* with explicit entry points, so it can be
 * pre-initialised (snapshotted) with Wizer. Cycle 3, ADR-C3-1; built only in CI.
 *
 * Exports
 *   wizer-initialize  runtime + context + qjs:std/os/bjson, the `--std` globals and sandboxd's
 *                     boot.js (lazy fetch/Headers/Response), evaluated once. Ends by resetting
 *                     wasi-libc's preopen table and environment.
 *   sandboxd-run      sets scriptArgs from this run's argv, evaluates /code/main.mjs as an ES
 *                     module, runs the job loop and exits like qjs (1 on an uncaught error).
 *
 * The runtime passes argv = ["qjs", "/code/main.mjs", <args>...].
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wasi/api.h>
#include <wasi/libc-environ.h>
#include <wasi/libc.h>

#include "quickjs-libc.h"
#include "quickjs.h"

static JSRuntime *rt;
static JSContext *ctx;

static JSContext *new_context(JSRuntime *r) {
    JSContext *c = JS_NewContext(r);
    if (c == NULL) {
        return NULL;
    }
    js_init_module_std(c, "qjs:std");
    js_init_module_os(c, "qjs:os");
    js_init_module_bjson(c, "qjs:bjson");
    return c;
}

static int eval_buf(const char *buf, size_t len, const char *name, int flags) {
    JSValue val;
    if ((flags & JS_EVAL_TYPE_MASK) == JS_EVAL_TYPE_MODULE) {
        val = JS_Eval(ctx, buf, len, name, flags | JS_EVAL_FLAG_COMPILE_ONLY);
        if (!JS_IsException(val)) {
            js_module_set_import_meta(ctx, val, true, true);
            val = JS_EvalFunction(ctx, val);
        }
        val = js_std_await(ctx, val);
    } else {
        val = JS_Eval(ctx, buf, len, name, flags);
    }
    if (JS_IsException(val)) {
        js_std_dump_error(ctx);
        JS_FreeValue(ctx, val);
        return -1;
    }
    JS_FreeValue(ctx, val);
    return 0;
}

static int eval_file(const char *path, int flags) {
    size_t len = 0;
    uint8_t *buf = js_load_file(ctx, &len, path);
    if (buf == NULL) {
        fprintf(stderr, "qjs: could not load '%s'\n", path);
        return -1;
    }
    int r = eval_buf((const char *)buf, len, path, flags);
    js_free(ctx, buf);
    return r;
}

static const char STD_GLOBALS[] =
    "import * as bjson from 'qjs:bjson';\n"
    "import * as std from 'qjs:std';\n"
    "import * as os from 'qjs:os';\n"
    "globalThis.bjson = bjson;\nglobalThis.std = std;\nglobalThis.os = os;\n";

__attribute__((export_name("wizer-initialize"))) void wizer_initialize(void) {
    rt = JS_NewRuntime();
    if (rt == NULL) {
        exit(70);
    }
    js_std_set_worker_new_context_func(new_context);
    js_std_init_handlers(rt);
    JS_SetModuleLoaderFunc2(rt, NULL, js_module_loader, js_module_check_attributes, NULL);
    ctx = new_context(rt);
    if (ctx == NULL) {
        exit(70);
    }
    /* Same as `qjs --std -I boot.js`: the globals, then the classic-script bootstrap. */
    if (eval_buf(STD_GLOBALS, strlen(STD_GLOBALS), "<std>", JS_EVAL_TYPE_MODULE) < 0 ||
        eval_file("/usr/local/lib/sandboxd/boot.js", JS_EVAL_TYPE_GLOBAL) < 0) {
        exit(70);
    }
    __wasilibc_reset_preopens();
    __wasilibc_deinitialize_environ();
}

__attribute__((export_name("sandboxd-run"))) void sandboxd_run(void) {
    /* wizer-initialize de-initialised the environment; std.getenviron()/getenv read the C
     * `environ`, so re-read this run's environment now. */
    __wasilibc_ensure_environ();
    __wasi_size_t argc = 0, buf_size = 0;
    if (__wasi_args_sizes_get(&argc, &buf_size) != 0 || argc < 2) {
        exit(70);
    }
    char **argv = calloc(argc + 1, sizeof(char *));
    char *buf = malloc(buf_size + 1);
    if (argv == NULL || buf == NULL || __wasi_args_get((uint8_t **)argv, (uint8_t *)buf) != 0) {
        exit(70);
    }
    /* qjs: scriptArgs = argv from the script onwards. */
    js_std_add_helpers(ctx, (int)argc - 1, argv + 1);
    int status = eval_file(argv[1], JS_EVAL_TYPE_MODULE) < 0 ? 1 : 0;
    if (status == 0) {
        /* Return type differs across quickjs-ng versions; errors are reported by the loop. */
        (void)js_std_loop(ctx);
    }
    js_std_free_handlers(rt);
    exit(status);
}

/* Session entry (C3-U4): scriptArgs as for a run, then the helper session loop (a module that
 * serves calls through /dev/sandbox/session until the host ends the session). */
__attribute__((export_name("sandboxd-session"))) void sandboxd_session(void) {
    __wasilibc_ensure_environ();
    __wasi_size_t argc = 0, buf_size = 0;
    if (__wasi_args_sizes_get(&argc, &buf_size) != 0 || argc < 1) {
        exit(70);
    }
    char **argv = calloc(argc + 1, sizeof(char *));
    char *buf = malloc(buf_size + 1);
    if (argv == NULL || buf == NULL || __wasi_args_get((uint8_t **)argv, (uint8_t *)buf) != 0) {
        exit(70);
    }
    js_std_add_helpers(ctx, (int)argc - 1, argv + 1);
    int status = eval_file("/usr/local/lib/sandboxd/session.mjs", JS_EVAL_TYPE_MODULE) < 0 ? 1 : 0;
    if (status == 0) {
        (void)js_std_loop(ctx);
    }
    js_std_free_handlers(rt);
    exit(status);
}
