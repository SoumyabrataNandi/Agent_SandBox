/*
 * sandboxd_python.c: CPython 3.15 for WASI as a *reactor* with explicit entry points, so it can
 * be pre-initialised (snapshotted) with Wizer. Cycle 3, ADR-C3-1; built only in CI.
 *
 * Exports
 *   wizer-initialize  one-time start-up, captured by the snapshot: interpreter initialisation
 *                     with today's flags (-I -S -B -X frozen_modules=on), the preload list
 *                     (design Q3) and the sandboxd network shims, already patched. It ends by
 *                     resetting wasi-libc's preopen table and environment, so nothing that is
 *                     specific to the init environment survives into runs.
 *   sandboxd-run      one program: applies this run's argv, environment and random seed, then
 *                     runs /code/main.py natively (PyRun_SimpleFileExFlags), exactly as CPython's
 *                     own `python file.py` does: same tracebacks, SystemExit handling and exit
 *                     codes, and no Python-level compile() (design Q2).
 *
 * The runtime passes argv = ["python", "/code/main.py", <args>...].
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wasi/api.h>
#include <wasi/libc-environ.h>
#include <wasi/libc.h>

/* Design Q3: curated preload list, plus the network stack patched once by sandbox_net. Runs in a
 * private namespace so nothing leaks into __main__. */
static const char PRELOAD[] =
    "import sys\n"
    "import json, re, collections, datetime, csv, math, statistics, decimal, fractions\n"
    "import functools, itertools, operator, string, textwrap, typing, dataclasses, enum\n"
    "import base64, hashlib, random, struct, io, pathlib\n"
    "import socket, http.client, urllib.request, urllib.parse, email.message\n"
    "sys.path.append('/usr/local/lib/sandboxd')\n"
    "import sandbox_net\n"
    "for _name in ('socket', 'http.client', 'urllib.request'):\n"
    "    sandbox_net._install(_name, sys.modules[_name])\n";

/* Per-run fix-ups that a snapshot can't contain. */
static const char PER_RUN[] =
    "import sys\n"
    "if 'random' in sys.modules:\n"
    "    sys.modules['random'].seed()\n"
    "_time = sys.modules.get('time')\n"
    "if _time is not None and hasattr(_time, 'tzset'):\n"
    "    _time.tzset()\n";

static void fatal(const char *what) {
    fprintf(stderr, "sandboxd-python: %s\n", what);
    if (PyErr_Occurred()) {
        PyErr_Print();
    }
    exit(70);
}

static void run_private(const char *code, const char *what) {
    PyObject *globals = PyDict_New();
    if (globals == NULL || PyDict_SetItemString(globals, "__builtins__", PyEval_GetBuiltins()) < 0) {
        fatal(what);
    }
    PyObject *r = PyRun_String(code, Py_file_input, globals, globals);
    if (r == NULL) {
        fatal(what);
    }
    Py_DECREF(r);
    Py_DECREF(globals);
}

__attribute__((export_name("wizer-initialize"))) void wizer_initialize(void) {
    PyConfig config;
    PyConfig_InitIsolatedConfig(&config); /* -I: isolated, safe_path, no user site, ignore env */
    config.site_import = 0;               /* -S */
    config.write_bytecode = 0;            /* -B */
    config.use_frozen_modules = 1;        /* -X frozen_modules=on */
    config.parse_argv = 0;
    /* use_hash_seed = 0: the hash secret is drawn from random_get now, i.e. once per snapshot
     * build on each host (design Q1). */
    PyStatus st = PyConfig_SetString(&config, &config.program_name, L"python");
    if (!PyStatus_Exception(st)) {
        st = Py_InitializeFromConfig(&config);
    }
    PyConfig_Clear(&config);
    if (PyStatus_Exception(st)) {
        Py_ExitStatusException(st);
    }
    run_private(PRELOAD, "preload failed");

    /* Nothing from the init environment may survive into runs. */
    __wasilibc_reset_preopens();
    __wasilibc_deinitialize_environ();
}

/* sys.argv / sys.orig_argv from this run's WASI args. */
static void apply_argv(void) {
    __wasi_size_t argc = 0, buf_size = 0;
    if (__wasi_args_sizes_get(&argc, &buf_size) != 0) {
        fatal("args_sizes_get failed");
    }
    uint8_t **argv = calloc(argc + 1, sizeof(uint8_t *));
    uint8_t *buf = malloc(buf_size + 1);
    if (argv == NULL || buf == NULL || __wasi_args_get(argv, buf) != 0) {
        fatal("args_get failed");
    }
    PyObject *orig = PyList_New(0);
    PyObject *args = PyList_New(0);
    for (__wasi_size_t i = 0; i < argc; i++) {
        PyObject *s = PyUnicode_DecodeFSDefault((const char *)argv[i]);
        if (s == NULL || PyList_Append(orig, s) < 0 || (i >= 1 && PyList_Append(args, s) < 0)) {
            fatal("argv");
        }
        Py_DECREF(s);
    }
    if (PySys_SetObject("argv", args) < 0 || PySys_SetObject("orig_argv", orig) < 0) {
        fatal("set argv");
    }
    Py_DECREF(args);
    Py_DECREF(orig);
    free(argv);
    free(buf);
}

/* Refill posix.environ in place: os.environ / os.environb wrap that same dict. */
static void apply_environ(void) {
    PyObject *posix = PyImport_ImportModule("posix");
    PyObject *env = posix ? PyObject_GetAttrString(posix, "environ") : NULL;
    if (env == NULL || !PyDict_Check(env)) {
        fatal("posix.environ");
    }
    PyDict_Clear(env);
    char **e = __wasilibc_get_environ();
    for (; e != NULL && *e != NULL; e++) {
        const char *eq = strchr(*e, '=');
        if (eq == NULL || eq == *e) {
            continue;
        }
        PyObject *k = PyBytes_FromStringAndSize(*e, eq - *e);
        PyObject *v = PyBytes_FromString(eq + 1);
        if (k == NULL || v == NULL || PyDict_SetItem(env, k, v) < 0) {
            fatal("environ item");
        }
        Py_DECREF(k);
        Py_DECREF(v);
    }
    Py_DECREF(env);
    Py_DECREF(posix);
}

__attribute__((export_name("sandboxd-run"))) void sandboxd_run(void) {
    apply_argv();
    apply_environ();
    run_private(PER_RUN, "per-run setup failed");

    const char *path = "/code/main.py";
    PyObject *argv = PySys_GetObject("argv"); /* borrowed */
    if (argv != NULL && PyList_Check(argv) && PyList_GET_SIZE(argv) > 0) {
        const char *p = PyUnicode_AsUTF8(PyList_GET_ITEM(argv, 0));
        if (p != NULL) {
            path = p;
        }
    }
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "python: can't open file '%s': [Errno %d] %s\n", path, errno, strerror(errno));
        exit(2);
    }
    PyCompilerFlags cf = {.cf_flags = 0, .cf_feature_version = PY_MINOR_VERSION};
    /* Handles SystemExit itself (finalises and exits with its code). */
    int rc = PyRun_SimpleFileExFlags(fp, path, 1, &cf);
    int status = rc == 0 ? 0 : 1;
    if (Py_FinalizeEx() < 0) {
        status = 120;
    }
    exit(status);
}
