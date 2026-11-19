#!/usr/bin/env bash
# Build the snapshot-capable interpreters for WASI (cycle 3, ADR-C3-1). CI only (ubuntu x86_64).
#
#   interpreters/build.sh <out-dir> python|quickjs
#
# Inputs are pinned in interpreters/sources.toml. Downloads and source trees are cached in
# $SANDBOXD_INTERP_WORK (default ~/.cache/sandboxd-interp). SANDBOXD_INTERP_MODE=release
# refuses unpinned inputs; the spike mode records their digests in <out>/digests.txt.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(realpath -m "${1:?usage: build.sh <out-dir> python|quickjs}")
WHAT=${2:?usage: build.sh <out-dir> python|quickjs}
WORK=${SANDBOXD_INTERP_WORK:-$HOME/.cache/sandboxd-interp}
MODE=${SANDBOXD_INTERP_MODE:-spike}
mkdir -p "$OUT" "$WORK/dl"

src() {
  python3 - "$HERE/sources.toml" "$1" "$2" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    print(tomllib.load(f)[sys.argv[2]][sys.argv[3]])
PY
}

# fetch <name>: download (cached), verify, print the local path.
fetch() {
  local name=$1 url sha file got
  url=$(src "$name" url)
  sha=$(src "$name" sha256)
  file="$WORK/dl/$(basename "$url")"
  if [ ! -f "$file" ]; then
    echo ">> downloading $name: $url" >&2
    curl -fsSL --retry 3 -o "$file.part" "$url"
    mv "$file.part" "$file"
  fi
  got=$(sha256sum "$file" | cut -d' ' -f1)
  echo "$name $got" >>"$OUT/digests.txt"
  if [ -n "$sha" ] && [ "$sha" != "$got" ]; then
    echo "sha256 mismatch for $name: got $got, pinned $sha" >&2
    exit 1
  fi
  if [ -z "$sha" ] && [ "$MODE" = release ]; then
    echo "unpinned input $name (sha256 $got) in release mode" >&2
    exit 1
  fi
  echo "$file"
}

unpack() { # unpack <archive> <dir>
  if [ ! -d "$2" ]; then
    mkdir -p "$2.tmp"
    tar -xf "$1" -C "$2.tmp" --strip-components=1
    mv "$2.tmp" "$2"
  fi
}

setup_wasi_sdk() {
  unpack "$(fetch wasi_sdk)" "$WORK/wasi-sdk-$(src wasi_sdk version)"
  export WASI_SDK_PATH="$WORK/wasi-sdk-$(src wasi_sdk version)"
  echo ">> wasi-sdk: $WASI_SDK_PATH" >&2
}

build_python() {
  setup_wasi_sdk
  unpack "$(fetch wasmtime_cli)" "$WORK/wasmtime-$(src wasmtime_cli version)"
  export PATH="$WORK/wasmtime-$(src wasmtime_cli version):$PATH"
  local ver cpy b
  ver=$(src cpython version)
  cpy="$WORK/cpython-$ver"
  unpack "$(fetch cpython)" "$cpy"
  if ! find "$cpy/cross-build" -maxdepth 2 -name python.wasm 2>/dev/null | grep -q .; then
    echo ">> building CPython $ver for WASI (Tools/wasm/wasi build)" >&2
    (cd "$cpy" && python3 Tools/wasm/wasi build)
  fi
  b=$(dirname "$(find "$cpy/cross-build" -maxdepth 2 -name python.wasm | head -n1)")
  echo ">> CPython WASI build dir: $b" >&2

  # Ask CPython's own Makefile for the exact compile/link flags of python.wasm.
  printf 'print-%%:\n\t@echo '\''$($*)'\''\n' >"$b/sbx-print.mk"
  mk() { make -s -C "$b" -f Makefile -f sbx-print.mk "print-$1"; }
  local cc cflags linkcc ldflags libs
  cc=$(mk CC)
  cflags="$(mk PY_CFLAGS) $(mk PY_CPPFLAGS)"
  linkcc=$(mk LINKCC)
  # PY_CORE_LDFLAGS carries the WASI-specific link flags (stack size, memory) that python.wasm uses.
  ldflags="$(mk PY_CORE_LDFLAGS) $(mk LINKFORSHARED)"
  libs="$(mk BLDLIBRARY) $(mk LIBS) $(mk MODLIBS) $(mk SYSLIBS)"
  {
    echo "python.wasm link (reference): $(mk LINKCC) $(mk PY_CORE_LDFLAGS) $(mk LINKFORSHARED) | $(mk LDFLAGS_NODIST) | $(mk CONFIGURE_LDFLAGS_NODIST)"
    echo "CC=$cc"
    echo "CFLAGS=$cflags"
    echo "LINKCC=$linkcc"
    echo "LDFLAGS=$ldflags"
    echo "LIBS=$libs"
  } >"$OUT/python-link.txt"
  (
    cd "$b"
    # shellcheck disable=SC2086
    $cc $cflags -c "$HERE/python/sandboxd_python.c" -o sandboxd_python.o
    # shellcheck disable=SC2086
    $linkcc $ldflags -mexec-model=reactor -Wl,--strip-debug -o sandboxd-python.wasm sandboxd_python.o $libs
  )
  cp "$b/sandboxd-python.wasm" "$OUT/"
  ls -l "$OUT/sandboxd-python.wasm" >&2
}

build_quickjs() {
  setup_wasi_sdk
  local ver qj bd
  ver=$(src quickjs version)
  qj="$WORK/quickjs-$ver"
  unpack "$(fetch quickjs)" "$qj"
  bd="$qj/build-wasi"
  cmake -S "$qj" -B "$bd" -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_TOOLCHAIN_FILE="$WASI_SDK_PATH/share/cmake/wasi-sdk.cmake" >&2
  cmake --build "$bd" --target qjs_exe -j "$(nproc)" >&2
  find "$bd" -name '*.a' >"$OUT/quickjs-libs.txt"
  # shellcheck disable=SC2046
  "$WASI_SDK_PATH/bin/clang" --target=wasm32-wasip1 -O2 -D_GNU_SOURCE -D_WASI_EMULATED_SIGNAL \
    -I"$qj" -mexec-model=reactor -Wl,-z,stack-size=1048576 \
    "$HERE/quickjs/sandboxd_qjs.c" $(cat "$OUT/quickjs-libs.txt") \
    -lwasi-emulated-signal -lm -o "$OUT/sandboxd-qjs.wasm"
  ls -l "$OUT/sandboxd-qjs.wasm" >&2
}

case "$WHAT" in
  python) build_python ;;
  quickjs) build_quickjs ;;
  *) echo "unknown target $WHAT" >&2; exit 2 ;;
esac
