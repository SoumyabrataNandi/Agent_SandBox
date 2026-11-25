#!/bin/sh
# sandboxd container entrypoint (cycle 5, FR-CI1).
#
# SANDBOXD_TOKENS="name=<sha256>[,name2=<sha256>...]" adds bearer tokens to the default config:
# the hashes printed by `sandboxd token new --name <name>` (never the tokens themselves).
# With your own config mounted at $SANDBOXD_CONFIG, SANDBOXD_TOKENS must be unset.
set -eu

if [ -n "${SANDBOXD_TOKENS:-}" ]; then
    if [ "${SANDBOXD_CONFIG:-}" != /etc/sandboxd/sandboxd.toml ] || grep -q '^\[auth\]' /etc/sandboxd/sandboxd.toml; then
        echo "sandboxd: SANDBOXD_TOKENS works only with the image's default config; put tokens in your own config instead" >&2
        exit 2
    fi
    entries=""
    old_ifs=$IFS
    IFS=','
    for pair in $SANDBOXD_TOKENS; do
        name=${pair%%=*}
        hash=${pair#*=}
        case "$name" in
            ''|*[!A-Za-z0-9_.-]*) echo "sandboxd: SANDBOXD_TOKENS: bad token name '$name'" >&2; exit 2 ;;
        esac
        if [ "$name" = "$pair" ] || [ "${#hash}" -ne 64 ] || ! printf '%s' "$hash" | grep -Eq '^[0-9a-fA-F]{64}$'; then
            echo "sandboxd: SANDBOXD_TOKENS: '$name' needs name=<64 hex sha256>" >&2
            exit 2
        fi
        entries="$entries{ name = \"$name\", sha256 = \"$hash\" }, "
    done
    IFS=$old_ifs
    cfg=$(mktemp /tmp/sandboxd-XXXXXX.toml)
    cat /etc/sandboxd/sandboxd.toml > "$cfg"
    printf '\n[auth]\ntokens = [ %s]\n' "$entries" >> "$cfg"
    export SANDBOXD_CONFIG="$cfg"
fi

exec /usr/local/bin/sandboxd "$@"
