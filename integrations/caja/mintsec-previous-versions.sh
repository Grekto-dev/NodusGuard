#!/bin/sh
# Integração de menu de contexto para Caja (~/.local/share/caja-python/scripts ou /usr/share/caja/scripts)
set -eu
target="${1:-}"
if [ -n "$target" ]; then
    exec mint-security-suite --page recovery --tab files --path="$target"
fi
exec mint-security-suite --page recovery --tab files
