#!/usr/bin/env bash

set -e

SCRIPT_DIR="$(
    cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
    pwd
)"

PROJECT_ROOT="$(
    cd -- "${SCRIPT_DIR}/.."
    pwd
)"

cd "${PROJECT_ROOT}"

echo "Starting SOC Engine..."

exec python3 -m engine.orchestration.soc_engine
