#!/usr/bin/env bash
# Backward-compatible alias: smoke check now delegates to doctor --deep.
exec bash "$(cd "$(dirname "$0")" && pwd)/doctor.sh" --deep "$@"
