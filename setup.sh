#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")"
uv run --with "mcp[cli]" --with rich cli.py setup
