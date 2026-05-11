#!/bin/sh
set -eux

cd "$(dirname "$0")"

uv run ruff check --fix .
uv run ruff format .
