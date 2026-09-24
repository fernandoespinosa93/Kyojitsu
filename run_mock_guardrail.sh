#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
python3 examples/mock_guardrail_server.py
