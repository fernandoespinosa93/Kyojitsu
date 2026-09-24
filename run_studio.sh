#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
export PYTHONPATH="$(pwd)/src${PYTHONPATH:+:$PYTHONPATH}"
python3 -m kyojitsu studio --host 127.0.0.1 --port 8765 --runs-dir runs
