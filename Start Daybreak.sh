#!/bin/sh
set -eu
launcher_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for python_command in python3 python3.14 python3.13 python3.12 python3.11; do
  if command -v "$python_command" >/dev/null 2>&1 && "$python_command" -c 'import sys; sys.exit(sys.version_info < (3,11))' 2>/dev/null; then
    exec "$python_command" "$launcher_dir/daybreak.py" "$@"
  fi
done
echo 'Install Python 3.11 or newer from https://www.python.org/downloads/ and rerun.' >&2
echo 'On macOS with Homebrew: brew install python@3.13' >&2
echo 'On Linux, use your distribution package manager to install Python 3.11 or newer.' >&2
exit 1
