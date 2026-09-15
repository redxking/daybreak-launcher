#!/bin/sh
launcher_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
sh "$launcher_dir/Start Daybreak.sh" "$@"
launcher_exit=$?
printf '\nPress Enter to close… '
read -r launcher_reply
exit "$launcher_exit"
