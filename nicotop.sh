#!/bin/sh
# Compatibility launcher. The sampling/rendering loop lives in the Go binary.
set -eu
project_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
binary="$project_dir/bin/nicotop"
needs_build=0
if [ -x "$binary" ]; then
  newer_sources="$(find "$project_dir/cmd" "$project_dir/internal" "$project_dir/go.mod" "$project_dir/go.sum" -type f -newer "$binary" -print)"
  if [ -n "$newer_sources" ]; then needs_build=1; fi
fi

if [ ! -x "$binary" ] || [ "$needs_build" -eq 1 ]; then
  if ! command -v go >/dev/null 2>&1; then
    printf '%s\n' 'nicotop: install Go 1.24+ and run make build, or use a prebuilt nicotop binary.' >&2
    exit 1
  fi
  printf '%s\n' 'Building EyesOfNico...' >&2
  (cd "$project_dir" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$binary" ./cmd/nicotop)
fi

exec "$binary" "$@"
