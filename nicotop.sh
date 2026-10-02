#!/usr/bin/env bash
# Compatibility launcher. The sampling/rendering loop lives in the Go binary.
set -euo pipefail
project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
binary="$project_dir/bin/nicotop"
needs_build=0
shopt -s globstar nullglob
for source in "$project_dir/go.mod" "$project_dir"/cmd/**/*.go "$project_dir"/internal/**/*.go; do
  if [[ "$source" -nt "$binary" ]]; then needs_build=1; break; fi
done

if [[ ! -x "$binary" || "$needs_build" -eq 1 ]]; then
  if ! command -v go >/dev/null 2>&1; then
    printf '%s\n' 'nicotop: install Go 1.22+ and run make build, or use a prebuilt nicotop binary.' >&2
    exit 1
  fi
  printf '%s\n' 'Building EyesOfNico...' >&2
  (cd "$project_dir" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$binary" ./cmd/nicotop)
fi

exec "$binary" "$@"
