#!/bin/sh
set -eu

oracle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_dir=$(CDPATH= cd -- "$oracle_dir/../../.." && pwd -P)
source_dir=${BSV_GO_SDK_PATH:?BSV_GO_SDK_PATH must name the pinned external Go SDK}
source_dir=$(CDPATH= cd -- "$source_dir" && pwd -P)
go_command=${GO_COMMAND:-go}
toolchain=${GOTOOLCHAIN:-go1.25.0}

actual_version=$(GOTOOLCHAIN="$toolchain" "$go_command" env GOVERSION)
if [ "$actual_version" != "go1.25.0" ] && [ -z "${GO_COMMAND:-}" ]; then
  module_cache=$(go env GOMODCACHE)
  host_os=$(go env GOOS)
  host_arch=$(go env GOARCH)
  cached_go="$module_cache/golang.org/toolchain@v0.0.1-go1.25.0.$host_os-$host_arch/bin/go"
  if [ -x "$cached_go" ]; then go_command=$cached_go; toolchain=local; fi
fi

case "$source_dir/" in
  "$repository_dir"/*) echo "Go SDK source must be outside the Swift repository" >&2; exit 3 ;;
esac

actual_version=$(GOTOOLCHAIN="$toolchain" "$go_command" env GOVERSION)
if [ "$actual_version" != "go1.25.0" ]; then
  echo "Go toolchain mismatch: got $actual_version, require go1.25.0" >&2
  exit 3
fi

temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/bsv-go-oracle-test.XXXXXX")
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM
cp -R "$oracle_dir" "$temporary_dir/oracle"
sed "s|@SOURCE@|$source_dir|g" "$oracle_dir/go.work.template" > "$temporary_dir/go.work"

export BSV_ORACLE_LOCK_PATH="$repository_dir/Tools/Conformance/go-sdk.lock.json"
export BSV_SWIFT_REPOSITORY_PATH="$repository_dir"
export GOTOOLCHAIN="$toolchain"
export GOPROXY=${GOPROXY:-off}
export GOSUMDB=${GOSUMDB:-off}
export GOWORK="$temporary_dir/go.work"
if [ -n "${BSV_GO_ORACLE_GOCACHE:-}" ]; then
  export GOCACHE=$BSV_GO_ORACLE_GOCACHE
else
  export GOCACHE="$repository_dir/.build/go-oracle-cache"
  mkdir -p "$GOCACHE"
  chmod 700 "$GOCACHE"
fi
cd "$temporary_dir/oracle"
"$go_command" test ./...
