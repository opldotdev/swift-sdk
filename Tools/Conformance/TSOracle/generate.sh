#!/bin/sh
# Generates the TypeScript wallet-wire oracle vectors with Bun.
#
#   BSV_TS_SDK_PATH=/path/to/ts-stack/packages/sdk Tools/Conformance/TSOracle/generate.sh [output]
#
# The default output is .build/ts-oracle/ts-wallet-wire-vectors.json. Point
# BSV_TS_WALLET_WIRE_VECTORS at it when running `swift test`. The external
# checkout is only read; generated vectors are never committed.
set -eu

oracle_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_dir=$(CDPATH= cd -- "$oracle_dir/../../.." && pwd -P)
sdk_dir=${BSV_TS_SDK_PATH:?BSV_TS_SDK_PATH must name the @bsv/sdk package directory (packages/sdk)}
sdk_dir=$(CDPATH= cd -- "$sdk_dir" && pwd -P)
output=${1:-"$repository_dir/.build/ts-oracle/ts-wallet-wire-vectors.json"}

[ -f "$sdk_dir/src/wallet/substrates/WalletWireProcessor.ts" ] || {
  echo "$sdk_dir is not the @bsv/sdk package directory" >&2
  exit 3
}
command -v bun >/dev/null 2>&1 || { echo "bun is required" >&2; exit 3; }

version=$(bun -e "console.log(require('$sdk_dir/package.json').version)")
commit=$(git -C "$sdk_dir" rev-parse --short HEAD 2>/dev/null || echo unknown)
mkdir -p "$(dirname -- "$output")"

BSV_TS_SDK_PATH="$sdk_dir" \
BSV_TS_ORACLE_OUTPUT="$output" \
BSV_TS_ORACLE_SOURCE="@bsv/sdk $version ($commit)" \
  bun "$oracle_dir/gen.ts" >/dev/null
echo "$output"
