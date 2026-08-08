#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
cd "$repository_root"
swift package dump-symbol-graph --minimum-access-level public

modules="BSV BSVCore BSVCrypto BSVKeys BSVMessage BSVScript BSVTransaction BSVInterpreter BSVSPV BSVNetwork BSVWallet BSVAuth"
for module in $modules; do
    graph=$(find .build -type f -path "*/symbolgraph/$module.symbols.json" -print | head -n 1)
    if [ -z "$graph" ]; then
        echo "error: missing public symbol graph for $module" >&2
        exit 1
    fi
    if grep -E 'BigInt|BigUInt' "$graph" >/dev/null; then
        echo "error: attaswift/BigInt type leaked into $module's public API" >&2
        grep -n -E 'BigInt|BigUInt' "$graph" >&2
        exit 1
    fi
done

echo "Public SDK symbol graphs contain no BigInt or BigUInt references."
