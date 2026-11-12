#!/usr/bin/env sh
# Builds securepi.ts and runs the test suites against a temporary HOME.
# Loads the build directly, then through a symlink, as pi does for symlinked extensions.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/build"
npx -y -p esbuild@0.24 esbuild "$ROOT/securepi.ts" --format=esm \
	--outfile="$WORK/build/securepi.mjs" --log-level=warning
cp -r "$ROOT/defaults" "$WORK/build/"
ln -s "$WORK/build/securepi.mjs" "$WORK/linked.mjs"

run() {
	rm -rf "$WORK/root"
	mkdir -p "$WORK/root/home"
	TEST_ROOT="$WORK/root" HOME="$WORK/root/home" DEFS="$WORK/build/defaults" \
		MOD="$1" node "$ROOT/test/securepi.test.mjs"
}

echo "== direct load =="
run "$WORK/build/securepi.mjs"
echo "== via symlink =="
run "$WORK/linked.mjs"
