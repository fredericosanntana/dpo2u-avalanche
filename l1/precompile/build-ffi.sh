#!/usr/bin/env bash
# Builds the Midnight verifier (Rust) into a static library the Go precompile links with cgo.
#
# The Rust library carries its own copy of blst (BLS12-381) and of the Rust runtime, and so does
# the node: avalanchego links blst through its Go bindings and firewood is a Rust static library.
# To keep the two from clashing at link time, everything in our archive is relinked into one
# object and every symbol except the C ABI below is made local.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
crate="$here/midnight-verifier-ffi"
out="$here/midnightverifier/lib"
cargo build --release --lib --manifest-path "$crate/Cargo.toml"
mkdir -p "$out"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
ld -r --whole-archive "$crate/target/release/libdpo2u_midnight_verifier_ffi.a" -o "$tmp/verifier.o"
printf '%s\n' dpo2u_midnight_verify dpo2u_midnight_check_vk dpo2u_midnight_check_params > "$tmp/exports"
objcopy --keep-global-symbols="$tmp/exports" "$tmp/verifier.o"
rm -f "$out/libdpo2u_midnight_verifier.a"
ar rcs "$out/libdpo2u_midnight_verifier.a" "$tmp/verifier.o"
echo "built $out/libdpo2u_midnight_verifier.a"
