#!/usr/bin/env bash
# Build the kernel and the filesystem image.
#
# fs.img is named explicitly: plain `make` stops at the kernel, so a user program
# that does not compile would go unnoticed. `make clean` first so nothing stale,
# committed or otherwise, stands in for your code. NETDEV=user keeps it root-free.
set -euo pipefail
cd "$(dirname "$0")/../.."
[ -f .github/ci/out/OVERBUDGET ] && { echo "not run: check budget used up" >&2; exit 1; }
cd xv6-riscv
make clean >/dev/null 2>&1 || true
make LAB=net NETDEV=user kernel/kernel fs.img
