#!/usr/bin/env bash
# Boot xv6 and confirm the shell answers.
#
# Waits for the prompt, types `echo <token>`, and passes only if the token comes
# back on a line of its own. The console's echo of what was typed starts with the
# prompt, so it does not count: a real shell has to run a real program.
#
# QEMU is started directly, not through `make qemu`: that target never exits, adds
# fixed host ports, and needs the e1000 option ROM, which a runner may not have.
# romfile= drops the ROM and keeps the device, which the LAB=net kernel requires.
set -uo pipefail
cd "$(dirname "$0")/../.."
CI="$PWD/.github/ci"
[ -f "$CI/out/OVERBUDGET" ] && { echo "not run: check budget used up" >&2; exit 1; }
CPUS=3
BOOT_TIMEOUT=180
cd xv6-riscv

if [ ! -f kernel/kernel ] || [ ! -f fs.img ]; then
  echo "FAIL: no kernel/kernel or fs.img; the build must succeed first" >&2
  exit 1
fi

mkdir -p "$CI/out"
LOG="$CI/out/boot.log"
IN="$CI/out/console.in"
rm -f "$LOG" "$IN"
: > "$LOG"
mkfifo "$IN"
exec 3<>"$IN"

timeout --foreground "$BOOT_TIMEOUT" qemu-system-riscv64 -machine virt -bios none \
  -kernel kernel/kernel -m 256M -smp "$CPUS" -nographic \
  -global virtio-mmio.force-legacy=false \
  -drive file=fs.img,if=none,format=raw,id=x0 \
  -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
  -netdev user,id=net0 -device e1000,netdev=net0,bus=pcie.0,romfile= \
  <&3 >"$LOG" 2>&1 &
QEMU=$!
trap 'kill "$QEMU" 2>/dev/null; wait "$QEMU" 2>/dev/null; rm -f "$IN"' EXIT

clean() { tr -d '\r' < "$LOG"; }
alive() { kill -0 "$QEMU" 2>/dev/null; }
fail() {
  echo "FAIL: $1" >&2
  echo "--- last lines of the console ---" >&2
  clean | tail -20 >&2
  exit 1
}

while ! clean | grep -q '^\$ '; do
  alive || fail "QEMU exited before the shell prompt appeared"
  sleep 1
done
echo "shell prompt reached"

# One character at a time: a burst makes the xv6 console drop characters.
TOKEN="boot-$(od -An -N4 -tu4 < /dev/urandom | tr -dc '0-9')"
sleep 1
for ((i = 0; i < ${#TOKEN} + 5; i++)); do
  line="echo $TOKEN"
  printf '%s' "${line:$i:1}" >&3
  sleep 0.05
done
printf '\n' >&3

for _ in $(seq 1 30); do
  if clean | grep -qx "$TOKEN"; then
    echo "PASS: xv6 booted and the shell answered"
    exit 0
  fi
  alive || fail "QEMU exited before the shell answered"
  sleep 1
done
fail "the shell did not answer"
