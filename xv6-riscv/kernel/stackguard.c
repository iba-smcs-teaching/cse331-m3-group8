//
// Stack-smashing protection (SSP) runtime support for the kernel.
//
// xv6 builds with -fstack-protector-strong -mstack-protector-guard=global (see the
// CFLAGS in the Makefile). For every protected function the compiler emits a prologue
// that copies the global __stack_chk_guard onto the stack just below the saved return
// address, and an epilogue that re-reads it; a contiguous stack buffer overflow
// (CWE-121) that reaches the saved return address must also overwrite this canary, so
// the corruption is caught in __stack_chk_fail() below -- before the poisoned "ret"
// can transfer control to an attacker-chosen address.
//
// This closes the one stack-overflow class xv6's existing guard pages (kernel/
// memlayout.h, kernel/exec.c) do NOT catch: they catch stack *exhaustion* (running off
// the end of the stack), not an in-frame return-address smash that stays in mapped
// stack memory.
//
// Mechanism / standards: SSP / StackGuard (Cowan et al., USENIX Security '98); the two
// symbols __stack_chk_guard / __stack_chk_fail are defined by the RISC-V psABI (ISO/IEC
// 9899, the C standard, does not specify stack protection). Linux's analog is
// CONFIG_STACKPROTECTOR_STRONG (KSPP).
//

#include "types.h"
#include "riscv.h"
#include "defs.h"

// The canary the compiler reads (global-guard model). Statically initialised to a
// non-zero value so any function that runs before stackguard_init() still sees a
// well-defined guard; re-seeded with real entropy at boot.
unsigned long __stack_chk_guard = 0x595a36d9b2c1f0e7UL;

// Re-seed __stack_chk_guard from the kernel entropy pool.
//
// The unpredictable value comes from rand64() (kernel/random.c), which mixes repeated
// `time`-CSR reads through SplitMix64 -- far stronger than one raw timer read, since a
// single boot-time `time` value is roughly guessable. random_init() must run first (it
// does: main() calls it immediately before this).
//
// Must NOT itself be stack-protected: it writes __stack_chk_guard, so a protected
// epilogue here would compare a frame canary captured from the OLD value against the
// NEW value and false-trip. (rand64() and random_init() are ordinary protected
// functions -- they never touch __stack_chk_guard, so the static guard they captured on
// entry still matches on their return; only the function that *rewrites* the guard must
// be unprotected.) It is called from main() (also no_stack_protector) on hart 0 before
// "started = 1", i.e. before any other hart runs a protected function, so no live
// protected frame straddles the change. main() and start() never return (the boot path
// ends in scheduler()), so their old-guard frames are never checked.
__attribute__((no_stack_protector))
void
stackguard_init(void)
{
  // CHECK CHAIN (boot canary):
  //   1. draw an unpredictable 64-bit value from the entropy pool (rand64)
  //   2. rand64() already guarantees non-zero, so the guard is never the forgeable 0
  __stack_chk_guard = rand64();
}

// Called by the compiler-generated epilogue of a protected function when its frame
// canary no longer matches __stack_chk_guard. Reaching here means a stack buffer
// overflow has already corrupted the frame; control-flow integrity is lost, so we
// halt rather than return. (POSIX/glibc would abort() -> SIGABRT; the kernel has no
// process to signal, so it panics.)
void
__stack_chk_fail(void)
{
  panic("stack smashing detected");
}
