//
// crt0 -- the user-program entry stub (ELF entry point; see ENTRY(_start) in user.ld).
//
// Stock xv6 has no crt0: the linker made each program's main() the entry, so there was
// nowhere to re-seed the per-program stack canary and it had to be a fixed constant (a
// constant canary is the same in every run, hence forgeable). _start runs before main()
// and gives every program a per-exec random canary via getentropy() (POSIX.1-2024),
// closing that gap -- the user-space analog of the kernel's boot-time canary seeding
// (kernel/stackguard.c).
//
// exec() (kernel/exec.c) enters here with the standard argument registers set: a0 = argc,
// a1 = argv. As an ordinary C function _start receives them in those same registers and
// forwards them to main() unchanged.
//

#include "kernel/types.h"
#include "user/user.h"

extern int main(int, char **);
extern unsigned long __stack_chk_guard; // the canary symbol, defined in user/stackguard.c

// no_stack_protector: _start *writes* __stack_chk_guard, so it must not itself carry a
// canary check (its epilogue would compare a frame canary captured from the old value
// against the new one). main() and everything it calls ARE protected -- they capture the
// freshly seeded guard on entry. _start never returns (it ends in exit()), so leaving it
// unprotected costs nothing.
//
// CHECK CHAIN:
//   1. getentropy() fills 8 unpredictable bytes for the canary
//   2. on failure, or the astronomically rare all-zero draw, fall back to the fixed
//      terminator canary so the guard is never 0 (a zero canary is trivially forgeable)
//   3. install the canary BEFORE calling the first protected frame (main)
//   4. forward argc/argv to main(); exit() with its return value (no return path)
__attribute__((no_stack_protector))
void
_start(int argc, char **argv)
{
  unsigned long g = 0;
  if(getentropy(&g, sizeof(g)) < 0 || g == 0)
    g = 0xff0a0d0000aaff00UL; // terminator-byte fallback (NUL, LF, CR, 0xff)
  __stack_chk_guard = g;

  exit(main(argc, argv));
}
