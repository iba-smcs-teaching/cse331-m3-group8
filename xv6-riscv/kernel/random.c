//
// Kernel randomness source.
//
// A single 64-bit entropy pool feeding rand64(), the unpredictable-value primitive used
// by the boot stack canary (kernel/stackguard.c), the getentropy() syscall
// (kernel/sysproc.c), and stack-base ASLR (kernel/exec.c).
//
// Why not the Park-Miller rand() in user/grind.c (or any plain PRNG)? A PRNG gives a
// statistically even *distribution*, not *unpredictability*: its algorithm is public and
// a constant seed reproduces the identical sequence on every boot, so an attacker who
// knows the code knows the canary. Security mitigations need values an attacker cannot
// guess. The unpredictability here therefore comes from real hardware entropy (timer
// jitter), with SplitMix64 used only to *diffuse* that entropy across all 64 bits.
//
// Entropy source: the `time` CSR (r_time()) sampled repeatedly. Only `time` is read,
// never `cycle`/`rdcycle` -- start.c enables S-mode access to `time` (mcounteren bit 1)
// but not `cycle` (bit 0), so reading `cycle` in supervisor mode traps. The low bits of
// successive `time` reads carry interrupt/scheduling jitter; clockintr() keeps folding
// fresh samples in over the system's lifetime (see random_add() call in kernel/trap.c).
//
// Diffusion: SplitMix64 (Steele, Lea & Flood, "Fast Splittable Pseudorandom Number
// Generators", OOPSLA 2014) -- the additive golden-ratio step plus the avalanche
// finalizer spread a low-entropy input across the whole word so the canary/ASLR offsets
// do not leak the raw timer value.
//

#include "types.h"
#include "param.h"
#include "riscv.h"
#include "spinlock.h"
#include "defs.h"

// SplitMix64 constants: the golden-ratio increment and the two avalanche multipliers.
#define SPLITMIX_GAMMA 0x9e3779b97f4a7c15UL
#define SPLITMIX_MIX1  0xbf58476d1ce4e5b9UL
#define SPLITMIX_MIX2  0x94d049bb133111ebUL

static struct spinlock randlock;
// The entropy pool. Seeded to a non-zero constant so the very first mix has a defined
// state; that constant is NOT the source of unpredictability (random_init folds in real
// timer entropy before any consumer runs). p->lock convention: randlock guards every
// read-modify-write of randstate against concurrent harts.
static uint64 randstate = 0x595a36d9b2c1f0e7UL;

// SplitMix64 avalanche finalizer: scramble z so every input bit affects every output bit.
static inline uint64
splitmix_finalize(uint64 z)
{
  z = (z ^ (z >> 30)) * SPLITMIX_MIX1;
  z = (z ^ (z >> 27)) * SPLITMIX_MIX2;
  return z ^ (z >> 31);
}

// Fold one entropy sample into the pool. Safe to call from interrupt context (e.g.
// clockintr): randlock is held only briefly with interrupts off, so a timer cannot
// re-enter on the same hart while it is held.
//
// CHECK CHAIN:
//   1. acquire randlock (interrupt-safe; serialises the pool against other harts)
//   2. add the sample plus the golden-ratio increment, then avalanche-finalize the state
//   3. release randlock
void
random_add(uint64 sample)
{
  acquire(&randlock);
  randstate += sample + SPLITMIX_GAMMA;
  randstate = splitmix_finalize(randstate);
  release(&randlock);
}

// Return a fresh unpredictable 64-bit value (one SplitMix64 step over the pool).
//
// CHECK CHAIN:
//   1. advance the pool by the golden-ratio increment (under randlock, hart-safe)
//   2. avalanche-finalize the new state so the output reveals nothing about the pool
//   3. never return 0 -- a zero canary is trivially forgeable and a zero ASLR offset is
//      no randomization, so substitute a non-zero constant in that astronomically rare case
uint64
rand64(void)
{
  uint64 z;

  acquire(&randlock);
  randstate += SPLITMIX_GAMMA;
  z = randstate;
  release(&randlock);

  z = splitmix_finalize(z);
  if(z == 0)
    z = SPLITMIX_GAMMA;
  return z;
}

// Seed the entropy pool at boot, before any consumer (the stack canary) runs.
//
// CHECK CHAIN:
//   1. initialise randlock so random_add()/rand64() can take it
//   2. fold several `time`-CSR reads (the only entropy source; `cycle` traps in S-mode --
//      see file header) plus the live stack pointer into the pool -- multiple samples taken
//      at slightly different instants capture timer jitter rather than one predictable boot
//      moment, and r_sp() adds whatever boot-layout variation exists
//
// Called from main() on hart 0 before "started = 1", i.e. while single-threaded, so the
// unlocked initlock here races with nothing.
void
random_init(void)
{
  initlock(&randlock, "random");
  for(int i = 0; i < 8; i++){
    random_add(r_time());
    random_add(r_sp());
  }
}
