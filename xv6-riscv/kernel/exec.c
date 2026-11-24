#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"

static int loadseg(pde_t *, uint64, struct inode *, uint, uint);

// Stack-base ASLR: number of page-granular entropy bits for the random gap inserted
// before the user stack, and the corresponding mask. 12 bits (up to 4095 pages, ~16 MiB)
// is modest next to Linux x86_64's 22, but xv6 has no PIE/shared-library/mmap layout to
// randomize -- only this one stack offset. See the use in kexec() below.
#define STACK_RND_BITS 12
#define STACK_RND_MASK ((1UL << STACK_RND_BITS) - 1)

// map ELF permissions to PTE permission bits.
int flags2perm(int flags)
{
    int perm = 0;
    if(flags & 0x1)
      perm = PTE_X;
    if(flags & 0x2)
      perm |= PTE_W;
    return perm;
}

//
// the implementation of the exec() system call
//
int
kexec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz = 0, sp, ustack[MAXARG], stackbase;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();

  begin_op();

  // Open the executable file.
  if((ip = namei(path)) == 0){
    end_op();
    return -1;
  }
  ilock(ip);

  // Read the ELF header.
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf))
    goto bad;

  // Is this really an ELF file?
  if(elf.magic != ELF_MAGIC)
    goto bad;

  if((pagetable = proc_pagetable(p)) == 0)
    goto bad;

  // W^X exemption (OpenBSD model): scan the program headers first for PT_OPENBSD_WXNEEDED.
  // A binary carrying that header is allowed to map a writable+executable segment (the
  // link-time wxneeded tag); every other binary is held to write-xor-execute by the reject
  // in the load loop below. This is a pre-pass because the marker header may sit after the
  // PT_LOAD it exempts, yet the W^X decision must be known before that segment is mapped.
  // (xv6 has a single root fs and no mount flags, so OpenBSD's wxallowed mount is implicit;
  // and no mmap/mprotect, so exec is the only path that can create a W+X user mapping.)
  // CHECK CHAIN:
  //   1. read each program header from the file        -> else -1 (truncated/bad ELF)
  //   2. ph.type == PT_OPENBSD_WXNEEDED for any header  -> set wxneeded = 1 (image exempt)
  int wxneeded = 0;
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type == PT_OPENBSD_WXNEEDED)
      wxneeded = 1;
  }

  // Load program into memory.
  for(i=0, off=elf.phoff; i<elf.phnum; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph))
      goto bad;
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz)
      goto bad;
    if(ph.vaddr + ph.memsz < ph.vaddr)
      goto bad;
    if(ph.vaddr % PGSIZE != 0)
      goto bad;
    int perm = flags2perm(ph.flags);
    // W^X (OpenBSD model; PaX/Linux NX): refuse a user segment mapped both writable and
    // executable -- executing injected/overwritten bytes is exactly the code-injection
    // primitive W^X removes. exec is the only path that can create a W+X user mapping
    // (xv6 has no mmap/mprotect), so this single check enforces the whole policy. RISC-V
    // Privileged-ISA PTE W/X bits. A wxneeded binary (PT_OPENBSD_WXNEEDED, e.g. the
    // -N/OMAGIC forktest) is exempt and allowed through.
    // CHECK CHAIN:
    //   1. (perm & PTE_W) && (perm & PTE_X)  -> a write+execute segment
    //   2. && !wxneeded                      -> not exempt -> refuse the exec (POSIX [EACCES])
    if((perm & PTE_W) && (perm & PTE_X) && !wxneeded)
      goto bad;
    uint64 sz1;
    if((sz1 = uvmalloc(pagetable, sz, ph.vaddr + ph.memsz, perm)) == 0)
      goto bad;
    sz = sz1;
    if(loadseg(pagetable, ph.vaddr, ip, ph.off, ph.filesz) < 0)
      goto bad;
  }
  iunlockput(ip);
  end_op();
  ip = 0;

  p = myproc();
  uint64 oldsz = p->sz;

  // Allocate some pages at the next page boundary.
  // Make the first inaccessible as a stack guard.
  // Use the rest as the user stack.
  sz = PGROUNDUP(sz);

  // Stack-base ASLR (modeled on Linux randomize_stack_top()): insert a random,
  // page-aligned gap before the guard/stack region so the stack does not begin at a
  // fixed, predictable address. The gap is unmapped virtual space, so it costs no
  // physical memory. Entropy comes from the kernel pool (rand64), not a PRNG.
  //
  // CHECK CHAIN:
  //   1. gap = (rand64() & STACK_RND_MASK) [a page count] * PGSIZE [bytes] -- page-granular,
  //      so PTE alignment and the guard-page invariant below are preserved
  //   2. if the gap would push the stack region past TRAPFRAME, drop it (gap = 0) so the
  //      address space never overflows into the trapframe/trampoline
  uint64 gap = (rand64() & STACK_RND_MASK) * PGSIZE;
  if(sz + gap + (USERSTACK+1)*PGSIZE > TRAPFRAME)
    gap = 0;
  sz += gap;

  uint64 sz1;
  if((sz1 = uvmalloc(pagetable, sz, sz + (USERSTACK+1)*PGSIZE, PTE_W)) == 0)
    goto bad;
  sz = sz1;
  uvmclear(pagetable, sz-(USERSTACK+1)*PGSIZE);
  sp = sz;
  stackbase = sp - USERSTACK*PGSIZE;

  // Enforce RLIMIT_AS on the freshly built image. growproc()/sbrk() guard later growth,
  // but exec builds the new address space directly via uvmalloc and would otherwise let a
  // process escape its cap simply by exec'ing a larger binary -- a confinement bypass.
  // Checked against the absolute limit (not rlimit_as_ok()'s shrink allowance) so a
  // lowered cap is honoured even if the old image happened to be larger.
  //
  // CHECK CHAIN:
  //   1. RLIMIT_AS == RLIM_INFINITY              -> unlimited, allow
  //   2. final image size sz (code + data + guard + stack) > limit -> fail (POSIX [ENOMEM])
  rlim_t aslim = p->rlim[RLIMIT_AS].rlim_cur;
  if(aslim != RLIM_INFINITY && sz > aslim)
    goto bad;

  // Copy argument strings into new stack, remember their
  // addresses in ustack[].
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16; // riscv sp must be 16-byte aligned
    if(sp < stackbase)
      goto bad;
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0)
      goto bad;
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  // push a copy of ustack[], the array of argv[] pointers.
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase)
    goto bad;
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0)
    goto bad;

  // a0 and a1 contain arguments to user main(argc, argv)
  // argc is returned via the system call return
  // value, which goes in a0.
  p->trapframe->a1 = sp;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
    
  // Commit to the user image.
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  p->sz = sz;
  p->trapframe->epc = elf.entry;  // initial program counter = ulib.c:start()
  p->trapframe->sp = sp; // initial stack pointer
  proc_freepagetable(oldpagetable, oldsz);

  return argc; // this ends up in a0, the first argument to main(argc, argv)

 bad:
  if(pagetable)
    proc_freepagetable(pagetable, sz);
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}

// Load an ELF program segment into pagetable at virtual address va.
// va must be page-aligned
// and the pages from va to va+sz must already be mapped.
// Returns 0 on success, -1 on failure.
static int
loadseg(pagetable_t pagetable, uint64 va, struct inode *ip, uint offset, uint sz)
{
  uint i, n;
  uint64 pa;

  for(i = 0; i < sz; i += PGSIZE){
    pa = walkaddr(pagetable, va + i);
    if(pa == 0)
      panic("loadseg: address should exist");
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, 0, (uint64)pa, offset+i, n) != n)
      return -1;
  }
  
  return 0;
}
