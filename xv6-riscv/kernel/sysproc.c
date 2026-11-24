#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"
#include "shm.h"
#include "random.h"

// External declarations
extern struct proc proc[NPROC];

/**
 * Wrapper functions for reading cycle, time, and instret CSRs
 */

uint64 sys_rdcycle(void)
{
  return r_cycle();
}

uint64 sys_rdtime(void)
{
  return r_time();
}

uint64 sys_rdinstret(void)
{
  return r_instret();
}

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0; // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if (t == SBRK_EAGER || n < 0)
  {
    if (growproc(n) < 0)
    {
      return -1;
    }
  }
  else
  {
    // Lazily allocate memory for this process: increase its memory
    // size but don't allocate memory. If the processes uses the
    // memory, vmfault() will allocate it.
    if (addr + n < addr)
      return -1;
    if (addr + n > TRAPFRAME)
      return -1;
    // PER-PROCESS ADDRESS-SPACE LIMIT (IEEE Std 1003.1-2017 setrlimit, RLIMIT_AS).
    // The lazy path grows p->sz directly (bypassing growproc), so the RLIMIT_AS check
    // must be applied here too -- otherwise a process could blow past its cap simply
    // by using lazy sbrk. Refused growth returns the POSIX [ENOMEM] analog (-1).
    if(!rlimit_as_ok(myproc(), addr + n))
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if (n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while (ticks - ticks0 < n)
  {
    if (killed(myproc()))
    {
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_shmget(void)
{
  char name[SHM_NAME_LEN];
  uint64 size;
  int flags;

  if (argstr(0, name, SHM_NAME_LEN) < 0)
    return -1;

  argaddr(1, &size);
  argint(2, &flags);

  return shm_get(name, size, flags);
}

uint64
sys_shmat(void)
{
  int shmid;
  uint64 uaddr;
  int flags;

  argint(0, &shmid);
  argaddr(1, &uaddr);
  argint(2, &flags);

  return (uint64)shm_attach(shmid, (void *)uaddr, flags);
}

uint64
sys_shmdt(void)
{
  uint64 shmaddr;

  argaddr(0, &shmaddr);

  return shm_detach((void *)shmaddr);
}

uint64
sys_shmctl(void)
{
  int shmid;
  int cmd;
  uint64 buf;

  argint(0, &shmid);
  argint(1, &cmd);
  argaddr(2, &buf);

  return shmctl(shmid, cmd, (void *)buf);
}

uint64
sys_getramused(void)
{
  return get_used_ram();
}

// setrlimit(int resource, const struct rlimit *rlp) -- IEEE Std 1003.1-2017.
// Set the calling process's soft (rlim_cur) and hard (rlim_max) limit for `resource`.
//
// CHECK CHAIN:
//   1. 0 <= resource < RLIM_NLIMITS            -> else -1 ([EINVAL] invalid resource)
//   2. copyin(rlp) from the user pointer       -> else -1 ([EFAULT] bad address)
//   3. rlim_cur <= rlim_max                     -> else -1 ([EINVAL] soft exceeds hard)
//   4. raising rlim_max needs CAP_SYS_RESOURCE  -> else -1 ([EPERM] not privileged)
//   5. store into myproc()->rlim[resource]      (acts on the CALLING process, per POSIX)
uint64
sys_setrlimit(void)
{
  int resource;
  uint64 rlp;
  struct rlimit lim;
  struct proc *p = myproc();

  argint(0, &resource);
  argaddr(1, &rlp);

  if(resource < 0 || resource >= RLIM_NLIMITS)
    return -1;
  if(copyin(p->pagetable, (char *)&lim, rlp, sizeof(lim)) < 0)
    return -1;
  if(lim.rlim_cur > lim.rlim_max)
    return -1;

  // POSIX "appropriate privileges": only a process holding CAP_SYS_RESOURCE may RAISE a
  // hard limit. Lowering rlim_max, or moving rlim_cur within rlim_max, stays unprivileged.
  // This is what turns RLIMIT_AS/RLIMIT_CPU into a real confinement boundary: a child whose
  // parent dropped the capability cannot escape its inherited cap. See capable().
  if(lim.rlim_max > p->rlim[resource].rlim_max && !capable(CAP_SYS_RESOURCE))
    return -1;

  // No lock needed -- same convention as p->sz. Only this process writes its own rlim[]
  // (setrlimit is self-targeted), and the one concurrent reader, cpuacct_tick() on the
  // timer interrupt, reads a single naturally-aligned 64-bit field (rlim_cur), whose
  // load/store is atomic on RV64. The struct copy below is two such word stores; the
  // reader can observe the old or new rlim_cur but never a torn value.
  p->rlim[resource] = lim;
  return 0;
}

// getrlimit(int resource, struct rlimit *rlp) -- IEEE Std 1003.1-2017.
// Copy out the calling process's current soft/hard limit for `resource`.
//
// CHECK CHAIN:
//   1. 0 <= resource < RLIM_NLIMITS            -> else -1 ([EINVAL] invalid resource)
//   2. copyout into the user pointer            -> else -1 ([EFAULT] bad address)
uint64
sys_getrlimit(void)
{
  int resource;
  uint64 rlp;
  struct proc *p = myproc();

  argint(0, &resource);
  argaddr(1, &rlp);

  if(resource < 0 || resource >= RLIM_NLIMITS)
    return -1;
  if(copyout(p->pagetable, rlp, (char *)&p->rlim[resource], sizeof(struct rlimit)) < 0)
    return -1;
  return 0;
}

// capget(void) -- return the calling process's capability set (POSIX.1e-style). The xv6
// analog of cap_get_proc(3); here a single 64-bit bitmask of CAP_* bits.
uint64
sys_capget(void)
{
  return myproc()->caps;
}

// capdrop(int cap) -- irreversibly drop capability `cap` from the calling process. A
// one-way ratchet (POSIX.1e permits dropping a held capability without privilege): a parent
// drops CAP_SYS_RESOURCE in a child before running untrusted code so the child can no longer
// raise its inherited resource hard limits.
//
// CHECK CHAIN:
//   1. 0 <= cap < 64   (valid bit index into the 64-bit caps mask) -> else -1 ([EINVAL])
//   2. clear the bit   (self-targeted; same no-lock convention as rlim[]/sz)
uint64
sys_capdrop(void)
{
  int cap;

  argint(0, &cap);
  if(cap < 0 || cap >= 64)
    return -1;
  myproc()->caps &= ~CAP_MASK(cap);
  return 0;
}

// getentropy(void *buffer, int length) -- IEEE Std 1003.1-2024 (POSIX.1-2024).
// Fill `buffer` with `length` unpredictable bytes from the kernel entropy pool (rand64,
// kernel/random.c). The xv6 analog of getentropy(3); unlike a PRNG seed it is meant to be
// unguessable, which is why it draws from the timer-jitter pool, not from rand().
//
// CHECK CHAIN:
//   1. 0 <= length <= GETENTROPY_MAX (256)      -> else -1 ([EINVAL] over-long request)
//   2. copyout `length` bytes into `buffer`     -> else -1 ([EFAULT] bad address)
//   3. on success return 0                        (POSIX returns 0/-1, not a byte count)
//
// The buffer is filled in 8-byte rand64() chunks; the final chunk writes only
// min(8, remaining) bytes, so a non-multiple-of-8 length never writes past `buffer`.
uint64
sys_getentropy(void)
{
  uint64 buf;
  int length;
  struct proc *p = myproc();

  argaddr(0, &buf);
  argint(1, &length);

  if(length < 0 || length > GETENTROPY_MAX)
    return -1;

  for(int off = 0; off < length; off += sizeof(uint64)){
    uint64 r = rand64();
    int n = length - off;
    if(n > (int)sizeof(uint64))
      n = sizeof(uint64);
    if(copyout(p->pagetable, buf + off, (char *)&r, n) < 0)
      return -1;
  }
  return 0;
}

// Keep the capability set consistent with POSIX "appropriate privileges" across a uid
// change (the Linux rule): a process that drops the euid-0 superuser identity loses its
// capabilities, and one that regains euid 0 gets the full set back. Called by setuid()/
// seteuid() with the euid the process had BEFORE the change.
static void
priv_adjust(struct proc *p, uid_t old_euid)
{
  if(old_euid == 0 && p->euid != 0)
    p->caps = 0;            // dropped root -> lose all capabilities
  else if(old_euid != 0 && p->euid == 0)
    p->caps = CAP_ALL;      // regained root -> full capability set
}

// getuid(void) -- IEEE Std 1003.1-2017. Return the calling process's real user ID. Cannot fail.
uint64
sys_getuid(void)
{
  return myproc()->ruid;
}

// geteuid(void) -- IEEE Std 1003.1-2017. Return the effective user ID. Cannot fail.
uint64
sys_geteuid(void)
{
  return myproc()->euid;
}

// setuid(uid_t uid) -- IEEE Std 1003.1-2017.
// A privileged process (euid 0) sets the real, effective, and saved set-user-IDs to uid;
// an unprivileged process may only set them to its real or saved uid (POSIX), and only the
// effective uid changes. Dropping the euid-0 identity clears the capability set (priv_adjust).
//
// CHECK CHAIN:
//   1. uid >= 0                                  -> else -1 ([EINVAL] invalid uid)
//   2. euid == 0 (privileged)                    -> set ruid = euid = suid = uid
//   3. else uid == ruid || uid == suid           -> set euid = uid only
//   4. else                                      -> -1 ([EPERM] uid not permitted)
//   5. adjust capabilities for an euid 0-boundary crossing (priv_adjust)
uint64
sys_setuid(void)
{
  int uid;
  struct proc *p = myproc();
  uid_t old_euid = p->euid;

  argint(0, &uid);
  if(uid < 0)
    return -1;

  if(p->euid == 0){
    p->ruid = p->euid = p->suid = (uid_t)uid;
  } else if((uid_t)uid == p->ruid || (uid_t)uid == p->suid){
    p->euid = (uid_t)uid;
  } else {
    return -1;
  }
  priv_adjust(p, old_euid);
  return 0;
}

// seteuid(uid_t euid) -- IEEE Std 1003.1-2017.
// Set only the effective uid. Allowed if the process is privileged (euid 0) or the argument
// equals the real or saved uid; the real and saved uids are unchanged. Crossing the euid-0
// boundary adjusts the capability set (priv_adjust) -- e.g. a setuid program may seteuid()
// down to its real uid and later restore it from the saved uid.
//
// CHECK CHAIN:
//   1. euid >= 0                                 -> else -1 ([EINVAL] invalid uid)
//   2. euid == 0 || arg == ruid || arg == suid   -> set euid = arg
//   3. else                                      -> -1 ([EPERM] euid not permitted)
//   4. adjust capabilities for an euid 0-boundary crossing (priv_adjust)
uint64
sys_seteuid(void)
{
  int euid;
  struct proc *p = myproc();
  uid_t old_euid = p->euid;

  argint(0, &euid);
  if(euid < 0)
    return -1;

  if(p->euid == 0 || (uid_t)euid == p->ruid || (uid_t)euid == p->suid){
    p->euid = (uid_t)euid;
  } else {
    return -1;
  }
  priv_adjust(p, old_euid);
  return 0;
}

uint64 
sys_thread_create(void)
{
  uint64 start_routine;
  uint64 arg;
  argaddr(0, &start_routine);
  argaddr(1, &arg);
  return thread_create(start_routine, arg);
}

uint64
sys_thread_join(void)
{
  int thread_id;
  argint(0, &thread_id);
  return thread_join(thread_id);
}

uint64
sys_thread_exit(void)
{
  thread_exit();
  return 0;
}

uint64
sys_yield(void)
{
  yield();
  return 0;
}

/**
 * @brief Set the priority of a process.
 * @param pid Process ID (0 means current process)
 * @param priority New priority value (lower = higher priority)
 * @return 0 on success, -1 on error
 *
 * @details
 * Only works with PRIORITY_SCHED or MLFQ_SCHED schedulers.
 * For MLFQ, sets the initial queue level based on priority.
 */
uint64
sys_setpriority(void)
{
#if !defined(PRIORITY_SCHED) && !defined(MLFQ_SCHED)
  // Priority scheduling not enabled - no-op
  return 0;
#else
  int pid, priority;
  struct proc *p;

  argint(0, &pid);
  argint(1, &priority);

  // Validate priority range (0-31, lower = higher priority)
  if (priority < 0 || priority > 31)
    return -1;

  // If pid is 0, use current process
  if (pid == 0) {
    p = myproc();
  } else {
    // Find process by PID
    p = 0;
    for (struct proc *iter = proc; iter < &proc[NPROC]; iter++) {
      acquire(&iter->lock);
      if (iter->pid == pid) {
        p = iter;
        // Keep lock held - we'll release it below
        break;
      }
      release(&iter->lock);
    }
    
    if (p == 0)
      return -1; // Process not found
  }

  // Set priority (lock already held for non-current processes)
  if (pid != 0) {
    p->priority = priority;
#ifdef MLFQ_SCHED
    // For MLFQ, map priority to queue level
    if (priority <= 10)
      p->queue_level = 0;      // High priority -> highest queue
    else if (priority <= 20)
      p->queue_level = 1;      // Medium priority -> middle queue
    else
      p->queue_level = 2;      // Low priority -> lowest queue
    p->time_slice = 1;         // Reset time slice
#endif
    release(&p->lock);
  } else {
    // Current process - no locking needed
    p->priority = priority;
#ifdef MLFQ_SCHED
    if (priority <= 10)
      p->queue_level = 0;
    else if (priority <= 20)
      p->queue_level = 1;
    else
      p->queue_level = 2;
    p->time_slice = 1;
#endif
  }

  return 0;
#endif
}