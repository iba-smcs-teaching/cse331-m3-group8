#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "defs.h"

volatile static int started = 0;

// start() jumps here in supervisor mode on all CPUs.
//
// no_stack_protector: main() seeds __stack_chk_guard (via stackguard_init() below)
// before any other hart runs a protected function, so its own frame must not be
// guarded -- otherwise its epilogue would compare a canary captured from the old
// guard against the freshly-seeded value. main() never returns (it ends in
// scheduler()), so leaving it unprotected costs nothing.
__attribute__((no_stack_protector))
void
main()
{
  if(cpuid() == 0){
    random_init();     // seed the entropy pool before its first consumer (the canary)
    stackguard_init(); // randomise the stack canary before any protected frame runs
    consoleinit();
#if defined(LAB_LOCK)
    statsinit();
#endif
    printfinit();
    printf("\n");
    printf("xv6 kernel is booting\n");
    printf("\n");
    kinit();         // physical page allocator
    kvminit();       // create kernel page table
    kvminithart();   // turn on paging
    procinit();      // process table
    trapinit();      // trap vectors
    trapinithart();  // install kernel trap vector
    plicinit();      // set up interrupt controller
    plicinithart();  // ask PLIC for device interrupts
    binit();         // buffer cache
    iinit();         // inode table
    fileinit();      // file table
    virtio_disk_init(); // emulated hard disk
    shm_init();      // shared memory system
#ifdef LAB_NET
    pci_init();
    netinit();
#endif    
    userinit();      // first user process
#ifdef KCSAN
    kcsaninit();
#endif

// Compile-time scheduler detection
#if defined(MLFQ_SCHED)
  printf("Scheduler: MLFQ (Multi-Level Feedback Queue)\n");
#elif defined(PRIORITY_SCHED)
  printf("Scheduler: Priority Scheduling\n");
#else
  printf("Scheduler: Round Robin (Default)\n");
#endif


    __sync_synchronize();
    started = 1;
  } else {
    while(atomic_read4((int *) &started) == 0)
      ;
    __sync_synchronize();
    printf("hart %d starting\n", cpuid());
    kvminithart();    // turn on paging
    trapinithart();   // install kernel trap vector
    plicinithart();   // ask PLIC for device interrupts
  }

#ifdef LAB_LOCK
  rwspinlock_test();
#endif
  scheduler();        
}
