
# To compile and run with a lab solution, set the lab name in conf/lab.mk
# (e.g., LAB=util).  Run make grade to test solution with the lab's
# grade script (e.g., grade-lab-util).

-include conf/lab.mk

K=kernel
U=user

# Scheduler configuration (can be overridden: make SCHED_FLAG=PRIORITY qemu)
# Options:
#   PRIORITY - Priority Scheduler
#   MLFQ     - Multi-Level Feedback Queue Scheduler
#   (default) - Round Robin Scheduler
SCHED_FLAG ?=

# Base kernel objects (always compiled)
OBJS = \
  $K/entry.o \
  $K/kalloc.o \
  $K/string.o \
  $K/main.o \
  $K/vm.o \
  $K/swtch.o \
  $K/trampoline.o \
  $K/trap.o \
  $K/syscall.o \
  $K/sysproc.o \
  $K/stackguard.o \
  $K/random.o \
  $K/shm.o \
  $K/bio.o \
  $K/fs.o \
  $K/log.o \
  $K/sleeplock.o \
  $K/file.o \
  $K/pipe.o \
  $K/exec.o \
  $K/sysfile.o \
  $K/kernelvec.o \
  $K/plic.o \
  $K/virtio_disk.o


# Always include proc.o (contains process management, not just scheduler)
OBJS += $K/proc.o

OBJS_KCSAN = \
  $K/start.o \
  $K/console.o \
  $K/printf.o \
  $K/uart.o \
  $K/spinlock.o

ifdef KCSAN
OBJS_KCSAN += \
	$K/kcsan.o
endif

ifeq ($(LAB),lock)
OBJS += \
	$K/stats.o\
	$K/sprintf.o
endif


ifeq ($(LAB),net)
OBJS += \
	$K/e1000.o \
	$K/net.o \
	$K/pci.o
endif


# riscv64-unknown-elf- or riscv64-linux-gnu-
# perhaps in /opt/riscv/bin
#
# Deliberately NOT assigned here: an unconditional assignment makes the ifndef
# inference below dead code and hard-fails on a machine whose toolchain is
# riscv64-unknown-elf- (the environment variable loses to a makefile '='). Set
# TOOLPREFIX in the environment or on the command line to pin a specific
# toolchain; otherwise it is detected.

# Try to infer the correct TOOLPREFIX if not set
ifndef TOOLPREFIX
TOOLPREFIX := $(shell if riscv64-unknown-elf-objdump -i 2>&1 | grep 'elf64-big' >/dev/null 2>&1; \
	then echo 'riscv64-unknown-elf-'; \
	elif riscv64-elf-objdump -i 2>&1 | grep 'elf64-big' >/dev/null 2>&1; \
	then echo 'riscv64-elf-'; \
	elif riscv64-linux-gnu-objdump -i 2>&1 | grep 'elf64-big' >/dev/null 2>&1; \
	then echo 'riscv64-linux-gnu-'; \
	elif riscv64-unknown-linux-gnu-objdump -i 2>&1 | grep 'elf64-big' >/dev/null 2>&1; \
	then echo 'riscv64-unknown-linux-gnu-'; \
	else echo "***" 1>&2; \
	echo "*** Error: Couldn't find a riscv64 version of GCC/binutils." 1>&2; \
	echo "*** To turn off this error, run 'gmake TOOLPREFIX= ...'." 1>&2; \
	echo "***" 1>&2; exit 1; fi)
endif

QEMU = qemu-system-riscv64
MIN_QEMU_VERSION = 7.2

CC = $(TOOLPREFIX)gcc
AS = $(TOOLPREFIX)gas
LD = $(TOOLPREFIX)ld
OBJCOPY = $(TOOLPREFIX)objcopy
OBJDUMP = $(TOOLPREFIX)objdump

CFLAGS = -Wall -Werror -O -fno-omit-frame-pointer -ggdb -gdwarf-2
CFLAGS = -Wall -Werror -Wno-unknown-attributes -O -fno-omit-frame-pointer -ggdb -gdwarf-2

XCFLAGS += -DSOL_COW -DLAB_COW

ifdef LAB
LABUPPER = $(shell echo $(LAB) | tr a-z A-Z)
XCFLAGS += -DSOL_$(LABUPPER) -DLAB_$(LABUPPER)
endif

CFLAGS += $(XCFLAGS)
CFLAGS += -MD
CFLAGS += -mcmodel=medany
CFLAGS += -ffreestanding
CFLAGS += -fno-common -nostdlib
CFLAGS += -fno-builtin-strncpy -fno-builtin-strncmp -fno-builtin-strlen -fno-builtin-memset
CFLAGS += -fno-builtin-memmove -fno-builtin-memcmp -fno-builtin-log -fno-builtin-bzero
CFLAGS += -fno-builtin-strchr -fno-builtin-exit -fno-builtin-malloc -fno-builtin-putc
CFLAGS += -fno-builtin-free
CFLAGS += -fno-builtin-memcpy -Wno-main
CFLAGS += -fno-builtin-printf -fno-builtin-fprintf -fno-builtin-vprintf
CFLAGS += -I.
# Stack-smashing protection (SSP / StackGuard, USENIX Sec '98; RISC-V psABI).
# Was -fno-stack-protector (canary disabled). We now request -fstack-protector-strong
# (the level Linux/KSPP CONFIG_STACKPROTECTOR_STRONG uses) so the compiler emits a
# canary around the saved return address of any frame with arrays / address-taken /
# large locals. -mstack-protector-guard=global makes GCC read the canary from the
# global symbol __stack_chk_guard (xv6 has no TLS / tp guard); the guard value and the
# __stack_chk_fail() handler live in kernel/stackguard.c (kernel) and user/stackguard.c
# (user). Probed so the build still works on a toolchain without the feature.
CFLAGS += $(shell $(CC) -fstack-protector-strong -E -x c /dev/null >/dev/null 2>&1 && echo -fstack-protector-strong -mstack-protector-guard=global)

# Conditional scheduler compilation based on SCHED_FLAG
ifeq ($(SCHED_FLAG),PRIORITY)
  # Priority scheduler: use sched_priority.c instead of proc.c scheduler
  CFLAGS += -DPRIORITY_SCHED
  OBJS += $K/sched_priority.o
else ifeq ($(SCHED_FLAG),MLFQ)
  # MLFQ scheduler: use sched_mlfq.c instead of proc.c scheduler
  CFLAGS += -DMLFQ_SCHED
  OBJS += $K/sched_mlfq.o
endif


ifeq ($(LAB),net)
CFLAGS += -DNET_TESTS_PORT=$(SERVERPORT)
endif

ifdef KCSAN
CFLAGS += -DKCSAN
KCSANFLAG = -fsanitize=thread -fno-inline
endif

# Disable PIE when possible (for Ubuntu 16.10 toolchain)
ifneq ($(shell $(CC) -dumpspecs 2>/dev/null | grep -e '[^f]no-pie'),)
CFLAGS += -fno-pie -no-pie
endif
ifneq ($(shell $(CC) -dumpspecs 2>/dev/null | grep -e '[^f]nopie'),)
CFLAGS += -fno-pie -nopie
endif

LDFLAGS = -z max-page-size=4096

$K/kernel: $(OBJS) $(OBJS_KCSAN) $K/kernel.ld
	@echo "DEBUG: Building kernel with CFLAGS=$(CFLAGS)"
	$(LD) $(LDFLAGS) -T $K/kernel.ld -o $K/kernel $(OBJS) $(OBJS_KCSAN)
	$(OBJDUMP) -S $K/kernel > $K/kernel.asm
	$(OBJDUMP) -t $K/kernel | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $K/kernel.sym
$(OBJS): EXTRAFLAG := $(KCSANFLAG)

$K/%.o: $K/%.c
	$(CC) $(CFLAGS) $(EXTRAFLAG) -c -o $@ $<

$K/%.o: $K/%.S
	$(CC) -g -c -o $@ $<

tags: $(OBJS)
	etags kernel/*.S kernel/*.c

ULIB = $U/crt0.o $U/ulib.o $U/usys.o $U/printf.o $U/umalloc.o $U/stackguard.o $U/testutil.o $U/xstdlib.o $U/xmath.o $U/xstrlib.o $U/mutex.o

ifeq ($(LAB),lock)
ULIB += $U/statistics.o
endif


# The xv6 filesystem caps a file at MAXFILE = NDIRECT + NINDIRECT = 268 blocks
# (274 KB with BSIZE 1024), and mkfs aborts on anything larger. These two
# programs link the transformer kernels and carry ~83% debug info, which pushed
# _distinf to 382 KB. The debug sections are stripped from the image copy only --
# the .asm and .sym files generated just above keep full symbol information for
# debugging, exactly as before. Raising MAXFILE instead would mean adding
# doubly-indirect blocks to the filesystem (the xv6 large-files lab), which is a
# separate change with its own verification.

# Special programs that need additional libraries
$U/_testftp: $U/testftp.o $(ULIB) $U/ftpclient.o $U/sha256.o
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/testftp.o $(ULIB) $U/ftpclient.o $U/sha256.o
	$(OBJDUMP) -S $@ > $U/testftp.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/testftp.sym

$U/_shardspike: $U/shardspike.o $(ULIB) $U/ftpclient.o $U/sha256.o
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/shardspike.o $(ULIB) $U/ftpclient.o $U/sha256.o
	$(OBJDUMP) -S $@ > $U/shardspike.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/shardspike.sym

$U/_testsha: $U/testsha.o $(ULIB) $U/sha256.o
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/testsha.o $(ULIB) $U/sha256.o
	$(OBJDUMP) -S $@ > $U/testsha.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/testsha.sym

$U/_llama: $U/llama.o $U/llama_core.o $U/perf.o $(ULIB) $U/ftpclient.o $U/sha256.o
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/llama.o $U/llama_core.o $U/perf.o $(ULIB) $U/ftpclient.o $U/sha256.o
	$(OBJDUMP) -S $@ > $U/llama.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/llama.sym
	$(OBJCOPY) --strip-debug $@

$U/_testperf: $U/testperf.o $U/perf.o $(ULIB)
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/testperf.o $U/perf.o $(ULIB)
	$(OBJDUMP) -S $@ > $U/testperf.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/testperf.sym

$U/_threadtest: $U/threadtest.o $U/perf.o $(ULIB)
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/threadtest.o $U/perf.o $(ULIB)
	$(OBJDUMP) -S $@ > $U/threadtest.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/threadtest.sym

$U/_schedtest: $U/schedtest.o $(ULIB)
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/schedtest.o $(ULIB)
	$(OBJDUMP) -S $@ > $U/schedtest.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/schedtest.sym

# Special compilation rule for schedtest.c to include scheduler flags
$U/schedtest.o: $U/schedtest.c
	$(CC) $(CFLAGS) -c -o $U/schedtest.o $U/schedtest.c 

_%: %.o $(ULIB) $U/user.ld
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $< $(ULIB)
	$(OBJDUMP) -S $@ > $*.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $*.sym

$U/usys.S : $U/usys.pl
	perl $U/usys.pl > $U/usys.S

$U/usys.o : $U/usys.S
	$(CC) $(CFLAGS) -c -o $U/usys.o $U/usys.S

$U/xstdlib.o: $U/xstdlib.c $U/xstdlib.h
	$(CC) $(CFLAGS) -c -o $U/xstdlib.o $U/xstdlib.c

$U/_forktest: $U/forktest.o $(ULIB) $U/wxneeded.ld
	# forktest has less library code linked in - needs to be small
	# in order to be able to max out the proc table. stackguard.o is tiny and is
	# required because ulib.o's protected functions reference __stack_chk_guard/_fail.
	# It links into a single OMAGIC R+W+X segment (to stay tiny), which violates W^X, so
	# it is tagged PT_OPENBSD_WXNEEDED via user/wxneeded.ld to be exempt from the kernel's
	# W^X enforcement (kernel/exec.c).
	$(LD) $(LDFLAGS) -N -e main -Ttext 0 -T $U/wxneeded.ld -o $U/_forktest $U/forktest.o $U/ulib.o $U/usys.o $U/stackguard.o
	$(OBJDUMP) -S $U/_forktest > $U/forktest.asm

# wxbad: a deliberately W^X-violating test binary -- a single OMAGIC R+W+X segment, but
# WITHOUT the PT_OPENBSD_WXNEEDED tag, so the kernel's W^X enforcement must refuse to exec
# it (proven by user/wxtest.c). Built like the old forktest (no wxneeded.ld).
$U/_wxbad: $U/wxbad.o $(ULIB)
	$(LD) $(LDFLAGS) -N -e main -Ttext 0 -o $U/_wxbad $U/wxbad.o $U/ulib.o $U/usys.o $U/stackguard.o
	$(OBJDUMP) -S $U/_wxbad > $U/wxbad.asm

$U/xdr.o: $U/xdr.c
	$(CC) $(CFLAGS) -c -o $@ $U/xdr.c

$U/_xdr: $U/xdr.o $(ULIB) $U/user.ld
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/xdr.o $(ULIB)
	$(OBJDUMP) -S $@ > $U/xdr.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/xdr.sym

$U/xdr_test.o: $U/xdr_test.c $U/xdr.h
	$(CC) $(CFLAGS) -c -o $@ $U/xdr_test.c
$U/_xdr_test: $U/xdr_test.o $U/xdr.o $(ULIB)
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/xdr_test.o $U/xdr.o $(ULIB)
	$(OBJDUMP) -S $@ > $U/xdr_test.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/xdr_test.sym

$U/rpc.o: $U/rpc.c $U/rpc.h $U/xdr.h
	$(CC) $(CFLAGS) -c -o $@ $U/rpc.c


$U/discovery.o: $U/discovery.c $U/rpc.h $U/xdr.h
	$(CC) $(CFLAGS) -I -I$K -c -o $@ $U/discovery.c

$U/distinf.o: $U/distinf.c $U/rpc.h $U/xdr.h
	$(CC) $(CFLAGS) -c -o $@ $U/distinf.c

$U/_distinf: $U/distinf.o $U/discovery.o $U/rpc.o $U/xdr.o $U/shard.o $U/llama_core.o $U/perf.o $U/ftpclient.o $U/sha256.o $(ULIB)
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/distinf.o $U/discovery.o $U/rpc.o $U/xdr.o $U/shard.o $U/llama_core.o $U/perf.o $U/ftpclient.o $U/sha256.o $(ULIB)
	$(OBJDUMP) -S $@ > $U/distinf.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/distinf.sym
	$(OBJCOPY) --strip-debug $@

$U/rpc_test.o: $U/rpc_test.c $U/rpc.h $U/xdr.h
	$(CC) $(CFLAGS) -c -o $@ $U/rpc_test.c
$U/_rpc_test: $U/rpc_test.o $U/rpc.o $U/xdr.o $(ULIB)
	$(LD) $(LDFLAGS) -T $U/user.ld -o $@ $U/rpc_test.o $U/rpc.o $U/xdr.o $(ULIB)
	$(OBJDUMP) -S $@ > $U/rpc_test.asm
	$(OBJDUMP) -t $@ | sed '1,/SYMBOL TABLE/d; s/ .* / /; /^$$/d' > $U/rpc_test.sym

mkfs/mkfs: mkfs/mkfs.c $K/fs.h $K/param.h
	gcc $(XCFLAGS) -Wno-unknown-attributes -Werror -Wall -I. -o mkfs/mkfs mkfs/mkfs.c

# Prevent deletion of intermediate files, e.g. cat.o, after first build, so
# that disk image changes after first build are persistent until clean.  More
# details:
# http://www.gnu.org/software/make/manual/html_node/Chained-Rules.html
.PRECIOUS: %.o

UPROGS=\
	$U/_cat\
	$U/_canarytest\
	$U/_rlimittest\
	$U/_randtest\
	$U/_aslrtest\
	$U/_wxtest\
	$U/_wxbad\
	$U/_idtest\
	$U/_echo\
	$U/_forktest\
	$U/_grep\
	$U/_init\
	$U/_kill\
	$U/_ln\
	$U/_ls\
	$U/_mkdir\
	$U/_rm\
	$U/_sh\
	$U/_stressfs\
	$U/_usertests\
	$U/_grind\
	$U/_wc\
	$U/_zombie\
	$U/_logstress\
	$U/_forphan\
	$U/_dorphan\
	$U/_testftp\
	$U/_fputest\
	$U/_runtests\
	$U/_testxstdlib\
	$U/_testxmath\
	$U/_testxstrlib\
	$U/_testsha\
	$U/_testshm\
	$U/_llama\
	$U/_threadtest\
	$U/_testram\
	$U/_testperf\
	$U/_schedtest\
	$U/_xdr_test\
	$U/_rpc_test\
	$U/_distinf\
	$U/_shardspike\
	$U/_threadstack\
	$U/_timeout_test\


ifeq ($(LAB),util)
UPROGS += \
	$U/_sleep\
	$U/_sixfive\
	$U/_find
endif
### ENDIF


ifeq ($(LAB),syscall)
UPROGS += \
	$U/_attack\
	$U/_secret
endif

ifeq ($(LAB),lock)
UPROGS += \
	$U/_stats
endif

ifeq ($(LAB),traps)
UPROGS += \
	$U/_call\
	$U/_bttest
endif

ifeq ($(LAB),lazy)
UPROGS += \
	$U/_lazytests
endif

UPROGS += $U/_cowtest

ifeq ($(LAB),thread)
UPROGS += \
	$U/_uthread

$U/uthread_switch.o : $U/uthread_switch.S
	$(CC) $(CFLAGS) -c -o $U/uthread_switch.o $U/uthread_switch.S

$U/_uthread: $U/uthread.o $U/uthread_switch.o $(ULIB)
	$(LD) $(LDFLAGS) -N -e main -Ttext 0 -o $U/_uthread $U/uthread.o $U/uthread_switch.o $(ULIB)
	$(OBJDUMP) -S $U/_uthread > $U/uthread.asm

ph: notxv6/ph.c
	gcc -o ph -g -O2 $(XCFLAGS) notxv6/ph.c -pthread

barrier: notxv6/barrier.c
	gcc -o barrier -g -O2 $(XCFLAGS) notxv6/barrier.c -pthread
endif

ifeq ($(LAB),pgtbl)
UPROGS += \
	$U/_pgtbltest
endif

ifeq ($(LAB),lock)
UPROGS += \
	$U/_kalloctest\
	$U/_bcachetest
endif

ifeq ($(LAB),fs)
UPROGS += \
	$U/_bigfile
endif


ifeq ($(LAB),mmap)
UPROGS += \
	$U/_mmaptest
endif

ifeq ($(LAB),net)
UPROGS += \
	$U/_nettest \
	$U/_netecho
endif

UEXTRA=
ifeq ($(LAB),util)
	UEXTRA += user/findtest.sh
	UEXTRA += user/sixfive.txt
	UPROGS += $U/_memdump
endif
ifeq ($(LAB),syscall)
	UEXTRA += user/exec.sh
endif

fs.img: mkfs/mkfs README $(UEXTRA) $(UPROGS)
	mkfs/mkfs fs.img README $(UEXTRA) $(UPROGS)

newfs.img: 
	-mv -f fs.img fs.img.bk

-include kernel/*.d user/*.d

clean:
	rm -rf *.tex *.dvi *.idx *.aux *.log *.ind *.ilg *.dSYM *.zip *.pcap \
	*/*.o */*.d */*.asm */*.sym \
	$K/kernel fs.img \
	mkfs/mkfs .gdbinit \
        $U/usys.S \
	$(UPROGS)

# try to generate a unique GDB port
GDBPORT = $(shell expr `id -u` % 5000 + 25000)
# QEMU's gdb stub command line changed in 0.11
QEMUGDB = $(shell if $(QEMU) -help | grep -q '^-gdb'; \
	then echo "-gdb tcp::$(GDBPORT)"; \
	else echo "-s -p $(GDBPORT)"; fi)
ifndef CPUS
CPUS := 8
endif
ifeq ($(LAB),fs)
CPUS := 1
endif

FWDPORT1 = $(shell expr `id -u` % 5000 + 25999)
FWDPORT2 = $(shell expr `id -u` % 5000 + 30999)

QEMUOPTS = -machine virt -bios none -kernel $K/kernel -m 256M -smp $(CPUS) -nographic
QEMUOPTS += -global virtio-mmio.force-legacy=false
QEMUOPTS += -drive file=fs.img,if=none,format=raw,id=x0
QEMUOPTS += -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0

ifeq ($(LAB),net)
ifeq ($(NETDEV),tap)
QEMUOPTS += -netdev tap,id=net0,ifname=tap0,script=no,downscript=no
else
QEMUOPTS += -netdev user,id=net0,hostfwd=udp::$(FWDPORT1)-:2000,hostfwd=udp::$(FWDPORT2)-:2001 -object filter-dump,id=net0,netdev=net0,file=packets.pcap
endif
QEMUOPTS += -device e1000,netdev=net0,bus=pcie.0
endif

# makes a new fs.img (default Round Robin scheduler)
qemu: check-qemu-version newfs.img $K/kernel fs.img
	$(QEMU) $(QEMUOPTS)

# runs with existing fs.img, if present
qemu-fs: check-qemu-version $K/kernel fs.img
	$(QEMU) $(QEMUOPTS)

# Convenience targets for different schedulers
# Usage: make qemu-priority  or  make qemu-mlfq

# Run with Priority Scheduler
qemu-priority: 
	@echo "Building xv6 with Priority Scheduler..."
	$(MAKE) clean
	$(MAKE) SCHED_FLAG=PRIORITY $K/kernel
	$(MAKE) SCHED_FLAG=PRIORITY qemu

# Run with MLFQ Scheduler
qemu-mlfq: 
	@echo "Building xv6 with MLFQ Scheduler..."
	$(MAKE) clean
	$(MAKE) SCHED_FLAG=MLFQ $K/kernel
	$(MAKE) SCHED_FLAG=MLFQ qemu

# Run with default Round Robin Scheduler
qemu-rr: 
	@echo "Building xv6 with Round Robin Scheduler (default)..."
	$(MAKE) clean
	$(MAKE) qemu

.gdbinit: .gdbinit.tmpl-riscv
	sed "s/:1234/:$(GDBPORT)/" < $^ > $@

qemu-gdb: $K/kernel .gdbinit fs.img
	@echo "*** Now run 'gdb' in another window." 1>&2
	$(QEMU) $(QEMUOPTS) -S $(QEMUGDB)

tap-setup:
	sudo ip tuntap add dev tap0 mode tap 2>/dev/null || true
	sudo ip addr add 10.0.0.1/24 dev tap0 2>/dev/null || true
	sudo ip link set tap0 up

qemu-tap: check-qemu-version newfs.img $K/kernel fs.img
	$(QEMU) $(QEMUOPTS_BASE) -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
		-device e1000,netdev=net0,bus=pcie.0

# Multi-node bring-up.
#
# The taps are created owned by the invoking user (`user $(id -un)`), which is
# what lets QEMU open /dev/net/tun without privilege. Without it the taps are
# root-owned and every node has to be launched under sudo, which makes the
# whole bring-up unautomatable. This target is therefore the ONLY privileged
# step: run it once per boot, and everything afterwards (building, booting the
# ring, driving the consoles, the gates) runs as an ordinary user.
bridge-setup:
	sudo ip link add br0 type bridge 2>/dev/null || true
	sudo ip addr add 10.0.0.1/24 dev br0 2>/dev/null || true
	sudo ip link set br0 up
	for t in 1 2 3 4 5 6; do \
		sudo ip tuntap add dev tap$$t mode tap user $$(id -un) 2>/dev/null || true; \
		sudo ip link set tap$$t master br0; \
		sudo ip link set tap$$t up; \
	done
	@echo "bridge-setup: br0 + tap1..tap6 up, owned by $$(id -un)"

# Verify the bridge is usable *before* QEMU fails with an opaque
# "could not open /dev/net/tun". Checks, in order:
#   1. br0 exists and is up, carrying the host end of 10.0.0.0/24 (10.0.0.1)
#   2. each tap exists and is enslaved to br0
#   3. each tap is owned by the invoking user, so QEMU can open it unprivileged
bridge-check:
	@ip link show br0 >/dev/null 2>&1 || { echo "FAIL: br0 missing - run 'make bridge-setup'"; exit 1; }
	@ip addr show br0 | grep -q 10.0.0.1 || { echo "FAIL: br0 has no 10.0.0.1"; exit 1; }
	@for t in 1 2 3 4 5 6; do \
		ip link show tap$$t >/dev/null 2>&1 || { echo "FAIL: tap$$t missing"; exit 1; }; \
		ip link show tap$$t | grep -q "master br0" || { echo "FAIL: tap$$t not on br0"; exit 1; }; \
	done
	@for t in 1 2 3 4 5 6; do \
		owner=$$(cat /sys/class/net/tap$$t/owner 2>/dev/null); \
		[ "$$owner" = "$$(id -u)" ] || { echo "FAIL: tap$$t owned by uid $$owner, not $$(id -u) - re-run 'make bridge-setup'"; exit 1; }; \
	done
	@echo "bridge-check: OK - br0 10.0.0.1, tap1..tap6 enslaved and owned by $$(id -un)"

QEMUOPTS_BASE = -machine virt -bios none -kernel $K/kernel -m 256M -smp $(CPUS) -nographic
QEMUOPTS_BASE += -global virtio-mmio.force-legacy=false
QEMUOPTS_BASE += -drive file=fs.img,if=none,format=raw,id=x0
QEMUOPTS_BASE += -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0

qemu-node1: check-qemu-version newfs.img fs.img
	$(MAKE) -B XCFLAGS="$(XCFLAGS) -DXV6_IP_D=2 -DXV6_MAC_LAST=0x56" $K/kernel
	$(QEMU) $(QEMUOPTS_BASE) -netdev tap,id=net0,ifname=tap1,script=no,downscript=no \
		-device e1000,netdev=net0,bus=pcie.0

qemu-node2: check-qemu-version newfs.img fs.img
	$(MAKE) -B XCFLAGS="$(XCFLAGS) -DXV6_IP_D=3 -DXV6_MAC_LAST=0x57" $K/kernel
	$(QEMU) $(QEMUOPTS_BASE) -netdev tap,id=net0,ifname=tap2,script=no,downscript=no \
		-device e1000,netdev=net0,bus=pcie.0

qemu-node3 : check-qemu-version newfs.img fs.img
	$(MAKE) -B XCFLAGS="$(XCFLAGS) -DXV6_IP_D=4 -DXV6_MAC_LAST=0x58" $K/kernel
	$(QEMU) $(QEMUOPTS_BASE) -netdev tap,id=net0,ifname=tap3,script=no,downscript=no \
		-device e1000,netdev=net0,bus=pcie.0

qemu-node4 : check-qemu-version newfs.img fs.img
	$(MAKE) -B XCFLAGS="$(XCFLAGS) -DXV6_IP_D=5 -DXV6_MAC_LAST=0x59" $K/kernel
	$(QEMU) $(QEMUOPTS_BASE) -netdev tap,id=net0,ifname=tap4,script=no,downscript=no \
		-device e1000,netdev=net0,bus=pcie.0

qemu-node5 : check-qemu-version newfs.img fs.img
	$(MAKE) -B XCFLAGS="$(XCFLAGS) -DXV6_IP_D=6 -DXV6_MAC_LAST=0x5a" $K/kernel
	$(QEMU) $(QEMUOPTS_BASE) -netdev tap,id=net0,ifname=tap5,script=no,downscript=no \
		-device e1000,netdev=net0,bus=pcie.0

qemu-node6 : check-qemu-version newfs.img fs.img
	$(MAKE) -B XCFLAGS="$(XCFLAGS) -DXV6_IP_D=7 -DXV6_MAC_LAST=0x5b" $K/kernel
	$(QEMU) $(QEMUOPTS_BASE) -netdev tap,id=net0,ifname=tap6,script=no,downscript=no \
		-device e1000,netdev=net0,bus=pcie.0

qemu-nox: check-qemu-version newfs.img $K/kernel fs.img
	$(QEMU) $(QEMUOPTS) -nographic

# Qemu nox but for priority scheduler
qemu-nox-priority: clean
	@echo "Building xv6 with Priority Scheduler..."
	$(MAKE) clean
	$(MAKE) SCHED_FLAG=PRIORITY qemu-nox

qemu-nox-mlfq: clean
	@echo "Building xv6 with MLFQ Scheduler..."
	$(MAKE) clean
	$(MAKE) SCHED_FLAG=MLFQ qemu-nox

qemu-nox-rr: clean
	@echo "Building xv6 with Round Robin Scheduler (default)..."
	$(MAKE) clean
	$(MAKE) qemu-nox

ifeq ($(LAB),net)
# try to generate a unique port for the echo server
SERVERPORT = $(shell expr `id -u` % 5000 + 25099)

endif

##
##  FOR testing lab grading script
##

ifneq ($(V),@)
GRADEFLAGS += -v
endif

print-gdbport:
	@echo $(GDBPORT)

grade:
	@echo $(MAKE) clean
	@$(MAKE) clean || \
          (echo "'make clean' failed.  HINT: Do you have another running instance of xv6?" && exit 1)
	./grade-lab-$(LAB) $(GRADEFLAGS)

##
## FOR submissions
##

submit-check:
	@if ! test -d .git; then \
		echo No .git directory, is this a git repository?; \
		false; \
	fi
	@if test "$$(git symbolic-ref HEAD)" != refs/heads/$(LAB); then \
		git branch; \
		read -p "You are not on the $(LAB) branch.  Hand-in the current branch? [y/N] " r; \
		test "$$r" = y; \
	fi
	@if ! git diff-files --quiet || ! git diff-index --quiet --cached HEAD; then \
		git status -s; \
		echo; \
		echo "You have uncomitted changes.  Please commit or stash them."; \
		false; \
	fi
	@if test -n "`git status -s`"; then \
		git status -s; \
		read -p "Untracked files will not be handed in.  Continue? [y/N] " r; \
		test "$$r" = y; \
	fi

zipball: clean submit-check
	git archive --verbose --format zip --output lab.zip HEAD

.PHONY: zipball clean grade submit-check check-qemu-version qemu-tap tap-setup

QEMU_VERSION := $(shell $(QEMU) --version | head -n 1 | sed -E 's/^QEMU emulator version ([0-9]+\.[0-9]+)\..*/\1/')
check-qemu-version:
	@if [ "$(shell echo "$(QEMU_VERSION) >= $(MIN_QEMU_VERSION)" | bc)" -eq 0 ]; then \
		echo "ERROR: Need qemu version >= $(MIN_QEMU_VERSION)"; \
		exit 1; \
	fi
