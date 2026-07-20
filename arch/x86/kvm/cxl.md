# KVM CXL In-Kernel MMIO Fast Path

## Overview

When a guest VM accesses CXL memory backed by a QEMU OpenCIS fixed memory
window, the access traps to KVM as an MMIO fault. Normally KVM exits to
userspace (QEMU) to service it, then re-enters the guest. This round-trip
dominates latency because the actual work QEMU does is trivial: a small cache
lookup plus a memcpy from an mmap'd file.

This feature moves that logic into KVM so the MMIO is handled entirely in the
kernel. The guest never leaves KVM for CXL accesses.

```
Before:  Guest -> KVM (EPT violation) -> QEMU userspace -> cache + mmap -> KVM -> Guest
After:   Guest -> KVM (EPT violation) -> in-kernel cache + vmap -> Guest
```

## Sysfs Interface

QEMU registers a CXL region at boot by writing to:

    /sys/module/kvm/parameters/cxl_config

**Register** (6 comma-separated fields):

    echo "1,PID,/dev/hugepages/cxl_dev.bin,/tmp/cxl.log,0x490000000,0x10000000" > cxl_config

- Field 1: CACHE_ENABLE -- `1` routes MMIO through the software cache,
  `0` bypasses the cache and writes the backing file directly
- Field 2: VMID -- the PID of the QEMU process (`getpid()`)
- Field 3: path to the hugetlbfs backing file
- Field 4: LOGBIN -- path to access log file (empty to disable)
- Field 5: guest-physical base address of the CXL window (hex)
- Field 6: size of the CXL window (hex)

LOGBIN may be empty (two consecutive commas = no logging):

    echo "1,PID,/dev/hugepages/cxl_dev.bin,,0x490000000,0x10000000" > cxl_config

The kernel matches the PID against running KVM instances, opens and vmaps the
backing file, initialises the cache (or marks it bypassed), and attaches the
result to the VM.  Toggling `CACHE_ENABLE` on a live VM requires an
unregister + re-register round-trip.

**Unregister** (VMID only):

    echo "PID" > cxl_config

**Read current registrations:**

    cat cxl_config

Each line shows `vm=<PID> cache=<0|1> base=0x... size=0x...`.

## How It Works

### MMIO Interception

The hook lives in `emulator_read_write()` (x86.c), the common path for both
emulated reads and writes. After MMIO fragments are assembled but before
`KVM_EXIT_MMIO` is set, `kvm_cxl_handle_mmio()` checks whether the guest
physical address falls inside the registered CXL window. If so it services the
access through the cache and returns `X86EMUL_CONTINUE`; the emulator never
exits to userspace.

### Backing Memory

At registration time the backing file's page cache is walked with
`filemap_get_folio()`. For hugetlbfs each 2 MB compound page is decomposed
into base-page pointers and the full region is mapped into kernel VA with
`vmap()`. All subsequent access is plain `memcpy` against that mapping -- no
VFS calls, no sleeping -- which is why the cache lock can be a spinlock.

### Host-Side Cache

Active when `CACHE_ENABLE=1`.  Ported from the QEMU OpenCIS implementation
(`cxl_hcache.c` / `cxl_type3_hcoh.c`). Parameters match exactly:

| Parameter     | Value |
|---------------|-------|
| Block size    | 64 B  |
| Associativity | 4-way |
| Sets          | 8     |
| Total size    | 2 KB  |
| Eviction      | LRU   |

On a **hit** the data is served from the cache block.

On a **miss** a victim is selected (invalid block first, then LRU). If the
victim is dirty (`MODIFIED`) its 64-byte line is written back to the vmap'd
region. The requested line is then filled from the vmap'd region, and the
original read or write is performed on the now-cached block.

Accesses that cross a 64-byte block boundary are split into two cache
operations, matching the QEMU behaviour.

### Cache Bypass (CACHE_ENABLE=0)

With `CACHE_ENABLE=0` the per-VM cache state is never touched.  Each MMIO
fragment is written through to (or read from) the vmap'd backing region
directly with a single `memcpy`, and a single log entry is emitted per
fragment.  Useful for A/B comparison against the cached path and for
workloads that want every access to hit the backing store immediately.

### Access Logging (LOGBIN)

When a LOGBIN path is provided, every backing-file access is logged.  In
**cache mode** that means cache-miss fills and dirty-eviction writebacks
(GPAs are 64-byte block aligned).  In **bypass mode** every guest MMIO
fragment produces exactly one entry at the raw access GPA (not block
aligned).  The output format is one line per event: vCPU ID, decimal GPA,
and `R`/`W`, separated by single spaces:

    0 19596050432 R
    2 19595788352 W

Multiple VMs may register the **same** LOGBIN path. The kernel shares a
single ring buffer and output file across all such VMs, keyed by path: the
first VM to register opens (and truncates) the file; later VMs join the
existing entry, and teardown happens only when the last reference drops.

Producers from any VM serialize on a single spinlock when pushing into the
shared ring, so events appear in the file in **strict push (≈ real-time)
order** across VMs — not just byte-non-interleaved. The cost is shared
backpressure: when the ring fills, vCPU producers from any VM block until
the single workqueue consumer drains.  This applies to both cache mode and
bypass mode.

The implementation uses a producer-consumer ring buffer to keep the hot path
fast:

- **Producer** (spinlock context): writes a 9-byte binary entry (`u8 is_write`
  \+ `u64 gpa`) into a 64 MB vmalloc'd ring buffer, then calls
  `schedule_work()`.
- **Consumer** (workqueue, can sleep): drains the ring buffer, formats each
  entry as text, and writes to the file with `kernel_write()`.

The ring buffer holds ~7 million entries of backlog. If it fills before the
workqueue drains it (sustained burst faster than disk I/O), entries are silently
dropped. On VM teardown the remaining buffer is flushed before the file is
closed.

### Cleanup

`kvm_cxl_vm_destroy()` is called from `kvm_arch_destroy_vm()`. It vunmaps the
region, closes the backing file, and frees the `kvm_cxl_info`.

## Source Files

| File            | Purpose                                        |
|-----------------|-------------------------------------------------|
| `cxl.h`         | `kvm_cxl_info` struct, cxl.c function prototypes |
| `cxl.c`         | MMIO handler, vmap setup, sysfs, cleanup         |
| `cxl_cache.h`   | Cache geometry, cache structs, log structs          |
| `cxl_cache.c`   | Cache init/lookup/evict/fill/access, log init/flush |

Modified upstream files:

- `arch/x86/include/asm/kvm_host.h` -- `struct kvm_cxl_info *cxl` in
  `struct kvm_arch`
- `arch/x86/kvm/x86.c` -- interception in `emulator_read_write()`, cleanup in
  `kvm_arch_destroy_vm()`
- `arch/x86/kvm/Kbuild` -- `cxl.o cxl_cache.o` added to `kvm-y`

## QEMU Side

In `hw/i386/pc.c`, after the CXL fixed-window loop sets `cxl_window_offset`
and `cxl_window_size`, QEMU writes the registration string to the sysfs file.
If the file does not exist (kernel without this feature) the write silently
fails and QEMU falls back to the existing userspace MMIO path.
