#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"

// xv6's ethernet and IP addresses
static uint8 local_mac[ETHADDR_LEN] = { 0x52, 0x54, 0x00, 0x12, XV6_MAC_LAST, 0x56};
static uint32 local_ip = MAKE_IP_ADDR(10, 0, 0, XV6_IP_D); // xv6's own IP address in host byte order

// qemu host's ethernet address.
static uint8 host_mac[ETHADDR_LEN] = { 0x86, 0x5c, 0xa8, 0x1d, 0xef, 0x13 };

uint32
sys_ip()
{
  return local_ip;
}

/**
 * @brief Kernel-internal structure for queuing received UDP datagrams awaiting application consumption
 * @author Syed Taha
 * @date 12th November 2025
 * 
 * @details
 * Represents a received UDP datagram that has been processed by the network stack and is 
 * queued for delivery to a user application. This structure serves as the fundamental 
 * unit of data transfer between the kernel's network stack and user-space processes
 * that have bound to specific UDP ports.
 * 
 * When a UDP packet arrives from the network:
 * 1. The E1000 driver receives the raw Ethernet frame into a kernel buffer
 * 2. net_rx() processes the Ethernet and IP headers, extracting protocol information
 * 3. ip_rx() validates the UDP packet and extracts critical metadata:
 *    - Source IP address (converted from network to host byte order)
 *    - Source port number (converted from network to host byte order) 
 *    - Payload length and data pointer
 * 4. A udp_packet structure is allocated and populated with this metadata
 * 5. The UDP payload is copied to a separate kernel buffer for safe persistence
 * 6. The structure is enqueued on the appropriate udp_port's receive queue
 * 
 * The structure forms a singly-linked list within each udp_port, enabling efficient
 * FIFO queuing semantics. Applications retrieve packets via the sys_recv() system call,
 * which dequeues udp_packet structures, copies their payload to user space, and then
 * frees both the structure and its associated data buffer.
 * 
 * @memory_lifecycle
 * - Allocation: kalloc() during packet reception in ip_rx()
 * - Persistence: Queued until application consumption
 * - Deallocation: kfree() after successful copyout() in sys_recv()
 * 
 * @synchronization
 * Access to udp_packet instances is protected by the spinlock in their containing
 * udp_port structure. The linked list manipulation (enqueue/dequeue) constitutes
 * a critical section that must be lock-protected.
 */
struct udp_packet {
  struct udp_packet *next; //< Forward pointer for singly-linked list maintenance.
  uint32 src_ip;           //< IPv4 source address in host byte order (32-bit big-endian).
  uint16 src_port;         //< UDP source port in host byte order (16-bit unsigned). 
  int len;                 //< Length of the UDP payload in bytes (32-bit signed integer).
  char* data;              //< Kernel virtual address pointing to the UDP payload copy.
};

/**
 * @brief Internal kernel structure managing the state and receive queue for a UDP port
 * @author Syed Taha
 * @date 12th November 2025
 * 
 * @details
 * This structure represents the kernel's per-port state for UDP communication. Each
 * instance manages the complete lifecycle of a bound UDP port, including:
 * - Port allocation tracking (inuse flag)
 * - Synchronization for concurrent access
 * - Receive queue management for incoming datagrams
 * - Process synchronization for blocking receive operations
 * 
 * The structure implements a thread-safe FIFO queue using a linked list of udp_packet
 * structures. Multiple producers (network stack via ip_rx) and single consumer
 * (application via sys_recv) access the queue concurrently, requiring proper synchronization.
 * 
 * @invariant When queue is empty: head == NULL && tail == NULL
 * @invariant When queue has one element: head == tail != NULL
 * @invariant When queue has multiple elements: head != tail, tail->next == NULL
 * 
 * @synchronization The spinlock must be held when modifying any field or traversing the queue.
 * Sleep/wakeup operations use this structure as the wait channel for blocking receives.
 * 
 * @flow_control The implementation limits queue depth to 16 packets per port to prevent
 * unbounded memory consumption and provide implicit flow control.
 */
struct udp_port {
  int inuse;               //< Port binding state (1 = actively bound, 0 = available for binding)
  struct spinlock lock;    //< Per-port spinlock for thread-safe queue operations
  struct udp_packet *head; //< Head pointer of the received packet queue (FIFO order)
  struct udp_packet *tail; //< Tail pointer of the received packet queue (for O(1) enqueue)
  uint32 bulk_peer;        //< Declared bulk-flow peer IP (0 = none); see udp_rate_ok()
};

/**
 * @brief Global array tracking all possible UDP ports in the system
 * @author Syed Taha  
 * @date 12th November 2025
 * 
 * @details
 * This static array provides O(1) access to the state of any UDP port by using the
 * port number as a direct index. The array spans the complete UDP port range
 * (0-65535) as defined by `UDP_PORTS`, enabling efficient port validation and
 * state management without searching or hashing.
 * 
 * The array is initialized during netinit() where all ports are marked as
 * available (inuse = 0) and their spinlocks are initialized.
 * 
 * @memory_footprint The array consumes approximately:
 * - ~24 bytes per udp_port struct (on 64-bit systems)
 * - 65536 ports × 24 bytes = ~1.5 MB total
 * This is acceptable for the xv6 environment given the O(1) access benefit.
 * 
 * @access_pattern Ports are accessed by:
 * - sys_bind(): Marks port as inuse during binding
 * - sys_recv(): Reads from port's queue during packet reception  
 * - ip_rx(): Writes to port's queue during packet delivery
 * - Various locations for port state validation
 * 
 * @note The 'static' keyword restricts visibility to net.c only, preventing
 * external modules from accessing the internal UDP implementation details.
 * This maintains proper encapsulation within the network subsystem.
 */
static struct udp_port udp_ports[UDP_PORTS];
static struct udp_bucket udp_rl[UDP_RL_SLOTS];
static struct spinlock udp_rl_lock;

static struct spinlock netlock;

static struct spinlock icmp_rl_lock;
static struct icmp_bucket icmp_rl[ICMP_RL_SLOTS];

static struct iface_rule iface_rules[] = {
    // iface_id   net (host byte order)     mask
    { 0,          0x0A000000,               0xFFFFFF00 },  // 10.0.0.0/24
};
#define NRULES (sizeof(iface_rules) / sizeof(iface_rules[0]))

static struct reasm_session reasm_table[MAX_REASM_SESSIONS];
static struct spinlock reasm_lock;

/**
 * @brief Compile-time static ARP binding table used by Dynamic ARP Inspection
 * @author Syed Taha
 * @date 12th June 2026
 *
 * @details
 * Each entry pairs a trusted IP address (host byte order) with its known MAC
 * address. arp_dai_ok() consults this table on every inbound ARP: if the
 * sender's claimed IP matches an entry but the accompanying MAC does not, the
 * packet is identified as a spoofing attempt and dropped before any further
 * processing occurs.
 *
 * Current entries (each node's MAC == its local_mac = 52:54:00:12:34:XV6_MAC_LAST):
 *   10.0.0.2  52:54:00:12:34:56  node1's address - prevents impersonation
 *   10.0.0.3  52:54:00:12:34:57  node2's address - trusted peer binding
 *   10.0.0.99 AA:BB:CC:DD:EE:FF  regression-test sentinel for DAI verification
 *
 * To register additional trusted nodes, append arp_entry structs here. IPs that
 * are absent from this table are accepted without MAC validation (fail-open).
 *
 * @note ARP_STATIC_ENTRIES is derived automatically from the array size so the
 * loop bounds in arp_dai_ok() stay correct without manual maintenance.
 */
// static struct arp_entry arp_static_table[] = {
//     // xv6 itself: reject any ARP claiming our IP with a different MAC
//     { MAKE_IP_ADDR(10, 0, 0, XV6_IP_D), { 0x52, 0x54, 0x00, 0x12, 0x34, XV6_MAC_LAST } },
//     { MAKE_IP_ADDR(10, 0, 0, 3),  { 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 } }, // node2, real MAC
//     { MAKE_IP_ADDR(10, 0, 0, 99), { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } }, // DAI test sentinel: 10.0.0.99 → AA:BB:CC:DD:EE:FF (used by regression tests)
// };
static struct arp_entry arp_static_table[] = {
    // Each node's anchor MAC must equal that node's local_mac, i.e.
    // { 0x52, 0x54, 0x00, 0x12, 0x34, XV6_MAC_LAST } (see local_mac above).
    // These are the sha values peers advertise in ARP requests/replies; if the
    // anchor disagreed, arp_dai_ok() would drop a legitimate peer as a spoof and
    // dynamic resolution (arp_lookup) would silently fail.
    { MAKE_IP_ADDR(10, 0, 0, 2),  { 0x52, 0x54, 0x00, 0x12, 0x56, 0x56 } }, // node1, real MAC
    { MAKE_IP_ADDR(10, 0, 0, 3),  { 0x52, 0x54, 0x00, 0x12, 0x57, 0x56 } }, // node2 == its local_mac
    { MAKE_IP_ADDR(10, 0, 0, 99), { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } }, // DAI test sentinel
};
#define ARP_STATIC_ENTRIES (sizeof(arp_static_table) / sizeof(arp_static_table[0]))

/**
 * @brief Dynamic ARP resolution cache (RFC 826)
 *
 * @details
 * Distinct from arp_static_table[] (the immutable Dynamic ARP Inspection trust
 * anchor): this table is learned at run time. arp_lookup() populates it by
 * broadcasting an ARP request on a cache miss and arp_rx() fills the answer in
 * from a validated reply, so the kernel resolves peers it was never pre-configured
 * with, per the classic RFC 826 request/reply algorithm.
 *
 * Each slot is a small state machine:
 *   ARP_FREE      unused slot (ip/mac undefined)
 *   ARP_PENDING   a request has been sent for ip; awaiting a reply
 *   ARP_RESOLVED  mac is valid; usable until it ages out (ARP_CACHE_TTL)
 *
 * Concurrency: arp_cache_lock serialises every access to arp_cache[]. A resolving
 * process sleeps under this lock (via &ticks, like sys_recvtimeo) while the
 * interrupt-driven arp_rx() flips a PENDING slot to RESOLVED; the sleeper observes
 * the change on the next clock tick. Lock order is arp_cache_lock -> tickslock.
 * The lock is initialised in netinit().
 */
enum { ARP_FREE = 0, ARP_PENDING, ARP_RESOLVED };

struct arp_cache_entry {
    uint32 ip;                 //< resolved IP in host byte order (valid when state != ARP_FREE)
    uint8  mac[ETHADDR_LEN];   //< learned MAC (valid when state == ARP_RESOLVED)
    int    state;              //< ARP_FREE / ARP_PENDING / ARP_RESOLVED
    uint   ts;                 //< tick of last state change (drives timeout + aging)
};

#define ARP_CACHE_SLOTS  16    // distinct IPs the dynamic cache can track at once
#define ARP_REQ_TIMEOUT  10    // ticks (~1s at ~10 Hz) to wait per request, RFC 1122 3.2.2.1
#define ARP_REQ_RETRIES  3     // total ARP requests before arp_lookup() gives up
#define ARP_CACHE_TTL    600   // ticks (~60s) a RESOLVED entry is trusted before re-resolving

static struct arp_cache_entry arp_cache[ARP_CACHE_SLOTS];
static struct spinlock        arp_cache_lock;

/**
 * @brief Token-bucket array and lock for ARP per-source rate limiting
 * @author Syed Taha
 * @date 12th June 2026
 *
 * @details
 * arp_rl holds ARP_RL_SLOTS arp_bucket entries, one per recently-seen Ethernet
 * source MAC. arp_rl_lock serialises all read-modify-write operations on the
 * table so that concurrent interrupt-driven packet arrivals do not corrupt
 * bucket state.
 *
 * The table is zero-initialised at boot; a zero MAC is treated as an empty
 * slot. When all slots are occupied the bucket with the most remaining tokens
 * (least recently active sender) is evicted, mirroring the eviction policy
 * used by udp_rl and icmp_rl.
 *
 * arp_rl_lock must be held for the duration of any access
 * to arp_rl[]. It is initialised in netinit().
 */
static struct arp_bucket arp_rl[ARP_RL_SLOTS];
static struct spinlock   arp_rl_lock;

/**
 * @brief Locate the dynamic-cache slot currently tracking an IP.
 *
 * @details Linear scan of arp_cache[]. The caller MUST hold arp_cache_lock.
 * Checks performed:
 *   1. Skip ARP_FREE slots (their ip field is meaningless).
 *   2. Return the first slot whose ip matches (PENDING or RESOLVED).
 *
 * @param ip  IP address in host byte order.
 * @return pointer to the matching slot, or 0 if the IP is not tracked.
 */
static struct arp_cache_entry *
arp_cache_find(uint32 ip)
{
  for(int i = 0; i < ARP_CACHE_SLOTS; i++) {
    if(arp_cache[i].state != ARP_FREE && arp_cache[i].ip == ip) {
      return &arp_cache[i];
    }
  }
  return 0;
}

/**
 * @brief Reserve (or reuse) a cache slot for an IP and mark it ARP_PENDING.
 *
 * @details The caller MUST hold arp_cache_lock. Slot selection:
 *   1. Reuse the existing slot for ip if one is already tracked.
 *   2. Else take the first ARP_FREE slot.
 *   3. Else evict the least-recently-updated slot (smallest ts) so the table
 *      never overflows (mirrors the udp_rl / icmp_rl eviction policy).
 * The chosen slot is (re)initialised to ARP_PENDING with ts = ticks.
 *
 * @param ip  IP address in host byte order to reserve.
 * @return pointer to the reserved slot (never 0).
 */
static struct arp_cache_entry *
arp_cache_alloc(uint32 ip)
{
  struct arp_cache_entry *e = arp_cache_find(ip);
  if(e == 0){
    e = &arp_cache[0];
    for(int i = 0; i < ARP_CACHE_SLOTS; i++){
      if(arp_cache[i].state == ARP_FREE){ e = &arp_cache[i]; break; }
      if(arp_cache[i].ts < e->ts) e = &arp_cache[i];
    }
  }
  e->ip    = ip;
  e->state = ARP_PENDING;
  e->ts    = ticks;
  return e;
}

/**
 * @brief Install a learned IP->MAC binding from a validated ARP reply.
 *
 * @details Called from arp_rx() (interrupt context) once a reply has cleared
 * every security check. Acquires arp_cache_lock internally. Steps:
 *   1. Find the slot for ip, or allocate one if the reply was unsolicited.
 *   2. Copy the MAC and mark the slot ARP_RESOLVED with a fresh ts.
 * A resolving arp_lookup() sleeping on &ticks observes the flip to RESOLVED on
 * the next clock tick; no explicit wakeup is required.
 *
 * @param ip   Sender IP in host byte order.
 * @param mac  Sender hardware address (ETHADDR_LEN bytes).
 */
static void
arp_cache_update(uint32 ip, uint8 *mac)
{
  acquire(&arp_cache_lock);
  struct arp_cache_entry *e = arp_cache_find(ip);
  if(e == 0)
    e = arp_cache_alloc(ip);
  memmove(e->mac, mac, ETHADDR_LEN);
  e->state = ARP_RESOLVED;
  e->ts    = ticks;
  release(&arp_cache_lock);
}

/**
 * @brief Broadcast an ARP request to resolve an IP (RFC 826).
 *
 * @details Builds and transmits a single Ethernet-broadcast ARP request. Checks
 * and fields set:
 *   1. kalloc a zeroed page (zero also leaves the target hw addr / tha unknown).
 *   2. Ethernet: dhost = ff:ff:ff:ff:ff:ff (broadcast), shost = local_mac,
 *      type = ETHTYPE_ARP (IEEE 802.3 framing).
 *   3. ARP: Ethernet/IPv4 template (hrd/pro/hln/pln), op = ARP_OP_REQUEST.
 *   4. sha/sip = our own MAC/IP so the peer can reply and learn us; tip = target.
 * Ownership of the buffer is handed to e1000_transmit(), matching arp_rx().
 *
 * @param tip  Target IP to resolve, in host byte order.
 */
static void
arp_send_request(uint32 tip)
{
  char *buf = kalloc();
  if(buf == 0){
    printf("arp_send_request: kalloc failed\n");
    return;
  }
  memset(buf, 0, PGSIZE);

  struct eth *eth = (struct eth *) buf;
  memset(eth->dhost, 0xff, ETHADDR_LEN);          // Ethernet broadcast (RFC 826)
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_ARP);

  struct arp *arp = (struct arp *)(eth + 1);
  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ETHTYPE_IP);
  arp->hln = ETHADDR_LEN;
  arp->pln = sizeof(uint32);
  arp->op  = htons(ARP_OP_REQUEST);
  memmove(arp->sha, local_mac, ETHADDR_LEN);
  arp->sip = htonl(local_ip);
  // arp->tha stays zero (unknown - that is what we are asking for)
  arp->tip = htonl(tip);

  e1000_transmit(buf, sizeof(*eth) + sizeof(*arp));
}

/**
 * @brief Resolve an IP to a MAC, performing dynamic ARP discovery on a miss (RFC 826).
 *
 * @details Replaces the former static-table-only lookup. Behaviour:
 *   1. Fast path: return immediately if the dynamic cache holds a RESOLVED, not
 *      yet aged-out (< ARP_CACHE_TTL) entry for ip.
 *   2. Miss/stale: reserve an ARP_PENDING slot for ip.
 *   3. Broadcast an ARP request and wait up to ARP_REQ_TIMEOUT ticks for a reply,
 *      retrying up to ARP_REQ_RETRIES times (RFC 1122 3.2.2.1 rate/retransmit).
 *   4. Wait uses the sys_recvtimeo idiom: sleep on &ticks under arp_cache_lock so
 *      the clock interrupt wakes us each tick to re-check; lock order is
 *      arp_cache_lock -> tickslock. The slot is re-found by ip after each wake so
 *      a concurrent eviction can never make us return another IP's MAC.
 *   5. On a reply, arp_rx() -> arp_cache_update() flips the slot to RESOLVED.
 *   6. Fail closed after all retries: release the reserved slot and return -1.
 *
 * Safe to sleep: the sole caller is sys_send() in process context.
 *
 * @param ip      Target IP in host byte order.
 * @param mac_out Buffer of at least ETHADDR_LEN bytes, filled on success.
 * @return 0 and mac_out set if resolved, -1 if resolution timed out.
 */
int
arp_lookup(uint32 ip, uint8 *mac_out)
{
  acquire(&arp_cache_lock);

  // (1) Fast path: a fresh RESOLVED entry answers without touching the wire.
  struct arp_cache_entry *e = arp_cache_find(ip);
  if(e && e->state == ARP_RESOLVED && (uint)(ticks - e->ts) < ARP_CACHE_TTL){
    memmove(mac_out, e->mac, ETHADDR_LEN);
    release(&arp_cache_lock);
    return 0;
  }

  // (2) Miss or stale: reserve a PENDING slot so we (and observers) know a
  //     resolution is in flight for this IP.
  arp_cache_alloc(ip);

  // (3) Discover: broadcast a request and wait for a reply, retrying on timeout.
  for(int attempt = 0; attempt < ARP_REQ_RETRIES; attempt++){
    release(&arp_cache_lock);
    arp_send_request(ip);                 // never hold arp_cache_lock across tx
    acquire(&arp_cache_lock);

    acquire(&tickslock);
    uint start = ticks;
    release(&tickslock);

    // (4) Sleep tick-by-tick until this IP resolves or the attempt times out.
    for(;;){
      struct arp_cache_entry *r = arp_cache_find(ip);
      if(r && r->state == ARP_RESOLVED){          // (5) a reply landed
        memmove(mac_out, r->mac, ETHADDR_LEN);
        // xv6's printf has no field-width support, so %02x would print literally.
        // printf("arp_lookup: resolved 0x%x -> %x:%x:%x:%x:%x:%x\n",
        //        ip, mac_out[0], mac_out[1], mac_out[2], mac_out[3], mac_out[4], mac_out[5]);
        release(&arp_cache_lock);
        return 0;
      }
      acquire(&tickslock);
      uint elapsed = ticks - start;
      release(&tickslock);
      if(elapsed >= ARP_REQ_TIMEOUT)
        break;                                    // resend (next attempt)
      sleep(&ticks, &arp_cache_lock);             // clock interrupt wakes us each tick
    }
  }

  // (6) No reply after every retry: release the slot and fail closed.
  struct arp_cache_entry *f = arp_cache_find(ip);
  if(f && f->state == ARP_PENDING)
    f->state = ARP_FREE;
  release(&arp_cache_lock);
  printf("arp_lookup: resolution timed out for 0x%x\n", ip);
  return -1;
}

void
netinit(void)
{
  initlock(&netlock, "netlock");
  initlock(&icmp_rl_lock, "icmp_rl");
  initlock(&udp_rl_lock, "udp_rl");
  initlock(&reasm_lock, "reasm_lock");
  initlock(&arp_rl_lock, "arp_rl");
  initlock(&arp_cache_lock, "arp_cache");

  // Initialize per-port spinlocks for all UDP ports to enable concurrent access
  // Each port gets its own lock for independent binding, reception, and queue management
  for(int i = 0; i < UDP_PORTS; i++){
    initlock(&udp_ports[i].lock, "udp_port");
  }
}

/**
 * @brief System call implementation for binding a UDP port to receive datagrams
 * @author Syed Taha
 * @date 12th November 2025
 * 
 * @details
 * Implements the bind() system call that allows a user process to claim exclusive
 * access to a specific UDP port for packet reception. This system call establishes
 * the necessary kernel infrastructure to receive and queue incoming UDP datagrams
 * addressed to the specified port.
 * 
 * The binding process:
 * 1. Validates the requested port number against the legal range (0-65535)
 * 2. Acquires the port-specific lock for atomic state modification
 * 3. Checks if the port is already bound by another process
 * 4. Initializes the port's receive queue and marks it as active
 * 5. Releases the lock and returns success
 * 
 * Once bound, the port becomes active for packet reception:
 * - Incoming UDP packets to this port are queued in the port's receive buffer
 * - Multiple processes cannot bind to the same port concurrently
 * - The binding process gains exclusive rights to receive from this port
 * 
 * @return uint64 Returns 0 on successful port binding, -1 on failure due to:
 * 
 *   - Invalid port number (out of range 0-65535)
 * 
 *   - Port already in use by another process
 * 
 * @note This implementation uses per-port locking rather than a global network lock,
 * allowing multiple ports to be bound concurrently without contention.
 * 
 * @note Port 0 binding is permitted but represents an ephemeral port assignment
 * in standard UDP semantics, though xv6 treats it as a normal port.
 */
uint64
sys_bind(void)
{
  //
  // bind(int port)
  // prepare to receive UDP packets address to the port,
  // i.e. allocate any queues &c needed.
  //

  // Extract the port number from system call argument 0
  // argint() copies the user-space integer argument into kernel-space 'port' variable
  int port;
  argint(0, &port);
  
  // Validate port number range: must be between 0 and UDP_PORTS-1 (65535)
  // Rejects invalid ports that could cause array out-of-bounds access
  if(port < 0 || port >= UDP_PORTS)
    return -1;

  // Get pointer to the udp_port structure for the requested port
  // Array indexing provides O(1) access to any port's state
  struct udp_port *up = &udp_ports[port];
  
  // Acquire the port-specific spinlock to ensure atomic state modification
  // Critical section begins: port state cannot change while lock is held
  acquire(&up->lock);
  
  // Check if port is already marked as inuse by another process
  // Port binding is exclusive - only one process can bind to a port at a time
  if(up->inuse){
    // Port is already bound, release lock and return failure
    // Caller should handle the error (e.g., choose a different port)
    release(&up->lock);
    return -1;
  }

  // Successfully claim the port for exclusive use by current process
  // Mark port as active to prevent other processes from binding to it
  up->inuse = 1;
  
  // Initialize the receive queue to empty state
  // head = 0 indicates no packets are queued, tail = 0 maintains queue integrity
  up->head = 0;
  up->tail = 0;

  // A fresh binding carries no rate-limit exemption: the new owner must declare
  // its own bulk peer, so an exemption can never be inherited from a previous one.
  up->bulk_peer = 0;

  // Release the port lock - critical section ends
  // Port is now ready to receive and queue incoming UDP packets
  release(&up->lock);
  
  // Return success to user process
  // Process can now call recv() to receive packets on this bound port
  return 0;
}

/**
 * @brief System call implementation for unbinding a UDP port and releasing resources
 * @author Syed Taha
 * @date 12th November 2025
 * 
 * @details
 * Implements the unbind() system call that releases a previously bound UDP port and
 * cleans up all associated kernel resources. This system call reverses the operations
 * performed by sys_bind(), making the port available for other processes to use.
 * 
 * The unbinding process:
 * 1. Validates the port number and checks if it is currently bound
 * 2. Marks the port as available for future binding
 * 3. Iterates through the receive queue and frees all queued packets
 * 4. Resets the queue state to empty
 * 5. Returns the port to uninitialized state
 * 
 * Resource cleanup includes:
 * - Freeing all udp_packet structures in the receive queue
 * - Freeing the data buffers associated with each queued packet
 * - Resetting queue pointers to prevent dangling references
 * 
 * After unbind completes:
 * - Incoming UDP packets to this port are silently dropped by ip_rx()
 * - The port becomes available for binding by any process
 * - Any sleeping processes waiting on this port remain blocked indefinitely
 * 
 * @return uint64 Returns 0 on successful unbinding, -1 on failure due to:
 *   - Invalid port number (out of range 0-65535)
 *   - Port not currently bound (already available)
 * 
 * @note Processes should ensure they have received all desired packets before
 * calling unbind(), as queued packets are irrevocably discarded.
 * 
 * @warning This function does not wake up processes sleeping in sys_recv() on
 * this port. Those processes will remain blocked until another packet arrives
 * or the process is terminated.
 * 
 * @memory_management Ensures no memory leaks by properly freeing both the
 * udp_packet structures and their associated data buffers.
 */

uint64
sys_unbind(void)
{
  //
  // unbind(int port)
  // release any resources previously created by bind(port);
  // from now on UDP packets addressed to port should be dropped.
  //

  // Extract port number from system call argument 0
  // Validates user-provided port parameter before proceeding
  int port;
  argint(0, &port);
  
  // Validate port number is within legal range (0-65535)
  // Prevents array out-of-bounds access to udp_ports[]
  if(port < 0 || port >= UDP_PORTS) return -1;
  
  // Get pointer to the udp_port structure for the specified port
  struct udp_port *up = &udp_ports[port];
  
  // Acquire port-specific lock to ensure atomic state modification
  // Critical section: port state and queue cannot change while lock held
  acquire(&up->lock);
  
  // Verify that the port is actually currently bound
  // Cannot unbind a port that isn't in use
  if(!up->inuse){
    release(&up->lock);
    return -1;
  }
  
  // Mark port as available for binding by other processes
  // From this point, ip_rx() will drop packets for this port
  up->inuse = 0;

  // Drop any bulk-flow declaration with the binding that made it, so the next
  // process to bind this port starts fully metered.
  up->bulk_peer = 0;

  // Iterate through the receive queue and free all queued packets
  // This prevents memory leaks when a port is unbound with pending packets
  struct udp_packet *pkt = up->head;
  while(pkt){
    // Save next pointer before freeing current packet
    // This maintains linked list traversal capability during cleanup
    struct udp_packet *next = pkt->next;
    
    // Free the packet's data buffer first
    // This was allocated with kalloc() during packet reception in ip_rx()
    kfree(pkt->data);
    
    // Free the udp_packet structure itself
    // This was allocated with kalloc() during packet queuing
    kfree(pkt);
    
    // Move to next packet in the queue
    pkt = next;
  }
  
  // Reset queue pointers to indicate empty state
  // Prevents dangling pointers and prepares port for future binding
  up->head = 0;
  up->tail = 0;
  
  // Release the port lock - critical section ends
  // Port is now completely cleaned and available for reuse
  release(&up->lock);
  
  // Return success to user process
  // Port unbinding and resource cleanup completed successfully
  return 0;
}

/**
 * @brief System call implementation for receiving UDP datagrams from a bound port
 * @author Syed Taha
 * @date 12th November 2025
 * 
 * @details
 * Implements the recv() system call that retrieves UDP datagrams from a previously
 * bound port. This function provides blocking semantics: if no packets are available,
 * the calling process sleeps until a packet arrives or an error occurs.
 * 
 * The reception process:
 * 1. Validates all parameters and port binding state
 * 2. Blocks the process if no packets are available (sleep/wakeup mechanism)
 * 3. Dequeues the oldest packet from the port's receive queue (FIFO semantics)
 * 4. Safely copies payload and metadata to user-space buffers
 * 5. Cleans up kernel resources for the delivered packet
 * 
 * Data transfer to user space occurs in three phases:
 * - UDP payload copied to user-provided buffer (respecting maxlen)
 * - Source IP address written to user-specified location
 * - Source port number written to user-specified location
 * 
 * @param dport Destination port number (host byte order) to receive from
 * @param src User-space pointer to store source IP address (host byte order)
 * @param sport User-space pointer to store source port number (host byte order)
 * @param buf User-space buffer to receive UDP payload data
 * @param maxlen Maximum number of bytes to copy to user buffer
 * 
 * @return uint64 Number of payload bytes copied on success, -1 on error due to:
 *   - Invalid port number or unbound port
 *   - Invalid user pointers (null or inaccessible)
 *   - Negative maxlen value
 *   - copyout() failure during data transfer
 * 
 * @note The function implements truncation semantics: if packet payload exceeds
 * maxlen, only the first maxlen bytes are copied and the rest are discarded.
 * 
 * @blocking_semantics Uses xv6's sleep/wakeup mechanism to efficiently wait for
 * packets without busy-waiting. Process sleeps on the udp_port structure and
 * is awakened by ip_rx() when new packets arrive.
 * 
 * @memory_safety All user pointers are validated through copyout(), which checks
 * page table permissions and ensures safe kernel-to-user data transfer.
 */
uint64
sys_recv(void)
{
  //
  // recv(int dport, int *src, short *sport, char *buf, int maxlen)
  // if there's a received UDP packet already queued that was
  // addressed to dport, then return it.
  // otherwise wait for such a packet.
  //
  // sets *src to the IP source address.
  // sets *sport to the UDP source port.
  // copies up to maxlen bytes of UDP payload to buf.
  // returns the number of bytes copied,
  // and -1 if there was an error.
  //
  // dport, *src, and *sport are host byte order.
  // bind(dport) must previously have been called.
  //

  // Get current process structure for page table access during copyout
  struct proc *p = myproc();
  
  // Declare variables for system call arguments
  int dport, maxlen;
  uint64 srcaddr, sportaddr, bufaddr;

  // Extract all five system call arguments from user space:
  // - dport: destination port to receive from
  // - srcaddr: user pointer for source IP return
  // - sportaddr: user pointer for source port return  
  // - bufaddr: user buffer for payload data
  // - maxlen: maximum bytes to copy to user buffer
  argint(0, &dport);
  argaddr(1, &srcaddr);
  argaddr(2, &sportaddr);
  argaddr(3, &bufaddr);
  argint(4, &maxlen);

  // Validate all input parameters before proceeding:
  // - Port must be within legal range
  // - User pointers must be non-null
  // - maxlen must be non-negative
  if(dport < 0 || dport >= UDP_PORTS) return -1;
  if(srcaddr == 0 || sportaddr == 0 || bufaddr == 0) return -1;
  if(maxlen < 0) return -1;

  // Access the udp_port structure for the specified destination port
  struct udp_port *up = &udp_ports[dport];
  
  // Acquire port lock to safely inspect and modify the receive queue
  acquire(&up->lock);
  
  // Verify that the port is actually bound by current process
  // recv() can only be called on ports previously bound with sys_bind()
  if(!up->inuse){
    release(&up->lock);
    return -1;
  }

  // BLOCKING WAIT: If no packets are available, sleep until one arrives
  // The process yields the CPU while waiting, avoiding busy-waiting
  // sleep() releases the lock and reacquires it upon wakeup
  while(up->head == 0){
    sleep(up, &up->lock);
  }

  // PACKET DEQUEUE: Remove the oldest packet from the receive queue (FIFO)
  // up->head points to the first packet in the queue (oldest arrival)
  struct udp_packet *pkt = up->head;
  up->head = pkt->next;
  
  // If queue becomes empty after dequeue, update tail pointer to maintain invariant
  if(up->head == 0)
    up->tail = 0;
  
  // Release port lock - queue manipulation complete
  // Critical section ends, other packets can now be enqueued/dequeued
  release(&up->lock);

  // PAYLOAD TRANSFER: Copy UDP payload to user-space buffer
  // Calculate actual bytes to copy (min of packet length and user buffer size)
  int tocopy = pkt->len;
  if(tocopy > maxlen) tocopy = maxlen;
  
  // Only attempt copy if there's data to transfer (tocopy > 0)
  if(tocopy > 0){
    // copyout() safely transfers data from kernel to user space, validating addresses
    // Returns -1 if user buffer is inaccessible or page fault occurs
    if(copyout(p->pagetable, bufaddr, pkt->data, tocopy) < 0){
      // Cleanup on copy failure: free both packet structure and data buffer
      kfree(pkt->data);
      kfree(pkt);
      return -1;
    }
  }

  // SOURCE IP TRANSFER: Copy source IP address to user-space location
  // Extract source IP from packet metadata (already in host byte order)
  uint32 src = pkt->src_ip;
  if(copyout(p->pagetable, srcaddr, (char *)&src, sizeof(src)) < 0){
    kfree(pkt->data);
    kfree(pkt);
    return -1;
  }

  // SOURCE PORT TRANSFER: Copy source port number to user-space location  
  // Extract source port from packet metadata (already in host byte order)
  uint16 sport = pkt->src_port;
  if(copyout(p->pagetable, sportaddr, (char *)&sport, sizeof(sport)) < 0){
    kfree(pkt->data);
    kfree(pkt);
    return -1;
  }

  // RESOURCE CLEANUP: Free kernel resources for the delivered packet
  // Both the data buffer and packet structure were allocated with kalloc()
  kfree(pkt->data);
  kfree(pkt);

  // Return actual number of payload bytes copied to user space
  // This may be less than original packet length due to maxlen truncation
  return tocopy;
}

uint64
sys_recvtimeo(void)
{
  struct proc *p = myproc();
  int dport, maxlen, timeout_ticks;
  uint64 srcaddr, sportaddr, bufaddr;

  argint(0, &dport);
  argaddr(1, &srcaddr);
  argaddr(2, &sportaddr);
  argaddr(3, &bufaddr);
  argint(4, &maxlen);
  argint(5, &timeout_ticks);

  if(dport < 0 || dport >= UDP_PORTS) return -1;
  if(srcaddr == 0 || sportaddr == 0 || bufaddr == 0) return -1;
  if(maxlen < 0) return -1;

  struct udp_port *up = &udp_ports[dport];
  acquire(&up->lock);
  if(!up->inuse){
    release(&up->lock);
    return -1;
  }

  acquire(&tickslock);
  uint start = ticks;
  release(&tickslock);

  while(up->head == 0){
    sleep(&ticks, &up->lock);   // woken every tick by the clock interrupt

    acquire(&tickslock);
    uint elapsed = ticks - start;
    release(&tickslock);

    if(elapsed >= (uint)timeout_ticks){
      release(&up->lock);
      return -2;  // timeout sentinel, distinct from -1 (real error)
    }
  }

  // PACKET DEQUEUE: Remove the oldest packet from the receive queue (FIFO)
  // up->head points to the first packet in the queue (oldest arrival)
  struct udp_packet *pkt = up->head;
  up->head = pkt->next;
  
  // If queue becomes empty after dequeue, update tail pointer to maintain invariant
  if(up->head == 0)
    up->tail = 0;
  
  // Release port lock - queue manipulation complete
  // Critical section ends, other packets can now be enqueued/dequeued
  release(&up->lock);

  // PAYLOAD TRANSFER: Copy UDP payload to user-space buffer
  // Calculate actual bytes to copy (min of packet length and user buffer size)
  int tocopy = pkt->len;
  if(tocopy > maxlen) tocopy = maxlen;
  
  // Only attempt copy if there's data to transfer (tocopy > 0)
  if(tocopy > 0){
    // copyout() safely transfers data from kernel to user space, validating addresses
    // Returns -1 if user buffer is inaccessible or page fault occurs
    if(copyout(p->pagetable, bufaddr, pkt->data, tocopy) < 0){
      // Cleanup on copy failure: free both packet structure and data buffer
      kfree(pkt->data);
      kfree(pkt);
      return -1;
    }
  }

  // SOURCE IP TRANSFER: Copy source IP address to user-space location
  // Extract source IP from packet metadata (already in host byte order)
  uint32 src = pkt->src_ip;
  if(copyout(p->pagetable, srcaddr, (char *)&src, sizeof(src)) < 0){
    kfree(pkt->data);
    kfree(pkt);
    return -1;
  }

  // SOURCE PORT TRANSFER: Copy source port number to user-space location  
  // Extract source port from packet metadata (already in host byte order)
  uint16 sport = pkt->src_port;
  if(copyout(p->pagetable, sportaddr, (char *)&sport, sizeof(sport)) < 0){
    kfree(pkt->data);
    kfree(pkt);
    return -1;
  }

  // RESOURCE CLEANUP: Free kernel resources for the delivered packet
  // Both the data buffer and packet structure were allocated with kalloc()
  kfree(pkt->data);
  kfree(pkt);

  // Return actual number of payload bytes copied to user space
  // This may be less than original packet length due to maxlen truncation
  return tocopy;
}



// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len)
{
  int nleft = len;
  const unsigned short *w = (const unsigned short *)addr;
  unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1) {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
}

// Ingress Filtering (BCP38)
// RFC 2827 (BCP 38) + RFC 3704 (update for multihomed networks)
  // RFC 2827 is titled "Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing." 
  // RFC 3704 updates the methods and tactics since BCP38 was written, and recommends ingress filtering not just at the ISP edge 
  // but also at routers connecting LANs to enterprise networks.
// drop packets whose source address shouldn't arrive on a given interface
// when a packet arrives on an interface, check if the source IP is valid for that interface (e.g., not from the outside on an inside interface)
int
ingress_filter(uint32 iface_id, uint32 src_ip)
{
  if (src_ip == local_ip)
    return FILTER_DROP;
  // Walk the rule table looking for a rule for this interface.
  for (int i = 0; i < NRULES; i++) {
      if (iface_rules[i].iface_id != iface_id)
          continue;

      // Check: src_ip must be within the allowed prefix.
      // (src_ip & mask) == net  →  packet is legitimate.
      if ((src_ip & iface_rules[i].mask) == iface_rules[i].net)
          return FILTER_ACCEPT;

      // Source is outside the expected range for this interface — drop.
      // This is the BCP38 drop condition: a packet has arrived on an
      // interface from a source address that could not legitimately
      // originate there (spoofed or misrouted).
      return FILTER_DROP;
    }

    // No rule found for this interface.
    // Fail-open (ACCEPT) keeps the kernel functional during development;
    // change to FILTER_DROP for a strict deployment.
    return FILTER_ACCEPT;
}

// Reassembly
static struct reasm_session *
reasm_find(uint32 src, uint32 dst, uint16 id, uint8 proto)
{
  struct reasm_session *s;
  // First pass: find existing session matching the 4-tuple
  for (int i = 0; i < MAX_REASM_SESSIONS; i++) {
      s = &reasm_table[i];
      if (s->inuse &&
          s->src_ip == src && s->dst_ip == dst &&
          s->ip_id  == id  && s->proto  == proto)
          return s;
  }
  return 0;
}

static void
reasm_free(struct reasm_session *s)
{
    // Free all fragment data buffers
    struct fragment *f = s->frags;
    struct fragment *next;
    while (f) {
        next = f->next;
        kfree(f->data);
        kfree(f);
        f = next;
    }
    memset(s, 0, sizeof(*s));  // clears inuse = 0
}

static struct reasm_session *
reasm_alloc(uint32 src, uint32 dst, uint16 id, uint8 proto)
{
    // Evict timed-out sessions first (RFC 1122: hosts MUST free state after timeout)
    uint now = ticks;
    for (int i = 0; i < MAX_REASM_SESSIONS; i++) {
        struct reasm_session *s = &reasm_table[i];
        if (s->inuse && (int)(now - s->expires) >= 0)
            reasm_free(s);  // defined below
    }

    // Find an unused slot
    // IMPORTANT: do NOT evict an active session to make room.
    // An attacker can deliberately trigger eviction to flush legitimate
    // reassembly state (session-slot exhaustion attack).
    // If all slots are full, drop the new fragment instead.
    for (int i = 0; i < MAX_REASM_SESSIONS; i++) {
        struct reasm_session *s = &reasm_table[i];
        if (!s->inuse) {
            s->inuse    = 1;
            s->src_ip   = src;
            s->dst_ip   = dst;
            s->ip_id    = id;
            s->proto    = proto;
            s->expires  = now + REASM_TIMEOUT_TICKS;
            s->total_len = -1;  // unknown until last fragment arrives
            s->frag_count = 0;
            s->frags    = 0;
            return s;
        }
    }
    return 0;  // table full, caller drops the fragment
}

// Insert a fragment into the session's sorted list.
// Returns 0 on success, -1 if the fragment should be dropped.
static int
reasm_insert(struct reasm_session *s, uint16 frag_offset, uint16 frag_len, char *data)
{
    // Per-session fragment cap (DoS guard)
    if (s->frag_count >= REASM_MAX_FRAGS)
        return -1;

    // Sanity: fragment must fit within IPv4 max datagram
    if ((uint32)frag_offset + frag_len > REASM_MAX_DGRAM)
        return -1;

    // Allocate fragment descriptor
    struct fragment *f = kalloc();
    if (!f) return -1;

    f->data = kalloc();
    if (!f->data) { kfree(f); return -1; }

    f->offset = frag_offset;
    f->len    = frag_len;
    f->next   = 0;
    memmove(f->data, data, frag_len);

    // Insert into sorted list (sorted by offset ascending)
    // Simultaneously check for overlaps per RFC 5722:
    // if any existing fragment overlaps this one, drop the new fragment.
    struct fragment **pp = &s->frags;
    while (*pp && (*pp)->offset < frag_offset) {
        struct fragment *prev = *pp;
        // Check: does prev fragment's range extend into ours?
        if ((uint32)prev->offset + prev->len > frag_offset) {
            // Overlap with preceding fragment — drop
            kfree(f->data);
            kfree(f);
            return -1;
        }
        pp = &(*pp)->next;
    }
    // Check: does our range extend into the next fragment?
    if (*pp && (uint32)frag_offset + frag_len > (*pp)->offset) {
        // Overlap with following fragment — drop
        kfree(f->data);
        kfree(f);
        return -1;
    }

    // Safe to insert
    f->next = *pp;
    *pp = f;
    s->frag_count++;
    return 0;
}

// Check if the session is complete (all fragments received with no gaps).
// If complete, allocate a contiguous buffer and write the reassembled payload into it.
// Returns the buffer + length on success, NULL on incomplete or error.
static struct ip *
reasm_try_complete(struct reasm_session *s, int *out_len)
{
    if (s->total_len < 0)
        return 0;  // haven't seen the last fragment yet (MF=0 fragment not received)

    // Walk the sorted fragment list verifying coverage of [0, total_len)
    int expected = 0;
    for (struct fragment *f = s->frags; f; f = f->next) {
        if (f->offset != expected)
            return 0;  // gap — not yet complete
        expected += f->len;
    }
    if (expected != s->total_len)
        return 0;  // coverage doesn't reach the end

    // Complete. Allocate reassembly buffer.
    // Note: total_lent can be up to 65535. kalloc() gives 4096.
    // For a real implementation you'd need a multi-page allocator.
    // For xv6's lab purposes, cap reassembly at PGSIZE and drop larger datagrams.
    if (s->total_len > PGSIZE) {
        return 0;
    }

    char *out = kalloc();
    if (!out) return 0;

    *out_len = s->total_len;
    // Build a fresh IP header at the front
    struct ip *iph = (struct ip *)out;
    iph->ip_vhl  = (4 << 4) | 5;          // IPv4, no options
    iph->ip_tos  = 0;
    iph->ip_len  = htons(20 + s->total_len);
    iph->ip_id   = 0;
    iph->ip_off  = 0;                      // no flags, no offset — fully reassembled
    iph->ip_ttl  = 64;
    iph->ip_p    = s->proto;              
    iph->ip_src  = s->src_ip;
    iph->ip_dst  = s->dst_ip;
    iph->ip_sum  = 0;
    // iph->ip_sum  = in_cksum(iph, 20);

    // Copy reassembled payload after the header
    int pos = 20;
    for (struct fragment *f = s->frags; f; f = f->next) {
        memmove(out + pos, f->data, f->len);
        pos += f->len;
    }

    *out_len = 20 + s->total_len;
    return (struct ip *)out;
}

uint16
reasm_check_id_collision(struct ip *ip)
{
    acquire(&reasm_lock);
    struct reasm_session *s = reasm_find(ip->ip_src, ip->ip_dst,
                                          ntohs(ip->ip_id), ip->ip_p);
    if (s) {
        reasm_free(s);  // poison any pending session with this ID
        release(&reasm_lock);
        return 1;  // collision detected
    }
    release(&reasm_lock);
    return 0;
}

struct ip *
ip_fragment_rx(struct ip *ip, int ip_total, int *frag_buf)
{
    uint16 ip_off     = ntohs(ip->ip_off);
    uint16 offset     = (ip_off & IP_OFFMASK) * 8;
    int    mf         = (ip_off & IP_MF) != 0;
    int    ip_hdr_len = (ip->ip_vhl & 0xf) * 4;

    char   *frag_data = (char *)ip + ip_hdr_len;
    uint16  frag_len  = ip_total - ip_hdr_len;

    acquire(&reasm_lock);

    struct reasm_session *s = reasm_find(ip->ip_src, ip->ip_dst,
                                          ntohs(ip->ip_id), ip->ip_p);
    if (s == 0) {
        s = reasm_alloc(ip->ip_src, ip->ip_dst,
                        ntohs(ip->ip_id), ip->ip_p);
        if (s == 0) {
            release(&reasm_lock);
            return 0;
        }
    }

    if (!mf)
        s->total_len = offset + frag_len;

    if (reasm_insert(s, offset, frag_len, frag_data) < 0) {
        reasm_free(s);
        release(&reasm_lock);
        return 0;
    }

    int   reassembled_len = 0;
    ip = reasm_try_complete(s, &reassembled_len);
    if (ip == 0) {
        release(&reasm_lock);
        return 0;
    }

    reasm_free(s);

    release(&reasm_lock);

    *frag_buf = 1;
    return ip;
}


/**
 * @brief Declare (or clear) a bulk UDP flow on a bound port.
 *
 * @details
 * udp_bulk(int port, int peer_ip)
 *
 * Datagrams arriving on @p port from @p peer_ip bypass the per-source token
 * bucket; everything else, including traffic to the same port from any other
 * address, stays metered. See udp_bulk_exempt() for why this exists and why the
 * exemption is scoped this narrowly.
 *
 * This is admission *policy*, so it is privileged: a process that has dropped
 * CAP_NET_ADMIN (or dropped root, which clears the capability set) can no longer
 * widen the node's exposure. Since processes start as root holding CAP_ALL,
 * unmodified programs are unaffected.
 *
 * Checks performed:
 *   1. Port number is inside the legal range (bounds the udp_ports[] index).
 *   2. Caller holds CAP_NET_ADMIN, else [EPERM]-style failure.
 *   3. The port is currently bound; declaring a flow on a closed port fails
 *      rather than arming an exemption for whoever binds it next.
 *   4. A zero @p peer_ip clears the declaration (back to fully metered).
 *
 * @return 0 on success, -1 on any failed check.
 */
uint64
sys_udp_bulk(void)
{
  int port;
  int peer_ip;

  argint(0, &port);
  argint(1, &peer_ip);

  if(port < 0 || port >= UDP_PORTS)
    return -1;

  if(!capable(CAP_NET_ADMIN))
    return -1;

  struct udp_port *up = &udp_ports[port];

  acquire(&up->lock);
  if(!up->inuse){
    release(&up->lock);
    return -1;
  }
  up->bulk_peer = (uint32)peer_ip;
  release(&up->lock);

  return 0;
}

//
// send(int sport, int dst, int dport, char *buf, int len)
//
uint64
sys_send(void)
{
  struct proc *p = myproc();
  int sport;
  int dst;
  int dport;
  uint64 bufaddr;
  int len;

  argint(0, &sport);
  argint(1, &dst);
  argint(2, &dport);
  argaddr(3, &bufaddr);
  argint(4, &len);

  int total = len + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp);
  if(total > PGSIZE)
    return -1;

  char *buf = kalloc();
  if(buf == 0){
    printf("sys_send: kalloc failed\n");
    return -1;
  }
  memset(buf, 0, PGSIZE);

  struct eth *eth = (struct eth *) buf;
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  uint8 dst_mac[ETHADDR_LEN];
  // arp_lookup() now resolves dynamically (RFC 826): it returns a cached MAC, or
  // broadcasts an ARP request and blocks until a reply arrives, or fails after
  // ARP_REQ_RETRIES timeouts for a host that never answers.
  if(arp_lookup(dst, dst_mac) < 0){
    kfree(buf);
    printf("sys_send: ARP resolution failed for dst ip 0x%x\n", dst);
    return -1;
  }
  memmove(eth->dhost, dst_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);

  struct ip *ip = (struct ip *)(eth + 1);
  ip->ip_vhl = 0x45; // version 4, header length 4*5
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udp) + len);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 100;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src = htonl(local_ip);
  ip->ip_dst = htonl(dst);
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));

  struct udp *udp = (struct udp *)(ip + 1);
  udp->sport = htons(sport);
  udp->dport = htons(dport);
  udp->ulen = htons(len + sizeof(struct udp));

  char *payload = (char *)(udp + 1);
  if(copyin(p->pagetable, payload, bufaddr, len) < 0){
    kfree(buf);
    printf("send: copyin failed\n");
    return -1;
  }

  // Fits the link MTU: send as one frame (the common case, e.g. every 15M
  // activation hop). On success the e1000 owns buf and frees it on descriptor reuse.
  if(sizeof(struct ip) + sizeof(struct udp) + len <= IP_SEND_MTU){
    int r = e1000_transmit(buf, total);
    if(r < 0){
      kfree(buf);
      return -1;
    }
    return 0;
  }

  /*
   * Outbound IP fragmentation (RFC 791 §2.3). The receive path already
   * reassembles (ip_rx + the hardened REASM_* logic), but the send path never
   * fragmented -- nothing sent over-MTU until the DistInf activation hop, whose
   * dim*4 + header exceeds 1500 for the 110M model (dim=768 -> 3096 bytes). The
   * e1000 RX buffers are one page each with no long-packet mode, so an over-MTU
   * frame is dropped at the receiver; it must go out as MTU-sized fragments.
   *
   * Checks performed:
   *   1. Each fragment's IP payload is <= (MTU - IP header) and, except the
   *      last, a multiple of 8 (the fragment-offset unit).
   *   2. Every fragment shares one ip_id; non-last fragments set IP_MF.
   *   3. A kalloc failure or a full TX ring aborts the datagram; already-sent
   *      fragments are harmless -- the receiver's reassembly timer drops them.
   */
  char *ipload = (char *)(ip + 1);              /* udp header, then the data */
  int   iplen  = sizeof(struct udp) + len;      /* bytes of IP payload to split */
  int   maxdata = (IP_SEND_MTU - (int)sizeof(struct ip)) & ~7;  /* 8-byte aligned */
  static uint16 frag_id = 1;
  uint16 id = frag_id++;
  int off = 0;
  int rc = 0;

  while(off < iplen){
    int fl = iplen - off;
    if(fl > maxdata) fl = maxdata;
    int more = (off + fl < iplen);

    char *fbuf = kalloc();
    if(fbuf == 0){ rc = -1; break; }
    memset(fbuf, 0, PGSIZE);

    struct eth *feth = (struct eth *)fbuf;
    memmove(feth, eth, sizeof(struct eth));     /* same L2 addressing */
    struct ip *fip = (struct ip *)(feth + 1);
    memmove(fip, ip, sizeof(struct ip));        /* base IP header, then patch */
    fip->ip_id  = htons(id);
    fip->ip_len = htons(sizeof(struct ip) + fl);
    fip->ip_off = htons((more ? IP_MF : 0) | (uint16)((off >> 3) & IP_OFFMASK));
    fip->ip_sum = 0;
    fip->ip_sum = in_cksum((unsigned char *)fip, sizeof(*fip));
    memmove((char *)(fip + 1), ipload + off, fl);

    if(e1000_transmit(fbuf, sizeof(struct eth) + sizeof(struct ip) + fl) < 0){
      kfree(fbuf);                              /* e1000 did not take it */
      rc = -1;
      break;
    }
    off += fl;                                  /* e1000 owns fbuf on success */
  }

  kfree(buf);                                   /* staging copy; no longer needed */
  return rc;
}

// Token-bucket admission check for an outgoing ICMP message we are about to send to src_ip
// (host byte order). Returns 1 and spends a token when within budget, else 0 (caller
// must then NOT send). See the ICMP_RL_* note above for the standards basis and caveats.
// Prevents our own box from being used as an amplifier
//
// STEPS:
//   1. find this peer's bucket, or claim a slot (prefer unused, else evict the idlest)
//   2. refill 1 token per elapsed tick, capped at ICMP_RL_BURST
//   3. if a token is available, spend it and allow (return 1); otherwise deny (return 0)
static int
icmp_rate_ok(uint32 src_ip)
{
  int ok = 0;

  acquire(&icmp_rl_lock);

  // Locate this peer's bucket, or claim a slot: prefer an unused one, otherwise evict
  // the idlest bucket (the one holding the most tokens, i.e. least recently spent).
  struct icmp_bucket *b = 0;
  for(int i = 0; i < ICMP_RL_SLOTS; i++){
    if(icmp_rl[i].ip != 0 && icmp_rl[i].ip == src_ip){ b = &icmp_rl[i]; break; }
  }
  if(b == 0){
    b = &icmp_rl[0];
    for(int i = 1; i < ICMP_RL_SLOTS; i++){
      if(icmp_rl[i].ip == 0){ b = &icmp_rl[i]; break; }
      if(icmp_rl[i].tokens > b->tokens) b = &icmp_rl[i];
    }
    b->ip = src_ip;
    b->tokens = ICMP_RL_BURST;
    b->last = ticks;
  }

  // Refill one token per elapsed tick (xv6 ticks ~10 Hz), capped at the burst depth.
  // A tight flood arrives within a single tick, so no refill happens mid-burst and the
  // bucket drains after ICMP_RL_BURST messages.
  uint now = ticks;
  uint elapsed = now - b->last;
  if(elapsed > 0){
    int add = elapsed > (uint)ICMP_RL_BURST ? (uint)ICMP_RL_BURST : (int)elapsed;
    b->tokens += add;
    if(b->tokens > (uint)ICMP_RL_BURST) b->tokens = (uint)ICMP_RL_BURST;
    b->last = now;
  }

  if(b->tokens > 0){
    b->tokens--;
    ok = 1;
  }

  release(&icmp_rl_lock);
  return ok;
}

/**
 * @brief Is this datagram part of a declared bulk flow, and so exempt from metering?
 *
 * @details
 * The per-source token bucket below (UDP_RL_BURST tokens, one refilled per tick)
 * caps any single peer at roughly ten datagrams per second. That is the right
 * default for unsolicited traffic, but it also throttles the traffic this node
 * asks for: fetching a model shard or streaming inference activations from a
 * known peer runs three orders of magnitude below the needed rate.
 *
 * No standard requires a host to meter legitimate UDP *data* delivery. RFC 1812
 * §4.3.2.8, which the ICMP limiter follows, governs the rate at which a router
 * generates ICMP *errors*; it says nothing about discarding datagrams a local
 * application is waiting for. Rate limiting here is therefore local DoS policy,
 * and policy belongs per-flow rather than fixed for the whole stack.
 *
 * The exemption is deliberately narrow, so the node's posture is unchanged for
 * everything it did not ask for:
 *
 * Checks performed:
 *   1. The destination port must be bound (a closed port is never exempt).
 *   2. A bulk peer must have been declared for it by sys_udp_bulk().
 *   3. The datagram's source IP must equal that declared peer, so a flood aimed
 *      at the same port from any other address is still metered. The declaration
 *      is cleared on unbind, so a later binder cannot inherit it.
 *
 * @param dport  Destination UDP port, host byte order.
 * @param src_ip Source IPv4 address, host byte order.
 * @return 1 if the datagram bypasses the token bucket, 0 if it must be metered.
 */
static int
udp_bulk_exempt(int dport, uint32 src_ip)
{
  struct udp_port *up = &udp_ports[dport];
  int exempt;

  acquire(&up->lock);
  exempt = up->inuse && up->bulk_peer != 0 && up->bulk_peer == src_ip;
  release(&up->lock);

  return exempt;
}

// Token-bucket admission check for an incoming UDP packet from src_ip:src_port.
// Prevents UDP floods by dropping packets when the sender is over a configured rate limit.
// No RFC specifies a UDP rate limit, but this follows Linux behavior
static int
udp_rate_ok(uint32 src_ip, uint16 src_port)
{
  int ok = 0;

  acquire(&udp_rl_lock);

  // find this ip's slot or claim one: prefer an unused slot, else evict the idlest (most tokens)
  struct udp_bucket *b = 0;
  for (int i = 0; i < UDP_RL_SLOTS; i++){
    if(udp_rl[i].ip == src_ip && udp_rl[i].port == src_port){
      b = &udp_rl[i];
      break;
    }
  }
  // If no existing bucket, find an unused one or evict the idlest (most tokens)
  if(b == 0){
    b = &udp_rl[0];
    for(int i = 0; i < UDP_RL_SLOTS; i++){
      if(udp_rl[i].ip == 0 && udp_rl[i].port == 0){ b = &udp_rl[i]; break; }
      if(udp_rl[i].tokens > b->tokens) b = &udp_rl[i];
    }
    b->ip = src_ip;
    b->port = src_port;
    b->tokens = UDP_RL_BURST;
    b->last = ticks;
  }
  // Refill one token per elapsed tick (xv6 ticks ~10 Hz), capped at the burst depth.
  uint now = ticks;
  uint elapsed = now - b->last;
  if(elapsed > 0){
    int add = elapsed > (uint)UDP_RL_BURST ? (uint)UDP_RL_BURST : (int)elapsed;
    b->tokens += add;
    if(b->tokens > (uint)UDP_RL_BURST) b->tokens = (uint)UDP_RL_BURST;
    b->last = now;
  }

  if(b->tokens > 0){
    b->tokens--;
    ok = 1;
  }

  release(&udp_rl_lock);
  return ok;

}

// This function is called by ip_rx() when it receives a UDP packet that is
// addressed to a port that is not bound. It sends an ICMP "port unreachable"
// message back to the sender.

static void
icmp_port_unreachable(char *buf, int len)
{
  if(len < (int)(sizeof(struct eth) + sizeof(struct ip) + 8))
    return;

  struct eth *ineth = (struct eth *)buf;
  struct ip *inip = (struct ip *)(ineth + 1);

  // Rate-limit the ICMP errors we generate (RFC 1812 4.3.2.8; see the ICMP_RL_* note).
  // Under a UDP flood this throttles the storm of port-unreachable replies.
  if(!icmp_rate_ok(ntohl(inip->ip_src)))
    return;

  char *out = kalloc();
  if(!out) return;
  memset(out, 0, PGSIZE);

  struct eth *eth = (struct eth *)out;
  memmove(eth->dhost, ineth->shost, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);

  struct ip *ip = (struct ip *)(eth + 1);
  ip->ip_vhl = 0x45;
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(struct ip) + sizeof(struct icmp) + sizeof(struct ip) + 8);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 64;
  ip->ip_p = IPPROTO_ICMP;
  ip->ip_src = htonl(local_ip);
  ip->ip_dst = inip->ip_src;
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));

  struct icmp *icmp = (struct icmp *)(ip + 1);
  icmp->type = ICMP_DEST_UNREACH;
  icmp->code = ICMP_PORT_UNREACH;
  icmp->id = 0;
  icmp->seq = 0;

  char *payload = (char *)(icmp + 1);
  memmove(payload, inip, sizeof(struct ip) + 8);

  icmp->checksum = in_cksum((unsigned char *)icmp,
                    sizeof(struct icmp) + sizeof(struct ip) + 8);

  e1000_transmit(out, sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) + sizeof(struct ip) + 8);
}

// Hardened inbound ICMP handler: replies to a ping (Echo Request) only after passing
// four defenses, and silently drops everything else. buf is the whole Ethernet frame.
//
// CHECK CHAIN (run in this order; any failed check -> silent drop, caller frees buf):
//    1. IP version == 4                         (RFC 1122 3.2.1.1)
//    2. IHL >= 5 (>= 20-byte header)            (RFC 791; honors IP options)
//    3. frame physically holds eth+IP+ICMP hdr  (over-read guard; net_rx only ensured eth+ip)
//    4. IP total length <= delivered octets     (RFC 791)
//    5. ICMP length: 8 <= icmp_len <= ICMP_MAX_LEN  (size / ping-of-death guard, RFC 791 + cap)
//    6. ICMP checksum over the whole message == 0   (RFC 792)
//    7. type filtering: Echo Reply(0) -> ignore; Echo Request(8) -> continue; any other
//       (unknown) type -> drop                  (RFC 1122 3.2.2 MUST discard unknown)
//    8. smurf / directed-broadcast: ip_dst == our unicast IP, else drop
//                                                (RFC 1122 3.2.2.6 MAY-discard; RFC 2644)
//    9. generation rate limit: per-source token bucket has budget, else drop
//                                                (RFC 1812 4.3.2.8; see ICMP_RL_* note)
//   10. build + send Echo Reply (type 0)         (RFC 1122 3.2.2.6: host MUST implement an
//                                                 Echo server; MAY be administratively disabled)
// Note: classic "ping of death" is a fragment-reassembly overflow; xv6 has no reassembly,
// so check 5 is defense-in-depth, not a fix for a live xv6 vulnerability.
static void
icmp_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *)buf;
  struct ip  *ip  = (struct ip *)(eth + 1);

  // IP VERSION: a datagram whose IP version is not 4 MUST be silently discarded
  // (RFC 1122 3.2.1.1).
  if((ip->ip_vhl >> 4) != 4)
    return;

  // IP HEADER LENGTH: IHL gives the header size in 32-bit words; 5 (20 bytes) is the
  // minimum (RFC 791). The ICMP header is read at this offset so IP options are honored.
  int ip_hdr_len = (ip->ip_vhl & 0x0f) * 4;
  if(ip_hdr_len < (int)sizeof(struct ip))
    return;

  // BUFFER BOUNDS: net_rx() only guaranteed eth + IP bytes, so confirm the frame also
  // holds the 8-byte ICMP header before any ICMP field is read.
  if(len < (int)sizeof(struct eth) + ip_hdr_len + (int)sizeof(struct icmp))
    return;

  // IP TOTAL LENGTH: the datagram may not claim more octets than the link delivered
  // (RFC 791 total length vs the received frame).
  int ip_total = ntohs(ip->ip_len);
  if(ip_total > len - (int)sizeof(struct eth))
    return;

  struct icmp *icmp = (struct icmp *)((char *)ip + ip_hdr_len);

  // ICMP SIZE VALIDATION: the message is everything after the IP header. Require at least
  // the 8-byte header and reject abnormally large messages (ping-of-death defense, see
  // ICMP_MAX_LEN in net.h).
  int icmp_len = ip_total - ip_hdr_len;
  if(icmp_len < (int)sizeof(struct icmp) || icmp_len > ICMP_MAX_LEN)
    return;

  // ICMP CHECKSUM (RFC 792): the ones-complement sum over the whole message is 0 if valid.
  if(in_cksum((unsigned char *)icmp, icmp_len) != 0)
    return;

  // TYPE FILTERING (RFC 1122 3.2.2): an unknown type MUST be silently discarded. We only
  // service Echo Request; an Echo Reply is accepted but needs no action.
  if(icmp->type == ICMP_ECHOREPLY)
    return;
  if(icmp->type != ICMP_ECHO)
    return;

  // SMURF / DIRECTED-BROADCAST DEFENSE (RFC 1122 3.2.2.6 MAY-discard; RFC 2644): with no
  // netmask configured, the safe rule is to answer only an Echo addressed to our own
  // unicast IP. This drops echoes to 255.255.255.255, a subnet-directed broadcast, or a
  // multicast group, so xv6 cannot be used as a smurf amplifier.
  if(ip->ip_dst != htonl(local_ip))
    return;

  // RATE LIMIT (RFC 1812 4.3.2.8): cap how many replies we emit to one peer.
  if(!icmp_rate_ok(ntohl(ip->ip_src)))
    return;

  // BUILD ECHO REPLY (mirrors icmp_port_unreachable's construction).
  char *out = kalloc();
  if(!out)
    return;
  memset(out, 0, PGSIZE);

  struct eth *oeth = (struct eth *)out;
  memmove(oeth->dhost, eth->shost, ETHADDR_LEN); // back to the sender
  memmove(oeth->shost, local_mac, ETHADDR_LEN);
  oeth->type = htons(ETHTYPE_IP);

  struct ip *oip = (struct ip *)(oeth + 1);
  oip->ip_vhl = 0x45; // IPv4, 20-byte header (reply carries no IP options)
  oip->ip_tos = 0;
  oip->ip_len = htons(sizeof(struct ip) + icmp_len);
  oip->ip_id  = 0;
  oip->ip_off = 0;
  oip->ip_ttl = 64;
  oip->ip_p   = IPPROTO_ICMP;
  oip->ip_src = htonl(local_ip);
  oip->ip_dst = ip->ip_src; // back to the requester
  oip->ip_sum = in_cksum((unsigned char *)oip, sizeof(*oip));

  // Echo the request's ICMP message verbatim (preserving id/seq/data), then convert it
  // into a reply and recompute the checksum over the whole message.
  struct icmp *oicmp = (struct icmp *)(oip + 1);
  memmove(oicmp, icmp, icmp_len);
  oicmp->type = ICMP_ECHOREPLY;
  oicmp->code = 0;
  oicmp->checksum = 0;
  oicmp->checksum = in_cksum((unsigned char *)oicmp, icmp_len);

  e1000_transmit(out, sizeof(struct eth) + sizeof(struct ip) + icmp_len);
}

/*
UDP checksum with psuedoheader
- Rejcts on allocation failure (kalloc returns 0)
- Rejects malformed packets with invalid length fields (UDP length < header size or > PGSIZE)
- Accepts packets with checksum of 0 (sender chose not to compute it)
*/
static int
udp_checksum_valid(struct ip *ip, struct udp *udp)
{
  // checksum of 0 means sender chose not to compute it, accept the packet
  if(udp->sum == 0)
    return 1;

  int udp_len = ntohs(udp->ulen);
  if(udp_len < (int)sizeof(struct udp) || udp_len > PGSIZE){
    return 0; // malformed length, drop
  }

  // build pseudo-header + udp segment in a temporary buffer
  char *buf = kalloc();
  if(!buf) return 0; // reject on allocation failure

  struct udp_pseudo_hdr *phdr = (struct udp_pseudo_hdr *)buf;
  phdr->src_ip  = ip->ip_src;
  phdr->dst_ip  = ip->ip_dst;
  phdr->zero    = 0;
  phdr->proto   = IPPROTO_UDP;
  phdr->udp_len = udp->ulen;

  // copy udp header + payload after pseudo-header
  memmove(buf + sizeof(struct udp_pseudo_hdr), udp, udp_len);

  uint16 computed = in_cksum((unsigned char *)buf,
                              sizeof(struct udp_pseudo_hdr) + udp_len);
  kfree(buf);
  return computed == 0;
}


/**
 * @brief IP packet receiver and UDP demultiplexer
 * @author Syed Taha
 * @date 12th November 2025
 * 
 * @details
 * Processes incoming IP packets from the network stack, specifically handling UDP
 * traffic by demultiplexing packets to the appropriate application ports. This
 * function serves as the bridge between the network driver layer and the
 * application-facing UDP interface.
 * 
 * Packet processing pipeline:
  // RFC-BACKED VALIDATION CHAIN (drops a malformed/hostile datagram before any of
  // its claimed lengths are trusted for a copy, the way Linux does):
  //   1. IP version != 4            -> drop (RFC 1122 3.2.1.1)
  //   2. IHL < 5                    -> drop (RFC 791); UDP is then read at the
  //                                    IHL-derived offset so IP options are honored,
  //                                    not assumed away
  //   3. frame too short for headers -> drop (over-read guard on the headers themselves)
  //   4. IP total length > delivered frame -> drop (RFC 791 ip_len vs reality; stops
  //                                    undelivered memory from being read as packet data)
  //   5. udp.ulen < 8               -> drop (RFC 768 minimum: header with no payload)
  //   6. udp.ulen > delivered bytes -> drop (RFC 768; this is the Heartbleed-shaped
  //                                    check -- without it, a packet could claim a
  //                                    bigger length than it actually carried and the
  //                                    memmove below would copy adjacent kernel memory
  //                                    out to the requesting application)
  //   7. trailing octets beyond ulen -> accepted, not copied (RFC 1122 1.2.2 robustness
  //                                    principle: be liberal in what you accept)
  //   8. BOGON FILTER: drop packets from source addresses that should never appear on the
  //      public Internet (RFC 1122, RFC 1918, RFC 3927, RFC 5737, RFC 6598)
  //   9. BCP38 INGRESS FILTER: drop packets arriving on an interface from a source address that
  //     could not legitimately originate there (spoofed or misrouted) (RFC 2827, RFC 3704)
  //   10. ICMP: if protocol is ICMP, hand off to the hardened ICMP handler (see icmp_rx) which applies its own checks
  //   11. IP protocol != UDP -> drop (protocol filtering)
 * 
 * @param buf Kernel buffer containing the complete Ethernet frame with IP packet
 * @param len Total length of the buffer in bytes
 * 
 * @note This function consumes the input buffer (frees it with kfree) regardless
 * of whether the packet is successfully processed or discarded.
 * @note The function maintains a static flag to print a one-time diagnostic
 * message when the first IP packet is received.
 * 
 * @flow_control Implements a maximum queue depth of 16 packets per port to
 * prevent unbounded memory consumption and provide backpressure to the network.
 * 
 * @memory_management Creates copies of UDP payloads in persistent kernel buffers
 * to allow the original receive buffer to be recycled by the E1000 driver.
 */
void
ip_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *) buf;
  
  struct ip *ip = (struct ip *)(eth + 1);

  int frag_buf = 0;

  // ETHERNET LEN CHECK
  if (len < (int)sizeof(struct eth) + sizeof(struct ip)) {
    printf("ip_rx: frame too short for Ethernet + IP header: len %d\n", len);
    goto drop_packet;
  }

  // IP VERSION: a datagram whose IP version is not 4 MUST be silently discarded
  // (RFC 1122 3.2.1.1)
  if ((ip->ip_vhl >> 4) != 4) {
    goto drop_packet;
  }

  // IP HEADER LENGTH: the IHL field gives the header size in 32-bit words; 5 (20 bytes)
  // is the minimum and options extend it up to 60 bytes (RFC 791). Reading the UDP
  // header at this offset honors IP options instead of assuming a fixed 20-byte header.
  int ip_hdr_len = (ip->ip_vhl & 0x0f) * 4;
  if (ip_hdr_len < (int)sizeof(struct ip)) {
    goto drop_packet;
  }

  // BUFFER BOUNDS: the received frame must physically hold the Ethernet, IP, and UDP
  // headers before any UDP field is read, so every read below stays inside the buffer
  if (len < (int)sizeof(struct eth) + ip_hdr_len + (int)sizeof(struct udp)) {
    goto drop_packet;
  }

  // IP TOTAL LENGTH: the IP datagram may not claim more octets than the link layer
  // actually delivered (RFC 791 total length vs the received frame). This is the bound
  // that stops undelivered memory from being treated as packet data.
  int ip_total = ntohs(ip->ip_len);
  if (ip_total > len - (int)sizeof(struct eth)) {
    goto drop_packet;
  }
  
  // BOGON FILTER: reject packets from addresses that should never appear
  // on the wire (RFC 1122, RFC 1918, RFC 3927, RFC 5737, RFC 6598)
  if (IS_BOGON(ip->ip_src)) {
    goto drop_packet;
  }

  // IP: BCP38 ingress filter (RFC 2827)
  // iface_id = 0 because xv6 has one NIC; extend if more needed.
  uint32 src = ntohl(ip->ip_src);
  if (ingress_filter(0, src) == FILTER_DROP) {
      goto drop_packet;
  }

  // FRAGMENT CHECK: if MF set or offset non-zero, this is a fragment
  uint ip_off = ntohs(ip->ip_off);
  int mf = (ip_off & IP_MF) != 0;
  int offset = (ip_off & IP_OFFMASK);  // in 8-byte units

  if (!mf && offset == 0)
    if (reasm_check_id_collision(ip)) {
        goto drop_packet;
    }

  if (mf || offset != 0) {
      // hand off to reassembly — do NOT fall through to UDP extraction
      ip = ip_fragment_rx(ip, ip_total, &frag_buf);
      // ip_fragment_rx either:
      //   - buffers the fragment and returns NULL (not done yet)
      //   - returns a fully reassembled datagram and sets frag_buf = 1
      if (ip == 0) {
          // fragment buffered or kalloc full, waiting for more; drop this packet for now
          goto drop_packet;
      }
      // Refresh ip_total from the reassembled IP header.
      // The local variable was set from the arriving fragment's ip_len; ip_fragment_rx
      // writes the full datagram size into new_ip->ip_len, so we must re-read it here.
      // Without this, udp_avail = ip_total - ip_hdr_len uses the fragment size and the
      // subsequent "udp_total > udp_avail" check drops every reassembled packet.
      ip_total = ntohs(ip->ip_len);
  }

  // ICMP: hand off to the hardened echo responder, which applies its own validation
  // (type filtering, size, smurf, and rate-limit guards). Added as a single dispatch
  // line into this function.
  if (ip->ip_p == IPPROTO_ICMP) {
    // After reassembly ip no longer points into buf, so icmp_rx (which expects a
    // complete Ethernet frame starting at buf) must receive a temporary buffer.
    if (frag_buf) {
      int reasm_total = sizeof(struct eth) + ip_total;
      char *icmp_buf = kalloc();
      if (icmp_buf) {
        memmove(icmp_buf, buf, sizeof(struct eth));          // copy original eth header
        memmove(icmp_buf + sizeof(struct eth), ip, ip_total); // append reassembled IP+payload
        icmp_rx(icmp_buf, reasm_total);
        kfree(icmp_buf);
      }
    } else {
      icmp_rx(buf, len);
    }
    goto drop_packet;
  }

  // PROTOCOL FILTERING: Only process UDP packets, discard others
  // ip->ip_p contains the IP protocol number (17 = UDP, 6 = TCP, etc.)
  if (ip->ip_p != IPPROTO_UDP) {
    goto drop_packet;
  }

  // UDP HEADER EXTRACTION: the UDP header follows the IP header at its IHL-derived
  // offset, which accounts for any IP options present
  struct udp *udp = (struct udp *)((char *)ip + ip_hdr_len);

  // UDP LENGTH VALIDATION (RFC 768): the length field counts the 8-byte header plus the
  // data, with a minimum of 8, and may not exceed the octets the IP datagram delivered.
  // A datagram claiming more than was delivered is malformed and is silently discarded
  // (RFC 1122). Trailing octets beyond the declared length are tolerated per the
  // robustness principle (RFC 1122 1.2.2) and are not copied to the application.
  int udp_avail = ip_total - ip_hdr_len;
  int udp_total = ntohs(udp->ulen);
  if (udp_total < (int)sizeof(struct udp) || udp_total > udp_avail) {
    goto drop_packet;
  }

  // PAYLOAD LENGTH CALCULATION: pure payload length is the validated UDP length minus
  // the 8-byte UDP header
  int udp_len = udp_total - sizeof(struct udp);

  // CHECKSUM VALIDATION: Verify UDP checksum if present
  // A checksum of 0 indicates the sender did not compute it, so we accept the packet
  // If checksum is non-zero, we compute the checksum and compare it to the value in the header
  if (!udp_checksum_valid(ip, udp)) {
    // Checksum validation failed - packet is corrupted or malicious, discard it
    goto drop_packet;
  }

  // DESTINATION PORT EXTRACTION: Get target port for demultiplexing
  // udp->dport is in network byte order, convert to host byte order for array indexing
  // (extracted before the rate check so the bulk-flow exemption can be consulted)
  int dport = ntohs(udp->dport);
  if (dport < 0 || dport >= UDP_PORTS) {
    goto drop_packet;
  }

  // RATE LIMITING: drop well-formed packets from flooding sources, unless this
  // datagram belongs to a flow the local application has declared bulk. The
  // exemption is scoped to (bound port, declared peer IP), so an unrelated or
  // spoofed source aimed at the same port is still metered by the token bucket.
  if (!udp_bulk_exempt(dport, ntohl(ip->ip_src)) &&
      !udp_rate_ok(ntohl(ip->ip_src), ntohs(udp->sport))) {
    goto drop_packet;
  }

  // PORT STATE VALIDATION: Check if destination port is bound and active
  // Access the udp_port structure for the destination port via array lookup
  // Port not bound - send ICMP destination unreachable (port unreachable)
  // per RFC 792. Note: silent drop is an alternative that prevents port
  // scanning but violates RFC compliance. Rate limiting should be added
  // at the security layer to prevent amplification attacks.
  struct udp_port *up = &udp_ports[dport];
  acquire(&up->lock);
  if (!up->inuse) {
    release(&up->lock);
    // After reassembly ip no longer points into buf; build a temporary frame so
    // icmp_port_unreachable can read the IP header and first 8 UDP bytes correctly.
    if (frag_buf) {
      int need = sizeof(struct eth) + ip_total;
      char *pu_buf = kalloc();
      if (pu_buf) {
        memmove(pu_buf, buf, sizeof(struct eth));
        memmove(pu_buf + sizeof(struct eth), ip, ip_total);
        icmp_port_unreachable(pu_buf, need);
        kfree(pu_buf);
      }
    } else {
      icmp_port_unreachable(buf, len);
    }
    goto drop_packet;
  }

  // FLOW CONTROL: Check current queue depth to prevent memory exhaustion
  // Count existing packets in the port's receive queue
  int count = 0;
  struct udp_packet *cur = up->head;
  while (cur) {
    count++;
    cur = cur->next;
  }
  // If queue has 16 or more packets, drop new packet (implicit flow control)
  if (count >= 16) {
    release(&up->lock);
    goto drop_packet;
  }

  // PACKET METADATA ALLOCATION: Create udp_packet structure for queuing
  // This structure will hold the parsed packet information for application delivery
  struct udp_packet *pkt = kalloc();
  if(!pkt){
    // Kernel memory exhausted - cannot queue packet, must drop it
    release(&up->lock);
    goto drop_packet;
  }

  // PAYLOAD BUFFER ALLOCATION: Create persistent copy of UDP data
  // Original buffer will be freed, so we need a separate copy for application
  pkt->data = kalloc();
  if(!pkt->data){
    // Cleanup on allocation failure: free metadata structure
    kfree(pkt);
    release(&up->lock);
    goto drop_packet;
  }

  // PACKET METADATA POPULATION: Fill udp_packet with extracted information
  pkt->next = 0;                          // Initialize as last element in queue
  pkt->src_ip = ntohl(ip->ip_src);        // Convert source IP to host byte order
  pkt->src_port = ntohs(udp->sport);      // Convert source port to host byte order
  
  // BOUNDS CHECK: Ensure UDP payload doesn't exceed allocated page size
  // kalloc() returns a 4096-byte page, so limit copy to prevent buffer overflow
  uint copy_len = udp_len > PGSIZE ? PGSIZE : udp_len;
  pkt->len = copy_len;                    // Store actual copied length for bounds checking
  memmove(pkt->data, (char *)(udp + 1), copy_len);  // Copy payload to persistent buffer

  // QUEUE OPERATION: Enqueue packet for application consumption
  // Add to tail of linked list for FIFO delivery semantics
  if (up->tail) {
    // Non-empty queue: append to end and update tail pointer
    up->tail->next = pkt;
    up->tail = pkt;
  } else {
    // Empty queue: initialize both head and tail pointers
    up->head = pkt;
    up->tail = pkt;
  }

  // PROCESS SYNCHRONIZATION: Wake up any processes waiting for packets
  // Processes sleeping in sys_recv() will be awakened to consume the new packet
  wakeup(up);

  // sys_recvtimeo() cannot sleep on `up`: it also has to wake when its timeout
  // expires, and only the clock interrupt (wakeup(&ticks)) provides that. So it
  // sleeps on &ticks, which means without the wakeup below a waiter is released
  // only on the next timer tick -- a 0-100 ms penalty on *every* receive, which
  // caps a chunked transfer at ~10 batches/s and would put a 100 ms floor under
  // every inference hop. Waking &ticks here delivers the packet immediately; the
  // few other &ticks sleepers (pause()) simply re-check their deadline and sleep
  // again, which is what they already do on a normal tick.
  wakeup(&ticks);

  // RELEASE RESOURCES: Port lock and original packet buffer
  release(&up->lock);
  goto drop_packet;

  drop_packet:
  kfree(buf);  // Free the original E1000 receive buffer for recycling
  if (frag_buf) {
    kfree(ip); // Free any fragment buffer if it was allocated
  }
  return;
}

/**
 * @brief Token-bucket admission check for inbound ARP packets, keyed on Ethernet source MAC
 * @author Syed Taha
 * @date 12th June 2026
 *
 * @details
 * Implements per-source ARP rate limiting to mitigate ARP flood attacks. The
 * function maintains a small hash table (arp_rl[ARP_RL_SLOTS]) of token buckets,
 * one per recently-seen source MAC address.
 *
 * Algorithm (identical to icmp_rate_ok / udp_rate_ok):
 *   1. Search the table for an existing bucket matching src_mac.
 *   2. If not found, claim a slot: prefer an unused (all-zero MAC) slot;
 *      otherwise evict the idlest bucket (most tokens = least recently used).
 *   3. Refill the bucket by 1 token per elapsed xv6 tick, capped at ARP_RL_BURST.
 *   4. If at least one token remains, consume it and return 1 (allow).
 *      Otherwise return 0 (drop).
 *
 * The rate limiter is keyed on the Ethernet source MAC rather than the ARP
 * sender IP because ARP is a Layer-2 protocol. A MAC is the authoritative
 * identity at that layer, and using it prevents an attacker from bypassing
 * the limiter by rotating the IP field while keeping the same NIC.
 *
 * @param src_mac  Pointer to the 6-byte Ethernet source MAC from the frame header
 * @return         1 if the packet is within the rate limit and should be processed,
 *                 0 if the bucket is exhausted and the packet should be dropped
 *
 * Acquires and releases arp_rl_lock internally; must not be
 * called with that lock already held.
 */
static int
arp_rate_ok(uint8 *src_mac)
{
  int ok = 0;
  uint8 zero[ETHADDR_LEN] = {0};

  acquire(&arp_rl_lock);

  struct arp_bucket *b = 0;
  for (int i = 0; i < ARP_RL_SLOTS; i++) {
    if (memcmp(arp_rl[i].mac, src_mac, ETHADDR_LEN) == 0) { b = &arp_rl[i]; break; }
  }
  if (b == 0) {
    b = &arp_rl[0];
    for (int i = 0; i < ARP_RL_SLOTS; i++) {
      if (memcmp(arp_rl[i].mac, zero, ETHADDR_LEN) == 0) { b = &arp_rl[i]; break; }
      if (arp_rl[i].tokens > b->tokens) b = &arp_rl[i];
    }
    memmove(b->mac, src_mac, ETHADDR_LEN);
    b->tokens = ARP_RL_BURST;
    b->last   = ticks;
  }

  uint now = ticks;
  uint elapsed = now - b->last;
  if (elapsed > 0) {
    int add = elapsed > (uint)ARP_RL_BURST ? ARP_RL_BURST : (int)elapsed;
    b->tokens += add;
    if (b->tokens > ARP_RL_BURST) b->tokens = ARP_RL_BURST;
    b->last = now;
  }
  if (b->tokens > 0) { b->tokens--; ok = 1; }

  release(&arp_rl_lock);
  return ok;
}

/**
 * @brief Dynamic ARP Inspection - validate sender's claimed IP/MAC against the static table
 * @author Syed Taha
 * @date 12th June 2026
 *
 * @details
 * Every ARP packet contains a "sender IP" (sip) and "sender hardware address"
 * (sha) - the sender is asserting: "I own this IP and my MAC is this." DAI
 * checks that assertion against arp_static_table[]:
 *
 *   - If sip appears in the table and sha matches the registered MAC → FILTER_ACCEPT.
 *   - If sip appears in the table but sha does NOT match             → FILTER_DROP.
 *   - If sip is not in the table at all                              → FILTER_ACCEPT
 *     (fail-open; unregistered hosts are not subject to MAC validation).
 *
 * This guards against ARP cache poisoning: an attacker who broadcasts a false
 * IP-to-MAC mapping for a known node will be silently dropped at this check
 * before xv6 can update its internal state (host_mac) or send a reply.
 *
 * @param sip  Sender IP address in host byte order (ntohl applied by caller)
 * @param sha  Pointer to the 6-byte sender hardware address from the ARP payload
 * @return     FILTER_ACCEPT (0) if the packet should continue processing,
 *             FILTER_DROP   (1) if a spoofed IP/MAC binding was detected
 */
static int
arp_dai_ok(uint32 sip, uint8 *sha)
{
  for (int i = 0; i < (int)ARP_STATIC_ENTRIES; i++) {
    if (arp_static_table[i].ip == sip)
      return memcmp(sha, arp_static_table[i].mac, ETHADDR_LEN) == 0
             ? FILTER_ACCEPT : FILTER_DROP;
  }
  return FILTER_ACCEPT;
}

/**
 * @brief Hardened ARP receive path with four-layer security validation
 * @author Syed Taha
 * @date 12th June 2026
 *
 * @details
 * Replaces the original minimal ARP handler, which blindly trusted every
 * incoming ARP and replied unconditionally. The new implementation runs each
 * packet through a sequential check chain; the first failing check drops the
 * packet and returns immediately without sending any reply:
 *
 *   1. Format validation
 *      Ensures the ARP packet describes an Ethernet/IPv4 binding (hrd=1,
 *      pro=0x0800, hln=6, pln=4). Malformed or non-IP ARP variants are dropped.
 *
 *   2. Rate limiting  (arp_rate_ok)
 *      Token bucket keyed on the Ethernet source MAC. Caps any single sender at
 *      ARP_RL_BURST back-to-back replies before throttling. Mitigates ARP floods.
 *
 *   3. Gratuitous ARP monitoring
 *      A gratuitous ARP has sender IP == target IP - the sender is broadcasting
 *      an unsolicited IP-to-MAC announcement (RFC 5227). These are dropped to
 *      prevent an attacker from silently overwriting xv6's ARP cache state.
 *
 *   4. Dynamic ARP Inspection  (arp_dai_ok)
 *      The sender's claimed IP/MAC pair is checked against arp_static_table[].
 *      If the sender IP is a known node but the MAC doesn't match, the packet is
 *      an ARP poisoning attempt and is dropped.
 *
 *   5. Reply learning  (RFC 826, arp_cache_update)
 *      A reply (op=2) addressed to local_ip carries a binding a pending
 *      arp_lookup() is waiting on; it is installed into the dynamic ARP cache.
 *      Because it runs after DAI, a spoofed binding is already dropped and
 *      cannot poison the cache. Requests fall through to check 6.
 *
 *   6. Target IP filter
 *      xv6 only answers ARP requests (op=1) whose target IP equals local_ip.
 *      Queries for other IPs are silently discarded.
 *
 * A request that passes all checks causes xv6 to:
 *   - Update host_mac from the validated sender hardware address.
 *   - Allocate a reply buffer and send an ARP reply (op=2) with local_mac.
 *
 * @param inbuf  Kernel buffer containing the complete Ethernet frame
 *               (Ethernet header + ARP payload). Ownership is transferred:
 *               this function always calls kfree(inbuf) before returning.
 */
void
arp_rx(char *inbuf)
{
  struct eth *ineth = (struct eth *) inbuf;
  struct arp *inarp = (struct arp *) (ineth + 1);

  // 1. Format validation: only handle Ethernet ARP for IPv4
  if (ntohs(inarp->hrd) != ARP_HRD_ETHER ||
      ntohs(inarp->pro) != ETHTYPE_IP    ||
      inarp->hln != ETHADDR_LEN          ||
      inarp->pln != sizeof(uint32)) {
    kfree(inbuf);
    return;
  }

  // 2. Rate limiting per Ethernet source MAC
  if (!arp_rate_ok((uint8 *)ineth->shost)) {
    kfree(inbuf);
    return;
  }

  // 3. Gratuitous ARP monitoring: sip == tip means the sender is advertising its own
  //    IP/MAC (RFC 5227). Drop to prevent unsolicited cache updates.
  if (inarp->sip == inarp->tip) {
    kfree(inbuf);
    return;
  }

  // 4. Dynamic ARP inspection: reject if sender's claimed IP is in the static table
  //    but the accompanying MAC doesn't match (ARP spoofing / cache poisoning attempt).
  if (arp_dai_ok(ntohl(inarp->sip), (uint8 *)inarp->sha) == FILTER_DROP) {
    kfree(inbuf);
    return;
  }

  // 5. Reply learning (RFC 826): a solicited reply addressed to our IP carries the
  //    IP->MAC binding a pending arp_lookup() is blocked on. The reply has already
  //    passed format/rate/gratuitous/DAI, so a spoofed binding was dropped above and
  //    cannot poison the cache here. Requests fall through to the responder below.
  if (ntohs(inarp->op) == ARP_OP_REPLY && ntohl(inarp->tip) == local_ip) {
    arp_cache_update(ntohl(inarp->sip), (uint8 *)inarp->sha);
    kfree(inbuf);
    return;
  }

  // Only respond to ARP requests that target our own IP
  if (ntohs(inarp->op) != ARP_OP_REQUEST || ntohl(inarp->tip) != local_ip) {
    kfree(inbuf);
    return;
  }

  // Learn sender MAC (packet has passed all security checks)
  memmove(host_mac, inarp->sha, ETHADDR_LEN);

  char *buf = kalloc();
  if (buf == 0)
    panic("arp_rx");

  struct eth *eth = (struct eth *) buf;
  memmove(eth->dhost, ineth->shost, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_ARP);

  struct arp *arp = (struct arp *)(eth + 1);
  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ETHTYPE_IP);
  arp->hln = ETHADDR_LEN;
  arp->pln = sizeof(uint32);
  arp->op  = htons(ARP_OP_REPLY);

  memmove(arp->sha, local_mac, ETHADDR_LEN);
  arp->sip = htonl(local_ip);
  memmove(arp->tha, inarp->sha, ETHADDR_LEN);
  arp->tip = inarp->sip;

  e1000_transmit(buf, sizeof(*eth) + sizeof(*arp));

  kfree(inbuf);
}

void
net_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *) buf;

  if(len >= sizeof(struct eth) + sizeof(struct arp) &&
     ntohs(eth->type) == ETHTYPE_ARP){
    arp_rx(buf);
  } else if(len >= sizeof(struct eth) + sizeof(struct ip) &&
     ntohs(eth->type) == ETHTYPE_IP){
    ip_rx(buf, len);
  } else {
    kfree(buf);
  }
}