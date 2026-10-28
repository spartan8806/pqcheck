/* pqcheck timing harness (dudect-style measurement server).
 *
 * Line protocol:
 *   info      -> OK kind=kem alg=<name> pk=N sk=N ct=N ss=N guard=1
 *   keygen -  -> OK <pk_hex> <sk_hex>
 *   encaps <pk_hex> -> OK <ss_hex> <ct_hex>
 *   measure <sk_hex> <ct_a_hex> <ct_b_hex> <iters>
 *             -> OK <cycles_A_csv> <cycles_B_csv>
 * In measure, A/B decapsulations run in RANDOMISED order (a fixed ABAB
 * pattern creates a position bias that fakes a signal on constant-time
 * code), timed with the hardware cycle counter. Local diagnostic only.
 *
 * Link extern kem entry points (see c_harness.c) with PQCHECK_EXTERNAL,
 * or use the built-in template for protocol testing.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#define strtok_r strtok_s
#endif
#ifndef PQ_PK_BYTES
#define PQ_PK_BYTES 32
#endif
#ifndef PQ_SK_BYTES
#define PQ_SK_BYTES 96
#endif
#ifndef PQ_CT_BYTES
#define PQ_CT_BYTES 32
#endif
#ifndef PQ_SS_BYTES
#define PQ_SS_BYTES 32
#endif

#ifdef PQCHECK_EXTERNAL
int pqc_kem_keygen(uint8_t *pk, uint8_t *sk);
int pqc_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqc_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#else
static uint64_t g_state = 0x123456789abcdefULL;
static void expand(const char *label, const uint8_t *a, size_t an, uint8_t *out, size_t outn) {
    uint64_t x = 1469598103934665603ULL;
    for (const char *p = label; *p; p++) { x ^= (uint8_t)*p; x *= 1099511628211ULL; }
    for (size_t i = 0; i < an; i++) { x ^= a[i]; x *= 1099511628211ULL; }
    if (!x) x = 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < outn; i++) { x ^= x << 13; x ^= x >> 7; x ^= x << 17; out[i] = (uint8_t)(x >> 56); }
}
static int pqc_kem_keygen(uint8_t *pk, uint8_t *sk) {
    g_state += 1;
    expand("sk", (uint8_t *)&g_state, 8, sk, 32);
    expand("pk", sk, 32, pk, 32);
    if (PQ_SK_BYTES >= 96) { memcpy(sk + 32, pk, 32); expand("z", sk, 32, sk + 64, 32); }
    return 0;
}
static int pqc_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    g_state += 1;
    expand("ct", pk, 32, ct, PQ_CT_BYTES);
    for (int i = 0; i < 8 && i < PQ_CT_BYTES; i++) ct[i] ^= (uint8_t)(g_state >> (8 * i));
    expand("ss", ct, PQ_CT_BYTES, ss, PQ_SS_BYTES);
    return 0;
}
static int pqc_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    (void)sk;
    expand("ss", ct, PQ_CT_BYTES, ss, PQ_SS_BYTES);
    return 0;
}
#endif

static uint64_t cycles_now(void) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#elif defined(__aarch64__)
    uint64_t v;
    __asm__ volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static uint8_t *parse_hex(const char *s, size_t *out_len) {
    if (strcmp(s, "-") == 0) { *out_len = 0; return malloc(1); }
    size_t n = strlen(s);
    if (n % 2) return NULL;
    uint8_t *buf = malloc(n / 2);
    if (!buf) return NULL;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(buf); return NULL; }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return buf;
}
static void print_hex(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: timing_harness kem <algorithm>\n"); return 64; }
    srand((unsigned)(time(NULL) ^ (long)argc));
    static char line[1 << 21];
    while (fgets(line, sizeof(line), stdin)) {
        if (!strchr(line, '\n') && !feof(stdin)) {
            int c; while ((c = getchar()) != '\n' && c != EOF) { }
            printf("ERR line exceeds this harness's input buffer\n"); fflush(stdout);
            continue;
        }
        char *save = NULL;
        char *cmd = strtok_r(line, " \r\n", &save);
        if (!cmd) continue;
        if (strcmp(cmd, "info") == 0) {
            printf("OK kind=kem alg=%s pk=%d sk=%d ct=%d ss=%d guard=1\n", argv[2], PQ_PK_BYTES, PQ_SK_BYTES, PQ_CT_BYTES, PQ_SS_BYTES);
            fflush(stdout);
        } else if (strcmp(cmd, "keygen") == 0) {
            uint8_t *pk = malloc(PQ_PK_BYTES), *sk = malloc(PQ_SK_BYTES);
            if (pqc_kem_keygen(pk, sk) == 0) { printf("OK "); print_hex(pk, PQ_PK_BYTES); printf(" "); print_hex(sk, PQ_SK_BYTES); printf("\n"); }
            else printf("REJ keygen refused\n");
            fflush(stdout); free(pk); free(sk);
        } else if (strcmp(cmd, "encaps") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save); size_t an = 0;
            uint8_t *ek = a ? parse_hex(a, &an) : NULL;
            uint8_t *ct = malloc(PQ_CT_BYTES), *ss = malloc(PQ_SS_BYTES);
            if (!ek) { printf("ERR bad hex\n"); fflush(stdout); free(ct); free(ss); continue; }
            if (pqc_kem_encaps(ct, ss, ek) == 0) { printf("OK "); print_hex(ss, PQ_SS_BYTES); printf(" "); print_hex(ct, PQ_CT_BYTES); printf("\n"); }
            else printf("REJ encaps refused\n");
            fflush(stdout); free(ek); free(ct); free(ss);
        } else if (strcmp(cmd, "measure") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save), *b = strtok_r(NULL, " \r\n", &save);
            char *c2 = strtok_r(NULL, " \r\n", &save), *d = strtok_r(NULL, " \r\n", &save);
            if (!a || !b || !c2 || !d) { printf("ERR measure needs 4 arguments\n"); fflush(stdout); continue; }
            size_t an = 0, bn = 0, cn = 0;
            uint8_t *sk = parse_hex(a, &an), *cta = parse_hex(b, &bn), *ctb = parse_hex(c2, &cn);
            long iters = strtol(d, NULL, 10);
            if (!sk || !cta || !ctb || iters <= 0 || iters > 100000) { printf("ERR bad measure arguments\n"); fflush(stdout); free(sk); free(cta); free(ctb); continue; }
            uint64_t *ca = malloc(sizeof(uint64_t) * iters), *cb = malloc(sizeof(uint64_t) * iters);
            uint8_t *ss = malloc(PQ_SS_BYTES);
            size_t na = 0, nb = 0;
            for (long i = 0; i < 2 * iters; i++) {
                int use_a;
                if ((long)na >= iters) use_a = 0;
                else if ((long)nb >= iters) use_a = 1;
                else use_a = rand() % 2;
                uint64_t t0 = cycles_now();
                pqc_kem_decaps(ss, use_a ? cta : ctb, sk);
                uint64_t t1 = cycles_now();
                if (use_a) ca[na++] = t1 - t0; else cb[nb++] = t1 - t0;
            }
            printf("OK ");
            for (size_t i = 0; i < na; i++) printf("%s%llu", i ? "," : "", (unsigned long long)ca[i]);
            printf(" ");
            for (size_t i = 0; i < nb; i++) printf("%s%llu", i ? "," : "", (unsigned long long)cb[i]);
            printf("\n"); fflush(stdout);
            free(sk); free(cta); free(ctb); free(ca); free(cb); free(ss);
        } else {
            printf("ERR unknown command\n"); fflush(stdout);
        }
    }
    return 0;
}
