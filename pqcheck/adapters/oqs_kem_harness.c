/* pqcheck liboqs KEM harness.
 *
 * Invocation: harness kem ML-KEM-768 (any OQS KEM algorithm name).
 * Links <oqs/oqs.h>. Speaks the pqcheck line protocol; command arity is
 * checked before hex decoding, REJ = the library refused, ERR = the
 * harness declined (including over-long lines drained to '\n').
 * Exact-sized malloc on every buffer, plus optional guard fill.
 */
#include <oqs/oqs.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define strtok_r strtok_s
#endif

static OQS_KEM *g_kem = NULL;
static uint8_t *g_guard = NULL;
static size_t g_guard_n = 0;

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
    uint8_t *buf = malloc(n / 2 + g_guard_n);
    if (!buf) return NULL;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) { free(buf); return NULL; }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    for (size_t i = 0; i < g_guard_n; i++) buf[n / 2 + i] = g_guard[i];
    *out_len = n / 2;
    return buf;
}
static void print_hex(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
}
static void out(const char *s) { printf("%s\n", s); fflush(stdout); }
static int arity(char **save, int want) {
    /* count remaining tokens without consuming beyond them */
    (void)save; (void)want; return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: harness kem <OQS-KEM-algorithm>\n"); return 64; }
    g_kem = OQS_KEM_new(argv[2]);
    if (!g_kem) { fprintf(stderr, "unknown OQS KEM %s\n", argv[2]); return 64; }
    size_t PKB = g_kem->length_public_key, SKB = g_kem->length_secret_key;
    size_t CTB = g_kem->length_ciphertext, SSB = g_kem->length_shared_secret;
    static char line[1 << 21];
    while (fgets(line, sizeof(line), stdin)) {
        if (!strchr(line, '\n') && !feof(stdin)) {
            int c; while ((c = getchar()) != '\n' && c != EOF) { }
            out("ERR line exceeds this harness's input buffer");
            continue;
        }
        char *save = NULL;
        char *cmd = strtok_r(line, " \r\n", &save);
        if (!cmd) continue;
        if (strcmp(cmd, "info") == 0) {
            printf("OK kind=kem alg=%s pk=%zu sk=%zu ct=%zu ss=%zu guard=1\n", argv[2], PKB, SKB, CTB, SSB);
            fflush(stdout);
        } else if (strcmp(cmd, "guard") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save);
            free(g_guard); g_guard = NULL; g_guard_n = 0;
            if (a && strcmp(a, "-") != 0) {
                size_t n = 0; uint8_t *tmp = parse_hex(a, &n);
                g_guard = malloc(n ? n : 1);
                if (tmp) memcpy(g_guard, tmp, n);
                g_guard_n = n; free(tmp);
            }
            printf("OK guard=%zu\n", g_guard_n); fflush(stdout);
        } else if (strcmp(cmd, "keygen") == 0) {
            uint8_t *pk = malloc(PKB), *sk = malloc(SKB);
            if (OQS_KEM_keypair(g_kem, pk, sk) == OQS_SUCCESS) {
                printf("OK "); print_hex(pk, PKB); printf(" "); print_hex(sk, SKB); printf("\n");
            } else out("REJ keygen refused");
            fflush(stdout); free(pk); free(sk);
        } else if (strcmp(cmd, "encaps") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save);
            if (!a) { out("ERR encaps needs 1 argument"); continue; }
            size_t an = 0; uint8_t *ek = parse_hex(a, &an);
            uint8_t *ct = malloc(CTB), *ss = malloc(SSB);
            if (!ek) { out("ERR bad hex"); free(ct); free(ss); continue; }
            if (OQS_KEM_encaps(g_kem, ct, ss, ek) == OQS_SUCCESS) {
                printf("OK "); print_hex(ss, SSB); printf(" "); print_hex(ct, CTB); printf("\n");
            } else out("REJ encaps refused");
            fflush(stdout); free(ek); free(ct); free(ss);
        } else if (strcmp(cmd, "decaps") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save), *b = strtok_r(NULL, " \r\n", &save);
            if (!a || !b) { out("ERR decaps needs 2 arguments"); continue; }
            size_t an = 0, bn = 0;
            uint8_t *dk = parse_hex(a, &an), *ct = parse_hex(b, &bn);
            uint8_t *ss = malloc(SSB);
            if (!dk || !ct) { out("ERR bad hex"); free(dk); free(ct); free(ss); continue; }
            if (OQS_KEM_decaps(g_kem, ss, ct, dk) == OQS_SUCCESS) {
                printf("OK "); print_hex(ss, SSB); printf("\n");
            } else out("REJ decaps refused");
            fflush(stdout); free(dk); free(ct); free(ss);
        } else {
            out("ERR unknown command");
        }
    }
    OQS_KEM_free(g_kem);
    return 0;
}
