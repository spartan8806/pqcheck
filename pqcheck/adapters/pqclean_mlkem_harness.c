/* pqcheck PQClean ML-KEM harness.
 *
 * One binary serves ML-KEM-512 / ML-KEM-768 / ML-KEM-1024 from PQClean
 * clean/ trees. Invocation: harness kem ML-KEM-768
 * Speaks the pqcheck line protocol; REJ = the library refused an input,
 * ERR = the harness declined (including over-long input lines). Buffers
 * are exact-sized malloc plus optional guard fill. The harness never
 * validates an input on behalf of the library.
 *
 * Build with the three clean/ trees on the include/link path, e.g.:
 *   gcc -O1 -I pqclean/crypto_kem/ml-kem-768/clean pqclean_mlkem_harness.c \
 *       pqclean/crypto_kem/ml-kem-*/clean/*.c
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define strtok_r strtok_s
#endif

#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES 800
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES 1632
#define PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES 768
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES 1184
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES 2400
#define PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES 1088
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_PUBLICKEYBYTES 1568
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_SECRETKEYBYTES 3168
#define PQCLEAN_MLKEM1024_CLEAN_CRYPTO_CIPHERTEXTBYTES 1568
#define SS_BYTES 32

int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

typedef int (*kem_fn)(uint8_t *, uint8_t *, const uint8_t *);
typedef int (*keypair_fn)(uint8_t *, uint8_t *);

static const char *g_alg = NULL;
static size_t PKB, SKB, CTB;
static keypair_fn g_keypair;
static kem_fn g_enc, g_dec;
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
    uint8_t *buf = malloc(n / 2 + g_guard_n + 1);
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

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: harness kem ML-KEM-{512,768,1024}\n"); return 64; }
    g_alg = argv[2];
    if (strcmp(g_alg, "ML-KEM-512") == 0) {
        PKB = 800; SKB = 1632; CTB = 768;
        g_keypair = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair;
        g_enc = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc;
        g_dec = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec;
    } else if (strcmp(g_alg, "ML-KEM-768") == 0) {
        PKB = 1184; SKB = 2400; CTB = 1088;
        g_keypair = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair;
        g_enc = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc;
        g_dec = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec;
    } else if (strcmp(g_alg, "ML-KEM-1024") == 0) {
        PKB = 1568; SKB = 3168; CTB = 1568;
        g_keypair = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair;
        g_enc = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc;
        g_dec = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec;
    } else { fprintf(stderr, "unsupported algorithm %s\n", g_alg); return 64; }

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
            printf("OK kind=kem alg=%s pk=%zu sk=%zu ct=%zu ss=%d guard=1\n", g_alg, PKB, SKB, CTB, SS_BYTES);
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
            int rc = g_keypair(pk, sk);
            if (rc == 0) { printf("OK "); print_hex(pk, PKB); printf(" "); print_hex(sk, SKB); printf("\n"); }
            else out("REJ keygen refused");
            fflush(stdout); free(pk); free(sk);
        } else if (strcmp(cmd, "encaps") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save); size_t an = 0;
            uint8_t *ek = a ? parse_hex(a, &an) : NULL;
            uint8_t *ct = malloc(CTB), *ss = malloc(SS_BYTES);
            if (!ek) { out("ERR bad hex"); free(ct); free(ss); continue; }
            int rc = g_enc(ct, ss, ek);
            if (rc == 0) { printf("OK "); print_hex(ss, SS_BYTES); printf(" "); print_hex(ct, CTB); printf("\n"); }
            else out("REJ encaps refused");
            fflush(stdout); free(ek); free(ct); free(ss);
        } else if (strcmp(cmd, "decaps") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save), *b = strtok_r(NULL, " \r\n", &save);
            size_t an = 0, bn = 0;
            uint8_t *dk = a ? parse_hex(a, &an) : NULL, *ct = b ? parse_hex(b, &bn) : NULL;
            uint8_t *ss = malloc(SS_BYTES);
            if (!dk || !ct) { out("ERR bad hex"); free(dk); free(ct); free(ss); continue; }
            int rc = g_dec(ss, ct, dk);
            if (rc == 0) { printf("OK "); print_hex(ss, SS_BYTES); printf("\n"); }
            else out("REJ decaps refused");
            fflush(stdout); free(dk); free(ct); free(ss);
        } else {
            out("ERR unknown command");
        }
    }
    return 0;
}
