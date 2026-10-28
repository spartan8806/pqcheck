/* pqcheck generic C harness.
 *
 * Line protocol on stdin/stdout:
 *   info                                   -> OK kind=<kem|sig> alg=<name> pk=N sk=N [ct=N ss=N | sig=N] guard=1
 *   keygen <seed_hex|->                    -> OK <pk_hex> <sk_hex>
 *   sign <sk_hex> <msg_hex|->              -> OK <sig_hex> | REJ <why> | ERR <why>
 *   verify <pk_hex> <msg_hex|-> <sig_hex>  -> OK | REJ <why> | ERR <why>
 *   encaps <ek_hex>                        -> OK <ss_hex> <ct_hex> | REJ <why> | ERR <why>
 *   decaps <dk_hex> <ct_hex>               -> OK <ss_hex> | REJ <why> | ERR <why>
 *   guard <hex|->                          -> OK guard=<n>
 *
 * Library entry points return 0 on success and 1 on controlled rejection;
 * any other return is reported as ERR (a harness/protocol problem, never as
 * a target rejection or crash).
 *
 * Buffer rule: every input and output buffer is malloc'd to the exact byte
 * length, plus guard_n caller-chosen bytes immediately past the declared
 * input length when a guard fill is active. Nothing is stack-allocated or
 * rounded up, so ASan catches one-byte over-reads/writes.
 *
 * Linking: by default this file carries a small deterministic template
 * implementation (NOT cryptography) so the protocol can be exercised
 * standalone. Define PQCHECK_EXTERNAL and link functions with these names:
 *   int pqc_kem_keygen(uint8_t *pk, uint8_t *sk);
 *   int pqc_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
 *   int pqc_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
 *   int pqc_sig_keygen(uint8_t *pk, uint8_t *sk);
 *   int pqc_sig_sign(uint8_t *sig, const uint8_t *sk, const uint8_t *msg, size_t msg_len);
 *   int pqc_sig_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len, const uint8_t *sig);
 * and compile with -DPQ_PK_BYTES=.. -DPQ_SK_BYTES=.. plus
 * -DPQ_CT_BYTES/-DPQ_SS_BYTES (KEM) or -DPQ_SIG_BYTES (SIG).
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#ifndef PQ_SIG_BYTES
#define PQ_SIG_BYTES 64
#endif

static uint8_t *g_guard = NULL;
static size_t g_guard_n = 0;
static unsigned long long g_counter = 0;

#ifdef PQCHECK_EXTERNAL
int pqc_kem_keygen(uint8_t *pk, uint8_t *sk);
int pqc_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqc_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int pqc_sig_keygen(uint8_t *pk, uint8_t *sk);
int pqc_sig_sign(uint8_t *sig, const uint8_t *sk, const uint8_t *msg, size_t msg_len);
int pqc_sig_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len, const uint8_t *sig);
#else
/* Deterministic template (FNV/xorshift expansion). Not cryptography. */
static void expand(const char *label, const uint8_t *a, size_t an,
                   const uint8_t *b, size_t bn, uint8_t *out, size_t outn) {
    uint64_t h = 1469598103934665603ULL;
    const uint8_t *parts[3] = {(const uint8_t *)label, a, b};
    size_t lens[3] = {strlen(label), an, bn};
    for (int p = 0; p < 3; p++)
        for (size_t i = 0; i < lens[p]; i++) { h ^= parts[p][i]; h *= 1099511628211ULL; }
    uint64_t x = h ? h : 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < outn; i++) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        out[i] = (uint8_t)(x >> 56);
    }
}
static int tpl_kem_keygen(uint8_t *pk, uint8_t *sk) {
    uint8_t ctr[8]; uint64_t c = ++g_counter;
    for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)(c >> (8 * i));
    expand("sk", ctr, 8, NULL, 0, sk, 32);
    expand("pk", sk, 32, NULL, 0, pk, PQ_PK_BYTES < 32 ? PQ_PK_BYTES : 32);
    if (PQ_SK_BYTES >= 96) {
        memcpy(sk + 32, pk, 32);
        /* H slot and z slot of the template dk layout */
        expand("h", pk, 32, NULL, 0, sk + 64, 32);
        expand("z", sk, 32, NULL, 0, sk + 64, 32);
        expand("h", pk, 32, NULL, 0, sk + 32, 32);
    }
    return 0;
}
static int tpl_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    uint8_t ctr[8]; uint64_t c = ++g_counter;
    for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)(c >> (8 * i));
    expand("ct", pk, PQ_PK_BYTES, ctr, 8, ct, PQ_CT_BYTES);
    expand("ss", pk, PQ_PK_BYTES, ct, PQ_CT_BYTES, ss, PQ_SS_BYTES);
    return 0;
}
static int tpl_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    uint8_t pk[32];
    expand("pk", sk, 32, NULL, 0, pk, 32);
    expand("ss", pk, 32, ct, PQ_CT_BYTES, ss, PQ_SS_BYTES);
    return 0;
}
static int tpl_sig_keygen(uint8_t *pk, uint8_t *sk) {
    uint8_t ctr[8]; uint64_t c = ++g_counter;
    for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)(c >> (8 * i));
    expand("sk", ctr, 8, NULL, 0, sk, PQ_SK_BYTES);
    expand("pk", sk, PQ_SK_BYTES, NULL, 0, pk, PQ_PK_BYTES);
    return 0;
}
static int tpl_sig_sign(uint8_t *sig, const uint8_t *sk, const uint8_t *msg, size_t msg_len) {
    uint8_t pk[PQ_PK_BYTES];
    expand("pk", sk, PQ_SK_BYTES, NULL, 0, pk, PQ_PK_BYTES);
    expand("sig", pk, PQ_PK_BYTES, msg, msg_len, sig, PQ_SIG_BYTES);
    return 0;
}
static int tpl_sig_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len, const uint8_t *sig) {
    uint8_t want[PQ_SIG_BYTES];
    expand("sig", pk, PQ_PK_BYTES, msg, msg_len, want, PQ_SIG_BYTES);
    return memcmp(want, sig, PQ_SIG_BYTES) == 0 ? 0 : 1;
}
#define pqc_kem_keygen tpl_kem_keygen
#define pqc_kem_encaps tpl_kem_encaps
#define pqc_kem_decaps tpl_kem_decaps
#define pqc_sig_keygen tpl_sig_keygen
#define pqc_sig_sign tpl_sig_sign
#define pqc_sig_verify tpl_sig_verify
#endif

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static uint8_t *parse_hex(const char *s, size_t *out_len) {
    if (strcmp(s, "-") == 0) { *out_len = 0; uint8_t *p = malloc(1); return p; }
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
static void reply_ok(void) { printf("OK\n"); fflush(stdout); }

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: harness <kem|sig> <algorithm>\n"); return 64; }
    const char *kind = argv[1], *alg = argv[2];
    int is_kem = strcmp(kind, "kem") == 0;
    char line[1 << 20];
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
            if (is_kem) printf("OK kind=kem alg=%s pk=%d sk=%d ct=%d ss=%d guard=1\n", alg, PQ_PK_BYTES, PQ_SK_BYTES, PQ_CT_BYTES, PQ_SS_BYTES);
            else printf("OK kind=sig alg=%s pk=%d sk=%d sig=%d guard=1\n", alg, PQ_PK_BYTES, PQ_SK_BYTES, PQ_SIG_BYTES);
            fflush(stdout);
        } else if (strcmp(cmd, "guard") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save);
            free(g_guard); g_guard = NULL; g_guard_n = 0;
            if (a && strcmp(a, "-") != 0) {
                size_t n = 0; uint8_t *tmp = parse_hex(a, &n);
                /* parse_hex appended the old (empty) guard; copy payload only */
                g_guard = malloc(n ? n : 1);
                if (tmp) memcpy(g_guard, tmp, n);
                g_guard_n = n; free(tmp);
            }
            printf("OK guard=%zu\n", g_guard_n); fflush(stdout);
        } else if (strcmp(cmd, "keygen") == 0) {
            uint8_t *pk = malloc(PQ_PK_BYTES), *sk = malloc(PQ_SK_BYTES);
            int rc = is_kem ? pqc_kem_keygen(pk, sk) : pqc_sig_keygen(pk, sk);
            if (rc == 0) { printf("OK "); print_hex(pk, PQ_PK_BYTES); printf(" "); print_hex(sk, PQ_SK_BYTES); printf("\n"); }
            else if (rc == 1) printf("REJ keygen refused\n");
            else printf("ERR keygen rc=%d\n", rc);
            fflush(stdout); free(pk); free(sk);
        } else if (strcmp(cmd, "encaps") == 0 && is_kem) {
            char *a = strtok_r(NULL, " \r\n", &save); size_t an = 0;
            uint8_t *ek = a ? parse_hex(a, &an) : NULL;
            uint8_t *ct = malloc(PQ_CT_BYTES), *ss = malloc(PQ_SS_BYTES);
            if (!ek) { printf("ERR bad hex\n"); fflush(stdout); free(ct); free(ss); continue; }
            int rc = pqc_kem_encaps(ct, ss, ek);
            if (rc == 0) { printf("OK "); print_hex(ss, PQ_SS_BYTES); printf(" "); print_hex(ct, PQ_CT_BYTES); printf("\n"); }
            else if (rc == 1) printf("REJ encaps refused\n");
            else printf("ERR encaps rc=%d\n", rc);
            fflush(stdout); free(ek); free(ct); free(ss);
        } else if (strcmp(cmd, "decaps") == 0 && is_kem) {
            char *a = strtok_r(NULL, " \r\n", &save), *b = strtok_r(NULL, " \r\n", &save);
            size_t an = 0, bn = 0;
            uint8_t *dk = a ? parse_hex(a, &an) : NULL, *ct = b ? parse_hex(b, &bn) : NULL;
            uint8_t *ss = malloc(PQ_SS_BYTES);
            if (!dk || !ct) { printf("ERR bad hex\n"); fflush(stdout); free(dk); free(ct); free(ss); continue; }
            int rc = pqc_kem_decaps(ss, ct, dk);
            if (rc == 0) { printf("OK "); print_hex(ss, PQ_SS_BYTES); printf("\n"); }
            else if (rc == 1) printf("REJ decaps refused\n");
            else printf("ERR decaps rc=%d\n", rc);
            fflush(stdout); free(dk); free(ct); free(ss);
        } else if (strcmp(cmd, "sign") == 0 && !is_kem) {
            char *a = strtok_r(NULL, " \r\n", &save), *b = strtok_r(NULL, " \r\n", &save);
            size_t an = 0, bn = 0;
            uint8_t *sk = a ? parse_hex(a, &an) : NULL, *msg = b ? parse_hex(b, &bn) : NULL;
            uint8_t *sig = malloc(PQ_SIG_BYTES);
            if (!sk || !msg) { printf("ERR bad hex\n"); fflush(stdout); free(sk); free(msg); free(sig); continue; }
            int rc = pqc_sig_sign(sig, sk, msg, bn);
            if (rc == 0) { printf("OK "); print_hex(sig, PQ_SIG_BYTES); printf("\n"); }
            else if (rc == 1) printf("REJ sign refused\n");
            else printf("ERR sign rc=%d\n", rc);
            fflush(stdout); free(sk); free(msg); free(sig);
        } else if (strcmp(cmd, "verify") == 0 && !is_kem) {
            char *a = strtok_r(NULL, " \r\n", &save), *b = strtok_r(NULL, " \r\n", &save), *c = strtok_r(NULL, " \r\n", &save);
            size_t an = 0, bn = 0, cn = 0;
            uint8_t *pk = a ? parse_hex(a, &an) : NULL, *msg = b ? parse_hex(b, &bn) : NULL, *sig = c ? parse_hex(c, &cn) : NULL;
            if (!pk || !msg || !sig) { printf("ERR bad hex\n"); fflush(stdout); free(pk); free(msg); free(sig); continue; }
            if (cn != PQ_SIG_BYTES) { printf("REJ bad sig length\n"); fflush(stdout); free(pk); free(msg); free(sig); continue; }
            int rc = pqc_sig_verify(pk, msg, bn, sig);
            if (rc == 0) reply_ok();
            else if (rc == 1) printf("REJ verify refused\n");
            else printf("ERR verify rc=%d\n", rc);
            fflush(stdout); free(pk); free(msg); free(sig);
        } else {
            printf("ERR unknown command\n"); fflush(stdout);
        }
    }
    return 0;
}
