/* pqcheck ctgrind KEM instrument.
 *
 * Poisons the secret key and shared secret with Valgrind memcheck
 * (VALGRIND_MAKE_MEM_UNDEFINED) while keeping the public key and
 * ciphertext defined, so any secret-dependent branch or memory access
 * during encaps/decaps is reported. Public inputs stay defined on
 * purpose: marking a public value as secret manufactures fake reports.
 *
 * Diagnostic for a maintainer's own build only. Link extern KEM entry
 * points (see c_harness.c) and compile with PQ_PK_BYTES etc. if needed.
 * Without <valgrind/memcheck.h> the poisoning macros are no-ops and the
 * program simply exercises the code paths.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__has_include)
#  if __has_include(<valgrind/memcheck.h>)
#    include <valgrind/memcheck.h>
#  endif
#endif
#ifndef VALGRIND_MAKE_MEM_UNDEFINED
#define VALGRIND_MAKE_MEM_UNDEFINED(addr, len) ((void)(addr), (void)(len))
#endif
#ifndef VALGRIND_MAKE_MEM_DEFINED
#define VALGRIND_MAKE_MEM_DEFINED(addr, len) ((void)(addr), (void)(len))
#endif

#ifndef PQ_PK_BYTES
#define PQ_PK_BYTES 1184
#endif
#ifndef PQ_SK_BYTES
#define PQ_SK_BYTES 2400
#endif
#ifndef PQ_CT_BYTES
#define PQ_CT_BYTES 1088
#endif
#ifndef PQ_SS_BYTES
#define PQ_SS_BYTES 32
#endif

int pqc_kem_keygen(uint8_t *pk, uint8_t *sk);
int pqc_kem_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int pqc_kem_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

int main(void) {
    uint8_t *pk = malloc(PQ_PK_BYTES), *sk = malloc(PQ_SK_BYTES);
    uint8_t *ct = malloc(PQ_CT_BYTES), *ss = malloc(PQ_SS_BYTES);
    uint8_t *ss2 = malloc(PQ_SS_BYTES);
    if (!pk || !sk || !ct || !ss || !ss2) return 70;
    if (pqc_kem_keygen(pk, sk) != 0) { fprintf(stderr, "keygen failed\n"); return 65; }
    /* secrets become undefined; public values remain defined */
    VALGRIND_MAKE_MEM_UNDEFINED(sk, PQ_SK_BYTES);
    if (pqc_kem_encaps(ct, ss, pk) != 0) { fprintf(stderr, "encaps failed\n"); return 65; }
    VALGRIND_MAKE_MEM_UNDEFINED(ss, PQ_SS_BYTES);
    VALGRIND_MAKE_MEM_DEFINED(ct, PQ_CT_BYTES);
    if (pqc_kem_decaps(ss2, ct, sk) != 0) { fprintf(stderr, "decaps failed\n"); return 65; }
    VALGRIND_MAKE_MEM_DEFINED(ss2, PQ_SS_BYTES);
    VALGRIND_MAKE_MEM_DEFINED(sk, PQ_SK_BYTES);
    VALGRIND_MAKE_MEM_DEFINED(ss, PQ_SS_BYTES);
    int ok = memcmp(ss, ss2, PQ_SS_BYTES) == 0;
    printf(ok ? "ctgrind-kem: round trip completed under poisoning\n"
              : "ctgrind-kem: round trip mismatch (functional failure, separate from ct reports)\n");
    free(pk); free(sk); free(ct); free(ss); free(ss2);
    return ok ? 0 : 1;
}
