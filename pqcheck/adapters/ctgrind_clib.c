/* pqcheck ctgrind instrument for a generic C library (KEM + SIG).
 *
 * Same poisoning contract as ctgrind_kem.c: secret key material is
 * marked undefined, public keys/messages/signatures stay defined, and
 * memcheck reports any secret-dependent control flow or addressing.
 * Diagnostic for a maintainer's own build only.
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
#define PQ_PK_BYTES 1312
#endif
#ifndef PQ_SK_BYTES
#define PQ_SK_BYTES 2560
#endif
#ifndef PQ_SIG_BYTES
#define PQ_SIG_BYTES 3309
#endif

int pqc_sig_keygen(uint8_t *pk, uint8_t *sk);
int pqc_sig_sign(uint8_t *sig, const uint8_t *sk, const uint8_t *msg, size_t msg_len);
int pqc_sig_verify(const uint8_t *pk, const uint8_t *msg, size_t msg_len, const uint8_t *sig);

int main(void) {
    static const uint8_t msg[] = "ctgrind public message";
    uint8_t *pk = malloc(PQ_PK_BYTES), *sk = malloc(PQ_SK_BYTES), *sig = malloc(PQ_SIG_BYTES);
    if (!pk || !sk || !sig) return 70;
    if (pqc_sig_keygen(pk, sk) != 0) { fprintf(stderr, "keygen failed\n"); return 65; }
    VALGRIND_MAKE_MEM_UNDEFINED(sk, PQ_SK_BYTES);
    if (pqc_sig_sign(sig, sk, msg, sizeof(msg) - 1) != 0) { fprintf(stderr, "sign failed\n"); return 65; }
    VALGRIND_MAKE_MEM_DEFINED(sk, PQ_SK_BYTES);
    VALGRIND_MAKE_MEM_DEFINED(sig, PQ_SIG_BYTES);
    int ok = pqc_sig_verify(pk, msg, sizeof(msg) - 1, sig) == 0;
    printf(ok ? "ctgrind-clib: sign/verify completed under poisoning\n"
              : "ctgrind-clib: verify failed (functional failure, separate from ct reports)\n");
    free(pk); free(sk); free(sig);
    return ok ? 0 : 1;
}
