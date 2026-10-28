/* pqcheck raw codec harness.
 * Protocol:
 *   info          -> OK kind=codec ncoef=8 sig=16 fixed=1
 *   encode <c0> <c1> ...   -> OK <hex> | REJ <why> | ERR <why>
 *   decode <hex|->         -> OK <hex of int16 coeff block> | REJ <why> | ERR <why>
 * Buffers are exact-sized malloc. Default template is an int16-LE codec;
 * define PQCHECK_EXTERNAL and link comp_encode/comp_decode to drive a real
 * codec:
 *   size_t comp_encode(uint8_t *out, const int16_t *coeffs, size_t ncoef);
 *   int comp_decode(int16_t *coeffs, size_t ncoef, const uint8_t *in, size_t in_len);
 * comp_decode returns 0 on success, 1 on controlled rejection.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define strtok_r strtok_s
#endif

#define NCOEF 8
#ifdef PQCHECK_EXTERNAL
size_t comp_encode(uint8_t *out, const int16_t *coeffs, size_t ncoef);
int comp_decode(int16_t *coeffs, size_t ncoef, const uint8_t *in, size_t in_len);
#else
static size_t comp_encode(uint8_t *out, const int16_t *coeffs, size_t ncoef) {
    for (size_t i = 0; i < ncoef; i++) {
        out[2 * i] = (uint8_t)(coeffs[i] & 0xff);
        out[2 * i + 1] = (uint8_t)((coeffs[i] >> 8) & 0xff);
    }
    return 2 * ncoef;
}
static int comp_decode(int16_t *coeffs, size_t ncoef, const uint8_t *in, size_t in_len) {
    if (in_len != 2 * ncoef) return 1;
    for (size_t i = 0; i < ncoef; i++)
        coeffs[i] = (int16_t)(in[2 * i] | (in[2 * i + 1] << 8));
    return 0;
}
#endif

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static void print_hex(const uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", buf[i]);
}

int main(void) {
    char line[1 << 16];
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
            printf("OK kind=codec ncoef=%d sig=%d fixed=1\n", NCOEF, 2 * NCOEF);
            fflush(stdout);
        } else if (strcmp(cmd, "encode") == 0) {
            int16_t *coeffs = malloc(sizeof(int16_t) * NCOEF);
            uint8_t *out = malloc(2 * NCOEF * 2);
            char *tok; int n = 0, bad = 0;
            while ((tok = strtok_r(NULL, " \r\n", &save)) != NULL) {
                if (n >= NCOEF) { bad = 1; break; }
                coeffs[n++] = (int16_t)strtol(tok, NULL, 10);
            }
            if (bad || n != NCOEF) { printf("ERR encode needs %d coefficients\n", NCOEF); fflush(stdout); free(coeffs); free(out); continue; }
            size_t outn = comp_encode(out, coeffs, NCOEF);
            printf("OK "); print_hex(out, outn); printf("\n"); fflush(stdout);
            free(coeffs); free(out);
        } else if (strcmp(cmd, "decode") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save);
            if (!a) { printf("ERR decode needs hex\n"); fflush(stdout); continue; }
            size_t hn = strlen(a);
            if (strcmp(a, "-") == 0) hn = 0;
            uint8_t *in = malloc(hn / 2);
            size_t in_len = hn / 2; int bad = 0;
            for (size_t i = 0; i < in_len; i++) {
                int hi = hexval(a[2 * i]), lo = hexval(a[2 * i + 1]);
                if (hi < 0 || lo < 0) bad = 1; else in[i] = (uint8_t)((hi << 4) | lo);
            }
            if (bad) { printf("ERR bad hex\n"); fflush(stdout); free(in); continue; }
            int16_t *coeffs = malloc(sizeof(int16_t) * NCOEF);
            int rc = comp_decode(coeffs, NCOEF, in, in_len);
            if (rc == 0) {
                uint8_t *out = malloc(2 * NCOEF);
                for (int i = 0; i < NCOEF; i++) { out[2 * i] = (uint8_t)(coeffs[i] & 0xff); out[2 * i + 1] = (uint8_t)((coeffs[i] >> 8) & 0xff); }
                printf("OK "); print_hex(out, 2 * NCOEF); printf("\n");
                free(out);
            } else if (rc == 1) printf("REJ decode refused\n");
            else printf("ERR decode rc=%d\n", rc);
            fflush(stdout); free(in); free(coeffs);
        } else {
            printf("ERR unknown command\n"); fflush(stdout);
        }
    }
    return 0;
}
