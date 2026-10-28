/* pqcheck ML-DSA hint harness.
 * Protocol:
 *   info                       -> OK kind=hint omega=8 k=4
 *   encode_hints <r0c0,r0c1;r1c0;...>  -> OK <hex> | ERR <why>
 *   decode_hints <hex>                 -> OK <hex> | REJ <why> | ERR <why>
 * Hint block: k rows x omega index bytes (used indices strictly increasing,
 * unused bytes zero), then k cumulative offset bytes. Buffers are
 * exact-sized malloc. Define PQCHECK_EXTERNAL and link hint_encode_raw /
 * hint_decode_raw to drive a real unpack_sig surface.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#define strtok_r strtok_s
#endif

#define OMEGA 8
#define KROWS 4
#define HINT_LEN (KROWS * OMEGA + KROWS)

#ifdef PQCHECK_EXTERNAL
int hint_encode_raw(uint8_t *out, const uint8_t *rows, const uint8_t *used);
int hint_decode_raw(uint8_t *rows, uint8_t *used, const uint8_t *in, size_t in_len);
#else
static int hint_encode_raw(uint8_t *out, const uint8_t *rows, const uint8_t *used) {
    uint8_t total = 0;
    for (int r = 0; r < KROWS; r++) {
        for (int i = 0; i < OMEGA; i++) out[r * OMEGA + i] = i < used[r] ? rows[r * OMEGA + i] : 0;
        total = (uint8_t)(total + used[r]);
        out[KROWS * OMEGA + r] = total;
    }
    return 0;
}
static int hint_decode_raw(uint8_t *rows, uint8_t *used, const uint8_t *in, size_t in_len) {
    if (in_len != HINT_LEN) return 1;
    uint8_t prev = 0;
    for (int r = 0; r < KROWS; r++) {
        uint8_t off = in[KROWS * OMEGA + r];
        if (off < prev || off - prev > OMEGA) return 1;
        used[r] = (uint8_t)(off - prev); prev = off;
        for (int i = 0; i < used[r]; i++) {
            rows[r * OMEGA + i] = in[r * OMEGA + i];
            if (i && rows[r * OMEGA + i] <= rows[r * OMEGA + i - 1]) return 1;
        }
        for (int i = used[r]; i < OMEGA; i++) if (in[r * OMEGA + i] != 0) return 1;
    }
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
            printf("OK kind=hint omega=%d k=%d\n", OMEGA, KROWS); fflush(stdout);
        } else if (strcmp(cmd, "encode_hints") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save);
            uint8_t *rows = calloc(KROWS * OMEGA, 1), *used = calloc(KROWS, 1);
            uint8_t *out = malloc(HINT_LEN);
            if (a) {
                int r = 0;
                char *row_save = NULL;
                char *row = strtok_r(a, ";", &row_save);
                while (row && r < KROWS) {
                    char *c_save = NULL; int n = 0;
                    char *c = strtok_r(row, ",", &c_save);
                    while (c && n < OMEGA) { rows[r * OMEGA + n++] = (uint8_t)strtol(c, NULL, 10); c = strtok_r(NULL, ",", &c_save); }
                    used[r++] = (uint8_t)n;
                    row = strtok_r(NULL, ";", &row_save);
                }
            }
            int rc = hint_encode_raw(out, rows, used);
            if (rc == 0) { printf("OK "); print_hex(out, HINT_LEN); printf("\n"); }
            else printf("ERR encode_hints rc=%d\n", rc);
            fflush(stdout); free(rows); free(used); free(out);
        } else if (strcmp(cmd, "decode_hints") == 0) {
            char *a = strtok_r(NULL, " \r\n", &save);
            if (!a) { printf("ERR decode_hints needs hex\n"); fflush(stdout); continue; }
            size_t in_len = strlen(a) / 2;
            uint8_t *in = malloc(in_len ? in_len : 1); int bad = 0;
            for (size_t i = 0; i < in_len; i++) {
                int hi = hexval(a[2 * i]), lo = hexval(a[2 * i + 1]);
                if (hi < 0 || lo < 0) bad = 1; else in[i] = (uint8_t)((hi << 4) | lo);
            }
            if (bad) { printf("ERR bad hex\n"); fflush(stdout); free(in); continue; }
            uint8_t *rows = calloc(KROWS * OMEGA, 1), *used = calloc(KROWS, 1);
            int rc = hint_decode_raw(rows, used, in, in_len);
            if (rc == 0) {
                uint8_t *out = malloc(HINT_LEN);
                hint_encode_raw(out, rows, used);
                printf("OK "); print_hex(out, HINT_LEN); printf("\n");
                free(out);
            } else if (rc == 1) printf("REJ decode_hints refused\n");
            else printf("ERR decode_hints rc=%d\n", rc);
            fflush(stdout); free(in); free(rows); free(used);
        } else {
            printf("ERR unknown command\n"); fflush(stdout);
        }
    }
    return 0;
}
