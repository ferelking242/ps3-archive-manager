#ifndef PAM_INFLATE_H
#define PAM_INFLATE_H

#include <stddef.h>
#include <stdint.h>

/*
 * PS3 Archive Manager — streaming DEFLATE (RFC 1951) decompressor.
 *
 * Dependency-free (no zlib: the same code runs on the host test suite and
 * on the PS3 PPU). The decoder is resumable: pam_inflate_run() decodes
 * until the block stream ends, until `limit` bytes were produced this
 * call (so the UI can repaint / honour pause-cancel), or on error.
 *
 * Input is pulled one byte at a time through get(); output is pushed in
 * chunks through put(). The bit reader never reads past the byte that
 * holds the final bit of the stream, so the caller's stream sits exactly
 * after the entry when the decoder reports completion.
 */

/* Pull one input byte: return 0..255, negative at EOF/error. */
typedef int (*pam_inflate_get)(void *ctx);
/* Push decompressed bytes: return 0 on success, nonzero aborts. */
typedef int (*pam_inflate_put)(void *ctx, const uint8_t *buf, size_t n);

typedef struct {
    uint16_t count[16];  /* number of codes of each length  */
    uint16_t symbol[288]; /* symbols in canonical order     */
} pam_huff;

enum {
    PAM_INFL_BLKHDR = 0, /* read BFINAL/BTYPE                     */
    PAM_INFL_STORED_HDR, /* read LEN/NLEN after byte alignment    */
    PAM_INFL_STORED,     /* copy stored bytes                     */
    PAM_INFL_DECODE,     /* decode literal/length symbols         */
    PAM_INFL_LENEXT,     /* read length extra bits                */
    PAM_INFL_DIST,       /* decode distance symbol                */
    PAM_INFL_DISTEXT,    /* read distance extra bits              */
    PAM_INFL_MATCH,      /* copy match bytes from the window      */
    PAM_INFL_DONE,
    PAM_INFL_BAD
};

typedef struct {
    pam_inflate_get get;
    pam_inflate_put put;
    void *ctx;

    int mode;
    int last_block;
    uint32_t bitbuf;
    int bitcnt; /* always < 8 between operations */

    /* stored block */
    uint32_t stored_left;

    /* dynamic table build scratch */
    int build_pos;          /* next length to fill in lengths[]   */
    int build_rep;          /* remaining repeats of 16/17/18      */
    int build_rep_sym;
    int hlit, hdist, hclen, nlen, ndist, ncode;
    uint8_t lengths[320];

    pam_huff litlen, dist, clen;

    /* current symbol */
    unsigned len_val;   /* match length                          */
    unsigned dist_val;  /* match distance                        */
    int len_extra, dist_extra;
    unsigned match_left;
    unsigned match_dist;

    /* output */
    uint8_t window[32768];
    uint32_t wpos;
    uint8_t out[4096];
    size_t out_len;
    unsigned long long produced; /* total for the current stream  */

    int err; /* 1 = corrupt data, 2 = input ended early, 3 = output error */
} pam_inflate_t;

void pam_inflate_init(pam_inflate_t *d, pam_inflate_get get,
                      pam_inflate_put put, void *ctx);

/*
 * Decode until the stream ends, until `limit` bytes were produced by this
 * call, or on error. Returns 1 = stream finished, 0 = yield (call again),
 * -1 = error (see d->err: 1 corrupt, 2 truncated input, 3 output refused).
 */
int pam_inflate_run(pam_inflate_t *d, unsigned long long limit);

int pam_inflate_done(const pam_inflate_t *d);
int pam_inflate_error(const pam_inflate_t *d);
unsigned long long pam_inflate_produced(const pam_inflate_t *d);

#endif /* PAM_INFLATE_H */
