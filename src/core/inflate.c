#include "inflate.h"

#include <string.h>

/* ---- bit reader ---------------------------------------------------------- */
/*
 * Bits are consumed LSB-first, one byte at a time, so after every call the
 * buffer holds less than one byte: at the end of the stream the reader has
 * consumed exactly the bytes of the entry (the last one partly) and the
 * caller's stream sits on the next ZIP structure. No push-back needed.
 */
static int ensure(pam_inflate_t *d, int n)
{
    while (d->bitcnt < n) {
        int b = d->get(d->ctx);
        if (b < 0) {
            d->err = 2; /* input ended early */
            return -1;
        }
        d->bitbuf |= (uint32_t)b << d->bitcnt;
        d->bitcnt += 8;
    }
    return 0;
}

static uint32_t bits(pam_inflate_t *d, int n)
{
    uint32_t v = d->bitbuf & ((1u << n) - 1u);
    d->bitbuf >>= n;
    d->bitcnt -= n;
    return v;
}

/* ---- huffman tables ------------------------------------------------------ */

/*
 * Build canonical decode tables from code lengths. Returns 0 for a complete
 * set, <0 when over-subscribed, >0 when incomplete (usable only in the
 * degenerate single-symbol case — see huff_incomplete_ok).
 */
static int huff_build(pam_huff *h, const uint8_t *lengths, int n)
{
    int symbol, len, left;
    uint16_t offs[16];

    for (len = 0; len < 16; len++)
        h->count[len] = 0;
    for (symbol = 0; symbol < n; symbol++)
        h->count[lengths[symbol]]++;
    if (h->count[0] == n)
        return 0; /* no codes at all */

    left = 1;
    for (len = 1; len < 16; len++) {
        left <<= 1;
        left -= h->count[len];
        if (left < 0)
            return left;
    }

    offs[1] = 0;
    for (len = 1; len < 15; len++)
        offs[len + 1] = (uint16_t)(offs[len] + h->count[len]);
    for (symbol = 0; symbol < n; symbol++)
        if (lengths[symbol] != 0)
            h->symbol[offs[lengths[symbol]]++] = (uint16_t)symbol;
    return left;
}

/* Incomplete tables are tolerated only for a single 1-bit code (the case
 * real encoders emit when a table has one symbol). */
static int huff_incomplete_ok(const pam_huff *h, int n)
{
    int nonzero = n - h->count[0];
    return nonzero == 1 && h->count[1] == 1;
}

/* Decode one symbol; negative = error (d->err set: 1 corrupt, 2 truncated). */
static int huff_decode(pam_inflate_t *d, const pam_huff *h)
{
    int code = 0, first = 0, index = 0, len;

    for (len = 1; len <= 15; len++) {
        int count;
        if (ensure(d, 1) != 0)
            return -1;
        code |= (int)(d->bitbuf & 1u);
        d->bitbuf >>= 1;
        d->bitcnt -= 1;
        count = h->count[len];
        if (code - count < first)
            return h->symbol[index + (code - first)];
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    d->err = 1; /* ran out of codes: invalid input */
    return -2;
}

/* ---- block headers ------------------------------------------------------- */

static const uint16_t LEN_BASE[29] = {
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
    67, 83, 99, 115, 131, 163, 195, 227, 258
};
static const uint8_t LEN_EXTRA[29] = {
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
    4, 4, 4, 4, 5, 5, 5, 5, 0
};
static const uint16_t DIST_BASE[30] = {
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
    769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577
};
static const uint8_t DIST_EXTRA[30] = {
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
    7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13
};
static const uint8_t CLEN_ORDER[19] = {
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15
};

static int build_fixed(pam_inflate_t *d)
{
    uint8_t lengths[288];
    int i;

    for (i = 0; i < 144; i++)
        lengths[i] = 8;
    for (; i < 256; i++)
        lengths[i] = 9;
    for (; i < 280; i++)
        lengths[i] = 7;
    for (; i < 288; i++)
        lengths[i] = 8;
    if (huff_build(&d->litlen, lengths, 288) < 0)
        return -1;

    for (i = 0; i < 30; i++)
        lengths[i] = 5;
    /* The fixed distance table is deliberately incomplete (2 of the 32
     * five-bit codes are invalid); over-subscription is still fatal. */
    if (huff_build(&d->dist, lengths, 30) < 0)
        return -1;
    return 0;
}

static int build_dynamic(pam_inflate_t *d)
{
    int pos, i, rc;

    if (ensure(d, 14) != 0)
        return -1;
    d->hlit = (int)bits(d, 5) + 257;
    d->hdist = (int)bits(d, 5) + 1;
    d->hclen = (int)bits(d, 4) + 4;
    d->nlen = d->hlit;
    d->ndist = d->hdist;
    d->ncode = d->hclen;

    /* Code-length alphabet (19 symbols, stored 3 bits each in CLEN_ORDER). */
    memset(d->lengths, 0, sizeof(d->lengths));
    for (i = 0; i < 19; i++)
        d->lengths[i] = 0;
    for (i = 0; i < d->ncode; i++) {
        if (ensure(d, 3) != 0)
            return -1;
        d->lengths[CLEN_ORDER[i]] = (uint8_t)bits(d, 3);
    }
    d->lengths[19] = 0; /* guard byte stays unused by the build below */
    rc = huff_build(&d->clen, d->lengths, 19);
    if (rc < 0 || (rc > 0 && !huff_incomplete_ok(&d->clen, 19))) {
        d->err = 1;
        return -1;
    }

    /* Expand nlen + ndist code lengths through the code-length alphabet. */
    memset(d->lengths, 0, sizeof(d->lengths));
    pos = 0;
    while (pos < d->nlen + d->ndist) {
        int s = huff_decode(d, &d->clen);
        int rep;
        if (s < 0)
            return -1;
        if (s < 16) {
            d->lengths[pos++] = (uint8_t)s;
            continue;
        }
        if (s == 16) {
            uint8_t prev;
            if (pos == 0) {
                d->err = 1;
                return -1;
            }
            prev = d->lengths[pos - 1];
            if (ensure(d, 2) != 0)
                return -1;
            rep = 3 + (int)bits(d, 2);
            while (rep-- > 0) {
                if (pos >= d->nlen + d->ndist)
                    break;
                d->lengths[pos++] = prev;
            }
            continue;
        }
        if (ensure(d, s == 17 ? 3 : 7) != 0)
            return -1;
        rep = (s == 17) ? 3 + (int)bits(d, 3) : 11 + (int)bits(d, 7);
        while (rep-- > 0) {
            if (pos >= d->nlen + d->ndist)
                break;
            d->lengths[pos++] = 0;
        }
    }
    if (pos != d->nlen + d->ndist) {
        d->err = 1;
        return -1;
    }

    /* Literal/length table: complete (or the single-symbol case) and it
     * must contain the end-of-block symbol. */
    if (d->lengths[256] == 0) {
        d->err = 1;
        return -1;
    }
    rc = huff_build(&d->litlen, d->lengths, d->nlen);
    if (rc < 0 || (rc > 0 && !huff_incomplete_ok(&d->litlen, d->nlen))) {
        d->err = 1;
        return -1;
    }

    /* Distance table: complete, empty, or the single-symbol case. */
    rc = huff_build(&d->dist, d->lengths + d->nlen, d->ndist);
    if (rc < 0 || (rc > 0 && !huff_incomplete_ok(&d->dist, d->ndist))) {
        d->err = 1;
        return -1;
    }
    return 0;
}

/* ---- output -------------------------------------------------------------- */

static int flush(pam_inflate_t *d)
{
    if (d->out_len == 0)
        return 0;
    if (d->put(d->ctx, d->out, d->out_len) != 0) {
        d->err = 3;
        return -1;
    }
    d->out_len = 0;
    return 0;
}

static void emit(pam_inflate_t *d, uint8_t b)
{
    d->window[d->wpos++ & 32767u] = b;
    d->out[d->out_len++] = b;
    d->produced++;
}

/* ---- driver -------------------------------------------------------------- */

void pam_inflate_init(pam_inflate_t *d, pam_inflate_get get,
                      pam_inflate_put put, void *ctx)
{
    memset(d, 0, sizeof(*d));
    d->get = get;
    d->put = put;
    d->ctx = ctx;
    d->mode = PAM_INFL_BLKHDR;
}

int pam_inflate_run(pam_inflate_t *d, unsigned long long limit)
{
    const unsigned long long start = d->produced;

    if (d->mode == PAM_INFL_BAD)
        return -1;
    if (d->mode == PAM_INFL_DONE) {
        if (flush(d) != 0)
            return -1;
        return 1;
    }

    for (;;) {
        if (d->mode == PAM_INFL_DONE) {
            if (flush(d) != 0)
                return -1;
            return 1;
        }
        if (d->mode == PAM_INFL_BAD)
            return -1;

        if (d->mode == PAM_INFL_BLKHDR) {
            uint32_t hdr;
            if (ensure(d, 3) != 0)
                goto input_bad;
            hdr = bits(d, 3);
            d->last_block = (int)(hdr & 1u);
            hdr >>= 1;
            if (hdr == 0) { /* stored */
                d->bitbuf = 0;
                d->bitcnt = 0; /* byte alignment: drop leftover bits */
                if (ensure(d, 32) != 0)
                    goto input_bad;
                {
                    uint32_t len = bits(d, 16);
                    uint32_t nlen = bits(d, 16);
                    if ((len ^ 0xFFFFu) != nlen) {
                        d->err = 1;
                        goto bad;
                    }
                    d->stored_left = len;
                }
                d->mode = PAM_INFL_STORED;
                continue;
            }
            if (hdr == 1) {
                if (build_fixed(d) != 0) {
                    d->err = 1;
                    goto bad;
                }
                d->mode = PAM_INFL_DECODE;
                continue;
            }
            if (hdr == 2) {
                if (build_dynamic(d) != 0)
                    goto io_or_bad;
                d->mode = PAM_INFL_DECODE;
                continue;
            }
            d->err = 1;
            goto bad;
        }

        if (d->mode == PAM_INFL_STORED) {
            while (d->stored_left > 0) {
                uint32_t n;
                if (d->produced - start >= limit) {
                    if (flush(d) != 0)
                        goto bad;
                    return 0;
                }
                if (d->out_len == sizeof(d->out) && flush(d) != 0)
                    goto bad;
                n = d->stored_left;
                if (n > sizeof(d->out) - d->out_len)
                    n = (uint32_t)(sizeof(d->out) - d->out_len);
                while (n-- > 0) {
                    int b = d->get(d->ctx);
                    if (b < 0) {
                        d->err = 2;
                        goto bad;
                    }
                    emit(d, (uint8_t)b);
                    d->stored_left--;
                }
            }
            d->mode = d->last_block ? PAM_INFL_DONE : PAM_INFL_BLKHDR;
            continue;
        }

        if (d->mode == PAM_INFL_DECODE) {
            for (;;) {
                int sym, dsym;

                if (d->produced - start >= limit) {
                    if (flush(d) != 0)
                        goto bad;
                    return 0;
                }
                /* Room for one literal plus a full match before flushing. */
                if (d->out_len + 300 > sizeof(d->out) && flush(d) != 0)
                    goto bad;

                sym = huff_decode(d, &d->litlen);
                if (sym < 0)
                    goto io_or_bad;
                if (sym < 256) {
                    emit(d, (uint8_t)sym);
                    continue;
                }
                if (sym == 256) {
                    d->mode = d->last_block ? PAM_INFL_DONE : PAM_INFL_BLKHDR;
                    break;
                }
                sym -= 257;
                if (sym >= 29) {
                    d->err = 1;
                    goto bad;
                }
                d->len_val = LEN_BASE[sym];
                if (LEN_EXTRA[sym] && ensure(d, LEN_EXTRA[sym]) != 0)
                    goto input_bad;
                d->len_val += bits(d, LEN_EXTRA[sym]);

                dsym = huff_decode(d, &d->dist);
                if (dsym < 0)
                    goto io_or_bad;
                if (dsym >= 30) {
                    d->err = 1;
                    goto bad;
                }
                d->dist_val = DIST_BASE[dsym];
                if (DIST_EXTRA[dsym] && ensure(d, DIST_EXTRA[dsym]) != 0)
                    goto input_bad;
                d->dist_val += bits(d, DIST_EXTRA[dsym]);

                if (d->dist_val == 0 || d->dist_val > d->produced) {
                    d->err = 1; /* distance too far back */
                    goto bad;
                }
                d->match_left = d->len_val;
                d->match_dist = d->dist_val;
                while (d->match_left-- > 0) {
                    uint32_t src = (d->wpos - d->match_dist) & 32767u;
                    emit(d, d->window[src]);
                }
            }
            continue;
        }

        d->err = 1; /* unreachable state */
        goto bad;
    }

input_bad:
    if (d->err == 0)
        d->err = 2;
bad:
    d->mode = PAM_INFL_BAD;
    return -1;

io_or_bad:
    if (d->err == 0)
        d->err = 1;
    goto bad;
}

int pam_inflate_done(const pam_inflate_t *d)
{
    return d->mode == PAM_INFL_DONE;
}

int pam_inflate_error(const pam_inflate_t *d)
{
    return d->mode == PAM_INFL_BAD ? d->err : 0;
}

unsigned long long pam_inflate_produced(const pam_inflate_t *d)
{
    return d->produced;
}
