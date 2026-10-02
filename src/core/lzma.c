/*
 * LZMA / LZMA2 decoders for the PS3 Archive Manager 7z reader.
 *
 * Algorithmically ported from Igor Pavlov's public-domain LzmaDec.c and
 * Lzma2Dec.c (7-Zip): same probability layout, same range coder, same
 * state machines — reshaped into small resumable steps so the caller can
 * stop after N output bytes (UI repaint, pause/cancel) and resume.
 *
 * Probability layout (uint16_t, "base" block = 1984 entries):
 *   isMatch[256] isRep[12] isRepG0[12] isRepG1[12] isRepG2[12]
 *   isRep0Long[256] repLen[512] len[512] distSlot[256] specPos[128]
 *   align[16] literal[0x300 << (lc+lp)]
 * The len/repLen 512-entry blocks follow LzmaDec's exact offsets:
 * choice@0, choice2@8, low@posState*16, mid@posState*16+8, high@256
 * (choice bits are shared across position states; only the low/mid trees
 * are position-indexed — verified against LzmaDec.c).
 */

#include "lzma.h"

#include <stdlib.h>
#include <string.h>

#define LZ_TOP_VALUE        ((uint32_t)1 << 24)
#define LZ_BIT_MODEL_TOTAL  2048u
#define LZ_MOVE_BITS        5
#define LZ_NUM_STATES       12
#define LZ_LIT_STATES       7
#define LZ_NUM_POS_BITS_MAX 4
#define LZ_END_POS_MODEL    14
#define LZ_ALIGN_BITS       4
#define LZ_MATCH_MIN_LEN    2
#define LZ_MATCH_SPEC_LEN   274 /* == kMatchSpecLenStart: end marker */
#define LZ_BAD_REP_CODE     (0xC0000000u - 0x400u)

#define P_IS_MATCH      0
#define P_IS_REP        (P_IS_MATCH + 256)
#define P_IS_REP_G0     (P_IS_REP + 12)
#define P_IS_REP_G1     (P_IS_REP_G0 + 12)
#define P_IS_REP_G2     (P_IS_REP_G1 + 12)
#define P_IS_REP0_LONG  (P_IS_REP_G2 + 12)
#define P_REP_LEN       (P_IS_REP0_LONG + 256)
#define P_LEN           (P_REP_LEN + 512)
#define P_DIST_SLOT     (P_LEN + 512)
#define P_SPEC_POS      (P_DIST_SLOT + 256)
#define P_ALIGN         (P_SPEC_POS + 128)
#define P_LITERAL       (P_ALIGN + 16) /* == 1984 */

#define LEN_CHOICE      0
#define LEN_CHOICE2     8
#define LEN_LOW(ps)     ((ps) << 4)
#define LEN_MID(ps)     (((ps) << 4) + 8)
#define LEN_HIGH        256

enum {
    L2_CONTROL = 0, L2_UNPACK0, L2_UNPACK1, L2_PACK0, L2_PACK1,
    L2_PROP, L2_DATA, L2_DATA_CONT, L2_FINISHED
};

struct pam_lzma {
    pam_lzma_get get;
    void *gctx;
    pam_lzma_put put;
    void *wctx;

    int mode; /* 0 = raw LZMA1, 1 = LZMA2 */
    unsigned lc, lp, pb;
    unsigned pb_mask;
    uint32_t lp_mask;
    uint32_t dic_size; /* announced dictionary size          */
    uint32_t dic_buf;  /* ring = min(dic_size, out_total)    */

    uint8_t *dic;
    uint32_t dic_pos;   /* write head in the ring             */
    uint32_t flush_pos; /* bytes already handed to put()      */

    uint16_t *probs;

    /* range coder */
    uint32_t range, code;
    int rc_init;    /* range coder needs its 5 init bytes    */
    int full_init;  /* probs/state/reps need re-initialising */
    int dic_reset_pending;

    /* lzma state */
    unsigned state;
    uint32_t reps[4];
    uint32_t processed_pos;
    uint32_t check_dic_size;
    int remain_len; /* pending match bytes, or LZ_MATCH_SPEC_LEN */

    unsigned long long produced;
    unsigned long long out_total;
    unsigned long long call_start;
    int finished;
    int err; /* 1 corrupt, 2 input ended early, 3 output refused */

    /* LZMA2 framing */
    int l2_state;
    int l2_control;
    int l2_uncompressed;
    uint32_t l2_unpack; /* output bytes left in this chunk     */
    uint32_t l2_pack;   /* input bytes left of this chunk      */
    unsigned l2_need_init;
};

/* ---- construction -------------------------------------------------------- */

pam_lzma *pam_lzma_create(void)
{
    return (pam_lzma *)calloc(1, sizeof(pam_lzma));
}

void pam_lzma_destroy(pam_lzma *d)
{
    if (d == NULL)
        return;
    free(d->dic);
    free(d->probs);
    free(d);
}

static int alloc_probs(pam_lzma *d, unsigned lclp)
{
    size_t n = (size_t)P_LITERAL + ((size_t)0x300 << lclp);
    free(d->probs);
    d->probs = (uint16_t *)malloc(n * sizeof(uint16_t));
    if (d->probs == NULL)
        return -1;
    memset(d->probs, 0, n * sizeof(uint16_t)); /* filled on full_init */
    return 0;
}

static void common_init(pam_lzma *d, pam_lzma_get get, void *gctx,
                        pam_lzma_put put, void *wctx,
                        unsigned long long out_total)
{
    d->get = get;
    d->gctx = gctx;
    d->put = put;
    d->wctx = wctx;
    d->out_total = out_total;
    d->produced = 0;
    d->finished = 0;
    d->err = 0;
    d->state = 0;
    d->processed_pos = 0;
    d->check_dic_size = 0;
    d->remain_len = 0;
    d->dic_pos = 0;
    d->flush_pos = 0;
    d->range = 0xFFFFFFFFu;
    d->code = 0;
    d->rc_init = 1;
    d->full_init = 1;
    d->dic_reset_pending = 0;
}

int pam_lzma_init_lzma(pam_lzma *d, const uint8_t props[5],
                       unsigned long long out_total, pam_lzma_get get,
                       void *gctx, pam_lzma_put put, void *wctx)
{
    unsigned encoded = props[0];
    uint32_t dsz;

    if (d == NULL || encoded >= 9 * 5 * 5)
        return -1;
    d->mode = 0;
    d->lc = encoded % 9;
    encoded /= 9;
    d->pb = encoded / 5;
    d->lp = encoded % 5;
    d->pb_mask = (1u << d->pb) - 1;
    d->lp_mask = ((uint32_t)0x100 << d->lp) - ((uint32_t)0x100 >> d->lc);
    dsz = (uint32_t)props[1] | ((uint32_t)props[2] << 8) |
          ((uint32_t)props[3] << 16) | ((uint32_t)props[4] << 24);
    if (dsz < 4096)
        dsz = 4096;
    d->dic_size = dsz;

    if (alloc_probs(d, d->lc + d->lp) != 0)
        return -1;
    {
        uint32_t ring = dsz;
        if (out_total > 0 && out_total < (unsigned long long)ring)
            ring = (uint32_t)out_total;
        if (ring == 0)
            ring = 1;
        d->dic_buf = ring;
    }
    free(d->dic);
    d->dic = (uint8_t *)malloc(d->dic_buf);
    if (d->dic == NULL)
        return -1;

    common_init(d, get, gctx, put, wctx, out_total);
    d->l2_state = L2_FINISHED; /* unused in mode 0 */
    return 0;
}

static uint32_t lzma2_dic_size_from_prop(unsigned prop)
{
    if (prop > 40)
        return 0;
    if (prop == 40)
        return 0xFFFFFFFFu;
    return ((uint32_t)2 | (prop & 1)) << (prop / 2 + 11);
}

int pam_lzma_init_lzma2(pam_lzma *d, uint8_t prop,
                        unsigned long long out_total, pam_lzma_get get,
                        void *gctx, pam_lzma_put put, void *wctx)
{
    uint32_t dsz = lzma2_dic_size_from_prop(prop);

    if (d == NULL || dsz == 0)
        return -1;
    d->mode = 1;
    d->lc = 3; /* LCLP_MAX start; each chunk with props re-sets these */
    d->lp = 0;
    d->pb = 2;
    d->pb_mask = (1u << d->pb) - 1;
    d->lp_mask = ((uint32_t)0x100 << d->lp) - ((uint32_t)0x100 >> d->lc);
    d->dic_size = dsz;

    if (alloc_probs(d, 4) != 0) /* room for the max lc+lp = 4 */
        return -1;
    {
        uint32_t ring = dsz;
        if (out_total > 0 && out_total < (unsigned long long)ring)
            ring = (uint32_t)out_total;
        if (ring == 0)
            ring = 1;
        d->dic_buf = ring;
    }
    free(d->dic);
    d->dic = (uint8_t *)malloc(d->dic_buf);
    if (d->dic == NULL)
        return -1;

    common_init(d, get, gctx, put, wctx, out_total);
    d->l2_state = L2_CONTROL;
    d->l2_need_init = 0xE0;
    d->l2_uncompressed = 0;
    d->l2_control = 0;
    d->l2_unpack = 0;
    d->l2_pack = 0;
    return 0;
}

/* ---- byte input ---------------------------------------------------------- */

/* In LZMA2 compressed-data phases the payload is bounded by packSize. */
static int lb_get(pam_lzma *d)
{
    if (d->mode == 1 && !d->l2_uncompressed &&
        (d->l2_state == L2_DATA || d->l2_state == L2_DATA_CONT)) {
        if (d->l2_pack == 0) {
            d->err = 2;
            return -1;
        }
        d->l2_pack--;
    }
    {
        int b = d->get(d->gctx);
        if (b < 0)
            d->err = 2;
        return b;
    }
}

/* ---- output -------------------------------------------------------------- */

static int flush_to(pam_lzma *d)
{
    /* Emit in <= 4096-byte chunks: callers may route output per chunk and
     * need a bound on how many bytes can arrive past an entry boundary. */
    while (d->dic_pos > d->flush_pos) {
        size_t n = (size_t)(d->dic_pos - d->flush_pos);
        if (n > 4096)
            n = 4096;
        if (d->put(d->wctx, d->dic + d->flush_pos, n) != 0) {
            d->err = 3;
            return -1;
        }
        d->flush_pos += (uint32_t)n;
    }
    return 0;
}

static void dic_put(pam_lzma *d, uint8_t b)
{
    d->dic[d->dic_pos++] = b;
    d->processed_pos++;
    d->produced++;
    if (d->mode == 1)
        d->l2_unpack--;
    if (d->check_dic_size == 0 && d->processed_pos >= d->dic_size)
        d->check_dic_size = d->dic_size;
}

/* ---- range coder --------------------------------------------------------- */

static int rc_norm(pam_lzma *d)
{
    if (d->range < LZ_TOP_VALUE) {
        int b = lb_get(d);
        if (b < 0)
            return -1;
        d->range <<= 8;
        d->code = (d->code << 8) | (uint32_t)b;
    }
    return 0;
}

/* Decode one adaptive bit. Returns 0/1, or -1 (d->err set). */
static int dec_bit(pam_lzma *d, uint16_t *pp)
{
    uint32_t bound;
    unsigned ttt = *pp;

    if (rc_norm(d) != 0)
        return -1;
    bound = (d->range >> 11) * ttt;
    if (d->code < bound) {
        d->range = bound;
        *pp = (uint16_t)(ttt + ((LZ_BIT_MODEL_TOTAL - ttt) >> LZ_MOVE_BITS));
        return 0;
    }
    d->range -= bound;
    d->code -= bound;
    *pp = (uint16_t)(ttt - (ttt >> LZ_MOVE_BITS));
    return 1;
}

/* Forward canonical bit tree: limit is a power of two (1<<n). */
static int dec_tree(pam_lzma *d, uint16_t *probs, unsigned limit,
                    unsigned *out)
{
    unsigned i = 1;
    do {
        int b = dec_bit(d, probs + i);
        if (b < 0)
            return -1;
        i = (i << 1) | (unsigned)b;
    } while (i < limit);
    *out = i - limit;
    return 0;
}

/* ---- symbol decode ------------------------------------------------------- */

static int dec_len(pam_lzma *d, uint16_t *p, unsigned *out)
{
    unsigned pos_state = d->processed_pos & d->pb_mask;
    unsigned v;
    int b = dec_bit(d, p + LEN_CHOICE);

    if (b < 0)
        return -1;
    if (b == 0) {
        if (dec_tree(d, p + LEN_LOW(pos_state), 8, &v) != 0)
            return -1;
        *out = v;
        return 0;
    }
    b = dec_bit(d, p + LEN_CHOICE2);
    if (b < 0)
        return -1;
    if (b == 0) {
        if (dec_tree(d, p + LEN_MID(pos_state), 8, &v) != 0)
            return -1;
        *out = 8 + v;
        return 0;
    }
    if (dec_tree(d, p + LEN_HIGH, 256, &v) != 0)
        return -1;
    *out = 16 + v;
    return 0;
}

/* Raw (direct) range-coder bits, MSB first. */
static int dec_direct(pam_lzma *d, unsigned n, unsigned *out)
{
    unsigned v = 0;
    while (n-- > 0) {
        int bit;
        if (rc_norm(d) != 0)
            return -1;
        d->range >>= 1;
        if (d->code >= d->range) {
            d->code -= d->range;
            bit = 1;
        } else {
            bit = 0;
        }
        v = (v << 1) | (unsigned)bit;
    }
    *out = v;
    return 0;
}

/* Decode a distance symbol into the 0-based distance. */
static int dec_dist(pam_lzma *d, unsigned len_code, uint32_t *out)
{
    unsigned lts = (len_code < 4) ? len_code : 3;
    unsigned slot, num, dist;

    if (dec_tree(d, d->probs + P_DIST_SLOT + (lts << 6), 64, &slot) != 0)
        return -1;
    if (slot < 4) {
        *out = slot;
        return 0;
    }
    num = (slot >> 1) - 1;
    dist = (2u | (slot & 1));
    if (slot < LZ_END_POS_MODEL) {
        /* Reverse bit tree into specPos, base embedded in the index. */
        unsigned i, m = 1;
        dist <<= num;
        i = dist + 1;
        while (num-- > 0) {
            int b = dec_bit(d, d->probs + P_SPEC_POS + i);
            if (b < 0)
                return -1;
            if (b) {
                m += m;
                i += m;
            } else {
                i += m;
                m += m;
            }
        }
        *out = i - m;
        return 0;
    }
    {
        unsigned raw, k = 0, align = 0, m = 1;
        unsigned direct = num - LZ_ALIGN_BITS;
        if (dec_direct(d, direct, &raw) != 0)
            return -1;
        dist = (dist << direct) | raw;
        dist <<= LZ_ALIGN_BITS;
        for (k = 0; k < LZ_ALIGN_BITS; k++) {
            int b = dec_bit(d, d->probs + P_ALIGN + m);
            if (b < 0)
                return -1;
            if (b)
                align |= 1u << k;
            m = (m << 1) | (unsigned)b;
        }
        *out = dist | align;
        return 0;
    }
}

static uint32_t ring_prev(const pam_lzma *d, uint32_t dist)
{
    uint32_t p = d->dic_pos;
    return d->dic[p < dist ? p + d->dic_buf - dist : p - dist];
}

/*
 * Decode one LZMA symbol. Returns 0 (work done, keep going), 1 (stream
 * finished), -1 error.
 */
static int lzma_symbol(pam_lzma *d)
{
    unsigned pos_state = d->processed_pos & d->pb_mask;
    unsigned comb = (pos_state << 4) + d->state;
    uint32_t dist0;
    unsigned len_code;
    int bit;

    bit = dec_bit(d, d->probs + P_IS_MATCH + comb);
    if (bit < 0)
        return -1;

    if (bit == 0) {
        /* literal */
        uint16_t *lp = d->probs + P_LITERAL;
        unsigned symbol = 1;
        unsigned i;

        if (!(d->processed_pos == 0 && d->check_dic_size == 0)) {
            unsigned prev = ring_prev(d, 1);
            lp += 3 * ((((d->processed_pos << 8) + prev) & d->lp_mask)
                       << d->lc);
        }
        if (d->state < LZ_LIT_STATES) {
            d->state = (d->state < 4) ? 0 : d->state - 3;
            for (i = 0; i < 8; i++) {
                int b = dec_bit(d, lp + symbol);
                if (b < 0)
                    return -1;
                symbol = (symbol << 1) | (unsigned)b;
            }
        } else {
            unsigned match_byte = ring_prev(d, d->reps[0]);
            unsigned offs = 0x100;
            d->state = (d->state < 10) ? d->state - 3 : d->state - 6;
            for (i = 0; i < 8; i++) {
                unsigned blit;
                int b;
                match_byte += match_byte;
                blit = offs;
                offs &= match_byte;
                b = dec_bit(d, lp + offs + blit + symbol);
                if (b < 0)
                    return -1;
                symbol = (symbol << 1) | (unsigned)b;
                if (b == 0)
                    offs ^= blit;
            }
        }
        dic_put(d, (uint8_t)symbol);
        return 0;
    }

    bit = dec_bit(d, d->probs + P_IS_REP + d->state);
    if (bit < 0)
        return -1;

    if (bit == 0) {
        /* fresh match: shift rep registers, decode length + distance */
        if (dec_len(d, d->probs + P_LEN, &len_code) != 0)
            return -1;
        if (dec_dist(d, len_code, &dist0) != 0)
            return -1;
        if (dist0 >= (d->check_dic_size == 0 ? d->processed_pos
                                             : d->check_dic_size) ||
            dist0 + 1 > d->dic_buf) {
            d->err = 1; /* distance too far back */
            return -1;
        }
        d->reps[3] = d->reps[2];
        d->reps[2] = d->reps[1];
        d->reps[1] = d->reps[0];
        d->reps[0] = dist0 + 1;
        d->state = (d->state < LZ_LIT_STATES) ? 7 : 10;
        d->remain_len = (int)len_code + LZ_MATCH_MIN_LEN;
        return 0;
    }

    bit = dec_bit(d, d->probs + P_IS_REP_G0 + d->state);
    if (bit < 0)
        return -1;
    if (bit == 0) {
        bit = dec_bit(d, d->probs + P_IS_REP0_LONG + comb);
        if (bit < 0)
            return -1;
        if (bit == 0) {
            /* short rep: copy one byte */
            if (d->reps[0] > d->processed_pos && d->check_dic_size == 0) {
                d->err = 1;
                return -1;
            }
            dic_put(d, ring_prev(d, d->reps[0]));
            d->state = (d->state < LZ_LIT_STATES) ? 9 : 11;
            return 0;
        }
        /* long rep0: distance stays reps[0] */
    } else {
        uint32_t dist;
        bit = dec_bit(d, d->probs + P_IS_REP_G1 + d->state);
        if (bit < 0)
            return -1;
        if (bit == 0) {
            dist = d->reps[1];
        } else {
            bit = dec_bit(d, d->probs + P_IS_REP_G2 + d->state);
            if (bit < 0)
                return -1;
            if (bit == 0) {
                dist = d->reps[2];
            } else {
                dist = d->reps[3];
                d->reps[3] = d->reps[2];
            }
            d->reps[2] = d->reps[1];
        }
        d->reps[1] = d->reps[0];
        d->reps[0] = dist;
    }
    if (d->reps[0] > d->processed_pos && d->check_dic_size == 0) {
        d->err = 1;
        return -1;
    }
    if (dec_len(d, d->probs + P_REP_LEN, &len_code) != 0)
        return -1;
    d->state = (d->state < LZ_LIT_STATES) ? 8 : 11;
    d->remain_len = (int)len_code + LZ_MATCH_MIN_LEN;
    return 0;
}

/* ---- LZMA2 framing ------------------------------------------------------- */

static int l2_control_byte(pam_lzma *d)
{
    int b = d->get(d->gctx);

    if (b < 0) {
        d->err = 2;
        return -1;
    }
    d->l2_control = b;
    if (b == 0) {
        d->l2_state = L2_FINISHED;
        return 1;
    }
    if ((b & 0x80) == 0) {
        /* uncompressed chunk */
        if (b == 1) {
            d->l2_need_init = 0xC0;
        } else if (b > 2 || d->l2_need_init == 0xE0) {
            d->err = 1;
            return -1;
        }
        d->l2_uncompressed = 1;
    } else {
        if ((unsigned)b < d->l2_need_init) {
            d->err = 1;
            return -1;
        }
        d->l2_need_init = 0;
        d->l2_uncompressed = 0;
        d->l2_unpack = ((uint32_t)b & 0x1F) << 16;
    }
    d->l2_state = L2_UNPACK0;
    return 0;
}

/* Consume framing bytes until the chunk data phase (or the end marker).
 * Returns 0 = in data, 1 = finished, -1 = error. */
static int l2_frame(pam_lzma *d)
{
    while (d->l2_state != L2_DATA && d->l2_state != L2_DATA_CONT &&
           d->l2_state != L2_FINISHED) {
        int b = d->get(d->gctx);
        if (b < 0) {
            d->err = 2;
            return -1;
        }
        switch (d->l2_state) {
        case L2_CONTROL:
            d->err = 1;
            return -1; /* unreachable: handled by l2_control_byte */
        case L2_UNPACK0:
            d->l2_unpack |= (uint32_t)b << 8;
            d->l2_state = L2_UNPACK1;
            break;
        case L2_UNPACK1:
            d->l2_unpack |= (uint32_t)b;
            d->l2_unpack++;
            d->l2_state = d->l2_uncompressed ? L2_DATA : L2_PACK0;
            if (d->l2_state == L2_DATA)
                return 0;
            break;
        case L2_PACK0:
            d->l2_pack = (uint32_t)b << 8;
            d->l2_state = L2_PACK1;
            break;
        case L2_PACK1:
            d->l2_pack |= (uint32_t)b;
            d->l2_pack++;
            d->l2_state = (d->l2_control & 0x40) ? L2_PROP : L2_DATA;
            if (d->l2_state == L2_DATA)
                return 0;
            break;
        case L2_PROP: {
            unsigned encoded = (unsigned)b;
            unsigned lc, lp;
            if (encoded >= 9 * 5 * 5) {
                d->err = 1;
                return -1;
            }
            lc = encoded % 9;
            encoded /= 9;
            d->pb = encoded / 5;
            lp = encoded % 5;
            if (lc + lp > 4) {
                d->err = 1;
                return -1;
            }
            d->lc = lc;
            d->lp = lp;
            d->pb_mask = (1u << d->pb) - 1;
            d->lp_mask = ((uint32_t)0x100 << d->lp) -
                         ((uint32_t)0x100 >> d->lc);
            d->l2_state = L2_DATA;
            return 0;
        }
        default:
            d->err = 1;
            return -1;
        }
    }
    return d->l2_state == L2_FINISHED ? 1 : 0;
}

/* Enter the data phase of a chunk: arm the range coder / state flags. */
static void l2_enter_data(pam_lzma *d)
{
    if (d->l2_uncompressed) {
        if (d->l2_control == 1) {
            d->rc_init = 1;
            d->full_init = 1;
            d->dic_reset_pending = 1;
        }
    } else {
        d->rc_init = 1;
        d->full_init = (d->l2_control >= 0xA0);
        if (d->l2_control >= 0xE0)
            d->dic_reset_pending = 1;
    }
    d->l2_state = L2_DATA;
}

/* ---- driver -------------------------------------------------------------- */

static int rc_init_bytes(pam_lzma *d)
{
    int b = lb_get(d);
    int i;
    uint32_t code = 0;

    if (b < 0)
        return -1;
    if (b != 0) {
        d->err = 1;
        return -1;
    }
    for (i = 0; i < 4; i++) {
        b = lb_get(d);
        if (b < 0)
            return -1;
        code = (code << 8) | (uint32_t)b;
    }
    d->code = code;
    d->range = 0xFFFFFFFFu;
    if (d->processed_pos == 0 && d->check_dic_size == 0 &&
        d->code >= LZ_BAD_REP_CODE) {
        d->err = 1;
        return -1;
    }
    d->rc_init = 0;
    return 0;
}

static void full_init(pam_lzma *d)
{
    size_t n = (size_t)P_LITERAL + ((size_t)0x300 << (d->lc + d->lp));
    size_t i;
    for (i = 0; i < n; i++)
        d->probs[i] = LZ_BIT_MODEL_TOTAL >> 1;
    d->reps[0] = d->reps[1] = d->reps[2] = d->reps[3] = 1;
    d->state = 0;
    d->full_init = 0;
}

/*
 * One resumable step. Returns 0 = call again, 1 = finished, -1 = error.
 * `room` = bytes still allowed this call (>= 1, dictionary-capped).
 */
static int step(pam_lzma *d, unsigned long long room)
{
    if (d->mode == 1) {
        if (d->l2_state == L2_FINISHED)
            return 1;
        if (d->l2_state == L2_CONTROL) {
            int rc = l2_control_byte(d);
            if (rc != 0)
                return rc;
        }
        if (d->l2_state != L2_DATA && d->l2_state != L2_DATA_CONT) {
            int rc = l2_frame(d);
            if (rc != 0)
                return rc;
            l2_enter_data(d);
            return 0;
        }
        if (d->l2_uncompressed) {
            uint32_t n = d->l2_unpack;
            uint32_t i;
            if ((unsigned long long)n > room)
                n = (uint32_t)room;
            for (i = 0; i < n; i++) {
                int b = d->get(d->gctx);
                if (b < 0) {
                    d->err = 2;
                    return -1;
                }
                dic_put(d, (uint8_t)b);
            }
            if (d->l2_unpack == 0)
                d->l2_state = L2_CONTROL;
            else
                d->l2_state = L2_DATA_CONT;
            return 0;
        }
        d->l2_state = L2_DATA_CONT;
    } else {
        if (d->produced >= d->out_total)
            return 1;
    }

    if (d->dic_reset_pending) {
        d->processed_pos = 0;
        d->check_dic_size = 0;
        d->dic_reset_pending = 0;
    }
    if (d->rc_init) {
        if (rc_init_bytes(d) != 0)
            return -1;
    }
    if (d->full_init)
        full_init(d);

    if (d->remain_len > 0 && d->remain_len < LZ_MATCH_SPEC_LEN) {
        uint32_t n = (uint32_t)((room < (unsigned long long)d->remain_len)
                                    ? room
                                    : (unsigned long long)d->remain_len);
        uint32_t i;
        for (i = 0; i < n; i++) {
            dic_put(d, ring_prev(d, d->reps[0]));
            if (d->mode == 1 && d->l2_unpack == 0 &&
                d->remain_len - (int)i - 1 > 0) {
                d->err = 1; /* match crosses the chunk boundary */
                return -1;
            }
        }
        d->remain_len -= (int)n;
        return 0;
    }
    if (d->remain_len >= LZ_MATCH_SPEC_LEN)
        return d->mode == 0 ? 1 : (d->err = 1, -1);

    return lzma_symbol(d);
}

int pam_lzma_run(pam_lzma *d, unsigned long long limit)
{
    if (d == NULL)
        return -1;
    if (d->err)
        return -1;
    d->call_start = d->produced;

    for (;;) {
        unsigned long long room;
        int r;

        if (d->finished)
            break;
        if (d->mode == 1 && d->l2_state != L2_FINISHED &&
            (d->l2_state == L2_DATA || d->l2_state == L2_DATA_CONT) &&
            d->l2_unpack == 0) {
            /* chunk complete: skip any unread pack bytes, next control */
            while (d->l2_pack > 0) {
                if (lb_get(d) < 0)
                    return -1;
            }
            d->l2_state = L2_CONTROL;
            continue;
        }
        if (d->mode == 0 && d->produced >= d->out_total) {
            d->finished = 1;
            break;
        }
        if (d->dic_pos == d->dic_buf) {
            if (flush_to(d) != 0)
                return -1;
            d->dic_pos = 0;
            d->flush_pos = 0;
        }

        room = limit - (d->produced - d->call_start);
        if (room == 0) {
            if (flush_to(d) != 0)
                return -1;
            return 0;
        }
        if ((unsigned long long)(d->dic_buf - d->dic_pos) < room)
            room = (unsigned long long)(d->dic_buf - d->dic_pos);
        if (d->mode == 0 &&
            d->out_total - d->produced < room)
            room = d->out_total - d->produced;
        if (d->mode == 1 &&
            (d->l2_state == L2_DATA || d->l2_state == L2_DATA_CONT) &&
            (unsigned long long)d->l2_unpack < room)
            room = d->l2_unpack;

        r = step(d, room);
        if (r < 0)
            return -1;
        if (r > 0) {
            d->finished = 1;
            break;
        }
    }

    if (flush_to(d) != 0)
        return -1;
    return 1;
}

int pam_lzma_done(const pam_lzma *d)
{
    return d != NULL && d->finished;
}

int pam_lzma_error(const pam_lzma *d)
{
    return d != NULL ? d->err : 1;
}

unsigned long long pam_lzma_produced(const pam_lzma *d)
{
    return d != NULL ? d->produced : 0;
}
