/*
 * PS3 Archive Manager — 7z reader.
 *
 * Container parsing follows the official 7z format document (DOC/7zFormat):
 * signature header, optional ENCODED_HEADER (itself a StreamsInfo whose
 * folder holds the real header), PackInfo/UnpackInfo/SubStreamsInfo,
 * FilesInfo properties. Folder data is decoded on the fly through the
 * shared resumable decoders (lzma.c / inflate.c) — nothing is loaded
 * into RAM beyond the header and one dictionary.
 *
 * Solid folders are streamed in file order: each substream (one file's
 * slice of a folder) is decoded when the caller reaches it, and entries
 * the caller skips are drained so the decoder stays in sync.
 *
 * Decoder output arrives in chunks of at most 4096 bytes (lzma.c flushes
 * that way, the inflater's out[] is 4096, the Copy coder copies 4096).
 * Bytes that arrive after the current entry ended are held in a bounded
 * pending FIFO and handed to the next entry — that is what lets a solid
 * folder be extracted entry by entry without a whole-folder buffer.
 *
 * Coder support: Copy (0x00), LZMA (0x030101), LZMA2 (0x21), Deflate
 * (0x040108) — single coders or paired with the x86 BCJ (0x03030103) or
 * Delta (0x03) filters. Anything else (PPMd, BZip2, other BCJ variants)
 * is reported as unsupported; AES (0x06F10701) as encrypted.
 */

#include "sevenzip.h"

#include "crc32.h"
#include "inflate.h"
#include "lzma.h"
#include "stream.h"

#include <stdlib.h>
#include <string.h>

#ifdef P7Z_TRACE
#include <stdio.h>
#define P7Z_T(...) fprintf(stderr, __VA_ARGS__)
#else
#define P7Z_T(...) do { } while (0)
#endif

#define P7Z_SIG_LEN        32
#define P7Z_MAX_FILES      32768
#define P7Z_MAX_FOLDERS    32768
#define P7Z_MAX_PACK       65536
#define P7Z_MAX_SUBS       65536
#define P7Z_MAX_CODERS     16
#define P7Z_MAX_STREAMS    1024 /* total in/out streams per folder */
#define P7Z_MAX_HEADER     (64u * 1024u * 1024u)
#define P7Z_PEND           8192
#define P7Z_SLACK          2048 /* run overshoot bound past an entry end */

/* NIDs from the 7z format document. */
enum {
    NID_END = 0x00,
    NID_HEADER = 0x01,
    NID_ARCHIVE_PROPERTIES = 0x02,
    NID_ADDITIONAL_STREAMS_INFO = 0x03,
    NID_MAIN_STREAMS_INFO = 0x04,
    NID_FILES_INFO = 0x05,
    NID_PACK_INFO = 0x06,
    NID_UNPACK_INFO = 0x07,
    NID_SUBSTREAMS_INFO = 0x08,
    NID_SIZE = 0x09,
    NID_CRC = 0x0A,
    NID_FOLDER = 0x0B,
    NID_CODERS_UNPACK_SIZE = 0x0C,
    NID_NUM_UNPACK_STREAM = 0x0D,
    NID_EMPTY_STREAM = 0x0E,
    NID_EMPTY_FILE = 0x0F,
    NID_ANTI = 0x10,
    NID_NAME = 0x11,
    NID_ATTRIBUTES = 0x15,
    NID_ENCODED_HEADER = 0x17
};

enum { DK_COPY = 0, DK_LZMA, DK_LZMA2, DK_DEFLATE };
enum { FILT_NONE = 0, FILT_X86, FILT_DELTA };

/* ---- data model --------------------------------------------------------- */

typedef struct {
    uint8_t id[16];
    unsigned id_size;
    uint64_t num_in, num_out;
    uint8_t props[256];
    unsigned props_size;
} p7z_coder;

typedef struct {
    p7z_coder *coders;
    unsigned num_coders;
    uint64_t num_in, num_out;
    uint64_t *binds;     /* pairs (in,out), flat stream indices */
    unsigned num_binds;
    uint64_t *packed;    /* packed input stream indices          */
    unsigned num_packed;
    uint64_t *outsz;     /* per flat output stream               */
    uint64_t unpack_size;/* folder output (root) size            */
    uint32_t crc;
    unsigned char crc_defined;
    unsigned char err;   /* 0 ok, 1 corrupt, 2 unsupported, 3 encrypted */
    unsigned char chain; /* 0 single coder, 1 comp→filter, 2 filter→comp */
    uint64_t pack_stream;/* first pack stream (assigned)         */
    uint64_t first_sub;  /* first substream index (assigned)     */
    uint64_t num_subs;
} p7z_folder;

typedef struct {
    uint64_t packpos, numpack;
    uint64_t *packsize;
    unsigned numfolders;
    p7z_folder *folders;
    uint64_t nsubs;
    uint64_t *sub_size;
    uint32_t *sub_crc;
    unsigned char *sub_known;
    unsigned *sub_folder;
} p7z_si;

typedef struct {
    char name[512];
    uint64_t size;
    uint32_t crc;
    uint64_t sub;
    unsigned char crc_known, is_dir, has_stream;
} p7z_file;

typedef struct {
    int kind;
    pam_stream *s;
    uint64_t pack_left;
    uint64_t out_total;
    unsigned long long produced;
    int finished;
    int err; /* 1 corrupt, 2 input ended early, 3 output refused */
    pam_lzma *lz;
    pam_inflate_t *inf;
    int (*sink)(void *user, const uint8_t *buf, size_t n);
    void *user;
    /* post-filter stage (0 none, 1 x86 BCJ, 2 Delta) */
    int filt;
    uint32_t bcj_state;
    uint64_t bcj_ip;
    uint8_t carry[8];
    unsigned carry_len;
    uint8_t d_hist[256];
    unsigned d_dist;
    uint64_t d_pos;
} p7z_dec;

struct pam7z_cursor {
    pam_stream s;
    p7z_si si;
    p7z_file *files;
    unsigned numfiles;

    unsigned cur_file;
    int have_entry;
    int entry_done;
    uint64_t entry_left;
    uint32_t crc;         /* running CRC of the current entry */
    uint32_t want_crc;    /* stored CRC of the current entry  */
    unsigned char want_known;
    FILE *efp;            /* output file while extract_current runs */

    uint8_t pend[P7Z_PEND];
    size_t pend_len, pend_pos;

    int fold;             /* folder the decoder is positioned on, -1 none */
    p7z_dec dec;

    int broken;           /* sticky error returned by next() */
};

/* ---- header reader (in-memory blob) ------------------------------------- */

typedef struct {
    const uint8_t *b;
    size_t n, i;
} hrd;

static int h_u8(hrd *h, uint8_t *v)
{
    if (h->i >= h->n)
        return -1;
    *v = h->b[h->i++];
    return 0;
}

/* 7z UINT64: first byte's high bits count the following raw bytes. */
static int h_number(hrd *h, uint64_t *v)
{
    uint64_t value = 0;
    uint8_t first, mask = 0x80;
    unsigned i;

    if (h_u8(h, &first) != 0)
        return -1;
    for (i = 0; i < 8; i++) {
        if ((first & mask) == 0) {
            value |= (uint64_t)(first & (uint8_t)(mask - 1)) << (8 * i);
            break;
        }
        if (h->i >= h->n)
            return -1;
        value |= (uint64_t)h->b[h->i++] << (8 * i);
        mask >>= 1;
    }
    *v = value;
    return 0;
}

static int h_bytes(hrd *h, void *dst, size_t n)
{
    if (h->n - h->i < n)
        return -1;
    memcpy(dst, h->b + h->i, n);
    h->i += n;
    return 0;
}

static int h_skip(hrd *h, uint64_t n)
{
    if (n > (uint64_t)(h->n - h->i))
        return -1;
    h->i += (size_t)n;
    return 0;
}

static int h_u32(hrd *h, uint32_t *v)
{
    uint8_t buf[4];

    if (h_bytes(h, buf, 4) != 0)
        return -1;
    *v = (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
         ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
    return 0;
}

/* Digests / attributes / times: AllAreDefined byte, then MSB-first bits. */
static int h_bools(hrd *h, size_t count, unsigned char *out)
{
    uint8_t all;
    size_t bytes = (count + 7) / 8, k;

    if (h_u8(h, &all) != 0)
        return -1;
    if (all != 0) {
        if (out != NULL)
            memset(out, 1, count);
        return 0;
    }
    if (h->n - h->i < bytes)
        return -1;
    for (k = 0; k < count; k++) {
        if (out != NULL)
            out[k] = (unsigned char)((h->b[h->i + k / 8] >> (7 - (k % 8))) & 1);
    }
    h->i += bytes;
    return 0;
}

/* kEmptyStream / kEmptyFile / kAnti: raw MSB-first bits, no prefix byte. */
static int h_bits_raw(hrd *h, size_t count, unsigned char *out)
{
    size_t bytes = (count + 7) / 8, k;

    if (h->n - h->i < bytes)
        return -1;
    for (k = 0; k < count; k++) {
        if (out != NULL)
            out[k] = (unsigned char)((h->b[h->i + k / 8] >> (7 - (k % 8))) & 1);
    }
    h->i += bytes;
    return 0;
}

/* ---- UTF-16LE names ------------------------------------------------------ */

static void put_utf8(char *out, size_t cap, size_t *o, uint32_t cp)
{
    uint8_t tmp[4];
    int n, k;

    if (cp < 0x80) {
        tmp[0] = (uint8_t)cp;
        n = 1;
    } else if (cp < 0x800) {
        tmp[0] = (uint8_t)(0xC0 | (cp >> 6));
        tmp[1] = (uint8_t)(0x80 | (cp & 0x3F));
        n = 2;
    } else if (cp < 0x10000) {
        tmp[0] = (uint8_t)(0xE0 | (cp >> 12));
        tmp[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        tmp[2] = (uint8_t)(0x80 | (cp & 0x3F));
        n = 3;
    } else {
        tmp[0] = (uint8_t)(0xF0 | (cp >> 18));
        tmp[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
        tmp[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        tmp[3] = (uint8_t)(0x80 | (cp & 0x3F));
        n = 4;
    }
    for (k = 0; k < n; k++) {
        if (*o + 1 < cap)
            out[(*o)++] = (char)tmp[k];
    }
}

/* Read one NUL-terminated UTF-16LE name; long names are truncated. */
static int h_name(hrd *h, char *out, size_t cap)
{
    size_t o = 0;

    if (cap == 0)
        return -1;
    for (;;) {
        uint32_t u, cp;

        if (h->n - h->i < 2)
            return -1;
        u = (uint32_t)h->b[h->i] | ((uint32_t)h->b[h->i + 1] << 8);
        h->i += 2;
        if (u == 0)
            break;
        cp = u;
        if (u >= 0xD800 && u <= 0xDBFF) {
            uint32_t u2;
            if (h->n - h->i < 2)
                return -1;
            u2 = (uint32_t)h->b[h->i] | ((uint32_t)h->b[h->i + 1] << 8);
            h->i += 2;
            if (u2 < 0xDC00 || u2 > 0xDFFF)
                return -1;
            cp = 0x10000u + ((u - 0xD800u) << 10) + (u2 - 0xDC00u);
        } else if (u >= 0xDC00 && u <= 0xDFFF) {
            return -1;
        }
        put_utf8(out, cap, &o, cp);
    }
    out[o] = '\0';
    return 0;
}

/* ---- folders / streams info ---------------------------------------------- */

static int parse_folder(hrd *h, p7z_folder *f)
{
    uint64_t n, j;

    memset(f, 0, sizeof(*f));
    if (h_number(h, &n) != 0 || n == 0 || n > P7Z_MAX_CODERS)
        return -1;
    f->num_coders = (unsigned)n;
    f->coders = (p7z_coder *)calloc(f->num_coders, sizeof(p7z_coder));
    if (f->coders == NULL)
        return -1;

    for (j = 0; j < f->num_coders; j++) {
        p7z_coder *co = &f->coders[j];
        uint8_t flags;

        if (h_u8(h, &flags) != 0)
            return -1;
        co->id_size = flags & 0x0F;
        if (co->id_size > sizeof(co->id))
            return -1;
        if (h_bytes(h, co->id, co->id_size) != 0)
            return -1;
        if ((flags & 0x10) != 0) {
            if (h_number(h, &co->num_in) != 0 ||
                h_number(h, &co->num_out) != 0)
                return -1;
            if (co->num_in == 0 || co->num_out == 0 ||
                co->num_in > P7Z_MAX_STREAMS || co->num_out > P7Z_MAX_STREAMS)
                return -1;
        } else {
            co->num_in = 1;
            co->num_out = 1;
        }
        f->num_in += co->num_in;
        f->num_out += co->num_out;
        if (f->num_in > P7Z_MAX_STREAMS || f->num_out > P7Z_MAX_STREAMS)
            return -1;
        if ((flags & 0x20) != 0) {
            uint64_t pl;
            if (h_number(h, &pl) != 0)
                return -1;
            if (pl > (uint64_t)(h->n - h->i))
                return -1;
            if (pl <= sizeof(co->props)) {
                if (h_bytes(h, co->props, (size_t)pl) != 0)
                    return -1;
                co->props_size = (unsigned)pl;
            } else {
                /* Oversized properties cannot be a coder we support. */
                if (h_skip(h, pl) != 0)
                    return -1;
                co->props_size = (unsigned)-1;
            }
        }
    }

    if (f->num_out < 1)
        return -1;
    f->num_binds = (unsigned)(f->num_out - 1);
    if (f->num_binds > 0) {
        f->binds = (uint64_t *)calloc((size_t)f->num_binds * 2, sizeof(uint64_t));
        if (f->binds == NULL)
            return -1;
        for (j = 0; j < f->num_binds; j++) {
            if (h_number(h, &f->binds[j * 2]) != 0 ||
                h_number(h, &f->binds[j * 2 + 1]) != 0)
                return -1;
            if (f->binds[j * 2] >= f->num_in ||
                f->binds[j * 2 + 1] >= f->num_out)
                return -1;
        }
    }

    if (f->num_in < (uint64_t)f->num_binds)
        return -1;
    f->num_packed = (unsigned)(f->num_in - f->num_binds);
    if (f->num_packed == 0)
        return -1;
    f->packed = (uint64_t *)calloc(f->num_packed, sizeof(uint64_t));
    if (f->packed == NULL)
        return -1;
    if (f->num_packed == 1) {
        /* The single packed index is the input not used by any bind. */
        uint64_t i;
        int found = 0;
        for (i = 0; i < f->num_in; i++) {
            unsigned b;
            int bound = 0;
            for (b = 0; b < f->num_binds; b++) {
                if (f->binds[b * 2] == i) {
                    bound = 1;
                    break;
                }
            }
            if (!bound) {
                f->packed[0] = i;
                found = 1;
                break;
            }
        }
        if (!found)
            return -1;
    } else {
        for (j = 0; j < f->num_packed; j++) {
            if (h_number(h, &f->packed[j]) != 0 ||
                f->packed[j] >= f->num_in)
                return -1;
        }
    }
    return 0;
}

static int id_eq(const p7z_coder *co, const uint8_t *id, unsigned n)
{
    return co->id_size == n && memcmp(co->id, id, n) == 0;
}

/* DK_* coder kind, or -1 when the id/property combination is not one we
 * can decode. */
static int coder_kind(const p7z_coder *co)
{
    if (co->id_size == 1 && co->id[0] == 0x00 && co->props_size == 0)
        return DK_COPY;
    if (co->id_size == 3 && co->id[0] == 0x03 && co->id[1] == 0x01 &&
        co->id[2] == 0x01 && co->props_size == 5)
        return DK_LZMA;
    if (co->id_size == 1 && co->id[0] == 0x21 && co->props_size == 1)
        return DK_LZMA2;
    if (co->id_size == 3 && co->id[0] == 0x04 && co->id[1] == 0x01 &&
        co->id[2] == 0x08 && co->props_size == 0)
        return DK_DEFLATE;
    return -1;
}

/* FILT_* filter kind, or 0 when the coder is not a filter we implement. */
static int coder_filter(const p7z_coder *co)
{
    static const uint8_t ID_X86[4] = { 0x03, 0x03, 0x01, 0x03 };
    if (id_eq(co, ID_X86, 4) && co->props_size == 0)
        return FILT_X86;
    if (co->id_size == 1 && co->id[0] == 0x03 && co->props_size == 1)
        return FILT_DELTA;
    return 0;
}

/* Accept the two-coder "compressor + filter" chains 7-Zip produces with
 * -mf=BCJ / Delta. Returns the chain flavour for dec_start(). */
static int chain_validate(const p7z_folder *f)
{
    const p7z_coder *comp, *filt;

    if (f->num_coders != 2 || f->num_in != 2 || f->num_out != 2 ||
        f->num_binds != 1 || f->num_packed != 1)
        return -1;
    if (f->binds[0] == 1 && f->binds[1] == 0 && f->packed[0] == 0) {
        comp = &f->coders[0]; /* packed → comp → filter → root */
        filt = &f->coders[1];
        if (coder_kind(comp) >= 0 && coder_filter(filt) > 0)
            return 1;
    } else if (f->binds[0] == 0 && f->binds[1] == 1 && f->packed[0] == 1) {
        comp = &f->coders[1]; /* packed → comp → filter → root */
        filt = &f->coders[0];
        if (coder_kind(comp) >= 0 && coder_filter(filt) > 0)
            return 2;
    }
    return -1;
}

/* Decide whether this folder can be decoded by us. */
static void classify_folder(p7z_folder *f)
{
    static const uint8_t ID_AES[4] = { 0x06, 0xF1, 0x07, 0x01 };
    unsigned k;
    int aes = 0;

    for (k = 0; k < f->num_coders; k++) {
        if (id_eq(&f->coders[k], ID_AES, 4))
            aes = 1;
    }
    P7Z_T("classify: ncoders=%u in=%llu out=%llu binds=%u packed=%u aes=%d"
          " id0=%02x%02x%02x%02x idsz=%u propsz=%u\n",
          f->num_coders, (unsigned long long)f->num_in,
          (unsigned long long)f->num_out, f->num_binds, f->num_packed, aes,
          f->num_coders ? f->coders[0].id[0] : 0,
          f->num_coders ? f->coders[0].id[1] : 0,
          f->num_coders ? f->coders[0].id[2] : 0,
          f->num_coders ? f->coders[0].id[3] : 0,
          f->num_coders ? f->coders[0].id_size : 0,
          f->num_coders ? f->coders[0].props_size : 0);
    if (f->num_coders > 1) {
        unsigned z;
        for (z = 1; z < f->num_coders; z++)
            P7Z_T("classify: coder[%u] id=%02x%02x%02x%02x%02x idsz=%u "
                  "propsz=%u in=%llu out=%llu\n",
                  z, f->coders[z].id[0], f->coders[z].id[1],
                  f->coders[z].id[2], f->coders[z].id[3],
                  f->coders[z].id[4], f->coders[z].id_size,
                  f->coders[z].props_size,
                  (unsigned long long)f->coders[z].num_in,
                  (unsigned long long)f->coders[z].num_out);
    }
    if (aes) {
        f->err = 3;
        return;
    }
    if (f->num_coders == 1 && f->num_in == 1 && f->num_out == 1 &&
        f->num_binds == 0 && f->num_packed == 1) {
        if (coder_kind(&f->coders[0]) < 0)
            f->err = 2;
        return;
    }
    {
        int chain = chain_validate(f);
        if (chain > 0) {
            f->chain = (unsigned char)chain;
            return;
        }
    }
    f->err = 2; /* filter chain we do not implement */
}

static int parse_pack_info(hrd *h, p7z_si *si)
{
    uint64_t i;
    uint8_t pid;

    if (h_number(h, &si->packpos) != 0 ||
        h_number(h, &si->numpack) != 0)
        return -1;
    if (si->numpack > P7Z_MAX_PACK)
        return -1;
    si->packsize = (uint64_t *)calloc(si->numpack > 0 ? (size_t)si->numpack : 1,
                                      sizeof(uint64_t));
    if (si->packsize == NULL)
        return -1;
    if (h_u8(h, &pid) != 0)
        return -1;
    if (pid == NID_SIZE) {
        for (i = 0; i < si->numpack; i++) {
            if (h_number(h, &si->packsize[i]) != 0)
                return -1;
        }
        if (h_u8(h, &pid) != 0)
            return -1;
    } else if (si->numpack > 0) {
        return -1; /* pack sizes are mandatory when streams exist */
    }
    if (pid == NID_CRC) {
        unsigned char *def = (unsigned char *)calloc(
            si->numpack > 0 ? (size_t)si->numpack : 1, 1);
        int rc = -1;
        if (def == NULL)
            return -1;
        if (h_bools(h, (size_t)si->numpack, def) == 0) {
            rc = 0;
            for (i = 0; i < si->numpack && rc == 0; i++) {
                uint32_t crc;
                if (def[i])
                    rc = h_u32(h, &crc);
            }
        }
        free(def);
        if (rc != 0)
            return -1;
        if (h_u8(h, &pid) != 0)
            return -1;
    }
    return pid == NID_END ? 0 : -1;
}

static int parse_unpack_info(hrd *h, p7z_si *si)
{
    uint64_t i, j, v;
    uint8_t pid;

    if (h_u8(h, &pid) != 0 || pid != NID_FOLDER)
        return -1;
    if (h_number(h, &v) != 0 || v == 0 || v > P7Z_MAX_FOLDERS)
        return -1;
    si->numfolders = (unsigned)v;
    si->folders =
        (p7z_folder *)calloc((size_t)v, sizeof(p7z_folder));
    if (si->folders == NULL)
        return -1;
    if (h_u8(h, &pid) != 0)
        return -1;
    if (pid != 0)
        return -1; /* external folder data: not supported */
    for (i = 0; i < si->numfolders; i++) {
        if (parse_folder(h, &si->folders[i]) != 0)
            return -1;
    }

    if (h_u8(h, &pid) != 0 || pid != NID_CODERS_UNPACK_SIZE)
        return -1;
    for (i = 0; i < si->numfolders; i++) {
        p7z_folder *f = &si->folders[i];
        f->outsz = (uint64_t *)calloc(f->num_out, sizeof(uint64_t));
        if (f->outsz == NULL)
            return -1;
        for (j = 0; j < f->num_out; j++) {
            if (h_number(h, &f->outsz[j]) != 0)
                return -1;
        }
        /* Folder size = the output stream no bind pair consumes. */
        f->unpack_size = f->outsz[f->num_out - 1];
        for (j = f->num_out; j-- > 0;) {
            unsigned b;
            int bound = 0;
            for (b = 0; b < f->num_binds; b++) {
                if (f->binds[b * 2 + 1] == j) {
                    bound = 1;
                    break;
                }
            }
            if (!bound) {
                f->unpack_size = f->outsz[j];
                break;
            }
        }
    }

    if (h_u8(h, &pid) != 0)
        return -1;
    if (pid == NID_CRC) {
        unsigned char *def = (unsigned char *)calloc(si->numfolders, 1);
        int rc = -1;
        if (def == NULL)
            return -1;
        if (h_bools(h, si->numfolders, def) == 0) {
            rc = 0;
            for (i = 0; i < si->numfolders && rc == 0; i++) {
                uint32_t crc = 0;
                if (def[i]) {
                    rc = h_u32(h, &crc);
                    if (rc == 0) {
                        si->folders[i].crc = crc;
                        si->folders[i].crc_defined = 1;
                    }
                }
            }
        }
        free(def);
        if (rc != 0)
            return -1;
        if (h_u8(h, &pid) != 0)
            return -1;
    }
    if (pid != NID_END)
        return -1;
    for (i = 0; i < si->numfolders; i++)
        classify_folder(&si->folders[i]);
    return 0;
}

static int parse_substreams_info(hrd *h, p7z_si *si)
{
    uint64_t *counts;
    uint64_t total = 0, gi = 0, i, j;
    uint8_t pid;
    int rc = -1;

    counts = (uint64_t *)calloc(si->numfolders > 0 ? si->numfolders : 1,
                                sizeof(uint64_t));
    if (counts == NULL)
        return -1;
    if (h_u8(h, &pid) != 0)
        goto out;
    if (pid == NID_NUM_UNPACK_STREAM) {
        for (i = 0; i < si->numfolders; i++) {
            if (h_number(h, &counts[i]) != 0)
                goto out;
            total += counts[i];
            if (total > P7Z_MAX_SUBS)
                goto out;
        }
        if (h_u8(h, &pid) != 0)
            goto out;
    } else {
        for (i = 0; i < si->numfolders; i++)
            counts[i] = 1;
        total = si->numfolders;
        if (total > P7Z_MAX_SUBS)
            goto out;
    }

    si->nsubs = total;
    si->sub_size = (uint64_t *)calloc(total > 0 ? (size_t)total : 1,
                                      sizeof(uint64_t));
    si->sub_crc = (uint32_t *)calloc(total > 0 ? (size_t)total : 1,
                                     sizeof(uint32_t));
    si->sub_known =
        (unsigned char *)calloc(total > 0 ? (size_t)total : 1, 1);
    si->sub_folder =
        (unsigned *)calloc(total > 0 ? (size_t)total : 1, sizeof(unsigned));
    if (si->sub_size == NULL || si->sub_crc == NULL ||
        si->sub_known == NULL || si->sub_folder == NULL)
        goto out;

    if (pid == NID_SIZE) {
        for (i = 0; i < si->numfolders; i++) {
            uint64_t sum = 0;
            p7z_folder *f = &si->folders[i];
            f->first_sub = gi;
            f->num_subs = counts[i];
            for (j = 0; j < counts[i]; j++) {
                uint64_t sz;
                if (j + 1 < counts[i]) {
                    if (h_number(h, &sz) != 0)
                        goto out;
                    sum += sz;
                    if (sum > f->unpack_size)
                        goto out;
                } else {
                    sz = f->unpack_size - sum; /* last substream */
                }
                si->sub_size[gi] = sz;
                si->sub_folder[gi] = (unsigned)i;
                gi++;
            }
        }
        if (h_u8(h, &pid) != 0)
            goto out;
    } else {
        for (i = 0; i < si->numfolders; i++) {
            p7z_folder *f = &si->folders[i];
            if (counts[i] > 1)
                goto out; /* substream sizes unknown */
            f->first_sub = gi;
            f->num_subs = counts[i];
            if (counts[i] == 1) {
                si->sub_size[gi] = f->unpack_size;
                si->sub_folder[gi] = (unsigned)i;
                gi++;
            }
        }
    }

    /* Digests cover the substreams whose CRC is not the folder CRC. */
    if (pid == NID_CRC) {
        uint64_t needed = 0, slot = 0;
        unsigned char *def;
        uint32_t *vals;
        for (i = 0; i < si->numfolders; i++) {
            p7z_folder *f = &si->folders[i];
            if (counts[i] != 1 || !f->crc_defined)
                needed += counts[i];
        }
        if (needed > P7Z_MAX_SUBS)
            goto out;
        def = (unsigned char *)calloc(needed > 0 ? (size_t)needed : 1, 1);
        vals = (uint32_t *)calloc(needed > 0 ? (size_t)needed : 1,
                                  sizeof(uint32_t));
        if (def == NULL || vals == NULL) {
            free(def);
            free(vals);
            goto out;
        }
        rc = -1;
        if (h_bools(h, (size_t)needed, def) == 0) {
            rc = 0;
            for (slot = 0; slot < needed && rc == 0; slot++) {
                if (def[slot])
                    rc = h_u32(h, &vals[slot]);
            }
        }
        if (rc == 0) {
            gi = 0;
            slot = 0;
            for (i = 0; i < si->numfolders && rc == 0; i++) {
                p7z_folder *f = &si->folders[i];
                for (j = 0; j < counts[i]; j++) {
                    if (counts[i] == 1 && f->crc_defined) {
                        si->sub_crc[gi] = f->crc;
                        si->sub_known[gi] = 1;
                    } else {
                        if (def[slot]) {
                            si->sub_crc[gi] = vals[slot];
                            si->sub_known[gi] = 1;
                        }
                        slot++;
                    }
                    gi++;
                }
            }
        }
        free(def);
        free(vals);
        if (rc != 0) {
            rc = -1;
            goto out;
        }
        if (h_u8(h, &pid) != 0) {
            rc = -1;
            goto out;
        }
    } else {
        gi = 0;
        for (i = 0; i < si->numfolders; i++) {
            p7z_folder *f = &si->folders[i];
            for (j = 0; j < counts[i]; j++) {
                if (counts[i] == 1 && f->crc_defined) {
                    si->sub_crc[gi] = f->crc;
                    si->sub_known[gi] = 1;
                }
                gi++;
            }
        }
    }

    if (pid != NID_END)
        goto out;
    rc = 0;
out:
    free(counts);
    return rc;
}

/* Synthesize one substream per folder when SubStreamsInfo is absent. */
static int substreams_default(p7z_si *si)
{
    uint64_t i;

    if (si->sub_size != NULL)
        return 0;
    si->nsubs = si->numfolders;
    if (si->nsubs > P7Z_MAX_SUBS)
        return -1;
    si->sub_size = (uint64_t *)calloc(si->nsubs > 0 ? (size_t)si->nsubs : 1,
                                      sizeof(uint64_t));
    si->sub_crc = (uint32_t *)calloc(si->nsubs > 0 ? (size_t)si->nsubs : 1,
                                     sizeof(uint32_t));
    si->sub_known =
        (unsigned char *)calloc(si->nsubs > 0 ? (size_t)si->nsubs : 1, 1);
    si->sub_folder =
        (unsigned *)calloc(si->nsubs > 0 ? (size_t)si->nsubs : 1,
                           sizeof(unsigned));
    if (si->sub_size == NULL || si->sub_crc == NULL ||
        si->sub_known == NULL || si->sub_folder == NULL)
        return -1;
    for (i = 0; i < si->nsubs; i++) {
        p7z_folder *f = &si->folders[i];
        f->first_sub = i;
        f->num_subs = 1;
        si->sub_size[i] = f->unpack_size;
        si->sub_folder[i] = (unsigned)i;
        if (f->crc_defined) {
            si->sub_crc[i] = f->crc;
            si->sub_known[i] = 1;
        }
    }
    return 0;
}

/* Pack stream index of each folder + pack bounds check. */
static int si_assign(p7z_si *si)
{
    uint64_t pk = 0;
    unsigned i;

    for (i = 0; i < si->numfolders; i++) {
        si->folders[i].pack_stream = pk;
        pk += si->folders[i].num_packed;
        if (pk > si->numpack)
            return -1;
    }
    return 0;
}

/* PackInfo + UnpackInfo + optional SubStreamsInfo + kEnd. */
static int parse_streams_body(hrd *h, p7z_si *si)
{
    uint8_t pid;

    if (h_u8(h, &pid) != 0) {
        P7Z_T("streams: eof reading first pid\n");
        return -1;
    }
    P7Z_T("streams: pid=%02x pos=%zu\n", pid, h->i);
    if (pid == NID_PACK_INFO) {
        if (parse_pack_info(h, si) != 0)
            return -1;
        if (h_u8(h, &pid) != 0)
            return -1;
    }
    if (pid == NID_UNPACK_INFO) {
        if (parse_unpack_info(h, si) != 0)
            return -1;
        if (h_u8(h, &pid) != 0)
            return -1;
    } else if (si->numfolders != 0) {
        return -1;
    }
    if (pid == NID_SUBSTREAMS_INFO) {
        if (si->numfolders == 0)
            return -1;
        if (parse_substreams_info(h, si) != 0)
            return -1;
        if (h_u8(h, &pid) != 0)
            return -1;
    } else if (si->numfolders > 0) {
        if (substreams_default(si) != 0)
            return -1;
    }
    if (pid != NID_END) {
        P7Z_T("streams: expected END got %02x pos=%zu\n", pid, h->i);
        return -1;
    }
    if (si_assign(si) != 0) {
        P7Z_T("streams: assign failed numpack=%llu folders=%u\n",
              (unsigned long long)si->numpack, si->numfolders);
        return -1;
    }
    return 0;
}

/* ---- FilesInfo ----------------------------------------------------------- */

static int parse_files_info(hrd *h, unsigned numfiles, p7z_file *files,
                             int *have_names)
{
    unsigned char *es = NULL, *ef = NULL, *attr_known = NULL;
    uint32_t *attr = NULL;
    const uint8_t *ef_slice = NULL;
    size_t ef_len = 0;
    uint64_t count_es = 0;
    uint64_t size;
    uint8_t pid;
    int rc = -1;
    unsigned i;

    for (;;) {
        hrd sub;
        if (h_u8(h, &pid) != 0)
            goto out;
        if (pid == NID_END)
            break;
        if (h_number(h, &size) != 0)
            goto out;
        if (size > (uint64_t)(h->n - h->i))
            goto out;
        sub.b = h->b + h->i;
        sub.n = (size_t)size;
        sub.i = 0;
        h->i += (size_t)size;

        switch (pid) {
        case NID_EMPTY_STREAM:
            P7Z_T("files: EMPTY_STREAM size=%llu\n", (unsigned long long)size);
            free(es);
            es = (unsigned char *)calloc(numfiles, 1);
            if (es == NULL || h_bits_raw(&sub, numfiles, es) != 0)
                goto out;
            break;
        case NID_EMPTY_FILE:
            P7Z_T("files: EMPTY_FILE size=%llu\n", (unsigned long long)size);
            /* Needs the empty-stream vector: parse after the loop. */
            ef_slice = sub.b;
            ef_len = sub.n;
            break;
        case NID_NAME: {
            uint8_t external;
            P7Z_T("files: NAME size=%llu pos=%zu\n", (unsigned long long)size,
                  h->i);
            if (h_u8(&sub, &external) != 0)
                goto out;
            if (external != 0)
                goto out; /* names in an external stream: unsupported */
            for (i = 0; i < numfiles; i++) {
                if (h_name(&sub, files[i].name, sizeof(files[i].name)) != 0) {
                    P7Z_T("files: name %u parse fail at %zu/%zu\n", i, sub.i,
                          sub.n);
                    goto out;
                }
            }
            *have_names = 1;
            P7Z_T("files: names[0]='%s' names[1]='%s'\n",
                  numfiles > 0 ? files[0].name : "",
                  numfiles > 1 ? files[1].name : "");
            break;
        }
        case NID_ATTRIBUTES: {
            uint8_t external;
            attr_known = (unsigned char *)calloc(numfiles, 1);
            attr = (uint32_t *)calloc(numfiles, sizeof(uint32_t));
            if (attr_known == NULL || attr == NULL)
                goto out;
            if (h_bools(&sub, numfiles, attr_known) != 0 ||
                h_u8(&sub, &external) != 0)
                goto out;
            if (external == 0) {
                for (i = 0; i < numfiles; i++) {
                    if (attr_known[i] && h_u32(&sub, &attr[i]) != 0)
                        goto out;
                }
            } else {
                memset(attr_known, 0, numfiles);
            }
            break;
        }
        default:
            P7Z_T("files: skip prop=%02x size=%llu\n", pid,
                  (unsigned long long)size);
            /* kCTime/kATime/kMTime/kAnti/kDummy/...: size-bounded, skip. */
            break;
        }
    }

    /* EmptyFile vector is indexed by empty-stream files only. */
    if (ef_slice != NULL) {
        uint64_t k;
        hrd sub;
        for (k = 0; k < numfiles; k++) {
            if (es != NULL && es[k])
                count_es++;
        }
        ef = (unsigned char *)calloc(count_es > 0 ? (size_t)count_es : 1, 1);
        if (ef == NULL)
            goto out;
        sub.b = ef_slice;
        sub.n = ef_len;
        sub.i = 0;
        if (h_bits_raw(&sub, (size_t)count_es, ef) != 0)
            goto out;
    }

    {
        uint64_t ordinal = 0;
        for (i = 0; i < numfiles; i++) {
            p7z_file *f = &files[i];
            int empty = es != NULL && es[i];
            if (empty) {
                int is_ef = ef != NULL && ordinal < count_es && ef[ordinal];
                ordinal++;
                f->has_stream = 0;
                f->is_dir = is_ef ? 0 : 1;
                f->size = 0;
            } else {
                f->has_stream = 1;
                f->is_dir = 0;
            }
            if (attr_known != NULL && attr_known[i] &&
                (attr[i] & 0x10u) != 0 && !f->has_stream)
                f->is_dir = 1;
            {
                size_t len = strlen(f->name);
                if (len > 0 && f->name[len - 1] == '/' && !f->has_stream)
                    f->is_dir = 1;
            }
        }
    }
    rc = 0;
out:
    free(es);
    free(ef);
    free(attr_known);
    free(attr);
    return rc;
}

/* ---- header / encoded header --------------------------------------------- */

/* Archive file name without directories or last extension (py7zr uses the
 * same fallback for archives whose FilesInfo carries no kName). */
static void archive_stem(const char *path, char *out, size_t cap)
{
    const char *base = path, *p;
    char *dot;
    size_t n = 0;

    for (p = path; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\')
            base = p + 1;
    }
    while (base[n] != '\0' && n + 1 < cap) {
        out[n] = base[n];
        n++;
    }
    out[n] = '\0';
    dot = strrchr(out, '.');
    if (dot != NULL && dot != out)
        *dot = '\0';
}

/* Append the decimal value of v at pos. Returns the new length. */
static size_t append_num(char *dst, size_t pos, size_t cap, unsigned v)
{
    char tmp[12];
    int n = 0;

    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v != 0);
    while (n > 0 && pos + 1 < cap)
        dst[pos++] = tmp[--n];
    if (pos < cap)
        dst[pos] = '\0';
    return pos;
}

/* Nameless archives: every file gets the archive stem; later duplicates
 * become stem_0, stem_1, … (same output names py7zr produces). */
static size_t scopy_name(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return n;
}

static void fallback_names(p7z_file *files, unsigned numfiles,
                           const char *first_path)
{
    char stem[256];
    unsigned i;

    archive_stem(first_path, stem, sizeof(stem));
    for (i = 0; i < numfiles; i++) {
        unsigned dup = 0;
        size_t len;

        len = scopy_name(files[i].name, sizeof(files[i].name), stem);
        for (;;) {
            unsigned j;
            int clash = 0;
            for (j = 0; j < i; j++) {
                if (strcmp(files[j].name, files[i].name) == 0) {
                    clash = 1;
                    break;
                }
            }
            if (!clash || dup > 9999)
                break;
            len = scopy_name(files[i].name, sizeof(files[i].name), stem);
            files[i].name[len] = '_';
            len = append_num(files[i].name, len + 1,
                             sizeof(files[i].name), dup);
            dup++;
        }
    }
}

static int parse_header_body(hrd *h, p7z_si *si, p7z_file **files_out,
                             unsigned *num_out, int *have_names)
{
    uint8_t pid;
    p7z_file *files = NULL;
    unsigned numfiles = 0;

    if (h_u8(h, &pid) != 0)
        return -1;
    P7Z_T("header: pid=%02x pos=%zu\n", pid, h->i);
    *have_names = 0;
    if (pid == NID_ARCHIVE_PROPERTIES) {
        for (;;) {
            uint8_t id;
            uint64_t sz;
            if (h_u8(h, &id) != 0)
                return -1;
            if (id == NID_END)
                break;
            if (h_number(h, &sz) != 0 || h_skip(h, sz) != 0)
                return -1;
        }
        if (h_u8(h, &pid) != 0)
            return -1;
    }
    if (pid == NID_ADDITIONAL_STREAMS_INFO)
        return -1; /* extra stream sets: not supported */
    if (pid == NID_MAIN_STREAMS_INFO) {
        if (parse_streams_body(h, si) != 0)
            return -1;
        if (h_u8(h, &pid) != 0)
            return -1;
    }
    if (pid == NID_FILES_INFO) {
        uint64_t nf;
        if (h_number(h, &nf) != 0)
            return -1;
        if (nf > P7Z_MAX_FILES)
            return -1;
        numfiles = (unsigned)nf;
        files = (p7z_file *)calloc(numfiles > 0 ? numfiles : 1,
                                   sizeof(p7z_file));
        if (files == NULL)
            return -1;
        if (parse_files_info(h, numfiles, files, have_names) != 0) {
            free(files);
            return -1;
        }
        *files_out = files;
        *num_out = numfiles;
        if (h_u8(h, &pid) != 0)
            return -1;
        P7Z_T("header: after files pid=%02x pos=%zu nf=%u\n", pid, h->i,
              numfiles);
    }
    if (pid != NID_END) {
        P7Z_T("header: expected END got %02x pos=%zu\n", pid, h->i);
        return -1;
    }
    return 0;
}

/* ---- one-shot folder decode into memory (encoded headers) ---------------- */

typedef struct {
    uint8_t *buf;
    size_t cap, len;
} mem_sink_ctx;

static int mem_sink(void *user, const uint8_t *b, size_t n)
{
    mem_sink_ctx *m = (mem_sink_ctx *)user;
    if (n > m->cap - m->len)
        return 1;
    memcpy(m->buf + m->len, b, n);
    m->len += n;
    return 0;
}

/* ---- decoder plumbing ----------------------------------------------------- */

/*
 * Classic x86 BCJ converter (Igor Pavlov, public domain — the algorithm
 * from 7-Zip's Bra86.c). Converts call/jmp targets between absolute and
 * relative form; `encoding` 1 = encode, 0 = decode. Processes at most
 * size-4 bytes and returns how many were consumed: the tail may hold a
 * partial window and must be re-fed with the next chunk (ip/state carry
 * the streaming context).
 */
static size_t x86_convert(uint8_t *data, size_t size, uint32_t ip,
                          uint32_t *state, int encoding)
{
    size_t pos = 0;
    uint32_t mask = *state & 7;
    const uint8_t *limit;

#define PAM_TEST86(b) (((((b) + 1) & 0xFE) == 0))
    if (size < 5)
        return 0;
    size -= 4;
    limit = data + size;
    ip += 5;

    for (;;) {
        uint8_t *p = data + pos;
        for (; p < limit; p++) {
            if ((*p & 0xFE) == 0xE8)
                break;
        }
        {
            size_t dd = (size_t)(p - data) - pos;
            pos = (size_t)(p - data);
            if (p >= limit) {
                *state = (dd > 2) ? 0 : (mask >> (unsigned)dd);
                return pos;
            }
            if (dd > 2) {
                mask = 0;
            } else {
                mask >>= (unsigned)dd;
                if (mask != 0 &&
                    (mask > 4 || mask == 3 ||
                     PAM_TEST86(p[(size_t)(mask >> 1) + 1]))) {
                    mask = (mask >> 1) | 4;
                    pos++;
                    continue;
                }
            }
        }
        if (PAM_TEST86(p[4])) {
            uint32_t v = ((uint32_t)p[4] << 24) | ((uint32_t)p[3] << 16) |
                         ((uint32_t)p[2] << 8) | (uint32_t)p[1];
            uint32_t cur = ip + (uint32_t)pos;
            pos += 5;
            if (encoding)
                v += cur;
            else
                v -= cur;
            if (mask != 0) {
                unsigned sh = (unsigned)((mask & 6) << 2);
                if (PAM_TEST86((uint8_t)(v >> sh))) {
                    v ^= (((uint32_t)0x100 << sh) - 1);
                    if (encoding)
                        v += cur;
                    else
                        v -= cur;
                }
                mask = 0;
            }
            p[1] = (uint8_t)v;
            p[2] = (uint8_t)(v >> 8);
            p[3] = (uint8_t)(v >> 16);
            p[4] = (uint8_t)(0 - ((v >> 24) & 1));
        } else {
            mask = (mask >> 1) | 4;
            pos++;
        }
    }
#undef PAM_TEST86
}

/* Streaming x86 BCJ: keep the ≤4-byte tail that may hold a window. */
static int chain_push_x86(p7z_dec *d, const uint8_t *buf, size_t n)
{
    while (n > 0) {
        uint8_t tmp[4104];
        size_t take = n;
        size_t m, ret, tail;

        if (take > 4096)
            take = 4096;
        memcpy(tmp, d->carry, d->carry_len);
        memcpy(tmp + d->carry_len, buf, take);
        m = d->carry_len + take;
        ret = x86_convert(tmp, m, (uint32_t)d->bcj_ip, &d->bcj_state, 0);
        if (ret > 0) {
            if (d->sink(d->user, tmp, ret) != 0)
                return 1;
            d->bcj_ip += ret;
        }
        tail = m - ret;
        if (tail > sizeof(d->carry))
            return 1;
        memcpy(d->carry, tmp + ret, tail);
        d->carry_len = (unsigned)tail;
        buf += take;
        n -= take;
    }
    return 0;
}

/* Streaming Delta: out[i] = enc[i] + out[i - dist] (dist = prop + 1). */
static int chain_push_delta(p7z_dec *d, const uint8_t *buf, size_t n)
{
    uint8_t tmp[4096];
    size_t i;

    if (n > sizeof(tmp) || d->d_dist == 0)
        return 1;
    for (i = 0; i < n; i++) {
        unsigned idx = (unsigned)(d->d_pos % d->d_dist);
        uint8_t out = (uint8_t)(buf[i] + d->d_hist[idx]);
        d->d_hist[idx] = out;
        d->d_pos++;
        tmp[i] = out;
    }
    return d->sink(d->user, tmp, n);
}

static int dec_get_byte(void *p)
{
    p7z_dec *d = (p7z_dec *)p;
    int b;

    if (d->pack_left == 0)
        return -1;
    b = pam_stream_get(d->s);
    if (b < 0)
        return -1;
    d->pack_left--;
    return b;
}

static int dec_push(void *p, const uint8_t *buf, size_t n)
{
    p7z_dec *d = (p7z_dec *)p;
    if (d->filt == FILT_X86)
        return chain_push_x86(d, buf, n);
    if (d->filt == FILT_DELTA)
        return chain_push_delta(d, buf, n);
    return d->sink(d->user, buf, n);
}

static void dec_stop(p7z_dec *d)
{
    if (d->lz != NULL) {
        pam_lzma_destroy(d->lz);
        d->lz = NULL;
    }
    if (d->inf != NULL) {
        free(d->inf);
        d->inf = NULL;
    }
}

static int dec_start(p7z_dec *d, pam_stream *s, const p7z_si *si,
                     const p7z_folder *f,
                     int (*sink)(void *, const uint8_t *, size_t),
                     void *user)
{
    static const uint8_t ID_COPY[1] = { 0x00 };
    static const uint8_t ID_LZMA[3] = { 0x03, 0x01, 0x01 };
    static const uint8_t ID_LZMA2[1] = { 0x21 };
    static const uint8_t ID_DEFLATE[3] = { 0x04, 0x01, 0x08 };
    const p7z_coder *co;
    const p7z_coder *fco = NULL;
    uint64_t off;
    unsigned k;

    dec_stop(d);
    memset(d, 0, sizeof(*d));
    co = &f->coders[0];
    if (f->chain != 0) {
        /* Two-coder chain: packed → comp → filter → root (either bind
         * order, see chain_validate). Filters are length-preserving, so
         * the compressor still produces f->unpack_size bytes. */
        if (f->chain == 1) {
            fco = &f->coders[1];
        } else {
            co = &f->coders[1];
            fco = &f->coders[0];
        }
        d->filt = coder_filter(fco);
        if (d->filt == FILT_DELTA)
            d->d_dist = (unsigned)fco->props[0] + 1u; /* props_size == 1 */
        else if (d->filt != FILT_X86)
            return -1;
        P7Z_T("dec_start: chain=%u filt=%d dist=%u\n", f->chain, d->filt,
              d->d_dist);
    }
    d->s = s;
    d->sink = sink;
    d->user = user;
    d->out_total = f->unpack_size;
    d->pack_left = si->packsize[f->pack_stream];

    off = (uint64_t)P7Z_SIG_LEN + si->packpos;
    for (k = 0; k < f->pack_stream; k++)
        off += si->packsize[k];
    if (pam_stream_seek(s, (long long)off) != 1) {
        P7Z_T("dec_start: seek %llu FAILED\n", (unsigned long long)off);
        return -1;
    }
    P7Z_T("dec_start: kind-try folder pack_off=%llu pack_left=%llu "
          "out=%llu\n",
          (unsigned long long)off, (unsigned long long)d->pack_left,
          (unsigned long long)d->out_total);

    if (id_eq(co, ID_COPY, 1)) {
        d->kind = DK_COPY;
    } else if (id_eq(co, ID_LZMA, 3)) {
        d->kind = DK_LZMA;
        d->lz = pam_lzma_create();
        if (d->lz == NULL)
            return -1;
        if (pam_lzma_init_lzma(d->lz, co->props, d->out_total,
                               dec_get_byte, d, dec_push, d) != 0) {
            dec_stop(d);
            return -1;
        }
    } else if (id_eq(co, ID_LZMA2, 1)) {
        d->kind = DK_LZMA2;
        d->lz = pam_lzma_create();
        if (d->lz == NULL)
            return -1;
        if (pam_lzma_init_lzma2(d->lz, co->props[0], d->out_total,
                                dec_get_byte, d, dec_push, d) != 0) {
            dec_stop(d);
            return -1;
        }
    } else if (id_eq(co, ID_DEFLATE, 3)) {
        d->kind = DK_DEFLATE;
        d->inf = (pam_inflate_t *)malloc(sizeof(pam_inflate_t));
        if (d->inf == NULL)
            return -1;
        pam_inflate_init(d->inf, dec_get_byte, dec_push, d);
    } else {
        return -1;
    }
    return 0;
}

/*
 * Folder decode complete. The BCJ stage holds up to 4 tail bytes that
 * x86_convert could not window yet — the encoder left them unconverted
 * too (Bra86 only processes size-4 bytes), so flush them through as-is,
 * exactly as liblzma does at end of stream. Delta holds nothing back.
 */
static int dec_finish(p7z_dec *d)
{
    d->finished = 1;
    if (d->filt == FILT_X86 && d->carry_len > 0) {
        size_t n = d->carry_len;
        d->carry_len = 0;
        if (d->sink(d->user, d->carry, n) != 0) {
            d->err = 3;
            return -1;
        }
    }
    return 1;
}

/*
 * Decode up to `limit` output bytes. Returns 1 = folder finished,
 * 0 = call again, -1 = error (d->err: 1 corrupt, 2 input, 3 output).
 */
static int dec_run(p7z_dec *d, unsigned long long limit)
{
    if (d->finished)
        return 1;
    if (limit == 0)
        limit = 1;

    switch (d->kind) {
    case DK_COPY: {
        uint8_t buf[4096];
        while (limit > 0 && !d->finished) {
            size_t chunk = sizeof(buf);
            uint64_t room;
            size_t got;

            if (d->produced >= d->out_total) {
                d->finished = 1;
                break;
            }
            room = d->out_total - d->produced;
            if (chunk > room)
                chunk = (size_t)room;
            if (chunk > limit)
                chunk = (size_t)limit;
            if (chunk > d->pack_left) {
                d->err = 2;
                return -1;
            }
            got = pam_stream_read(d->s, buf, chunk);
            if (got != chunk) {
                d->err = 2;
                return -1;
            }
            if (dec_push(d, buf, got) != 0) {
                d->err = 3;
                return -1;
            }
            d->pack_left -= got;
            d->produced += got;
            limit -= got;
        }
        return d->finished ? dec_finish(d) : 0;
    }
    case DK_LZMA:
    case DK_LZMA2: {
        int r = pam_lzma_run(d->lz, limit);
        d->produced = pam_lzma_produced(d->lz);
        if (r > 0)
            return dec_finish(d);
        if (r < 0) {
            int e = pam_lzma_error(d->lz);
            d->err = (e == 2) ? 2 : (e == 3) ? 3 : 1;
            return -1;
        }
        return 0;
    }
    case DK_DEFLATE: {
        unsigned long long room = limit;
        int r;

        if (d->produced >= d->out_total)
            return dec_finish(d);
        if (room > d->out_total - d->produced)
            room = d->out_total - d->produced;
        r = pam_inflate_run(d->inf, room);
        d->produced = pam_inflate_produced(d->inf);
        if (r > 0)
            return dec_finish(d);
        if (r < 0) {
            int e = pam_inflate_error(d->inf);
            d->err = (e == 2) ? 2 : (e == 3) ? 3 : 1;
            return -1;
        }
        return 0;
    }
    default:
        d->err = 1;
        return -1;
    }
}

/* ---- cursor output routing ------------------------------------------------ */

/*
 * Route decoder output: bytes of the active entry go to its file + CRC,
 * everything else is held for the next entry (bounded: decoders emit at
 * most 4096-byte chunks and runs stop within P7Z_SLACK of an entry end).
 */
static int route_sink(void *user, const uint8_t *b, size_t n)
{
    pam7z_cursor *c = (pam7z_cursor *)user;

    while (n > 0) {
        if (c->have_entry && !c->entry_done && c->entry_left > 0) {
            size_t take = n;
            if ((uint64_t)take > c->entry_left)
                take = (size_t)c->entry_left;
            if (c->efp != NULL &&
                fwrite(b, 1, take, c->efp) != take)
                return 1; /* I/O error: decoder aborts (err = output) */
            c->crc = pam_crc32_update(c->crc, b, take);
            c->entry_left -= take;
            if (c->entry_left == 0)
                c->entry_done = 1;
            b += take;
            n -= take;
        } else {
            if (c->pend_len + n > sizeof(c->pend))
                return 1;
            memcpy(c->pend + c->pend_len, b, n);
            c->pend_len += n;
            n = 0;
        }
    }
    return 0;
}

/* ---- open ----------------------------------------------------------------- */

static void si_free(p7z_si *si)
{
    unsigned i;

    free(si->packsize);
    if (si->folders != NULL) {
        for (i = 0; i < si->numfolders; i++) {
            free(si->folders[i].coders);
            free(si->folders[i].binds);
            free(si->folders[i].packed);
            free(si->folders[i].outsz);
        }
    }
    free(si->folders);
    free(si->sub_size);
    free(si->sub_crc);
    free(si->sub_known);
    free(si->sub_folder);
    memset(si, 0, sizeof(*si));
}

static int folder_err_code(const p7z_folder *f)
{
    switch (f->err) {
    case 0:  return 0;
    case 2:  return PAM_7Z_ERR_UNSUPPORTED;
    case 3:  return PAM_7Z_ERR_ENCRYPTED;
    default: return PAM_7Z_ERR_CORRUPT;
    }
}

/* Decode the ENCODED_HEADER folder into a fresh buffer holding the
 * real header. Returns 0 and sets out/out_n, or -1. */
static int decode_header_blob(pam_stream *s, const uint8_t *blob, size_t n,
                              uint8_t **out, size_t *out_n)
{
    hrd h;
    p7z_si tsi;
    p7z_dec d;
    mem_sink_ctx m;
    const p7z_folder *f;
    int r = -1;

    memset(&tsi, 0, sizeof(tsi));
    h.b = blob;
    h.n = n;
    h.i = 0;
    if (parse_streams_body(&h, &tsi) != 0) {
        P7Z_T("ehdr: streams parse failed pos=%zu/%zu\n", h.i, h.n);
        goto done;
    }
    if (tsi.numfolders != 1) {
        P7Z_T("ehdr: numfolders=%u\n", tsi.numfolders);
        goto done;
    }
    f = &tsi.folders[0];
    if (folder_err_code(f) != 0) {
        P7Z_T("ehdr: folder err=%u\n", f->err);
        goto done;
    }
    if (f->unpack_size == 0 || f->unpack_size > P7Z_MAX_HEADER) {
        P7Z_T("ehdr: unpack=%llu\n", (unsigned long long)f->unpack_size);
        goto done;
    }
    *out = (uint8_t *)malloc((size_t)f->unpack_size);
    if (*out == NULL)
        goto done;
    m.buf = *out;
    m.cap = (size_t)f->unpack_size;
    m.len = 0;

    memset(&d, 0, sizeof(d));
    if (dec_start(&d, s, &tsi, f, mem_sink, &m) != 0) {
        P7Z_T("ehdr: dec_start failed\n");
        dec_stop(&d);
        free(*out);
        *out = NULL;
        goto done;
    }
    do {
        r = dec_run(&d, 1u << 20);
    } while (r == 0);
    P7Z_T("ehdr: decode r=%d produced=%llu want=%llu crcdef=%u\n", r,
          d.produced, (unsigned long long)f->unpack_size, f->crc_defined);
    if (r > 0 && d.produced == f->unpack_size && m.len == m.cap &&
        (!f->crc_defined ||
         pam_crc32_final(pam_crc32_update(PAM_CRC32_INIT, m.buf, m.len)) ==
             f->crc)) {
        *out_n = m.len;
        r = 0;
    } else {
        free(*out);
        *out = NULL;
        r = -1;
    }
    dec_stop(&d);
done:
    si_free(&tsi);
    return r;
}

pam7z_cursor *pam7z_open(const char *first_path)
{
    pam7z_cursor *c;
    uint8_t hdr[P7Z_SIG_LEN];
    uint8_t *blob = NULL, *real = NULL;
    size_t real_n = 0;
    uint64_t next_off, next_size;
    uint32_t start_crc, next_crc, calc;
    hrd h;
    uint8_t pid;
    int have_names = 0;

    c = (pam7z_cursor *)calloc(1, sizeof(*c));
    if (c == NULL)
        return NULL;
    c->fold = -1;

    if (pam_stream_open(&c->s, first_path) != 0)
        goto fail;
    if (pam_stream_read_exact(&c->s, hdr, P7Z_SIG_LEN) != 1)
        goto fail;
    if (memcmp(hdr, "7z\xBC\xAF\x27\x1C", 6) != 0)
        goto fail;
    start_crc = (uint32_t)hdr[8] | ((uint32_t)hdr[9] << 8) |
                ((uint32_t)hdr[10] << 16) | ((uint32_t)hdr[11] << 24);
    calc = pam_crc32_final(
        pam_crc32_update(PAM_CRC32_INIT, hdr + 12, P7Z_SIG_LEN - 12));
    if (calc != start_crc)
        goto fail;
    next_off = (uint64_t)hdr[12] | ((uint64_t)hdr[13] << 8) |
               ((uint64_t)hdr[14] << 16) | ((uint64_t)hdr[15] << 24) |
               ((uint64_t)hdr[16] << 32) | ((uint64_t)hdr[17] << 40) |
               ((uint64_t)hdr[18] << 48) | ((uint64_t)hdr[19] << 56);
    next_size = (uint64_t)hdr[20] | ((uint64_t)hdr[21] << 8) |
                ((uint64_t)hdr[22] << 16) | ((uint64_t)hdr[23] << 24) |
                ((uint64_t)hdr[24] << 32) | ((uint64_t)hdr[25] << 40) |
                ((uint64_t)hdr[26] << 48) | ((uint64_t)hdr[27] << 56);
    next_crc = (uint32_t)hdr[28] | ((uint32_t)hdr[29] << 8) |
               ((uint32_t)hdr[30] << 16) | ((uint32_t)hdr[31] << 24);

    if (next_size == 0) /* empty archive */
        return c;
    if (next_size > P7Z_MAX_HEADER || next_size > (uint64_t)-1 - P7Z_SIG_LEN)
        goto fail;
    blob = (uint8_t *)malloc((size_t)next_size);
    if (blob == NULL)
        goto fail;
    if (pam_stream_seek(&c->s, (long long)(P7Z_SIG_LEN + next_off)) != 1 ||
        pam_stream_read_exact(&c->s, blob, (size_t)next_size) != 1)
        goto fail;
    calc = pam_crc32_final(
        pam_crc32_update(PAM_CRC32_INIT, blob, (size_t)next_size));
    if (calc != next_crc)
        goto fail;

    h.b = blob;
    h.n = (size_t)next_size;
    h.i = 0;
    if (h_u8(&h, &pid) != 0)
        goto fail;
    P7Z_T("open: blob pid=%02x size=%llu off=%llu\n", pid,
          (unsigned long long)next_size, (unsigned long long)next_off);
    if (pid == NID_ENCODED_HEADER) {
        if (decode_header_blob(&c->s, h.b + h.i, h.n - h.i, &real, &real_n) != 0) {
            P7Z_T("open: encoded header decode FAILED\n");
            goto fail;
        }
        h.b = real;
        h.n = real_n;
        h.i = 0;
        if (h_u8(&h, &pid) != 0)
            goto fail;
        P7Z_T("open: real header pid=%02x size=%zu\n", pid, real_n);
    }
    if (pid != NID_HEADER) {
        P7Z_T("open: expected HEADER got %02x\n", pid);
        goto fail;
    }
    if (parse_header_body(&h, &c->si, &c->files, &c->numfiles,
                          &have_names) != 0) {
        P7Z_T("open: header body FAILED\n");
        goto fail;
    }
    if (!have_names && c->numfiles > 0)
        fallback_names(c->files, c->numfiles, first_path);
    P7Z_T("open: parsed files=%u folders=%u nsubs=%llu\n", c->numfiles,
          c->si.numfolders, (unsigned long long)c->si.nsubs);
    {
        unsigned i;
        for (i = 0; i < c->numfiles && i < 25; i++)
            P7Z_T("open: file[%u] name='%s' stream=%u dir=%u\n", i,
                  c->files[i].name, c->files[i].has_stream,
                  c->files[i].is_dir);
        for (i = 0; i < c->si.numfolders && i < 8; i++)
            P7Z_T("open: folder[%u] pack=%llu nsubs=%llu first=%llu "
                  "unpack=%llu err=%u\n",
                  i, (unsigned long long)c->si.folders[i].pack_stream,
                  (unsigned long long)c->si.folders[i].num_subs,
                  (unsigned long long)c->si.folders[i].first_sub,
                  (unsigned long long)c->si.folders[i].unpack_size,
                  c->si.folders[i].err);
    }

    /* Files with a stream consume substreams in order. */
    {
        uint64_t sub = 0;
        unsigned i;
        for (i = 0; i < c->numfiles; i++) {
            p7z_file *f = &c->files[i];
            if (!f->has_stream)
                continue;
            if (sub >= c->si.nsubs) {
                P7Z_T("open: file %u has stream but only %llu subs\n", i,
                      (unsigned long long)c->si.nsubs);
                goto fail;
            }
            f->sub = sub;
            f->size = c->si.sub_size[sub];
            f->crc = c->si.sub_crc[sub];
            f->crc_known = c->si.sub_known[sub];
            sub++;
        }
    }

    free(blob);
    free(real);
    return c;

fail:
    free(blob);
    free(real);
    pam7z_close(c);
    return NULL;
}

/* ---- iteration / extraction ------------------------------------------------ */

static int folder_activate(pam7z_cursor *c, unsigned fi)
{
    const p7z_folder *f = &c->si.folders[fi];
    int rc = folder_err_code(f);

    if (rc != 0)
        return rc;
    if (c->fold == (int)fi)
        return 0;
    if (dec_start(&c->dec, &c->s, &c->si, f, route_sink, c) != 0)
        return PAM_7Z_ERR_CORRUPT;
    c->fold = (int)fi;
    return 0;
}

/* Consume the rest of the current entry, discarding its bytes. */
static int drain_entry(pam7z_cursor *c)
{
    c->efp = NULL;
    while (!c->entry_done) {
        unsigned long long before = c->dec.produced;
        unsigned long long run = c->entry_left + P7Z_SLACK;
        int r;

        if (run > 65536)
            run = 65536;
        r = dec_run(&c->dec, run);
        if (r < 0)
            return -1;
        if (r > 0)
            return c->entry_done ? 0 : -1;
        if (c->dec.produced == before && !c->entry_done)
            return -1;
    }
    return 0;
}

int pam7z_next(pam7z_cursor *c, pam7z_entry *e)
{
    const p7z_file *f;
    unsigned folder = 0;
    int rc;

    if (c == NULL || e == NULL)
        return PAM_7Z_ERR_CORRUPT;
    if (c->broken != 0)
        return c->broken;

    if (c->have_entry && !c->entry_done) {
        if (drain_entry(c) != 0) {
            c->broken = PAM_7Z_ERR_CORRUPT;
            return c->broken;
        }
    }
    c->have_entry = 0;
    c->efp = NULL;

    if (c->cur_file >= c->numfiles)
        return PAM_7Z_OK_EOF;

    f = &c->files[c->cur_file];
    P7Z_T("next: file=%u name='%s' stream=%u dir=%u size=%llu sub=%llu\n",
          c->cur_file, f->name, f->has_stream, f->is_dir,
          (unsigned long long)f->size, (unsigned long long)f->sub);
    memcpy(e->name, f->name, sizeof(e->name));
    e->size = f->size;
    e->crc32 = f->crc;
    e->crc_known = f->crc_known;
    e->is_dir = f->is_dir;

    if (f->has_stream) {
        if (f->sub >= c->si.nsubs) {
            c->broken = PAM_7Z_ERR_CORRUPT;
            return c->broken;
        }
        folder = c->si.sub_folder[f->sub];
        rc = folder_activate(c, folder);
        if (rc != 0) {
            c->broken = rc; /* entry name is already filled in *e */
            return rc;
        }
    }

    c->cur_file++;
    c->have_entry = 1;
    c->crc = PAM_CRC32_INIT;
    c->want_crc = f->crc;
    c->want_known = f->crc_known;
    if (f->has_stream) {
        c->entry_left = f->size;
        c->entry_done = (f->size == 0) ? 1 : 0;
    } else {
        c->entry_left = 0;
        c->entry_done = 1;
    }
    return PAM_7Z_OK_ENTRY;
}

int pam7z_entry_done(const pam7z_cursor *c)
{
    if (c == NULL || !c->have_entry || c->entry_done)
        return 1;
    return 0;
}

long long pam7z_extract_current(pam7z_cursor *c, FILE *out_fp,
                                unsigned long long limit,
                                uint32_t *crc32_out)
{
    long long wrote = 0;

    if (c == NULL)
        return -1;
    if (!c->have_entry || c->entry_done) {
        if (crc32_out != NULL)
            *crc32_out = pam_crc32_final(c->crc);
        return 0;
    }
    c->efp = out_fp;

    /* Bytes already decoded for this entry come from the pending FIFO. */
    while (!c->entry_done && c->entry_left > 0 &&
           c->pend_pos < c->pend_len &&
           (unsigned long long)wrote < limit) {
        size_t avail = c->pend_len - c->pend_pos;
        size_t take = (size_t)((c->entry_left < (uint64_t)avail)
                                   ? c->entry_left
                                   : (uint64_t)avail);
        if ((unsigned long long)take > limit - (unsigned long long)wrote)
            take = (size_t)(limit - (unsigned long long)wrote);
        if (take == 0)
            break;
        if (out_fp != NULL &&
            fwrite(c->pend + c->pend_pos, 1, take, out_fp) != take)
            goto io_error;
        c->crc = pam_crc32_update(c->crc, c->pend + c->pend_pos, take);
        c->pend_pos += take;
        c->entry_left -= take;
        wrote += (long long)take;
        if (c->pend_pos == c->pend_len)
            c->pend_pos = c->pend_len = 0;
        if (c->entry_left == 0) {
            c->entry_done = 1;
            c->efp = NULL;
        }
    }

    while (!c->entry_done && (unsigned long long)wrote < limit) {
        unsigned long long room = limit - (unsigned long long)wrote;
        unsigned long long run = room;
        unsigned long long before;
        uint64_t left_before = c->entry_left;
        int r;

        if (run > c->entry_left + P7Z_SLACK)
            run = c->entry_left + P7Z_SLACK;
        before = c->dec.produced;
        r = dec_run(&c->dec, run);
        wrote += (long long)(left_before - c->entry_left);
        if (r < 0) {
            P7Z_T("extract: dec err=%d produced=%llu pack_left=%llu "
                  "entry_left=%llu kind=%d\n",
                  c->dec.err, c->dec.produced,
                  (unsigned long long)c->dec.pack_left,
                  (unsigned long long)c->entry_left, c->dec.kind);
            goto io_error;
        }
        if (r > 0) {
            if (!c->entry_done) {
                P7Z_T("extract: folder ended early entry_left=%llu\n",
                      (unsigned long long)c->entry_left);
                goto io_error; /* folder ended before the entry did */
            }
            break;
        }
        if (c->dec.produced == before)
            goto io_error; /* decoder made no progress */
    }

    c->efp = NULL;
    if (crc32_out != NULL)
        *crc32_out = pam_crc32_final(c->crc);
    return wrote;

io_error:
    c->efp = NULL;
    if (crc32_out != NULL)
        *crc32_out = pam_crc32_final(c->crc);
    return -1;
}

int pam7z_entry_verify(const pam7z_cursor *c, uint32_t computed_crc)
{
    if (c == NULL)
        return -1;
    if (!c->want_known)
        return 0;
    return computed_crc == c->want_crc ? 1 : -1;
}

const char *pam7z_strerror(int rc)
{
    switch (rc) {
    case PAM_7Z_OK_EOF:
        return "fin d'archive";
    case PAM_7Z_ERR_CORRUPT:
        return "archive 7z corrompue ou tronquee";
    case PAM_7Z_ERR_UNSUPPORTED:
        return "codage 7z non pris en charge";
    case PAM_7Z_ERR_ENCRYPTED:
        return "archive chiffree";
    default:
        return "erreur 7z inconnue";
    }
}

void pam7z_close(pam7z_cursor *c)
{
    if (c == NULL)
        return;
    dec_stop(&c->dec);
    si_free(&c->si);
    free(c->files);
    pam_stream_close(&c->s);
    free(c);
}
