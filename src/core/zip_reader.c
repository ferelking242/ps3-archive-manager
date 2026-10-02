#include "zip_reader.h"
#include "archive.h"
#include "crc32.h"
#include "inflate.h"
#include "stream.h"

#include <stdlib.h>
#include <string.h>

enum { ZK_NONE = 0, ZK_STORED, ZK_DEFLATE };

struct pam_zip_cursor {
    pam_stream s;
    pam_inflate_t inf;
    pam_zip_entry entry; /* authoritative: updated by data descriptors */

    int has_entry;
    int done;
    int broken;
    int last_err;
    int kind;
    int started;    /* inflater prepared for the current entry        */
    int size_known; /* uncompressed_size is trustworthy               */
    uint16_t flags;
    long long data_start; /* global offset right after the local header */
    uint64_t hdr_csize;
    long long stored_left;
    uint64_t produced;
    uint32_t crc; /* running CRC of the entry so far                 */
    long long put_made; /* bytes the inflater wrote on the last call  */
    FILE *out_fp;
};

/* ---- inflate adapters ---------------------------------------------------- */

static int zget(void *ctx)
{
    pam_zip_cursor *c = (pam_zip_cursor *)ctx;
    int b = pam_stream_get(&c->s);
    return b < 0 ? -1 : b; /* I/O error surfaces as end-of-input */
}

static int zput(void *ctx, const uint8_t *buf, size_t n)
{
    pam_zip_cursor *c = (pam_zip_cursor *)ctx;
    if (c->out_fp != NULL && fwrite(buf, 1, n, c->out_fp) != n)
        return 1;
    c->crc = pam_crc32_update(c->crc, buf, n);
    c->produced += n;
    c->put_made += (long long)n;
    return 0;
}

/* ---- helpers ------------------------------------------------------------- */

static void break_out(pam_zip_cursor *c, int err)
{
    c->broken = 1;
    c->last_err = err;
    c->has_entry = 0;
    c->done = 1;
    c->kind = ZK_NONE;
    c->started = 0;
}

/* Scan for the next local file header (PK\x03\x04), crossing volumes.
 * Returns 1 found, 0 end of archive, -1 I/O error. */
static int scan_local(pam_zip_cursor *c)
{
    uint8_t w[4];
    int i, b;

    for (i = 0; i < 4; i++) {
        b = pam_stream_get(&c->s);
        if (b < 0)
            return c->s.err ? -1 : 0;
        w[i] = (uint8_t)b;
    }
    for (;;) {
        if (w[0] == 'P' && w[1] == 'K' && w[2] == 0x03 && w[3] == 0x04)
            return 1;
        w[0] = w[1];
        w[1] = w[2];
        w[2] = w[3];
        b = pam_stream_get(&c->s);
        if (b < 0)
            return c->s.err ? -1 : 0;
        w[3] = (uint8_t)b;
    }
}

static int skip_bytes(pam_zip_cursor *c, long long n)
{
    if (n <= 0)
        return 0;
    if (pam_stream_skip(&c->s, n) != 1) {
        break_out(c, PAM_ZIP_ERR_CORRUPT);
        return -1;
    }
    return 0;
}

/*
 * After the compressed data: optionally align past the declared csize,
 * then read the data descriptor when general purpose bit 3 is set.
 * The descriptor wins over the (zeroed) local header values.
 */
static void finish_entry(pam_zip_cursor *c)
{
    if (c->hdr_csize > 0) {
        long long target = c->data_start + (long long)c->hdr_csize;
        long long cur = pam_stream_tell(&c->s);
        if (cur < target)
            (void)pam_stream_skip(&c->s, target - cur);
    }

    if ((c->flags & 8) != 0 && (c->flags & 0x40) == 0) {
        uint8_t sig[4];
        long long save = pam_stream_tell(&c->s);
        int have = pam_stream_read_exact(&c->s, sig, 4);
        uint32_t crc = 0, csize = 0, usize = 0;
        int ok = 0;

        if (have == 1) {
            if (sig[0] == 'P' && sig[1] == 'K') {
                if (sig[2] == 0x07 && sig[3] == 0x08) {
                    if (pam_stream_u32(&c->s, &crc) == 1 &&
                        pam_stream_u32(&c->s, &csize) == 1 &&
                        pam_stream_u32(&c->s, &usize) == 1)
                        ok = 1;
                } else {
                    /* Next structure already reached: no descriptor here. */
                    (void)pam_stream_seek(&c->s, save);
                }
            } else {
                /* Legacy descriptor without signature: sig[] holds the CRC. */
                crc = (uint32_t)sig[0] | ((uint32_t)sig[1] << 8) |
                      ((uint32_t)sig[2] << 16) | ((uint32_t)sig[3] << 24);
                if (pam_stream_u32(&c->s, &csize) == 1 &&
                    pam_stream_u32(&c->s, &usize) == 1)
                    ok = 1;
            }
        }
        if (have < 1)
            (void)pam_stream_seek(&c->s, save);

        if (ok) {
            c->entry.crc32 = crc;
            c->entry.crc_known = 1;
            c->entry.uncompressed_size = usize;
            c->entry.compressed_size = csize;
            c->size_known = 1;
        } else {
            /* Fall back to whatever the local header claimed. */
            (void)pam_stream_seek(&c->s, save);
            c->size_known = c->hdr_csize != 0 && c->entry.uncompressed_size != 0;
        }
    }
    c->done = 1;
    c->started = 0;
}

/* Read and validate the local header; fills c->entry. Returns 1 on
 * success, or a negative PAM_ZIP error code (e filled when possible). */
static int read_entry(pam_zip_cursor *c, pam_zip_entry *e)
{
    uint16_t version = 0, flags = 0, method = 0, time = 0, date = 0;
    uint16_t name_len = 0, extra_len = 0;
    uint32_t crc = 0, csize = 0, usize = 0;
    uint16_t i;
    int rc;

    (void)version;
    (void)time;
    (void)date;

    rc = pam_stream_u16(&c->s, &version);
    if (rc != 1) goto corrupt;
    rc = pam_stream_u16(&c->s, &flags);
    if (rc != 1) goto corrupt;
    rc = pam_stream_u16(&c->s, &method);
    if (rc != 1) goto corrupt;
    rc = pam_stream_u16(&c->s, &time);
    if (rc != 1) goto corrupt;
    rc = pam_stream_u16(&c->s, &date);
    if (rc != 1) goto corrupt;
    rc = pam_stream_u32(&c->s, &crc);
    if (rc != 1) goto corrupt;
    rc = pam_stream_u32(&c->s, &csize);
    if (rc != 1) goto corrupt;
    rc = pam_stream_u32(&c->s, &usize);
    if (rc != 1) goto corrupt;
    rc = pam_stream_u16(&c->s, &name_len);
    if (rc != 1) goto corrupt;
    rc = pam_stream_u16(&c->s, &extra_len);
    if (rc != 1) goto corrupt;

    if (name_len == 0 || name_len >= sizeof(c->entry.name))
        goto corrupt;
    for (i = 0; i < name_len; i++) {
        int b = pam_stream_get(&c->s);
        if (b < 0)
            goto corrupt;
        c->entry.name[i] = (char)b;
    }
    c->entry.name[name_len] = '\0';
    if (skip_bytes(c, extra_len) != 0)
        goto corrupt;

    c->entry.crc32 = crc;
    c->entry.compressed_size = csize;
    c->entry.uncompressed_size = usize;
    c->entry.method = method;
    c->entry.flags = flags;
    c->entry.is_dir = c->entry.name[name_len - 1] == '/';
    c->entry.crc_known = (flags & 8) == 0 || crc != 0;

    c->flags = flags;
    c->hdr_csize = csize;
    c->data_start = pam_stream_tell(&c->s);
    c->crc = PAM_CRC32_INIT;
    c->produced = 0;
    c->put_made = 0;
    c->size_known = (flags & 8) == 0 || usize != 0;
    c->started = 0;

    *e = c->entry;

    if (flags & 1)
        return PAM_ZIP_ERR_ENCRYPTED;
    if (method != 0 && method != 8)
        return PAM_ZIP_ERR_UNSUPPORTED;
    if (csize == 0xFFFFFFFFu || usize == 0xFFFFFFFFu)
        return PAM_ZIP_ERR_UNSUPPORTED; /* ZIP64 */
    if (method == 0 && (flags & 8) && csize == 0)
        return PAM_ZIP_ERR_UNSUPPORTED; /* descriptor length unknowable */

    c->has_entry = 1;
    c->kind = (method == 0) ? ZK_STORED : ZK_DEFLATE;
    c->stored_left = (method == 0)
                         ? (long long)(csize > 0 ? csize : usize)
                         : 0;
    c->done = (c->kind == ZK_STORED && c->stored_left == 0 &&
               (flags & 8) == 0);
    if (c->done)
        c->started = 0;
    return PAM_ZIP_OK_ENTRY;

corrupt:
    return PAM_ZIP_ERR_CORRUPT;
}

/* ---- public API ---------------------------------------------------------- */

pam_zip_cursor *pam_zip_open(const char *first_part_path)
{
    pam_zip_cursor *c = (pam_zip_cursor *)calloc(1, sizeof(*c));
    if (c == NULL)
        return NULL;
    if (pam_stream_open(&c->s, first_part_path) != 0) {
        free(c);
        return NULL;
    }
    return c;
}

void pam_zip_close(pam_zip_cursor *c)
{
    if (c == NULL)
        return;
    pam_stream_close(&c->s);
    free(c);
}

int pam_zip_entry_done(const pam_zip_cursor *c)
{
    return c == NULL || !c->has_entry || c->done;
}

const pam_zip_entry *pam_zip_current(const pam_zip_cursor *c)
{
    return c != NULL ? &c->entry : NULL;
}

long long pam_zip_extract_current(pam_zip_cursor *c, FILE *out_fp,
                                  unsigned long long limit,
                                  uint32_t *crc32_out)
{
    long long made = 0;

    if (c == NULL) {
        return -1;
    }
    if (!c->has_entry || c->done) {
        if (crc32_out != NULL)
            *crc32_out = pam_crc32_final(c->crc);
        return 0;
    }

    c->out_fp = out_fp;

    if (c->kind == ZK_STORED) {
        uint8_t tmp[4096];
        while (c->stored_left > 0 && (unsigned long long)made < limit) {
            size_t want = sizeof(tmp);
            size_t got;
            if ((unsigned long long)want > limit - made)
                want = (size_t)(limit - made);
            if ((long long)want > c->stored_left)
                want = (size_t)c->stored_left;
            got = pam_stream_read(&c->s, tmp, want);
            if (got == 0 || (out_fp != NULL &&
                             fwrite(tmp, 1, got, out_fp) != got)) {
                break_out(c, PAM_ZIP_ERR_CORRUPT);
                return -1;
            }
            c->crc = pam_crc32_update(c->crc, tmp, got);
            c->produced += got;
            c->stored_left -= (long long)got;
            made += (long long)got;
            if (got < want) { /* short read without EOF flag: re-loop */
                if (c->s.err) {
                    break_out(c, PAM_ZIP_ERR_CORRUPT);
                    return -1;
                }
            }
        }
        if (c->stored_left == 0 && !c->done)
            finish_entry(c);
    } else if (c->kind == ZK_DEFLATE) {
        if (!c->started) {
            pam_inflate_init(&c->inf, zget, zput, c);
            c->started = 1;
        }
        while (!pam_inflate_done(&c->inf)) {
            unsigned long long room =
                (limit > (unsigned long long)made)
                    ? limit - (unsigned long long)made
                    : 0;
            int rc;
            c->put_made = 0;
            rc = pam_inflate_run(&c->inf, room);
            if (rc < 0) {
                break_out(c, PAM_ZIP_ERR_CORRUPT);
                return -1;
            }
            made += c->put_made;
            if (rc == 0)
                break; /* yielded at the byte limit */
        }
        if (pam_inflate_done(&c->inf) && !c->done)
            finish_entry(c);
    } else {
        break_out(c, PAM_ZIP_ERR_CORRUPT);
        return -1;
    }

    if (crc32_out != NULL)
        *crc32_out = pam_crc32_final(c->crc);
    return made;
}

static int drain(pam_zip_cursor *c)
{
    long long guard = 0;
    while (!c->done) {
        long long n = pam_zip_extract_current(c, NULL, 1 << 20, NULL);
        if (n < 0)
            return -1;
        if (n == 0 && !c->done) {
            break_out(c, PAM_ZIP_ERR_CORRUPT);
            return -1;
        }
        if (++guard > (1LL << 30)) {
            break_out(c, PAM_ZIP_ERR_CORRUPT);
            return -1;
        }
    }
    return 0;
}

int pam_zip_next(pam_zip_cursor *c, pam_zip_entry *e)
{
    int rc;

    memset(e, 0, sizeof(*e));
    if (c == NULL)
        return PAM_ZIP_ERR_CORRUPT;
    if (c->broken)
        return c->last_err;
    if (c->has_entry && !c->done && drain(c) != 0)
        return c->last_err;

    c->has_entry = 0;
    c->kind = ZK_NONE;

    rc = scan_local(c);
    if (rc < 0) {
        break_out(c, PAM_ZIP_ERR_CORRUPT);
        return PAM_ZIP_ERR_CORRUPT;
    }
    if (rc == 0)
        return PAM_ZIP_OK_EOF;

    rc = read_entry(c, e);
    if (rc != PAM_ZIP_OK_ENTRY) {
        int err = rc;
        break_out(c, err); /* e keeps the entry name for diagnostics */
        return err;
    }
    return PAM_ZIP_OK_ENTRY;
}

int pam_zip_entry_verify(const pam_zip_cursor *c, uint32_t computed_crc)
{
    if (c == NULL || !c->done || c->kind == ZK_NONE)
        return 0;
    if (c->entry.crc_known && computed_crc != c->entry.crc32)
        return -1;
    if (c->size_known &&
        c->produced != c->entry.uncompressed_size)
        return -1;
    return (c->entry.crc_known || c->size_known) ? 1 : 0;
}

const char *pam_zip_strerror(int rc)
{
    switch (rc) {
    case PAM_ZIP_OK_EOF:
        return "fin d'archive";
    case PAM_ZIP_ERR_CORRUPT:
        return "archive corrompue ou tronquee";
    case PAM_ZIP_ERR_UNSUPPORTED:
        return "entree ZIP non prise en charge";
    case PAM_ZIP_ERR_ENCRYPTED:
        return "archive chiffree";
    default:
        return "erreur ZIP inconnue";
    }
}
