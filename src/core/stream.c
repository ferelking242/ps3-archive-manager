#include "stream.h"
#include "archive.h"

#include <stdlib.h>
#include <string.h>

#define STREAM_BUF 16384

static int grow_parts(pam_stream *s)
{
    int ncap = s->cap ? s->cap * 2 : 4;
    FILE **fp = (FILE **)realloc(s->parts, sizeof(FILE *) * (size_t)ncap);
    long long *sz;
    if (fp == NULL)
        return -1;
    s->parts = fp;
    sz = (long long *)realloc(s->psize, sizeof(long long) * (size_t)ncap);
    if (sz == NULL)
        return -1;
    s->psize = sz;
    s->cap = ncap;
    return 0;
}

/* Append one opened volume and measure it. 0 ok, -1 error. */
static int add_part(pam_stream *s, FILE *f)
{
    long long sz;

    if (f == NULL)
        return -1;
    if (s->nparts == s->cap && grow_parts(s) != 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0 ||
        fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    s->parts[s->nparts] = f;
    s->psize[s->nparts] = sz;
    s->nparts++;
    return 0;
}

int pam_stream_open(pam_stream *s, const char *first_path)
{
    char base[512], ext[64], path[600];
    int part;

    memset(s, 0, sizeof(*s));
    s->cap_buf = STREAM_BUF;
    s->buf = (uint8_t *)malloc(s->cap_buf);
    if (s->buf == NULL)
        return -1;

    if (add_part(s, fopen(first_path, "rb")) != 0) {
        pam_stream_close(s);
        return -1;
    }

    /* Numeric split member? Walk .002, .003 … until a gap. */
    if (pam_split_parse(first_path, base, sizeof(base), ext, sizeof(ext),
                        &part) == 1) {
        for (part = 2; part <= 999; part++) {
            FILE *f;
            if (pam_split_part_name(base, ext, part, path, sizeof(path)) != 0)
                break;
            f = fopen(path, "rb");
            if (f == NULL)
                break; /* gaps must be rejected before extraction */
            if (add_part(s, f) != 0) {
                pam_stream_close(s);
                return -1;
            }
        }
    }
    return 0;
}

void pam_stream_close(pam_stream *s)
{
    int i;
    if (s == NULL)
        return;
    for (i = 0; i < s->nparts; i++)
        if (s->parts[i])
            fclose(s->parts[i]);
    free(s->parts);
    free(s->psize);
    free(s->buf);
    memset(s, 0, sizeof(*s));
}

/* Fill the buffer from the current volume (single fread: never spans two
 * volumes). Advances to the next volume when the current one is spent.
 * Returns 1 when bytes were buffered, 0 at end of stream, -1 on error. */
static int refill(pam_stream *s)
{
    for (;;) {
        size_t r;
        if (s->cur >= s->nparts)
            return 0;
        r = fread(s->buf, 1, s->cap_buf, s->parts[s->cur]);
        if (r > 0) {
            s->len = r;
            s->pos = 0;
            return 1;
        }
        if (ferror(s->parts[s->cur])) {
            s->err = 1;
            return -1;
        }
        s->cur++; /* volume exhausted */
        /* The next volume may have been read before (e.g. the header at
         * the end of a later part): restart it from its beginning, which
         * is where sequential continuation resumes. */
        if (s->cur < s->nparts &&
            fseek(s->parts[s->cur], 0, SEEK_SET) != 0) {
            s->err = 1;
            return -1;
        }
    }
}

int pam_stream_get(pam_stream *s)
{
    if (s->pos == s->len) {
        int rc = refill(s);
        if (rc <= 0)
            return rc < 0 ? -2 : -1;
    }
    return s->buf[s->pos++];
}

size_t pam_stream_read(pam_stream *s, void *dst, size_t n)
{
    uint8_t *out = (uint8_t *)dst;
    size_t done = 0;

    while (done < n) {
        size_t avail, take;
        if (s->pos == s->len) {
            if (refill(s) <= 0)
                break;
        }
        avail = s->len - s->pos;
        take = (n - done) < avail ? (n - done) : avail;
        memcpy(out + done, s->buf + s->pos, take);
        s->pos += take;
        done += take;
    }
    return done;
}

int pam_stream_read_exact(pam_stream *s, void *dst, size_t n)
{
    size_t got = pam_stream_read(s, dst, n);
    if (got < n)
        return s->err ? -1 : 0;
    return 1;
}

long long pam_stream_tell(const pam_stream *s)
{
    long long base = 0;
    long phys;
    int i;

    if (s->cur >= s->nparts)
        return 0; /* at the very end: total size */
    for (i = 0; i < s->cur; i++)
        base += s->psize[i];
    phys = ftell(s->parts[s->cur]);
    if (phys < 0)
        return base;
    return base + phys - (long long)(s->len - s->pos);
}

int pam_stream_seek(pam_stream *s, long long off)
{
    long long base = 0;
    int i;

    if (off < 0)
        return -1;
    for (i = 0; i < s->nparts; i++) {
        if (off < base + s->psize[i]) {
            if (fseek(s->parts[i], (long)(off - base), SEEK_SET) != 0)
                return -1;
            s->cur = i;
            s->len = s->pos = 0;
            return 1;
        }
        base += s->psize[i];
    }
    return -1;
}

int pam_stream_skip(pam_stream *s, long long n)
{
    while (n > 0) {
        long long avail;
        if (s->pos == s->len) {
            int rc = refill(s);
            if (rc < 0)
                return -1;
            if (rc == 0)
                return 0; /* EOF before finishing the skip */
        }
        avail = (long long)(s->len - s->pos);
        if (n < avail) {
            s->pos += (size_t)n;
            return 1;
        }
        n -= avail;
        s->pos = s->len;
    }
    return 1;
}

void pam_stream_pushback(pam_stream *s, size_t n)
{
    if (n > s->pos)
        n = s->pos;
    s->pos -= n;
}

int pam_stream_u16(pam_stream *s, uint16_t *v)
{
    uint8_t b[2];
    int rc = pam_stream_read_exact(s, b, 2);
    if (rc != 1)
        return rc;
    *v = (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
    return 1;
}

int pam_stream_u32(pam_stream *s, uint32_t *v)
{
    uint8_t b[4];
    int rc = pam_stream_read_exact(s, b, 4);
    if (rc != 1)
        return rc;
    *v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) |
         ((uint32_t)b[3] << 24);
    return 1;
}

int pam_stream_u64(pam_stream *s, uint64_t *v)
{
    uint8_t b[8];
    uint64_t r = 0;
    int rc = pam_stream_read_exact(s, b, 8);
    int i;
    if (rc != 1)
        return rc;
    for (i = 7; i >= 0; i--)
        r = (r << 8) | b[i];
    *v = r;
    return 1;
}
