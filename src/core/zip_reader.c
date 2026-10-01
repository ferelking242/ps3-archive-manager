#include "zip_reader.h"
#include "archive.h"

#include <stdlib.h>
#include <string.h>

#define SIG_LOCAL 0x04034b50u

struct pam_zip_cursor {
    FILE **parts;        /* opened part files, in order      */
    int part_count;
    int current_part;    /* index into parts                 */
    long long remaining; /* bytes left in current entry      */
    uint32_t crc;        /* running CRC of the current entry */
};

/* CRC-32 (IEEE), incremental, small table — fine at USB speeds. */
static uint32_t crc32_update(uint32_t running, const uint8_t *buf, size_t len)
{
    static uint32_t table[256];
    static int ready = 0;
    size_t i;

    if (!ready) {
        for (uint32_t n = 0; n < 256; n++) {
            uint32_t c = n;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        ready = 1;
    }
    for (i = 0; i < len; i++)
        running = table[(running ^ buf[i]) & 0xFF] ^ (running >> 8);
    return running;
}

pam_zip_cursor *pam_zip_open(const char *first_part_path)
{
    pam_zip_cursor *c = (pam_zip_cursor *)calloc(1, sizeof(*c));
    FILE **chain = NULL;
    int count = 0, cap = 4;
    char base[512], ext[64], path[600];
    int part = 1;

    if (c == NULL)
        return NULL;

    chain = (FILE **)malloc(sizeof(FILE *) * cap);
    if (chain == NULL) {
        free(c);
        return NULL;
    }

    chain[count++] = fopen(first_part_path, "rb");
    if (chain[0] == NULL) {
        free(chain);
        free(c);
        return NULL;
    }

    if (pam_split_parse(first_part_path, base, sizeof(base), ext,
                        sizeof(ext), &part) == 1) {
        for (part = 2; part <= 999; part++) {
            FILE *f;
            if (pam_split_part_name(base, ext, part, path, sizeof(path)) != 0)
                break;
            f = fopen(path, "rb");
            if (f == NULL)
                break; /* gaps must be rejected before extraction */
            if (count == cap) {
                FILE **grown =
                    (FILE **)realloc(chain, sizeof(FILE *) * cap * 2);
                if (grown == NULL)
                    break;
                chain = grown;
                cap *= 2;
            }
            chain[count++] = f;
        }
    }

    c->parts = chain;
    c->part_count = count;
    return c;
}

static FILE *advance_part(pam_zip_cursor *c)
{
    if (c->current_part + 1 < c->part_count)
        return c->parts[++c->current_part];
    return NULL;
}

static int read_byte(pam_zip_cursor *c, uint8_t *b)
{
    FILE *f = c->parts[c->current_part];
    while (f != NULL && fread(b, 1, 1, f) != 1)
        f = advance_part(c);
    return f != NULL;
}

static int read_u16(pam_zip_cursor *c, uint16_t *v)
{
    uint8_t lo, hi;
    if (!read_byte(c, &lo) || !read_byte(c, &hi))
        return 0;
    *v = (uint16_t)(lo | ((uint16_t)hi << 8));
    return 1;
}

static int read_u32(pam_zip_cursor *c, uint32_t *v)
{
    uint16_t lo, hi;
    if (!read_u16(c, &lo) || !read_u16(c, &hi))
        return 0;
    *v = (uint32_t)lo | ((uint32_t)hi << 16);
    return 1;
}

int pam_zip_next(pam_zip_cursor *c, pam_zip_entry *e)
{
    uint8_t w0 = 0, w1 = 0, w2 = 0, w3 = 0;
    uint16_t flags, time, date, name_len, extra_len;
    uint32_t crc, csize, usize;

    memset(e, 0, sizeof(*e));

    /* Scan for the local-header signature with a rolling 4-byte window
     * that crosses part boundaries. */
    if (!read_byte(c, &w0) || !read_byte(c, &w1) ||
        !read_byte(c, &w2) || !read_byte(c, &w3))
        return 0; /* empty/EOF */
    for (;;) {
        if (w0 == 0x50 && w1 == 0x4B && w2 == 0x03 && w3 == 0x04)
            break;
        w0 = w1;
        w1 = w2;
        w2 = w3;
        if (!read_byte(c, &w3))
            return 0; /* no more signatures: end of archive */
    }

    /* Header payload after "PK\003\004": version(2) flags(2) method(2)
     * time(2) date(2) crc(4) csize(4) usize(4) name(n) extra(m). */
    {
        uint16_t version;
        if (!read_u16(c, &version)) return -1;
        if (!read_u16(c, &flags))   return -1;
        if (!read_u16(c, &e->method)) return -1;
        if (!read_u16(c, &time))    return -1;
        if (!read_u16(c, &date))    return -1;
        if (!read_u32(c, &crc))     return -1;
        if (!read_u32(c, &csize))   return -1;
        if (!read_u32(c, &usize))   return -1;
        if (!read_u16(c, &name_len))  return -1;
        if (!read_u16(c, &extra_len)) return -1;
        e->crc32 = crc;
    }

    if (name_len >= sizeof(e->name))
        return -1;
    for (uint16_t i = 0; i < name_len; i++) {
        uint8_t b;
        if (!read_byte(c, &b))
            return -1;
        e->name[i] = (char)b;
    }
    e->name[name_len] = '\0';
    for (uint16_t i = 0; i < extra_len; i++) {
        uint8_t b;
        if (!read_byte(c, &b))
            return -1;
    }

    if (e->method != 0)
        return -2; /* deflated entries arrive with zlib in Phase 3 */

    e->compressed_size = usize;
    e->uncompressed_size = usize;
    c->remaining = (long long)usize;
    c->crc = 0xFFFFFFFFu;
    return 1;
}

long long pam_zip_extract_current(pam_zip_cursor *c, FILE *out_fp,
                                  unsigned long long limit,
                                  uint32_t *crc32_out)
{
    static uint8_t block[256 * 1024];
    long long done = 0;

    while (c->remaining > 0) {
        size_t want;
        size_t got = 0;

        want = c->remaining < (long long)sizeof(block)
                   ? (size_t)c->remaining
                   : sizeof(block);
        if ((unsigned long long)done + want > limit)
            want = (size_t)((unsigned long long)limit -
                            (unsigned long long)done);
        if (want == 0)
            break;

        while (got < want) {
            FILE *f = c->parts[c->current_part];
            size_t r = fread(block + got, 1, want - got, f);
            if (r == 0) {
                f = advance_part(c);
                if (f == NULL)
                    return -1;
                continue;
            }
            got += r;
        }

        c->crc = crc32_update(c->crc, block, got);
        if (out_fp != NULL && fwrite(block, 1, got, out_fp) != got)
            return -1;
        c->remaining -= (long long)got;
        done += (long long)got;
    }

    if (crc32_out != NULL)
        *crc32_out = c->crc ^ 0xFFFFFFFFu;
    return done;
}

void pam_zip_close(pam_zip_cursor *c)
{
    if (c == NULL)
        return;
    for (int i = 0; i < c->part_count; i++)
        if (c->parts[i])
            fclose(c->parts[i]);
    free(c->parts);
    free(c);
}
