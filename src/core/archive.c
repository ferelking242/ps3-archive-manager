#include "archive.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- signatures ---------------------------------------------------------- */

static const uint8_t SIG_ZIP_LOCAL[] = { 'P', 'K', 0x03, 0x04 };
static const uint8_t SIG_ZIP_EMPTY[] = { 'P', 'K', 0x05, 0x06 };
static const uint8_t SIG_ZIP_SPANNED[] = { 'P', 'K', 0x07, 0x08 };
static const uint8_t SIG_7Z[] = { '7', 'z', 0xBC, 0xAF, 0x27, 0x1C };
static const uint8_t SIG_GZIP[] = { 0x1F, 0x8B };
static const uint8_t SIG_BZIP2[] = { 'B', 'Z', 'h' };
static const uint8_t SIG_XZ[] = { 0xFD, '7', 'z', 'X', 'Z', 0x00 };

void pam_sniff_signature(const uint8_t *data, size_t len, pam_signature *out)
{
    out->format = PAM_FMT_UNKNOWN;
    out->is_tar = 0;

    if (len < 2)
        return;

    if (memcmp(data, SIG_ZIP_LOCAL, 4) == 0 ||
        memcmp(data, SIG_ZIP_EMPTY, 4) == 0 ||
        memcmp(data, SIG_ZIP_SPANNED, 4) == 0) {
        out->format = PAM_FMT_ZIP;
        return;
    }
    if (len >= 6 && memcmp(data, SIG_7Z, 6) == 0) {
        out->format = PAM_FMT_7Z;
        return;
    }
    if (len >= 2 && memcmp(data, SIG_GZIP, 2) == 0) {
        out->format = PAM_FMT_GZIP;
        return;
    }
    if (len >= 3 && memcmp(data, SIG_BZIP2, 3) == 0) {
        out->format = PAM_FMT_BZIP2;
        return;
    }
    if (len >= 6 && memcmp(data, SIG_XZ, 6) == 0) {
        out->format = PAM_FMT_XZ;
        return;
    }
    /* POSIX tar: "ustar" at offset 257 (GNU + old SysV variants). */
    if (len >= 265 && memcmp(data + 257, "ustar", 5) == 0) {
        out->format = PAM_FMT_TAR;
        out->is_tar = 1;
        return;
    }
}

/* ---- name helpers -------------------------------------------------------- */

static const char *ext_of(const char *name)
{
    const char *dot = strrchr(name, '.');
    return dot != NULL ? dot : name; /* no dot: point at NUL */
}

static int all_digits(const char *s, size_t n)
{
    size_t i;
    if (n == 0)
        return 0;
    for (i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9')
            return 0;
    return 1;
}

int pam_split_parse(const char *path, char *base, size_t base_size,
                    char *ext, size_t ext_size, int *part)
{
    const char *dot = strrchr(path, '.');
    const char *base_dot = NULL;
    const char *p;
    size_t tail_len, base_len, ext_len;

    if (dot == NULL)
        return 0;
    tail_len = strlen(dot + 1);
    if (!all_digits(dot + 1, tail_len) || tail_len < 2)
        return 0;

    /* The base extension is the LAST dot before the numeric tail:
     * "Game.zip.013" -> base "Game", ext ".zip"; "Game.001" -> ext "". */
    for (p = path; p < dot; p++)
        if (*p == '.')
            base_dot = p;
    base_len = base_dot != NULL ? (size_t)(base_dot - path)
                                : (size_t)(dot - path);
    ext_len = base_dot != NULL ? (size_t)(dot - base_dot) : 0;

    if (base_len + 1 > base_size || (ext != NULL && ext_len + 1 > ext_size))
        return -1;

    memcpy(base, path, base_len);
    base[base_len] = '\0';
    /* "Game.001": the numeric tail is the member number, not an extension,
     * so the base must NOT include it (base_len stops before the dot). */
    if (ext != NULL) {
        memcpy(ext, base_dot != NULL ? base_dot : "", ext_len);
        ext[ext_len] = '\0';
    }
    *part = (int)strtol(dot + 1, NULL, 10);
    return 1;
}

int pam_split_part_name(const char *base, const char *ext, int part,
                        char *out, size_t out_size)
{
    int n = snprintf(out, out_size, "%s%s.%03d", base, ext, part);
    return (n >= 0 && (size_t)n < out_size) ? 0 : -1;
}

/* ---- classification ------------------------------------------------------ */

void pam_classify_name(const char *name, const pam_signature *sig,
                       pam_archive_info *out)
{
    const char *e = ext_of(name);
    char base[512], ext[64];
    int part = 0;

    out->format = PAM_FMT_UNKNOWN;
    out->split = PAM_SPLIT_NONE;
    out->has_start = 1;
    out->has_end_marker = 1;

    /* ".NNN" style multi-volume member? */
    if (pam_split_parse(name, base, sizeof(base), ext, sizeof(ext),
                        &part) == 1) {
        const char *inner = ext_of(ext[0] ? ext + 1 : base);
        out->split = PAM_SPLIT_NUMERIC;
        out->has_start = (part == 1);
        out->has_end_marker = 0;
        if (strcmp(inner, ".zip") == 0 || strcmp(inner, ".7z") == 0)
            out->format = sig->format != PAM_FMT_UNKNOWN
                              ? sig->format
                              : PAM_FMT_UNKNOWN;
        return;
    }

    /* "name.z01" style: ZIP split with the catalog as the last volume. */
    {
        size_t el = strlen(e);
        if (el == 4 && e[1] == 'z' &&
            all_digits(e + 2, 2) && strncmp(name, e, el) != 0) {
            out->split = PAM_SPLIT_ZIP_LAST;
            out->has_start = 0;
            out->format = PAM_FMT_ZIP;
            return;
        }
    }

    /* Single-file archive: trust the signature first, then the extension. */
    if (sig != NULL && sig->format != PAM_FMT_UNKNOWN)
        out->format = sig->format;
    else if (strcmp(e, ".zip") == 0)
        out->format = PAM_FMT_ZIP;
    else if (strcmp(e, ".7z") == 0)
        out->format = PAM_FMT_7Z;
    else if (strcmp(e, ".tar") == 0)
        out->format = PAM_FMT_TAR;
    else if (strcmp(e, ".gz") == 0)
        out->format = PAM_FMT_GZIP;
    else if (strcmp(e, ".bz2") == 0)
        out->format = PAM_FMT_BZIP2;
    else if (strcmp(e, ".xz") == 0)
        out->format = PAM_FMT_XZ;
}
