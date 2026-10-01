#ifndef PAM_ARCHIVE_H
#define PAM_ARCHIVE_H

/*
 * PS3 Archive Manager — archive detection.
 *
 * Pure C, no platform dependencies: compiled for PowerPC (PS3) and for the
 * host test suite. Identification is signature-based; the manager never
 * assumes that a file named ".zip.001" is a ZIP until its bytes agree.
 */

#include <stddef.h>
#include <stdint.h>

typedef enum {
    PAM_FMT_UNKNOWN = 0,
    PAM_FMT_ZIP,
    PAM_FMT_7Z,
    PAM_FMT_TAR,
    PAM_FMT_GZIP,
    PAM_FMT_BZIP2,
    PAM_FMT_XZ,
} pam_format;

/* Known multi-volume naming styles. */
typedef enum {
    PAM_SPLIT_NONE = 0,   /* single-file archive                     */
    PAM_SPLIT_NUMERIC,    /* name.ext.001 / name.ext.002 / ...       */
    PAM_SPLIT_ZIP_LAST,   /* name.z01 ... name.z99 + name.zip (last) */
} pam_split_style;

typedef struct {
    pam_format format;      /* detected container/format           */
    pam_split_style split;  /* multi-volume naming style           */
    int has_start;          /* .001 (or base .zip for z01) present */
    int has_end_marker;     /* final part detected by name         */
} pam_archive_info;

typedef struct {
    pam_format format;      /* signature detected in the bytes     */
    int is_tar;             /* tar signatures are position-based   */
} pam_signature;

/*
 * Identify a container from its leading bytes (up to 512 bytes are enough
 * for every signature this module knows, including POSIX tar).
 */
void pam_sniff_signature(const uint8_t *data, size_t len,
                         pam_signature *out);

/*
 * Classify a file name. sig may be PAM_FMT_UNKNOWN when no data was read;
 * detection then relies on the extension only and format stays UNKNOWN
 * unless the split name style gives enough information to report a split.
 */
void pam_classify_name(const char *name, const pam_signature *sig,
                       pam_archive_info *out);

/*
 * Split naming: for "path/Game.zip.013" fills base="path/Game.zip",
 * ext=".zip", part=13 and returns 1. Returns 0 when the name does not end
 * with ".NNN" (3+ digits). base/ext are bounded writes (strncpy-style).
 */
int pam_split_parse(const char *path, char *base, size_t base_size,
                    char *ext, size_t ext_size, int *part);

/*
 * Build part N of a split: snprintf(base + ".%03d") into out.
 * Returns 0 on success, -1 when out is too small.
 */
int pam_split_part_name(const char *base, const char *ext, int part,
                        char *out, size_t out_size);

#endif /* PAM_ARCHIVE_H */
