#ifndef PAM_ZIP_READER_H
#define PAM_ZIP_READER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * PS3 Archive Manager — minimal streaming ZIP reader (stored entries).
 *
 * Scope: extract entries with method 0 (stored) and, later, delegate
 * deflated entries to a zlib build. Entry data is streamed in blocks so a
 * multi-GB ISO never touches RAM. Single- and multi-volume (".001"-style)
 * ZIPs are supported through the pam_zippart layer.
 */

typedef struct {
    char name[256];
    uint32_t crc32;
    uint64_t compressed_size;
    uint64_t uncompressed_size;
    uint16_t method; /* 0 = stored, 8 = deflate (not yet decoded) */
} pam_zip_entry;

typedef struct pam_zip_cursor pam_zip_cursor;

/* Iterate local file headers sequentially (streaming, no central dir). */
pam_zip_cursor *pam_zip_open(const char *first_part_path);
/* Next entry; returns 1 and fills e, 0 at end of archive, -1 on error. */
int pam_zip_next(pam_zip_cursor *c, pam_zip_entry *e);
/* Stream the current entry's data to out_fp in chunks. Returns bytes
 * written, or -1 on read/write error. crc32_out receives the CRC. */
long long pam_zip_extract_current(pam_zip_cursor *c, FILE *out_fp,
                                  unsigned long long limit,
                                  uint32_t *crc32_out);
void pam_zip_close(pam_zip_cursor *c);

#endif /* PAM_ZIP_READER_H */
