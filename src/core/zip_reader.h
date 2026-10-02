#ifndef PAM_ZIP_READER_H
#define PAM_ZIP_READER_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * PS3 Archive Manager — streaming ZIP reader (stored + deflated entries).
 *
 * Entries are iterated from the local headers (no central directory), so
 * multi-volume "name.ext.001"-style ZIPs work by feeding the volumes to
 * the pam_stream layer. Method 0 (stored) is copied straight through,
 * method 8 (deflate) is decoded by the built-in inflater (no zlib).
 *
 * Return codes shared by pam_zip_next() and friends:
 *   1   entry available
 *   0   end of archive
 *  -1   corrupt / truncated data
 *  -2   unsupported feature (method, ZIP64, data-descriptor edge case…)
 *  -3   encrypted entry
 * After a negative return the cursor is "broken": extraction of that
 * archive must stop (the entry is named in *e when the header was read).
 */

#define PAM_ZIP_OK_EOF      0
#define PAM_ZIP_OK_ENTRY    1
#define PAM_ZIP_ERR_CORRUPT (-1)
#define PAM_ZIP_ERR_UNSUPPORTED (-2)
#define PAM_ZIP_ERR_ENCRYPTED (-3)

typedef struct {
    char name[256];
    uint32_t crc32;
    uint64_t compressed_size;
    uint64_t uncompressed_size; /* 0 while unknown (data descriptor)   */
    uint16_t method;            /* 0 = stored, 8 = deflate             */
    uint16_t flags;             /* general purpose bit flag            */
    int is_dir;                 /* name ends with '/'                  */
    int crc_known;              /* 0 until a data descriptor supplies it */
} pam_zip_entry;

typedef struct pam_zip_cursor pam_zip_cursor;

/* Open the archive (and any ".002" volume successors). NULL on failure. */
pam_zip_cursor *pam_zip_open(const char *first_part_path);
/* Next entry (1/0/-1/-2/-3, see above). Any unread entry is drained. */
int pam_zip_next(pam_zip_cursor *c, pam_zip_entry *e);
/* 1 when there is no active entry or it was fully consumed. */
int pam_zip_entry_done(const pam_zip_cursor *c);
/*
 * Stream up to `limit` bytes of the current entry to out_fp (NULL just
 * advances and CRCs). Returns bytes written this call (0 when the entry
 * is already done), or -1 on error. crc32_out receives the finalized
 * CRC-32 of the bytes consumed so far (valid when the entry is done).
 */
long long pam_zip_extract_current(pam_zip_cursor *c, FILE *out_fp,
                                  unsigned long long limit,
                                  uint32_t *crc32_out);
/* The entry as the reader knows it now (data descriptors may have
 * updated the CRC/size after pam_zip_next() returned it). */
const pam_zip_entry *pam_zip_current(const pam_zip_cursor *c);
/* After the entry is done: 1 verified, 0 nothing to verify, -1 mismatch. */
int pam_zip_entry_verify(const pam_zip_cursor *c, uint32_t computed_crc);
void pam_zip_close(pam_zip_cursor *c);
/* French description of a pam_zip_next()/extract return code. */
const char *pam_zip_strerror(int rc);

#endif /* PAM_ZIP_READER_H */
