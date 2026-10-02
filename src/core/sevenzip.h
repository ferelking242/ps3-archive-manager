#ifndef PAM_SEVENZIP_H
#define PAM_SEVENZIP_H

#include <stdint.h>
#include <stdio.h>

/*
 * PS3 Archive Manager — 7z reader.
 *
 * Parses the 7z container (signature header, raw or encoded header,
 * streams/folders/files info) and decompresses the coders used by real
 * archives: Copy (0x00), Deflate (0x040108), LZMA (0x030101) and LZMA2
 * (0x21), single- or multi-volume (".7z.001"), including the x86 BCJ
 * (0x03030103) and Delta (0x03) filter chains 7-Zip builds with -mf=.
 * Solid archives (several files packed into one folder) are streamed in
 * order. Coders we do not implement (PPMd, BZip2, other BCJ variants)
 * and encryption are reported instead of failing silently:
 *
 *   1   entry available          0   end of archive
 *  -1   corrupt / truncated      -2  unsupported coder/feature
 *  -3   encrypted
 */

#define PAM_7Z_OK_EOF           0
#define PAM_7Z_OK_ENTRY         1
#define PAM_7Z_ERR_CORRUPT      (-1)
#define PAM_7Z_ERR_UNSUPPORTED  (-2)
#define PAM_7Z_ERR_ENCRYPTED    (-3)

typedef struct {
    char name[512];
    uint64_t size;
    uint32_t crc32;
    int is_dir;
    int crc_known;
} pam7z_entry;

typedef struct pam7z_cursor pam7z_cursor;

pam7z_cursor *pam7z_open(const char *first_path);
int pam7z_next(pam7z_cursor *c, pam7z_entry *e);
int pam7z_entry_done(const pam7z_cursor *c);
long long pam7z_extract_current(pam7z_cursor *c, FILE *out_fp,
                                unsigned long long limit,
                                uint32_t *crc32_out);
/* After the entry is done: 1 verified, 0 nothing to verify, -1 mismatch. */
int pam7z_entry_verify(const pam7z_cursor *c, uint32_t computed_crc);
const char *pam7z_strerror(int rc);
void pam7z_close(pam7z_cursor *c);

#endif /* PAM_SEVENZIP_H */
