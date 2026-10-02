#ifndef PAM_EXTRACT_H
#define PAM_EXTRACT_H

#include "archive.h"

#include <stddef.h>
#include <stdint.h>

/*
 * PS3 Archive Manager — extraction pipeline.
 *
 * One entry point drives both containers (ZIP and 7z, detected by
 * signature): entry iteration, path safety, directory creation, chunked
 * writing with CRC-32 verification, progress/pause/cancel callbacks and
 * a structured result. The PS3 UI and the host test suite share this
 * exact code path.
 */

#define PAM_EXTRACT_OK          0
#define PAM_EXTRACT_CANCELLED   (-1)
#define PAM_EXTRACT_UNSUPPORTED (-2)
#define PAM_EXTRACT_ENCRYPTED   (-3)
#define PAM_EXTRACT_FAILED      (-4) /* corrupt data or I/O error      */
#define PAM_EXTRACT_UNSAFE      (-5) /* reserved: unsafe names are skipped */

typedef struct {
    void *user;
    /*
     * Create one directory (each parent is offered separately).
     * Return 0 on success; a failure is non fatal — the file write that
     * follows will report it. May be NULL.
     */
    int (*mkdir)(const char *path, void *user);
    /*
     * Before each chunk of an entry: done/total bytes for this entry
     * (total = 0 when the size is not known yet). Return 0 to continue,
     * -1 to cancel the whole extraction. The UI may block here to wait
     * for pause/resume — by the time it returns, the state is settled.
     */
    int (*progress)(const char *name, long long done, long long total,
                    void *user);
    /*
     * After each file: ok = 1 verified, 0 failed. Lets the UI offer the
     * "move to PS3ISO" prompt for extracted ISOs, etc. May be NULL.
     */
    void (*after_entry)(const char *name, const char *dest_path, int ok,
                        void *user);
} pam_extract_ops;

typedef struct {
    int status;        /* PAM_EXTRACT_* code                          */
    char message[192]; /* French description of the last problem      */
    char entry[512];   /* entry concerned by `message` (may be empty) */
    int files;         /* files written and verified                  */
    int dirs;          /* directories created                         */
    int failed;        /* files not verified (CRC/IO)                 */
    int crc_errors;    /* subset of `failed`: CRC-32 mismatches        */
    int unsafe_skips;  /* entries skipped for path safety             */
    long long bytes;   /* verified bytes written                      */
} pam_extract_result;

/* Read up to 512 bytes and identify the container. 0 ok, -1 unreadable. */
int pam_sniff_path(const char *path, pam_signature *sig);

/*
 * Extract archive_path into dest_dir (which must exist).
 * `ops` may be NULL for a silent extraction. Returns out->status.
 */
int pam_extract_to_dir(const char *archive_path, const char *dest_dir,
                       const pam_extract_ops *ops,
                       pam_extract_result *out);

const char *pam_extract_strerror(int status);

#endif /* PAM_EXTRACT_H */
