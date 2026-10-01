#ifndef PAM_SPLIT_H
#define PAM_SPLIT_H

#include "archive.h"

#include <stddef.h>

/*
 * PS3 Archive Manager — split-volume set scanning.
 *
 * Given "Game.zip.001" the scanner verifies that parts 1..N form a complete,
 * gapless set, ignoring stray numbered files that do not belong to the set
 * (e.g. "Game.iso.999" when scanning "Game.zip.001"). The caller supplies a
 * directory-listing callback so the same code runs on the PS3 (sysLv2Fs*),
 * in host tests (fixture directories) and later on the desktop tool.
 */

typedef struct {
    const char *root;         /* directory holding the parts            */
    char base[512];           /* shared base path without .NNN          */
    char ext[64];             /* inner extension, e.g. ".zip" or ""     */
    int first_part;           /* usually 1                              */
    int last_part;            /* highest contiguous part present        */
    int expected_parts;       /* first..last when the set is complete   */
    int present_parts;        /* how many parts actually exist          */
    int complete;             /* 1 when no gaps between first and last  */
    int first_missing;        /* lowest missing part number, or 0       */
    int last_hole;            /* internal: gap detected above last walk   */
    unsigned long long total_bytes; /* sum of present part sizes        */
} pam_split_set;

/* Directory entry callback: returns 1 when name exists in root, 0 if not. */
typedef int (*pam_dir_exists)(const char *root, const char *name,
                              unsigned long long *size, void *user);

/*
 * Scan a split set starting from any member path ("...zip.004" works).
 * Returns 0 on success (fields filled), -1 on bad arguments, -2 when the
 * path is not a numeric split member.
 */
int pam_split_scan(const char *any_part_path, pam_dir_exists exists_cb,
                   void *user, pam_split_set *out);

/* Fill a human-readable report line ("Game.zip.004", "12/13 parties", ...). */
int pam_split_report(const pam_split_set *set, char *out, size_t out_size);

#endif /* PAM_SPLIT_H */
