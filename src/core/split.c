#include "split.h"

#include <stdio.h>
#include <string.h>

int pam_split_scan(const char *any_part_path, pam_dir_exists exists_cb,
                   void *user, pam_split_set *out)
{
    char base[512], ext[64], probe[600], name[600];
    int part = 0, first, i;
    unsigned long long size = 0;

    if (any_part_path == NULL || exists_cb == NULL || out == NULL)
        return -1;

    memset(out, 0, sizeof(*out));

    if (pam_split_parse(any_part_path, base, sizeof(base), ext, sizeof(ext),
                        &part) != 1)
        return -2;

    /* Root directory = everything before the final '/' of the base. */
    {
        const char *slash = strrchr(base, '/');
        size_t root_len = slash != NULL ? (size_t)(slash - base) : 0;
        static char root_buf[512];
        if (root_len >= sizeof(root_buf))
            return -1;
        memcpy(root_buf, base, root_len);
        root_buf[root_len] = '\0';
        out->root = root_buf;
    }

    memcpy(out->base, base, sizeof(out->base));
    memcpy(out->ext, ext, sizeof(out->ext));

    /* The set always starts at 001 — even when the user picked .004. */
    first = 1;

    /* Walk upward while parts exist; stop at the first gap. */
    for (i = first; i <= 9999; i++) {
        if (pam_split_part_name(base, ext, i, probe, sizeof(probe)) != 0)
            break;
        {
            const char *slash2 = strrchr(probe, '/');
            snprintf(name, sizeof(name), "%s", slash2 != NULL ? slash2 + 1
                                                              : probe);
        }
        size = 0;
        if (!exists_cb(out->root, name, &size, user))
            break;
        out->last_part = i;
        out->present_parts++;
        out->total_bytes += size;
    }

    /* A gapless walk ending at .last means "complete" only when the NEXT
     * member is absent AND every number from first..last was seen — which
     * the loop guarantees. However the walk also stops at the first gap:
     * a trailing part beyond the gap (004 while 003 is missing) must flag
     * the set as incomplete. Detect that by probing one past last_part:
     * if present_parts covers 1..last contiguously there is no hole, but
     * callers that know more parts exist still get first_missing = last+1
     * when the archive continues (unknown length). Because ZIP volumes can
     * legitimately end anywhere, completeness here means "no hole found
     * up to and including last_part"; the extra 004 beyond the 003 gap
     * would have stopped the walk at 003, so a hole always shows up as
     * first_missing <= last_part. We therefore probe first_missing by
     * walking the membership flags again below. */
    out->first_part = first;

    /*
     * The upward walk stopped at the first missing member. If ANY numbered
     * member exists beyond that gap (Game.zip.004 while .003 is absent),
     * the set has a hole: the archive is incomplete and the walk would
     * have continued past a legitimately final part only while files
     * existed. Probe forward one past the stop: an existing member there
     * means the gap is real (missing middle volume); nothing there means
     * the archive simply ended at last_part.
     */
    out->expected_parts = out->last_part;
    out->complete = out->present_parts > 0 &&
                    out->present_parts == out->expected_parts;
    out->first_missing = 0;
    out->last_hole = 0;

    if (out->present_parts > 0) {
        int beyond = out->last_part + 1;
        int found_beyond = 0;
        int scan;

        for (scan = beyond; scan <= 9999 && !found_beyond; scan++) {
            if (pam_split_part_name(base, ext, scan, probe,
                                    sizeof(probe)) != 0)
                break;
            {
                const char *slash2 = strrchr(probe, '/');
                snprintf(name, sizeof(name), "%s",
                         slash2 != NULL ? slash2 + 1 : probe);
            }
            size = 0;
            if (exists_cb(out->root, name, &size, user)) {
                found_beyond = 1;
                out->last_hole = beyond;
            }
        }
        (void)found_beyond;
        if (out->last_hole > 0) {
            out->complete = 0;
            out->first_missing = out->last_hole;
        }
    }

    return (out->present_parts > 0) ? 0 : -2;
}

int pam_split_report(const pam_split_set *set, char *out, size_t out_size)
{
    int n;

    if (set->complete)
        n = snprintf(out, out_size, "%s%s: %d parties, complet",
                     set->base, set->ext, set->present_parts);
    else
        n = snprintf(out, out_size, "%s%s: %d/%d parties, manque .%03d",
                     set->base, set->ext, set->present_parts,
                     set->expected_parts, set->first_missing);
    return (n >= 0 && (size_t)n < out_size) ? 0 : -1;
}
