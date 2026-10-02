#include "extract.h"
#include "sevenzip.h"
#include "zip_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define EX_CHUNK (256 * 1024)
#define EX_PATH_MAX 1024

/* ---- sniffing ----------------------------------------------------------- */

int pam_sniff_path(const char *path, pam_signature *sig)
{
    FILE *f = fopen(path, "rb");
    uint8_t buf[512];
    size_t n;

    memset(sig, 0, sizeof(*sig));
    sig->format = PAM_FMT_UNKNOWN;
    if (f == NULL)
        return -1;
    n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    pam_sniff_signature(buf, n, sig);
    return 0;
}

static const char *format_name(pam_format fmt)
{
    switch (fmt) {
    case PAM_FMT_ZIP:    return "ZIP";
    case PAM_FMT_7Z:     return "7z";
    case PAM_FMT_TAR:    return "TAR";
    case PAM_FMT_GZIP:   return "GZ";
    case PAM_FMT_BZIP2:  return "BZ2";
    case PAM_FMT_XZ:     return "XZ";
    default:             return "inconnu";
    }
}

/* ---- path safety and construction -------------------------------------- */

static const char *next_sep(const char *p)
{
    for (; *p != '\0'; p++)
        if (*p == '/' || *p == '\\')
            return p;
    return NULL;
}

/* Reject absolute paths, drive letters and ".." segments. */
static int name_is_safe(const char *name)
{
    const char *seg = name;

    if (name[0] == '/' || name[0] == '\\')
        return 0;
    if (strchr(name, ':') != NULL)
        return 0;
    for (;;) {
        const char *sep = next_sep(seg);
        size_t len = sep ? (size_t)(sep - seg) : strlen(seg);
        if (len == 2 && seg[0] == '.' && seg[1] == '.')
            return 0;
        if (sep == NULL)
            break;
        seg = sep + 1;
    }
    return 1;
}

/* dest_dir + "/" + name, with backslashes normalized to '/'. */
static int build_path(char *out, size_t cap, size_t *base_end,
                      const char *dest_dir, const char *name)
{
    size_t dl = strlen(dest_dir);
    size_t i, nlen = strlen(name);

    while (dl > 1 && dest_dir[dl - 1] == '/')
        dl--;
    if (dl + 1 + nlen + 1 > cap)
        return -1;
    memcpy(out, dest_dir, dl);
    out[dl] = '/';
    for (i = 0; i < nlen; i++)
        out[dl + 1 + i] = (name[i] == '\\') ? '/' : name[i];
    out[dl + 1 + nlen] = '\0';
    if (base_end != NULL)
        *base_end = dl;
    return 0;
}

/* Create every directory prefix of path beyond base_end. */
static void make_dirs(char *path, size_t base_end, int include_last,
                      const pam_extract_ops *ops)
{
    size_t i, len;

    if (ops == NULL || ops->mkdir == NULL)
        return;
    len = strlen(path);
    for (i = base_end + 1; i < len; i++) {
        if (path[i] == '/') {
            char save = path[i];
            path[i] = '\0';
            ops->mkdir(path, ops->user);
            path[i] = save;
        }
    }
    if (include_last && len > base_end + 1 && path[len - 1] != '/')
        ops->mkdir(path, ops->user);
}

/* ---- result helpers ----------------------------------------------------- */

static void set_err(pam_extract_result *out, int status, const char *msg,
                    const char *entry)
{
    out->status = status;
    snprintf(out->message, sizeof(out->message), "%s", msg);
    if (entry != NULL)
        snprintf(out->entry, sizeof(out->entry), "%s", entry);
}

static int cancelled_check(const pam_extract_ops *ops, const char *name,
                           long long done, long long total)
{
    if (ops == NULL || ops->progress == NULL)
        return 0;
    return ops->progress(name, done, total, ops->user) < 0 ? 1 : 0;
}

static void notify(const pam_extract_ops *ops, const char *name,
                   const char *full, int ok)
{
    if (ops != NULL && ops->after_entry != NULL)
        ops->after_entry(name, full, ok, ops->user);
}

/* Keep the offending name in out->entry, never concatenated into
 * out->message: the fixed buffer must not trigger truncation warnings. */
static void set_err_crc(pam_extract_result *out, const char *entry)
{
    snprintf(out->message, sizeof(out->message), "CRC invalide");
    snprintf(out->entry, sizeof(out->entry), "%s", entry);
}

/* ---- ZIP ---------------------------------------------------------------- */

static void zip_fail_status(int rc, int *status)
{
    switch (rc) {
    case PAM_ZIP_ERR_ENCRYPTED:  *status = PAM_EXTRACT_ENCRYPTED; break;
    case PAM_ZIP_ERR_UNSUPPORTED: *status = PAM_EXTRACT_UNSUPPORTED; break;
    default:                     *status = PAM_EXTRACT_FAILED; break;
    }
}

static int extract_zip(const char *path, const char *dest,
                       const pam_extract_ops *ops, pam_extract_result *out)
{
    pam_zip_cursor *c = pam_zip_open(path);

    if (c == NULL) {
        set_err(out, PAM_EXTRACT_FAILED, "impossible d'ouvrir l'archive", "");
        return out->status;
    }

    for (;;) {
        pam_zip_entry e;
        long long done = 0, total, n;
        uint32_t crc = 0;
        char full[EX_PATH_MAX];
        size_t be = 0;
        FILE *f;
        int rc = pam_zip_next(c, &e);

        if (rc == PAM_ZIP_OK_EOF)
            break;
        if (rc != PAM_ZIP_OK_ENTRY) {
            char msg[192];
            int status;
            zip_fail_status(rc, &status);
            snprintf(msg, sizeof(msg), "%s", pam_zip_strerror(rc));
            set_err(out, status, msg, e.name);
            break;
        }

        if (!name_is_safe(e.name)) {
            out->unsafe_skips++;
            snprintf(out->message, sizeof(out->message),
                     "chemin non sur ignore");
            snprintf(out->entry, sizeof(out->entry), "%s", e.name);
            continue;
        }
        if (build_path(full, sizeof(full), &be, dest, e.name) != 0) {
            out->unsafe_skips++;
            continue;
        }

        if (e.is_dir) {
            make_dirs(full, be, 1, ops);
            out->dirs++;
            continue;
        }

        make_dirs(full, be, 0, ops);
        total = (long long)e.uncompressed_size;
        f = fopen(full, "wb");
        if (f == NULL) {
            out->failed++;
            set_err(out, PAM_EXTRACT_FAILED, "ecriture impossible", e.name);
            notify(ops, e.name, full, 0);
            break;
        }
        if (cancelled_check(ops, e.name, 0, total)) {
            fclose(f);
            out->status = PAM_EXTRACT_CANCELLED;
            snprintf(out->entry, sizeof(out->entry), "%s", e.name);
            break;
        }
        while (!pam_zip_entry_done(c)) {
            n = pam_zip_extract_current(c, f, EX_CHUNK, &crc);
            if (n < 0) {
                fclose(f);
                out->failed++;
                set_err(out, PAM_EXTRACT_FAILED,
                        pam_zip_strerror(PAM_ZIP_ERR_CORRUPT), e.name);
                notify(ops, e.name, full, 0);
                break;
            }
            done += n;
            if (cancelled_check(ops, e.name, done, total)) {
                fclose(f);
                out->status = PAM_EXTRACT_CANCELLED;
                snprintf(out->entry, sizeof(out->entry), "%s", e.name);
                break;
            }
        }
        if (out->status == PAM_EXTRACT_CANCELLED ||
            out->status == PAM_EXTRACT_FAILED)
            break;
        fclose(f);

        if (pam_zip_entry_verify(c, crc) < 0) {
            out->failed++;
            out->crc_errors++;
            set_err_crc(out, e.name);
            notify(ops, e.name, full, 0);
        } else {
            out->files++;
            out->bytes += done;
            (void)cancelled_check(ops, e.name, done,
                                  total > 0 ? total : done);
            notify(ops, e.name, full, 1);
        }
    }

    pam_zip_close(c);
    if (out->status == PAM_EXTRACT_OK && out->crc_errors > 0) {
        char msg[192];
        snprintf(msg, sizeof(msg), "%d fichier(s) avec CRC invalide",
                 out->crc_errors);
        snprintf(out->message, sizeof(out->message), "%s", msg);
    }
    return out->status;
}

/* ---- 7z ---------------------------------------------------------------- */

static void seven_fail_status(int rc, int *status)
{
    switch (rc) {
    case PAM_7Z_ERR_ENCRYPTED:   *status = PAM_EXTRACT_ENCRYPTED; break;
    case PAM_7Z_ERR_UNSUPPORTED: *status = PAM_EXTRACT_UNSUPPORTED; break;
    default:                     *status = PAM_EXTRACT_FAILED; break;
    }
}

static int extract_7z(const char *path, const char *dest,
                      const pam_extract_ops *ops, pam_extract_result *out)
{
    pam7z_cursor *c = pam7z_open(path);

    if (c == NULL) {
        set_err(out, PAM_EXTRACT_FAILED, "archive 7z illisible", "");
        return out->status;
    }

    for (;;) {
        pam7z_entry e;
        long long done = 0, total, n;
        uint32_t crc = 0;
        char full[EX_PATH_MAX];
        size_t be = 0;
        FILE *f;
        int rc = pam7z_next(c, &e);

        if (rc == PAM_ZIP_OK_EOF)
            break;
        if (rc != PAM_ZIP_OK_ENTRY) {
            char msg[192];
            int status;
            seven_fail_status(rc, &status);
            snprintf(msg, sizeof(msg), "%s", pam7z_strerror(rc));
            set_err(out, status, msg, e.name);
            break;
        }

        if (!name_is_safe(e.name)) {
            out->unsafe_skips++;
            snprintf(out->message, sizeof(out->message),
                     "chemin non sur ignore");
            snprintf(out->entry, sizeof(out->entry), "%s", e.name);
            continue;
        }
        if (build_path(full, sizeof(full), &be, dest, e.name) != 0) {
            out->unsafe_skips++;
            continue;
        }

        if (e.is_dir) {
            make_dirs(full, be, 1, ops);
            out->dirs++;
            continue;
        }

        make_dirs(full, be, 0, ops);
        total = (long long)e.size;
        f = fopen(full, "wb");
        if (f == NULL) {
            out->failed++;
            set_err(out, PAM_EXTRACT_FAILED, "ecriture impossible", e.name);
            notify(ops, e.name, full, 0);
            break;
        }
        if (cancelled_check(ops, e.name, 0, total)) {
            fclose(f);
            out->status = PAM_EXTRACT_CANCELLED;
            snprintf(out->entry, sizeof(out->entry), "%s", e.name);
            break;
        }
        while (!pam7z_entry_done(c)) {
            n = pam7z_extract_current(c, f, EX_CHUNK, &crc);
            if (n < 0) {
                fclose(f);
                out->failed++;
                set_err(out, PAM_EXTRACT_FAILED, pam7z_strerror(PAM_7Z_ERR_CORRUPT),
                        e.name);
                notify(ops, e.name, full, 0);
                break;
            }
            done += n;
            if (cancelled_check(ops, e.name, done, total)) {
                fclose(f);
                out->status = PAM_EXTRACT_CANCELLED;
                snprintf(out->entry, sizeof(out->entry), "%s", e.name);
                break;
            }
        }
        if (out->status == PAM_EXTRACT_CANCELLED ||
            out->status == PAM_EXTRACT_FAILED)
            break;
        fclose(f);

        if (pam7z_entry_verify(c, crc) < 0) {
            out->failed++;
            out->crc_errors++;
            set_err_crc(out, e.name);
            notify(ops, e.name, full, 0);
        } else {
            out->files++;
            out->bytes += done;
            (void)cancelled_check(ops, e.name, done,
                                  total > 0 ? total : done);
            notify(ops, e.name, full, 1);
        }
    }

    pam7z_close(c);
    if (out->status == PAM_EXTRACT_OK && out->crc_errors > 0) {
        char msg[192];
        snprintf(msg, sizeof(msg), "%d fichier(s) avec CRC invalide",
                 out->crc_errors);
        snprintf(out->message, sizeof(out->message), "%s", msg);
    }
    return out->status;
}

/* ---- entry point -------------------------------------------------------- */

int pam_extract_to_dir(const char *archive_path, const char *dest_dir,
                       const pam_extract_ops *ops, pam_extract_result *out)
{
    pam_signature sig;
    char msg[192];

    memset(out, 0, sizeof(*out));
    out->status = PAM_EXTRACT_OK;

    if (pam_sniff_path(archive_path, &sig) != 0) {
        set_err(out, PAM_EXTRACT_FAILED, "impossible de lire l'archive", "");
        return out->status;
    }

    switch (sig.format) {
    case PAM_FMT_ZIP:
        return extract_zip(archive_path, dest_dir, ops, out);
    case PAM_FMT_7Z:
        return extract_7z(archive_path, dest_dir, ops, out);
    default:
        snprintf(msg, sizeof(msg),
                 "format %s non pris en charge (voir README: phases)",
                 format_name(sig.format));
        set_err(out, PAM_EXTRACT_UNSUPPORTED, msg, "");
        return out->status;
    }
}

const char *pam_extract_strerror(int status)
{
    switch (status) {
    case PAM_EXTRACT_OK:          return "succes";
    case PAM_EXTRACT_CANCELLED:   return "extraction annulee";
    case PAM_EXTRACT_UNSUPPORTED: return "format non pris en charge";
    case PAM_EXTRACT_ENCRYPTED:   return "archive chiffree";
    case PAM_EXTRACT_FAILED:      return "echec de l'extraction";
    case PAM_EXTRACT_UNSAFE:      return "chemin non sur";
    default:                      return "erreur inconnue";
    }
}
