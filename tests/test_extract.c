/*
 * PS3 Archive Manager — end-to-end extraction tests.
 *
 * Runs the full pam_extract_to_dir() pipeline against committed fixtures:
 *
 *   - real 7z archives (Copy / LZMA / LZMA2 / Deflate, x86 BCJ and
 *     Delta filter chains, solid folders, multi-volume ".7z.001",
 *     multi-folder, unicode names, empty files and directories) checked
 *     byte for byte against expected/ trees produced by py7zr;
 *   - stored and deflated ZIPs checked against the same kind of trees;
 *   - archives using coders we deliberately do not support (PPMd) must
 *     report "unsupported", the encrypted one "encrypted", the corrupted
 *     ones a failure or a CRC error;
 *   - progress-callback cancellation must stop with PAM_EXTRACT_CANCELLED.
 *
 * Runs on the build machine only: no PS3 toolchain, no network.
 */

#include "archive.h"
#include "extract.h"
#include "sevenzip.h"
#include "zip_reader.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                     \
        }                                                                   \
    } while (0)

#define PATH_CAP 1024
#define MAX_ENTRIES 4096

/* ---- small path helpers (no snprintf: unbounded names, -Werror) --------- */

static size_t scopy(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n >= cap)
        n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
    return n;
}

static void cat2(char *dst, size_t cap, const char *a, const char *b)
{
    size_t n = scopy(dst, cap, a);
    if (n + 1 < cap)
        scopy(dst + n, cap - n, b);
}

static void cat3(char *dst, size_t cap, const char *a, const char *b,
                 const char *c)
{
    size_t n = scopy(dst, cap, a);
    if (n + 1 < cap) {
        n += scopy(dst + n, cap - n, b);
        if (n + 1 < cap)
            scopy(dst + n, cap - n, c);
    }
}

/* ---- directory tree walking ---------------------------------------------- */

/* Entries are stored as "F path" so one sort orders both trees alike. */
typedef struct {
    char *paths; /* MAX_ENTRIES * PATH_CAP */
    int n;
} plist;

static void plist_init(plist *p)
{
    p->paths = (char *)calloc(MAX_ENTRIES, PATH_CAP);
    p->n = 0;
}

static void plist_free(plist *p)
{
    free(p->paths);
    p->paths = NULL;
    p->n = 0;
}

static void plist_add(plist *p, char kind, const char *rel)
{
    char *slot;
    if (p->n >= MAX_ENTRIES || p->paths == NULL)
        return;
    slot = p->paths + (size_t)p->n * PATH_CAP;
    slot[0] = kind;
    slot[1] = ' ';
    scopy(slot + 2, PATH_CAP - 2, rel);
    p->n++;
}

static int cmp_ent(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static void walk(const char *root, const char *rel, plist *p)
{
    char full[PATH_CAP * 2];
    DIR *d;
    struct dirent *de;

    if (rel[0] == '\0')
        scopy(full, sizeof(full), root);
    else
        cat3(full, sizeof(full), root, "/", rel);
    d = opendir(full);
    if (d == NULL)
        return;
    while ((de = readdir(d)) != NULL) {
        char child_rel[PATH_CAP];
        char child_full[PATH_CAP * 2];
        struct stat st;

        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (rel[0] == '\0')
            cat2(child_rel, sizeof(child_rel), "", de->d_name);
        else
            cat3(child_rel, sizeof(child_rel), rel, "/", de->d_name);
        cat3(child_full, sizeof(child_full), root, "/", child_rel);
        if (stat(child_full, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode)) {
            /* Files only: git cannot store empty directories, so a fresh
             * checkout lacks them — the directory layout is implied by
             * the file paths, and res.dirs is asserted against the
             * manifest instead. */
            walk(root, child_rel, p);
        } else {
            plist_add(p, 'F', child_rel);
        }
    }
    closedir(d);
}

/* Count directories in an extracted tree (dest only: unlike the committed
 * expected/ trees, a freshly extracted dest contains its empty dirs). */
static int count_dirs(const char *root, const char *rel)
{
    char full[PATH_CAP * 2];
    DIR *d;
    struct dirent *de;
    int n = 0;

    if (rel[0] == '\0')
        scopy(full, sizeof(full), root);
    else
        cat3(full, sizeof(full), root, "/", rel);
    d = opendir(full);
    if (d == NULL)
        return 0;
    while ((de = readdir(d)) != NULL) {
        char child_rel[PATH_CAP], child_full[PATH_CAP * 2];
        struct stat st;
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;
        if (rel[0] == '\0')
            cat2(child_rel, sizeof(child_rel), "", de->d_name);
        else
            cat3(child_rel, sizeof(child_rel), rel, "/", de->d_name);
        cat3(child_full, sizeof(child_full), root, "/", child_rel);
        if (stat(child_full, &st) == 0 && S_ISDIR(st.st_mode)) {
            n++;
            n += count_dirs(root, child_rel);
        }
    }
    closedir(d);
    return n;
}

static int files_equal(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");
    unsigned char ba[8192], bb[8192];
    int ok = 1;

    if (fa == NULL || fb == NULL) {
        if (fa != NULL)
            fclose(fa);
        if (fb != NULL)
            fclose(fb);
        return 0;
    }
    for (;;) {
        size_t na = fread(ba, 1, sizeof(ba), fa);
        size_t nb = fread(bb, 1, sizeof(bb), fb);
        if (na != nb || memcmp(ba, bb, na) != 0) {
            ok = 0;
            break;
        }
        if (na == 0)
            break;
    }
    fclose(fa);
    fclose(fb);
    return ok;
}

static void compare_trees(const char *expected, const char *got, int line)
{
    plist e, g;
    int i;

    plist_init(&e);
    plist_init(&g);
    walk(expected, "", &e);
    walk(got, "", &g);
    qsort(e.paths, (size_t)e.n, PATH_CAP, cmp_ent);
    qsort(g.paths, (size_t)g.n, PATH_CAP, cmp_ent);
    if (e.n != g.n) {
        fprintf(stderr, "FAIL line %d: tree size %d != %d\n", line, g.n, e.n);
        failures++;
    }
    for (i = 0; i < e.n && i < g.n; i++) {
        const char *ee = e.paths + (size_t)i * PATH_CAP;
        const char *gg = g.paths + (size_t)i * PATH_CAP;
        if (strcmp(ee, gg) != 0) {
            fprintf(stderr, "FAIL line %d: entry [%s] != [%s]\n", line, gg,
                    ee);
            failures++;
            continue;
        }
        if (ee[0] == 'F') {
            char pa[PATH_CAP * 2], pb[PATH_CAP * 2];
            cat3(pa, sizeof(pa), expected, "/", ee + 2);
            cat3(pb, sizeof(pb), got, "/", gg + 2);
            if (!files_equal(pa, pb)) {
                fprintf(stderr, "FAIL line %d: content differs: %s\n", line,
                        ee + 2);
                failures++;
            }
        }
    }
    plist_free(&e);
    plist_free(&g);
}

/* ---- extraction ops ------------------------------------------------------- */

static int mkdir_cb(const char *path, void *user)
{
    (void)user;
    if (mkdir(path, 0755) == 0 || errno == EEXIST)
        return 0;
    return -1;
}

static int cancel_cb(const char *name, long long done, long long total,
                     void *user)
{
    (void)name;
    (void)done;
    (void)total;
    (void)user;
    return -1; /* cancel on the first progress call */
}

static void rm_rf(const char *dir)
{
    char cmd[PATH_CAP * 2];
    cat2(cmd, sizeof(cmd), "rm -rf ", dir);
    if (system(cmd) != 0)
        fprintf(stderr, "warn: cleanup %s failed\n", dir);
}

/* ---- per-fixture expectations -------------------------------------------- */

static int unsupported_coder_fixture(const char *name)
{
    return strcmp(name, "ppmd.7z") == 0;
}

static void run_7z_fixture(const char *name, const char *status,
                           const char *detail, long long files,
                           long long dirs, long long bytes, int line)
{
    char dest[] = "/tmp/pamexXXXXXX";
    char data[PATH_CAP], expected[PATH_CAP];
    pam_extract_ops ops;
    pam_extract_result res;

    memset(&ops, 0, sizeof(ops));
    ops.mkdir = mkdir_cb;

    if (unsupported_coder_fixture(name)) {
        /* py7zr supports these coders; we must say so instead of
         * silently writing nothing. */
        CHECK(strcmp(status, "OK") == 0);
        cat2(data, sizeof(data), "tests/fixtures/data/", name);
        if (mkdtemp(dest) == NULL) {
            CHECK(0);
            return;
        }
        CHECK(pam_extract_to_dir(data, dest, &ops, &res) ==
              PAM_EXTRACT_UNSUPPORTED);
        CHECK(res.files == 0);
        rm_rf(dest);
        return;
    }
    if (strcmp(status, "FAIL") == 0) {
        cat2(data, sizeof(data), "tests/fixtures/data/", name);
        if (mkdtemp(dest) == NULL) {
            CHECK(0);
            return;
        }
        CHECK(pam_extract_to_dir(data, dest, &ops, &res) == res.status);
        if (strstr(detail, "PasswordRequired") != NULL) {
            CHECK(res.status == PAM_EXTRACT_ENCRYPTED);
        } else if (strstr(detail, "CrcError") != NULL) {
            /* Data decodes; the stored CRC disagrees. */
            CHECK(res.status == PAM_EXTRACT_OK);
            CHECK(res.crc_errors >= 1);
            CHECK(res.failed >= 1);
        } else {
            CHECK(res.status == PAM_EXTRACT_FAILED);
        }
        rm_rf(dest);
        return;
    }

    /* Status OK in the manifest: full byte-for-byte extraction. */
    CHECK(strcmp(status, "OK") == 0);
    cat2(data, sizeof(data), "tests/fixtures/data/", name);
    scopy(expected, sizeof(expected), "tests/fixtures/expected/");
    {
        size_t n = strlen(expected);
        scopy(expected + n, sizeof(expected) - n, name);
        /* multi-volume: data is ".7z.001", expected tree is ".7z" */
        if (strstr(name, ".001") != NULL) {
            char *dot = strstr(expected, ".001");
            if (dot != NULL)
                *dot = '\0';
        }
    }
    if (mkdtemp(dest) == NULL) {
        CHECK(0);
        return;
    }
    CHECK(pam_extract_to_dir(data, dest, &ops, &res) == res.status);
    if (res.status != PAM_EXTRACT_OK || res.failed != 0 ||
        res.crc_errors != 0 || res.unsafe_skips != 0) {
        fprintf(stderr,
                "FAIL line %d: %s status=%d files=%d failed=%d crc=%d "
                "unsafe=%d msg=%s entry=%s\n",
                line, name, res.status, res.files, res.failed, res.crc_errors,
                res.unsafe_skips, res.message, res.entry);
        failures++;
    } else {
        CHECK(res.files == files);
        /* Directory layout: the manifest counts py7zr's extracted tree;
         * res.dirs only counts explicit metadata entries (longpath.7z
         * creates all 13 dirs implicitly from file paths). */
        if (count_dirs(dest, "") != dirs) {
            fprintf(stderr, "FAIL line %d: %s tree dirs=%d want=%lld\n", line,
                    name, count_dirs(dest, ""), dirs);
            failures++;
        }
        CHECK(res.bytes == bytes);
        compare_trees(expected, dest, line);
    }
    rm_rf(dest);
}

static void test_manifest_fixtures(void)
{
    FILE *mf = fopen("tests/fixtures/expected/MANIFEST.tsv", "r");
    char line[1024];
    int lineno = 0;

    CHECK(mf != NULL);
    if (mf == NULL)
        return;
    while (fgets(line, sizeof(line), mf) != NULL) {
        char *cols[6];
        int ncol = 0;
        char *tok;

        lineno++;
        if (line[0] == '#' || line[0] == '\n')
            continue;
        for (tok = strtok(line, "\t\n"); tok != NULL && ncol < 6;
             tok = strtok(NULL, "\t\n"))
            cols[ncol++] = tok;
        if (ncol < 3)
            continue;
        run_7z_fixture(cols[0], cols[1], ncol > 2 ? cols[2] : "",
                       ncol > 4 ? atoll(cols[2]) : -1,
                       ncol > 4 ? atoll(cols[3]) : -1,
                       ncol > 4 ? atoll(cols[4]) : -1, lineno);
    }
    fclose(mf);
}

/* ---- ZIP fixtures --------------------------------------------------------- */

static void run_zip_fixture(const char *name, long long files,
                            long long bytes)
{
    char dest[] = "/tmp/pamzipXXXXXX";
    char data[PATH_CAP], expected[PATH_CAP];
    pam_extract_ops ops;
    pam_extract_result res;

    memset(&ops, 0, sizeof(ops));
    ops.mkdir = mkdir_cb;

    cat2(data, sizeof(data), "tests/fixtures/data/", name);
    cat2(expected, sizeof(expected), "tests/fixtures/expected/", name);
    if (strstr(name, ".zip") != NULL) {
        char *dot = strstr(expected, ".zip");
        if (dot != NULL)
            *dot = '\0';
    }
    if (mkdtemp(dest) == NULL) {
        CHECK(0);
        return;
    }
    CHECK(pam_extract_to_dir(data, dest, &ops, &res) == res.status);
    if (res.status != PAM_EXTRACT_OK || res.failed != 0) {
        fprintf(stderr, "FAIL: %s status=%d files=%d failed=%d msg=%s\n", name,
                res.status, res.files, res.failed, res.message);
        failures++;
    } else {
        CHECK(res.files == files);
        CHECK(res.bytes == bytes);
        compare_trees(expected, dest, __LINE__);
    }
    rm_rf(dest);
}

/* ---- behavioural tests ----------------------------------------------------- */

static void test_cancel(void)
{
    char dest[] = "/tmp/pamcanXXXXXX";
    pam_extract_ops ops;
    pam_extract_result res;

    memset(&ops, 0, sizeof(ops));
    ops.mkdir = mkdir_cb;
    ops.progress = cancel_cb;

    if (mkdtemp(dest) == NULL) {
        CHECK(0);
        return;
    }
    CHECK(pam_extract_to_dir("tests/fixtures/data/copy.7z", dest, &ops,
                             &res) == PAM_EXTRACT_CANCELLED);
    rm_rf(dest);
}

static void test_unknown_format(void)
{
    char dest[] = "/tmp/pamunkXXXXXX";
    const char *tmp = "/tmp/pam-not-an-archive.bin";
    pam_extract_ops ops;
    pam_extract_result res;
    FILE *f = fopen(tmp, "wb");

    CHECK(f != NULL);
    if (f == NULL)
        return;
    fwrite("hello, this is not an archive at all\n", 1, 36, f);
    fclose(f);

    memset(&ops, 0, sizeof(ops));
    ops.mkdir = mkdir_cb;
    if (mkdtemp(dest) == NULL) {
        CHECK(0);
        unlink(tmp);
        return;
    }
    CHECK(pam_extract_to_dir(tmp, dest, &ops, &res) ==
          PAM_EXTRACT_UNSUPPORTED);
    unlink(tmp);
    rm_rf(dest);
}

int main(void)
{
    test_manifest_fixtures();
    run_zip_fixture("tiny-store.zip", 3, 73);
    run_zip_fixture("tiny-deflate.zip", 3, 73);
    test_cancel();
    test_unknown_format();

    if (failures == 0)
        puts("extract tests passed");
    return failures == 0 ? 0 : 1;
}
