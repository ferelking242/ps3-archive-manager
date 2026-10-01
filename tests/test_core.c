/*
 * PS3 Archive Manager — host tests for the core modules.
 *
 * Everything runs on the build machine: no PS3 toolchain required. The
 * split fixtures are tiny ZIPs created on the fly in a temp directory.
 */

#include "archive.h"
#include "split.h"
#include "zip_reader.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#define _GNU_SOURCE 1
#include <unistd.h>

static int failures;

#define CHECK(cond)                                                         \
    do {                                                                    \
        if (!(cond)) {                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            failures++;                                                     \
        }                                                                   \
    } while (0)

/* ---- fixtures ------------------------------------------------------------ */

static int dir_exists_cb(const char *root, const char *name,
                         unsigned long long *size, void *user)
{
    char path[1024];
    struct stat st;
    (void)user;

    snprintf(path, sizeof(path), "%s/%s", root, name);
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return 0;
    *size = (unsigned long long)st.st_size;
    return 1;
}

/* Writes a stored-only ZIP with one entry. */
static void write_zip(const char *path, const char *entry_name,
                      const char *content)
{
    FILE *f = fopen(path, "wb");
    size_t n = strlen(content);
    uint16_t name_len = (uint16_t)strlen(entry_name);
    uint32_t crc = 0;

    /* CRC32 of content (table-free reference) */
    {
        static uint32_t table[256];
        static int ready = 0;
        if (!ready) {
            for (uint32_t i = 0; i < 256; i++) {
                uint32_t c = i;
                for (int k = 0; k < 8; k++)
                    c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
                table[i] = c;
            }
            ready = 1;
        }
        crc = 0xFFFFFFFFu;
        for (size_t i = 0; i < n; i++)
            crc = table[(crc ^ (uint8_t)content[i]) & 0xFF] ^ (crc >> 8);
        crc ^= 0xFFFFFFFFu;
    }

    fwrite("PK\x03\x04", 1, 4, f);
    { uint16_t v = 20; fwrite(&v, 2, 1, f); }         /* version   */
    { uint16_t v = 0;  fwrite(&v, 2, 1, f); }         /* flags     */
    { uint16_t v = 0;  fwrite(&v, 2, 1, f); }         /* method    */
    { uint16_t v = 0;  fwrite(&v, 2, 1, f); }         /* time      */
    { uint16_t v = 0x21; fwrite(&v, 2, 1, f); }       /* date      */
    fwrite(&crc, 4, 1, f);
    { uint32_t v = (uint32_t)n; fwrite(&v, 4, 1, f); } /* csize    */
    { uint32_t v = (uint32_t)n; fwrite(&v, 4, 1, f); } /* usize    */
    fwrite(&name_len, 2, 1, f);
    { uint16_t v = 0; fwrite(&v, 2, 1, f); }          /* extra len */
    fwrite(entry_name, 1, name_len, f);
    fwrite(content, 1, n, f);
    fwrite("PK\x05\x06", 1, 4, f);                    /* EOCD      */
    { uint16_t z = 0; for (int i = 0; i < 5; i++) fwrite(&z, 2, 1, f); }
    { uint32_t v = (uint32_t)n + name_len + 30; fwrite(&v, 4, 1, f); }
    { uint16_t z = 0; fwrite(&z, 2, 1, f); }
    fclose(f);
}

int main(void)
{
    /* ---- 1. signature sniffing -------------------------------------- */
    {
        const uint8_t zip[] = { 'P', 'K', 3, 4, 0, 0 };
        const uint8_t z7[]  = { '7', 'z', 0xBC, 0xAF, 0x27, 0x1C };
        const uint8_t gz[]  = { 0x1F, 0x8B, 8 };
        uint8_t tar[300] = { 0 };
        pam_signature s;

        pam_sniff_signature(zip, sizeof(zip), &s);
        CHECK(s.format == PAM_FMT_ZIP);
        pam_sniff_signature(z7, sizeof(z7), &s);
        CHECK(s.format == PAM_FMT_7Z);
        pam_sniff_signature(gz, sizeof(gz), &s);
        CHECK(s.format == PAM_FMT_GZIP);
        memcpy(tar + 257, "ustar  \0", 8);
        pam_sniff_signature(tar, sizeof(tar), &s);
        CHECK(s.format == PAM_FMT_TAR && s.is_tar);
    }

    /* ---- 2. name classification ------------------------------------- */
    {
        pam_signature s0 = { PAM_FMT_UNKNOWN, 0 };
        pam_archive_info info;

        pam_classify_name("Game.iso.001", &s0, &info);
        CHECK(info.split == PAM_SPLIT_NUMERIC && info.has_start);

        pam_classify_name("Game.iso.003", &s0, &info);
        CHECK(info.split == PAM_SPLIT_NUMERIC && !info.has_start);

        pam_classify_name("My.Game.v2.zip.001", &s0, &info);
        CHECK(info.split == PAM_SPLIT_NUMERIC && info.has_start);

        pam_classify_name("Game.zip", &s0, &info);
        CHECK(info.split == PAM_SPLIT_NONE && info.format == PAM_FMT_ZIP);

        pam_classify_name("Game.7z", &s0, &info);
        CHECK(info.format == PAM_FMT_7Z);

        pam_classify_name("Movie.mkv", &s0, &info);
        CHECK(info.format == PAM_FMT_UNKNOWN &&
              info.split == PAM_SPLIT_NONE);
    }

    /* ---- 3. split naming -------------------------------------------- */
    {
        char base[512], ext[64], out[600];
        int part = 0;

        CHECK(pam_split_parse("/usb/Games/My.Game.v2.zip.013", base,
                              sizeof(base), ext, sizeof(ext), &part) == 1);
        CHECK(strcmp(base, "/usb/Games/My.Game.v2") == 0);
        CHECK(strcmp(ext, ".zip") == 0);
        CHECK(part == 13);

        CHECK(pam_split_parse("Game.001", base, sizeof(base), ext,
                              sizeof(ext), &part) == 1);
        CHECK(strcmp(base, "Game") == 0 && part == 1);

        CHECK(pam_split_parse("Game.zip", base, sizeof(base), ext,
                              sizeof(ext), &part) == 0);

        CHECK(pam_split_part_name("/usb/Game", ".zip", 2, out,
                                  sizeof(out)) == 0);
        CHECK(strcmp(out, "/usb/Game.zip.002") == 0);
    }

    /* ---- 4. split set scanning with real files ---------------------- */
    {
        char dir[] = "/tmp/pamtestXXXXXX";
        char p[1024];
        pam_split_set set;

        if (mkdtemp(dir) == NULL) { perror("mkdtemp"); return 2; }
        write_zip("/tmp/x.zip.001", "ignored", "x");
        (void)p;

        /* complete set of 3 */
        snprintf(p, sizeof(p), "%s/My.Game.v2.zip.001", dir);
        write_zip(p, "a.txt", "hello ");
        snprintf(p, sizeof(p), "%s/My.Game.v2.zip.002", dir);
        write_zip(p, "b.txt", "world ");
        snprintf(p, sizeof(p), "%s/My.Game.v2.zip.003", dir);
        write_zip(p, "c.txt", "!!!");
        /* decoy that must NOT belong to the set */
        snprintf(p, sizeof(p), "%s/Game.iso.999", dir);
        write_zip(p, "decoy", "decoy");

        snprintf(p, sizeof(p), "%s/My.Game.v2.zip.002", dir);
        CHECK(pam_split_scan(p, dir_exists_cb, NULL, &set) == 0);
        CHECK(set.complete);
        CHECK(set.present_parts == 3 && set.expected_parts == 3);
        CHECK(set.first_part == 1 && set.last_part == 3);
        CHECK(set.first_missing == 0);

        /* broken set: 001,002 present, 003 missing -> walk stops there */
        snprintf(p, sizeof(p), "%s/My.Game.v2.zip.003", dir);
        unlink(p);
        snprintf(p, sizeof(p), "%s/My.Game.v2.zip.004", dir);
        write_zip(p, "d.txt", "late");
        snprintf(p, sizeof(p), "%s/My.Game.v2.zip.002", dir);
        CHECK(pam_split_scan(p, dir_exists_cb, NULL, &set) == 0);
        CHECK(!set.complete);
        CHECK(set.present_parts == 2);
        CHECK(set.first_missing == 3);
        {
            char report[256];
            CHECK(pam_split_report(&set, report, sizeof(report)) == 0);
            CHECK(strstr(report, "manque .003") != NULL);
        }
        /* cleanup below via recursive rm */
        {
            char cmd[1100];
            snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
            if (system(cmd) != 0)
                fprintf(stderr, "warn: cleanup %s failed\n", dir);
        }
    }

    /* ---- 5. streaming ZIP extraction (single + split) --------------- */
    {
        char dir[] = "/tmp/pamzipXXXXXX";
        if (mkdtemp(dir) == NULL) { perror("mkdtemp"); return 2; }

        /* single zip */
        {
            char zp[1024], op[1024];
            pam_zip_cursor *c;
            pam_zip_entry e;
            FILE *out;
            uint32_t crc = 0;
            long long n;

            snprintf(zp, sizeof(zp), "%s/single.zip", dir);
            write_zip(zp, "readme.txt", "hello archive manager");
            snprintf(op, sizeof(op), "%s/out.txt", dir);

            c = pam_zip_open(zp);
            CHECK(c != NULL);
            CHECK(pam_zip_next(c, &e) == 1);
            CHECK(strcmp(e.name, "readme.txt") == 0);
            CHECK(e.uncompressed_size == strlen("hello archive manager"));
            out = fopen(op, "wb");
            n = pam_zip_extract_current(c, out, e.uncompressed_size, &crc);
            fclose(out);
            CHECK(n == (long long)e.uncompressed_size);
            CHECK(crc == e.crc32);
            {
                char back[64] = {0};
                out = fopen(op, "rb");
                if (fread(back, 1, sizeof(back) - 1, out) > 0) {
                    CHECK(strcmp(back, "hello archive manager") == 0);
                }
                fclose(out);
            }
            CHECK(pam_zip_next(c, &e) == 0); /* EOCD, no more entries */
            pam_zip_close(c);
        }

        /* split zip across three parts */
        {
            char zp[1024], op[1024];
            pam_zip_cursor *c;
            pam_zip_entry e;
            FILE *out;
            long long total = 0;

            for (int i = 1; i <= 3; i++) {
                char label[8];
                snprintf(label, sizeof(label), "%d", i);
                snprintf(zp, sizeof(zp), "%s/big.zip.%03d", dir, i);
                write_zip(zp, label, label);
            }
            snprintf(zp, sizeof(zp), "%s/big.zip.001", dir);
            snprintf(op, sizeof(op), "%s/joined.txt", dir);

            c = pam_zip_open(zp);
            CHECK(c != NULL);
            while (pam_zip_next(c, &e) == 1) {
                out = fopen(op, "ab");
                total += pam_zip_extract_current(c, out,
                                                 e.uncompressed_size, NULL);
                fclose(out);
            }
            pam_zip_close(c);
            CHECK(total == 3);
        }

        {
            char cmd[1100];
            snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
            if (system(cmd) != 0)
                fprintf(stderr, "warn: cleanup %s failed\n", dir);
        }
    }

    if (failures == 0)
        puts("core tests passed");
    return failures == 0 ? 0 : 1;
}
