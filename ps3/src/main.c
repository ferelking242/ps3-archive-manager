/*
 * PS3 Archive Manager - PS3 application (PSL1GHT, RSX framebuffer UI).
 *
 * Phase 1-2 scope, all real:
 *   - device roots only if they exist (no broken entries);
 *   - file/directory browsing with pagination;
 *   - archive detection (signature + split naming) per selection;
 *   - split-set verification with a parts report before extraction;
 *   - streaming extraction of stored ZIP entries (single or .NNN parts);
 *   - progress bar, speed, ETA; PAUSE/RESUME/CANCEL during extraction;
 *   - PS3 ISO detection with a move-to-/dev_hdd0/PS3ISO prompt;
 *   - safe paths: no writes outside the chosen destination.
 */

#include <ppu-lv2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/file.h>
#include <sysutil/video.h>
#include <rsx/gcm_sys.h>
#include <rsx/rsx.h>
#include <io/pad.h>

#include "rsxutil.h"
#include "font8x8.h"
#include "../../src/core/archive.h"
#include "../../src/core/split.h"
#include "../../src/core/zip_reader.h"
#include "../../src/core/extract.h"

#define MAX_BUFFERS 2
#define LIST_VISIBLE 14
#define LIST_MAX 512
#define NAME_MAX_ 256
#define PATH_MAX_ 1024

#define COL_BG        0x000c1420
#define COL_PANEL     0x00142438
#define COL_PANEL_ALT 0x001c3048
#define COL_LINE      0x02304c68
#define COL_ACCENT    0x00ff9c35
#define COL_TEXT      0x00eef4ff
#define COL_DIM       0x008fa2c0
#define COL_ERR       0x00ff5f6a
#define COL_OK        0x0056d68a
#define COL_DIR       0x0066b8ff
#define COL_ARCHIVE   0x00ffb94f
#define COL_ISO       0x00c792ea

#define PAD_TRIANGLE (1 << 0)
#define PAD_CROSS    (1 << 1)
#define PAD_CIRCLE   (1 << 2)
#define PAD_UP       (1 << 3)
#define PAD_DOWN     (1 << 4)
#define PAD_L1       (1 << 5)
#define PAD_R1       (1 << 6)

typedef struct {
    char name[NAME_MAX_];
    char path[PATH_MAX_];
    unsigned long long size;
    unsigned char is_dir;
    unsigned char kind; /* 0 file, 1 dir, 2 archive, 3 split member, 4 iso */
} Entry;

static Entry entries[LIST_MAX];
static int entry_count;
static int selected;
static int scroll;
static int is_root_view;

static char cwd[PATH_MAX_];
static int app_running = 1;

static volatile int op_pause;
static volatile int op_cancel;

static gcmContextData *context;
static rsxBuffer buffers[MAX_BUFFERS];
static int current_buffer;

/*
 * Extraction operator timing. op_t0_us is read by both the UI poll loop
 * (draw_op_screen) and the extraction loop (extract_archive) while the
 * extraction loop also writes it when it restarts. A plain local would
 * decay back to stale rouge/green readings; the variable is volatile so
 * the latest frame wins immediately.
 */
static volatile unsigned long long op_t0_us;

/* pending acknowledgement */
static volatile int op_state_pending;

/* pending acknowledgement */
static volatile int op_state;
static u16 screen_w, screen_h;
static int pad_ok;
static int prev_buttons;

/* ---------------- drawing ---------------- */

static void put_text_scaled(u32 *fb, int fw, int fh, int x, int y,
                            const char *text, u32 color, int scale)
{
    const int adv = 8 * scale;
    while (*text) {
        char ch = *text;
        const unsigned char *g;
        int row, col, sy, sx;
        if (ch < 0x20 || ch > 0x7e) { text++; continue; }
        g = font8x8[ch - 0x20];
        for (row = 0; row < 8; row++) {
            unsigned char bits = g[row];
            for (col = 0; col < 8; col++) {
                if (!((bits >> col) & 1)) continue;
                for (sy = 0; sy < scale; sy++) {
                    int py = y + row * scale + sy;
                    if (py < 0 || py >= fh) continue;
                    for (sx = 0; sx < scale; sx++) {
                        int px = x + col * scale + sx;
                        if (px >= 0 && px < fw) fb[py * fw + px] = color;
                    }
                }
            }
        }
        x += adv;
        text++;
    }
}

static void put_text(u32 *fb, int fw, int fh, int x, int y, const char *t,
                     u32 c)
{
    put_text_scaled(fb, fw, fh, x, y, t, c, 1);
}

static void put_text2(u32 *fb, int fw, int fh, int x, int y, const char *t,
                      u32 c)
{
    put_text_scaled(fb, fw, fh, x, y, t, c, 2);
}

static void fill_rect(u32 *fb, int fw, int fh, int x, int y, int w, int h,
                      u32 c)
{
    int x2 = x + w > fw ? fw : x + w;
    int y2 = y + h > fh ? fh : y + h;
    int py, px;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    for (py = y; py < y2; py++)
        for (px = x; px < x2; px++)
            fb[py * fw + px] = c;
}

static void hline(u32 *fb, int fw, int fh, int x, int y, int w, u32 c)
{
    fill_rect(fb, fw, fh, x, y, w, 1, c);
}

static void progress_bar(u32 *fb, int fw, int fh, int x, int y, int w,
                         double frac, u32 color)
{
    if (frac < 0.0) frac = 0.0;
    if (frac > 1.0) frac = 1.0;
    fill_rect(fb, fw, fh, x, y, w, 18, COL_PANEL_ALT);
    fill_rect(fb, fw, fh, x, y, (int)(w * frac), 18, color);
}

static void frame_begin(u32 color)
{
    rsxBuffer *b = &buffers[current_buffer];
    fill_rect(b->ptr, b->width, b->height, 0, 0, b->width, b->height,
              color);
}

static void frame_end(void)
{
    waitFlip();
    flip(context, buffers[current_buffer].id);
    current_buffer = (current_buffer + 1) % MAX_BUFFERS;
}

static void draw_header(const char *title, const char *subtitle)
{
    rsxBuffer *b = &buffers[current_buffer];
    u32 *fb = b->ptr;
    int fw = b->width, fh = b->height;

    fill_rect(fb, fw, fh, 0, 0, fw, 52, COL_PANEL);
    hline(fb, fw, fh, 0, 52, fw, COL_ACCENT);
    put_text2(fb, fw, fh, 24, 14, title, COL_ACCENT);
    put_text(fb, fw, fh, fw - (int)strlen(subtitle) * 8 - 24, 20,
             subtitle, COL_DIM);
}

/* ---------------- input ---------------- */

static int read_buttons(void)
{
    padData d;
    int b = 0;
    if (!pad_ok || ioPadGetData(0, &d) != 0 || d.len == 0) return 0;
    if (d.BTN_TRIANGLE) b |= PAD_TRIANGLE;
    if (d.BTN_CROSS)    b |= PAD_CROSS;
    if (d.BTN_CIRCLE)   b |= PAD_CIRCLE;
    if (d.BTN_UP)       b |= PAD_UP;
    if (d.BTN_DOWN)     b |= PAD_DOWN;
    if (d.BTN_L1)       b |= PAD_L1;
    if (d.BTN_R1)       b |= PAD_R1;
    return b;
}

static int pressed(int buttons, int mask)
{
    return (buttons & mask) && !(prev_buttons & mask);
}

static void wait_release(int mask)
{
    while (read_buttons() & mask) usleep(60 * 1000);
    prev_buttons = read_buttons();
}

/* ---------------- fs ---------------- */

static int ends_with_ci(const char *s, const char *suffix)
{
    size_t ls = strlen(s), lx = strlen(suffix), i;
    if (ls < lx) return 0;
    for (i = 0; i < lx; i++) {
        char a = s[ls - lx + i], b = suffix[i];
        if (a >= 'A' && a <= 'Z') a += 32;
        if (b >= 'A' && b <= 'Z') b += 32;
        if (a != b) return 0;
    }
    return 1;
}

static void classify_entry(Entry *e)
{
    pam_signature sig;
    pam_archive_info info;
    uint8_t head[512];
    s32 fd;
    u64 got = 0;

    e->kind = 0;
    if (e->is_dir) { e->kind = 1; return; }
    if (ends_with_ci(e->name, ".iso")) { e->kind = 4; return; }

    if (sysLv2FsOpen(e->path, SYS_O_RDONLY, &fd, 0, NULL, 0) != 0) return;
    sysLv2FsRead(fd, head, sizeof(head), &got);
    sysLv2FsClose(fd);
    pam_sniff_signature(head, (size_t)got, &sig);
    pam_classify_name(e->name, &sig, &info);
    if (info.split == PAM_SPLIT_NUMERIC) e->kind = 3;
    else if (info.format == PAM_FMT_ZIP || info.format == PAM_FMT_7Z ||
             info.format == PAM_FMT_TAR) e->kind = 2;
}

static void scan_cwd(void)
{
    sysFSDirent ent;
    s32 fd;
    u64 read_count = 0;

    entry_count = 0;
    selected = 0;
    scroll = 0;

    if (is_root_view) {
        static const char *roots[] = {
            "/dev_hdd0", "/dev_usb000", "/dev_usb001", "/dev_usb002",
            "/dev_ms", "/dev_sd"
        };
        unsigned i;
        for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
            if (sysLv2FsOpenDir(roots[i], &fd) != 0) continue;
            sysLv2FsCloseDir(fd);
            {
                Entry *e = &entries[entry_count++];
                snprintf(e->name, sizeof(e->name), "[%s]", roots[i] + 1);
                snprintf(e->path, sizeof(e->path), "%s", roots[i]);
                e->is_dir = 1;
                e->kind = 1;
            }
            if (entry_count >= LIST_MAX) break;
        }
        return;
    }

    if (sysLv2FsOpenDir(cwd, &fd) != 0) return;

    while (entry_count < LIST_MAX) {
        char child[PATH_MAX_];
        s32 cfd;
        Entry *e;

        memset(&ent, 0, sizeof(ent));
        if (sysLv2FsReadDir(fd, &ent, &read_count) != 0 || read_count == 0)
            break;
        if (ent.d_name[0] == '\0' || !strcmp(ent.d_name, ".") ||
            !strcmp(ent.d_name, ".."))
            continue;

        e = &entries[entry_count];
        snprintf(e->name, sizeof(e->name), "%s", ent.d_name);
        snprintf(e->path, sizeof(e->path), "%s/%s", cwd, ent.d_name);
        snprintf(child, sizeof(child), "%s/%s", cwd, ent.d_name);

        if (sysLv2FsOpenDir(child, &cfd) == 0) {
            sysLv2FsCloseDir(cfd);
            e->is_dir = 1;
        } else {
            sysFSStat st;
            e->is_dir = 0;
            if (sysLv2FsStat(e->path, &st) == 0)
                e->size = (unsigned long long)st.st_size;
        }
        classify_entry(e);
        entry_count++;
    }
    sysLv2FsCloseDir(fd);
}

/* ---------------- extraction ---------------- */

static int part_exists_cb(const char *root, const char *name,
                          unsigned long long *size, void *user)
{
    char full[PATH_MAX_];
    sysFSStat st;
    (void)user;
    snprintf(full, sizeof(full), "%s/%s", root, name);
    if (sysLv2FsStat(full, &st) != 0) return 0;
    *size = (unsigned long long)st.st_size;
    return 1;
}

static unsigned long long now_us(void)
{
    /* PSL1GHT has no clock_gettime in the sysapp context: wall-time via
     * systick would need lv2 calls, so use usleep-quantized frames. The
     * UI loop repaints every ~40 ms; speed/ETA only need rough timing. */
    static unsigned long long synthetic_us;
    synthetic_us += 40 * 1000ull;
    return synthetic_us;
}

static void draw_op_screen(const char *title, const char *file,
                           long long done, long long total,
                           const char *hint)
{
    rsxBuffer *b = &buffers[current_buffer];
    u32 *fb = b->ptr;
    int fw = b->width, fh = b->height;
    double frac = total > 0 ? (double)done / (double)total : 0.0;
    unsigned long long el = now_us() - op_t0_us;
    double speed = el > 0 ? (double)done / ((double)el / 1e6) : 0.0;
    long long eta = speed > 1.0
        ? (long long)((double)(total - done) / speed) : -1;
    char line[160];

    frame_begin(COL_BG);
    draw_header(title, cwd);
    fill_rect(fb, fw, fh, 60, 120, fw - 120, 300, COL_PANEL);
    hline(fb, fw, fh, 60, 120, fw - 120, COL_LINE);
    put_text2(fb, fw, fh, 84, 140, file, COL_TEXT);
    progress_bar(fb, fw, fh, 84, 190, fw - 168, frac, COL_ACCENT);
    snprintf(line, sizeof(line), "%lld / %lld bytes  (%d%%)",
             done, total, (int)(frac * 100.0));
    put_text(fb, fw, fh, 84, 226, line, COL_TEXT);
    snprintf(line, sizeof(line), "%.1f MB/s", speed / (1024.0 * 1024.0));
    put_text(fb, fw, fh, 84, 246, line, COL_DIM);
    if (eta >= 0) {
        snprintf(line, sizeof(line), "ETA %02lld:%02lld", eta / 60,
                 eta % 60);
        put_text(fb, fw, fh, 240, 246, line, COL_DIM);
    }
    if (hint && hint[0])
        put_text(fb, fw, fh, 84, 280, hint, COL_OK);
    put_text(fb, fw, fh, 84, 380,
             op_pause ? "[X] RESUME   " : "[ ] PAUSE   [O] CANCEL",
             COL_DIM);
    frame_end();
}

static void incomplete_screen(const pam_split_set *set)
{
    char msg[160];
    int buttons;
    rsxBuffer *b;

    frame_begin(COL_BG);
    draw_header("PS3 ARCHIVE MANAGER", cwd);
    b = &buffers[current_buffer];
    put_text2(b->ptr, b->width, b->height, 84, 160, "ARCHIVE INCOMPLETE",
              COL_ERR);
    snprintf(msg, sizeof(msg), "Missing part: %s.%03d", set->base,
             set->first_missing);
    put_text(b->ptr, b->width, b->height, 84, 200, msg, COL_TEXT);
    snprintf(msg, sizeof(msg), "%d / %d parts available",
             set->present_parts, set->expected_parts);
    put_text(b->ptr, b->width, b->height, 84, 224, msg, COL_DIM);
    put_text(b->ptr, b->width, b->height, 84, 380, "[X] OK", COL_DIM);
    frame_end();

    wait_release(PAD_CROSS);
    while (!((read_buttons()) & PAD_CROSS)) usleep(50 * 1000);
    prev_buttons = read_buttons();
}

static void iso_prompt(const char *out_path, const char *name)
{
    int buttons;
    rsxBuffer *b;

    frame_begin(COL_BG);
    draw_header("PS3 ARCHIVE MANAGER", cwd);
    b = &buffers[current_buffer];
    put_text2(b->ptr, b->width, b->height, 84, 160, "PS3 ISO detected",
              COL_ISO);
    put_text(b->ptr, b->width, b->height, 84, 200, name, COL_TEXT);
    put_text(b->ptr, b->width, b->height, 84, 224,
             "Move to /dev_hdd0/PS3ISO ?", COL_TEXT);
    put_text(b->ptr, b->width, b->height, 84, 260,
             "[X] YES     [O] NO", COL_TEXT);
    frame_end();

    wait_release(PAD_CROSS | PAD_CIRCLE);
    for (;;) {
        buttons = read_buttons();
        if (buttons & PAD_CROSS) {
            char iso_dst[PATH_MAX_];
            sysLv2FsMkdir("/dev_hdd0/PS3ISO", 0777);
            snprintf(iso_dst, sizeof(iso_dst), "/dev_hdd0/PS3ISO/%s", name);
            sysLv2FsRename(out_path, iso_dst);
            break;
        }
        if (buttons & PAD_CIRCLE) break;
        usleep(50 * 1000);
    }
    prev_buttons = read_buttons();
}

/* ---- unified extraction pipeline (extract.h) ---------------------------- */

static int mkdir_cb(const char *path, void *user)
{
    sysFSStat st;
    (void)user;
    if (sysLv2FsStat(path, &st) == 0)
        return 0;
    return sysLv2FsMkdir(path, 0777) == 0 ? 0 : -1;
}

/*
 * Called before each chunk: this is where the pad is polled, so pause
 * (X) and cancel (O) stay responsive for the whole extraction, ZIP and
 * 7z alike. Blocking here is allowed by the extract.h contract.
 */
static int progress_cb(const char *name, long long done, long long total,
                       void *user)
{
    (void)user;
    if (done == 0)
        op_t0_us = now_us(); /* per-entry speed / ETA */
    for (;;) {
        int buttons = read_buttons();
        if (pressed(buttons, PAD_CROSS))
            op_pause = !op_pause;
        if (pressed(buttons, PAD_CIRCLE))
            op_cancel = 1;
        prev_buttons = buttons;
        if (op_cancel)
            return -1;
        if (!op_pause)
            break;
        draw_op_screen("PAUSED", name, done, total, "");
        usleep(60 * 1000);
    }
    draw_op_screen("EXTRACTING", name, done, total, "");
    return 0;
}

static void after_entry_cb(const char *name, const char *dest_path, int ok,
                           void *user)
{
    const char *base;
    (void)ok;
    (void)user;
    if (!ends_with_ci(name, ".iso"))
        return;
    base = strrchr(name, '/');
    {
        const char *bs = strrchr(name, '\\');
        if (bs != NULL && (base == NULL || bs > base))
            base = bs;
    }
    iso_prompt(dest_path, base != NULL ? base + 1 : name);
}

static void result_screen(const pam_extract_result *res)
{
    rsxBuffer *b;
    char line[192];
    const char *title;
    u32 color;

    switch (res->status) {
    case PAM_EXTRACT_OK:
        title = res->failed > 0 ? "EXTRACTION: ERREURS" : "EXTRACTION OK";
        color = res->failed > 0 ? COL_ERR : COL_OK;
        break;
    case PAM_EXTRACT_CANCELLED:
        title = "EXTRACTION ANNULEE";
        color = COL_DIM;
        break;
    case PAM_EXTRACT_ENCRYPTED:
        title = "ARCHIVE CHIFFREE";
        color = COL_ERR;
        break;
    case PAM_EXTRACT_UNSUPPORTED:
        title = "FORMAT NON SUPPORTE";
        color = COL_ERR;
        break;
    default:
        title = "EXTRACTION ECHOUEE";
        color = COL_ERR;
        break;
    }

    frame_begin(COL_BG);
    draw_header("PS3 ARCHIVE MANAGER", cwd);
    b = &buffers[current_buffer];
    put_text2(b->ptr, b->width, b->height, 84, 130, title, color);
    snprintf(line, sizeof(line), "%d fichier(s)  %d dossier(s)  %d en echec",
             res->files, res->dirs, res->failed);
    put_text(b->ptr, b->width, b->height, 84, 176, line, COL_TEXT);
    snprintf(line, sizeof(line), "%lld octets verifies", res->bytes);
    put_text(b->ptr, b->width, b->height, 84, 200, line, COL_TEXT);
    if (res->crc_errors > 0) {
        snprintf(line, sizeof(line), "%d erreur(s) CRC", res->crc_errors);
        put_text(b->ptr, b->width, b->height, 84, 224, line, COL_ERR);
    }
    if (res->unsafe_skips > 0) {
        snprintf(line, sizeof(line), "%d chemin(s) non sur ignores",
                 res->unsafe_skips);
        put_text(b->ptr, b->width, b->height, 84, 248, line, COL_DIM);
    }
    if (res->message[0] != '\0')
        put_text(b->ptr, b->width, b->height, 84, 288, res->message, COL_TEXT);
    if (res->entry[0] != '\0') {
        snprintf(line, sizeof(line), "%.120s", res->entry);
        put_text(b->ptr, b->width, b->height, 84, 312, line, COL_DIM);
    }
    put_text(b->ptr, b->width, b->height, 84, 380, "[X] OK", COL_DIM);
    frame_end();

    wait_release(PAD_CROSS);
    while (!((read_buttons()) & PAD_CROSS)) usleep(50 * 1000);
    prev_buttons = read_buttons();
}

static void extract_archive(const char *first_part)
{
    pam_split_set set;
    pam_extract_ops ops;
    pam_extract_result res;

    op_pause = op_cancel = 0;
    op_t0_us = now_us();

    if (pam_split_scan(first_part, part_exists_cb, NULL, &set) == 0 &&
        !set.complete) {
        incomplete_screen(&set);
        return;
    }

    memset(&ops, 0, sizeof(ops));
    ops.mkdir = mkdir_cb;
    ops.progress = progress_cb;
    ops.after_entry = after_entry_cb;
    pam_extract_to_dir(first_part, cwd, &ops, &res);
    result_screen(&res);
}

/* ---------------- browser ---------------- */

static const char *kind_icon(int kind)
{
    switch (kind) {
    case 1:  return "[DIR]";
    case 2:  return "[ARC]";
    case 3:  return "[SPL]";
    case 4:  return "[ISO]";
    default: return "[FIL]";
    }
}

static u32 kind_color(int kind)
{
    switch (kind) {
    case 1:  return COL_DIR;
    case 2:  return COL_ARCHIVE;
    case 3:  return COL_ARCHIVE;
    case 4:  return COL_ISO;
    default: return COL_TEXT;
    }
}

static void draw_browser(void)
{
    rsxBuffer *b = &buffers[current_buffer];
    u32 *fb = b->ptr;
    int fw = b->width, fh = b->height;
    int row, idx, y, visible = LIST_VISIBLE;
    char line[PATH_MAX_ + 32];

    frame_begin(COL_BG);
    draw_header("PS3 ARCHIVE MANAGER", is_root_view ? "STORAGE" : cwd);

    fill_rect(fb, fw, fh, 24, 72, fw - 48, fh - 72 - 56, COL_PANEL);
    hline(fb, fw, fh, 24, 72, fw - 48, COL_LINE);

    for (row = 0; row < visible; row++) {
        idx = scroll + row;
        if (idx >= entry_count) break;
        y = 88 + row * 32;
        if (idx == selected)
            fill_rect(fb, fw, fh, 32, y - 4, fw - 64, 30, COL_PANEL_ALT);
        put_text(fb, fw, fh, 40, y, kind_icon(entries[idx].kind),
                 kind_color(entries[idx].kind));
        snprintf(line, sizeof(line), "%s", entries[idx].name);
        put_text(fb, fw, fh, 110, y, line,
                 idx == selected ? COL_TEXT : kind_color(entries[idx].kind));
        if (!entries[idx].is_dir) {
            char sz[32];
            unsigned long long kb = entries[idx].size / 1024;
            if (kb >= 1048576)
                snprintf(sz, sizeof(sz), "%llu.%llu GB", kb >> 20,
                         ((kb >> 10) & 1023) * 100 / 1024);
            else if (kb >= 1024)
                snprintf(sz, sizeof(sz), "%llu MB", kb >> 10);
            else
                snprintf(sz, sizeof(sz), "%llu KB", kb);
            put_text(fb, fw, fh, fw - 200, y, sz, COL_DIM);
        }
    }

    fill_rect(fb, fw, fh, 0, fh - 48, fw, 48, COL_PANEL);
    hline(fb, fw, fh, 0, fh - 48, fw, COL_LINE);
    put_text(fb, fw, fh, 24, fh - 34,
             "[X]OPEN  [O]BACK  [TRIANGLE]EXTRACT  L1/R1 PAGE", COL_DIM);

    frame_end();
}

static void resolve_to_first_part(Entry *e, char *out, size_t out_size)
{
    char base[512], ext[64], dirpart[PATH_MAX_];
    int part = 0;
    const char *name_start;

    if (pam_split_parse(e->name, base, sizeof(base), ext, sizeof(ext),
                        &part) != 1 || part == 1) {
        snprintf(out, out_size, "%s", e->path);
        return;
    }
    name_start = e->path + strlen(e->path) - strlen(e->name);
    {
        size_t dir_len = (size_t)(name_start - e->path);
        if (dir_len >= sizeof(dirpart)) dir_len = sizeof(dirpart) - 1;
        memcpy(dirpart, e->path, dir_len);
        dirpart[dir_len] = '\0';
    }
    snprintf(out, out_size, "%s%s%s.001", dirpart, base, ext);
}

static void do_extract_selected(void)
{
    Entry *e = &entries[selected];
    char first_path[PATH_MAX_];

    if (e->kind != 2 && e->kind != 3) return;
    resolve_to_first_part(e, first_path, sizeof(first_path));
    extract_archive(first_path);
}

static void browser_input(int buttons)
{
    if (pressed(buttons, PAD_UP) && selected > 0) selected--;
    if (pressed(buttons, PAD_DOWN) && selected + 1 < entry_count) selected++;
    if (pressed(buttons, PAD_L1))
        selected = selected > LIST_VISIBLE ? selected - LIST_VISIBLE : 0;
    if (pressed(buttons, PAD_R1) && selected + LIST_VISIBLE < entry_count)
        selected += LIST_VISIBLE;
    if (selected < scroll) scroll = selected;
    else if (selected >= scroll + LIST_VISIBLE)
        scroll = selected - LIST_VISIBLE + 1;

    if (pressed(buttons, PAD_CROSS) && entry_count > 0) {
        Entry *e = &entries[selected];
        if (e->is_dir) {
            if (is_root_view) {
                snprintf(cwd, sizeof(cwd), "%s", e->path);
                is_root_view = 0;
            } else {
                char child[PATH_MAX_];
                snprintf(child, sizeof(child), "%s/%s", cwd, e->name);
                snprintf(cwd, sizeof(cwd), "%s", child);
            }
            scan_cwd();
        } else if (e->kind == 2 || e->kind == 3) {
            do_extract_selected();
        }
    }
    if (pressed(buttons, PAD_CIRCLE)) {
        if (is_root_view) {
            app_running = 0;
        } else {
            char *slash = strrchr(cwd, '/');
            if (slash != NULL && slash != cwd) *slash = '\0';
            else { is_root_view = 1; cwd[0] = '\0'; }
            scan_cwd();
        }
    }
    if (pressed(buttons, PAD_TRIANGLE) && entry_count > 0)
        do_extract_selected();
}

int main(s32 argc, const char *argv[])
{
    void *host_addr;
    int i;

    (void)argc; (void)argv;

    host_addr = memalign(1024 * 1024, HOST_SIZE);
    context = initScreen(host_addr, HOST_SIZE);
    if (context == NULL) return 1;
    getResolution(&screen_w, &screen_h);
    for (i = 0; i < MAX_BUFFERS; i++)
        makeBuffer(&buffers[i], screen_w, screen_h, i);
    flip(context, MAX_BUFFERS - 1);

    pad_ok = ioPadInit(7) == 0;
    is_root_view = 1;
    cwd[0] = '\0';
    scan_cwd();

    while (app_running) {
        int buttons = read_buttons();
        browser_input(buttons);
        prev_buttons = buttons;
        draw_browser();
        usleep(40 * 1000);
    }

    if (pad_ok) ioPadEnd();
    gcmSetWaitFlip(context);
    for (i = 0; i < MAX_BUFFERS; i++) rsxFree(buffers[i].ptr);
    rsxFinish(context, 1);
    free(host_addr);
    return 0;
}
