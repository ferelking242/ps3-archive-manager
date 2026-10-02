#ifndef PAM_STREAM_H
#define PAM_STREAM_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * PS3 Archive Manager — multi-volume byte stream.
 *
 * Concatenates "name.ext.001/.002/..." (or a single file) into one linear
 * reader with a read-ahead buffer. The buffer is always filled by a single
 * fread from one volume, so it never spans two volumes: a caller that
 * over-reads (the DEFLATE bit reader does) can push its read-ahead back
 * in memory with pam_stream_pushback().
 *
 * Global offsets address the concatenated byte space, which is what the
 * 7z pack stream layout uses. Note: part sizes are measured with ftell(),
 * so a single volume above 2 GB is not representable on the PS3 (FAT32
 * volumes are split below that limit by convention).
 */

typedef struct {
    FILE **parts;
    long long *psize; /* size of each volume                    */
    int nparts;
    int cap;
    int cur;          /* index of the volume being read         */
    uint8_t *buf;     /* read-ahead buffer (never spans volumes)*/
    size_t cap_buf;
    size_t len;       /* valid bytes in buf                     */
    size_t pos;       /* consumed bytes in buf                  */
    int eof;          /* all volumes exhausted                  */
    int err;          /* sticky I/O error                       */
} pam_stream;

/* Open first_path and any "…NNN" successors. 0 ok, -1 error. */
int pam_stream_open(pam_stream *s, const char *first_path);
void pam_stream_close(pam_stream *s);

/* Next byte 0..255, -1 at end of stream, -2 on I/O error. */
int pam_stream_get(pam_stream *s);
/* Read up to n bytes; returns how many were read (short at EOF). */
size_t pam_stream_read(pam_stream *s, void *dst, size_t n);
/* 1 when n bytes were read, 0 on short read/EOF, -1 on I/O error. */
int pam_stream_read_exact(pam_stream *s, void *dst, size_t n);
/* Skip n forward bytes. 1 ok, 0 hit EOF first, -1 on I/O error. */
int pam_stream_skip(pam_stream *s, long long n);
/* Logical offset of the next byte to be read. */
long long pam_stream_tell(const pam_stream *s);
/* Seek to a global offset. 1 ok, -1 out of range/error. */
int pam_stream_seek(pam_stream *s, long long off);
/* Push back the n most recently read bytes (n <= bytes read since the
 * last refill boundary). Used after a decoder finished a stream. */
void pam_stream_pushback(pam_stream *s, size_t n);

/* Little-endian scalar readers. 1 ok, 0 short of bytes, -1 error. */
int pam_stream_u16(pam_stream *s, uint16_t *v);
int pam_stream_u32(pam_stream *s, uint32_t *v);
int pam_stream_u64(pam_stream *s, uint64_t *v);

#endif /* PAM_STREAM_H */
