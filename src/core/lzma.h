#ifndef PAM_LZMA_H
#define PAM_LZMA_H

#include <stddef.h>
#include <stdint.h>

/*
 * PS3 Archive Manager — LZMA / LZMA2 decoders for the 7z reader.
 *
 * Ported from the algorithmic structure of Igor Pavlov's public-domain
 * LzmaDec.c / Lzma2Dec.c (7-Zip), reshaped to be resumable: pam_lzma_run()
 * stops after `limit` output bytes so the UI can repaint and honour
 * pause/cancel, then continues where it left off.
 *
 * Input is pulled one byte at a time through get(); output goes to put()
 * in dictionary-sized chunks. The dictionary is a ring buffer sized from
 * min(dictionary, total output), so a small archive never allocates the
 * full 16-64 MB dictionary a header may announce.
 */

/* Pull one input byte: return 0..255, negative at EOF/error. */
typedef int (*pam_lzma_get)(void *ctx);
/* Push output bytes: return 0 on success, nonzero aborts. */
typedef int (*pam_lzma_put)(void *ctx, const uint8_t *buf, size_t n);

typedef struct pam_lzma pam_lzma;

pam_lzma *pam_lzma_create(void);
void pam_lzma_destroy(pam_lzma *d);

/*
 * Configure the decoder. `out_total` is the number of bytes the whole
 * stream will produce (folder unpack size) — it bounds the dictionary.
 * Both inits return 0, or -1 on bad properties / allocation failure.
 */
int pam_lzma_init_lzma(pam_lzma *d, const uint8_t props[5],
                       unsigned long long out_total, pam_lzma_get get,
                       void *gctx, pam_lzma_put put, void *wctx);
int pam_lzma_init_lzma2(pam_lzma *d, uint8_t prop,
                        unsigned long long out_total, pam_lzma_get get,
                        void *gctx, pam_lzma_put put, void *wctx);

/*
 * Decode until `limit` bytes were produced this call, the stream ends,
 * or an error occurs. Returns 1 = finished, 0 = yield (call again),
 * -1 = error (truncated input or corrupt data).
 */
int pam_lzma_run(pam_lzma *d, unsigned long long limit);

int pam_lzma_done(const pam_lzma *d);
int pam_lzma_error(const pam_lzma *d);
unsigned long long pam_lzma_produced(const pam_lzma *d);

#endif /* PAM_LZMA_H */
