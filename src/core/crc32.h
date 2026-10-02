#ifndef PAM_CRC32_H
#define PAM_CRC32_H

#include <stddef.h>
#include <stdint.h>

/*
 * Incremental CRC-32 (IEEE 802.3, the ZIP/7z variant).
 * Seed with PAM_CRC32_INIT, feed the bytes in order, then apply
 * pam_crc32_final() before comparing with a stored checksum.
 */

#define PAM_CRC32_INIT 0xFFFFFFFFu
#define pam_crc32_final(running) ((running) ^ 0xFFFFFFFFu)

uint32_t pam_crc32_update(uint32_t running, const uint8_t *buf, size_t len);

#endif /* PAM_CRC32_H */
