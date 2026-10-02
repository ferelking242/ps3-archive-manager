#include "crc32.h"

/* CRC-32 (IEEE), incremental, small table — fine at USB speeds. */
uint32_t pam_crc32_update(uint32_t running, const uint8_t *buf, size_t len)
{
    static uint32_t table[256];
    static int ready = 0;
    size_t i;

    if (!ready) {
        for (uint32_t n = 0; n < 256; n++) {
            uint32_t c = n;
            for (int k = 0; k < 8; k++)
                c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        ready = 1;
    }
    for (i = 0; i < len; i++)
        running = table[(running ^ buf[i]) & 0xFF] ^ (running >> 8);
    return running;
}
