# Third-party components

| Component | Files | Licence | Source |
| --- | --- | --- | --- |
| PSL1GHT rsxutil sample | `ps3/src/rsxutil.c`, `ps3/src/rsxutil.h` | GPL-3.0 (PSL1GHT) | https://github.com/ps3dev/PSL1GHT |
| PSL1GHT compat shim | `ps3/src/psl1ght_compat.h` | GPL-3.0 (PSL1GHT samples) | https://github.com/ps3dev/PSL1GHT |
| font8x8 (Daniel Hepper) | `ps3/src/font8x8.h` | Public Domain | http://www.github.com/dhepper/font8x8 |
| x86 BCJ converter (Bra86.c, Igor Pavlov) — algorithm, rewritten as a streaming converter | `src/core/sevenzip.c` (`x86_convert`) | Public Domain (7-Zip) | https://github.com/ip7z/7zip |
| LZMA / LZMA2 decoder structure (LzmaDec.c / Lzma2Dec.c, Igor Pavlov) — restructured to be resumable | `src/core/lzma.c` | Public Domain (7-Zip) | https://github.com/ip7z/7zip |

Phase 3 deliberately vendors **no** libraries:

- ZIP deflate: own inflater (`src/core/inflate.c`, RFC 1951) — no zlib.
- 7z container and coders: own reader (`src/core/sevenzip.c`,
  `src/core/lzma.c`) — no LZMA SDK.
- CRC-32: own table-free implementation (`src/core/crc32.c`).

No code has been copied from other homebrew projects.
