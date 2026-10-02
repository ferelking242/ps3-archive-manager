# Changelog

## 0.2.0 — Phase 3

- Deflate decode for ZIP entries (own RFC 1951 inflater, no zlib)
- Full 7z reader: raw and encoded headers, solid folders, multi-volume
  `.7z.001`, Copy / LZMA / LZMA2 / Deflate coders
- 7z filter chains: x86 BCJ (`0x03030103`) and Delta (`0x03`), either
  bind order — the archives 7-Zip writes with `-mf=BCJ` / `-mf=Delta`
- Unified extraction pipeline (`src/core/extract.c`) shared by the PS3 UI
  and the host test suite: path-safety checks, directory creation, chunked
  writing with CRC-32 verification, progress / pause / cancel callbacks,
  structured result
- PS3 UI: extraction result screen (files / bytes / CRC errors), pad
  polling for pause + cancel during every extraction, ISO move prompt
  after each extracted ISO
- Fixture test suite: 24 real 7z archives + ZIPs, checked byte-for-byte
  against trees produced by py7zr
- Unsupported 7z coders (PPMd, BZip2, other BCJ variants) and encrypted
  archives report an explicit status instead of failing silently

## 0.1.0 — Phase 1–2

- Device browser with runtime device detection (HDD/USB/MS/SD)
- Archive signature detection: ZIP, 7z, TAR, GZ, BZ2, XZ
- `.NNN` multi-volume scanning: gapless walk, missing-part report
- Streaming extraction of stored ZIP entries with CRC-32 check
- Pause / resume / cancel during extraction
- PS3 ISO detection with move-to-PS3ISO prompt
- CI: host tests + PKG build + rolling `ci-latest` release
