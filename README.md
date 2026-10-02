<div align="center">

# PS3 Archive Manager

**A modern archive manager and file explorer for PS3 HEN**

Windows Explorer × 7-Zip, on your couch.

</div>

---

PS3 Archive Manager is an open-source homebrew application for PlayStation 3
consoles running **HEN**. It lets you manage files and extract archives
directly from the XMB-era system with a gamepad-friendly interface:

- Browse `/dev_hdd0`, USB devices, `/dev_ms`, `/dev_sd`
- Detect and extract **multi-volume archives** (`Game.zip.001` → `.013`)
- Stream **multi-GB files** without loading them into RAM
- Follow progress with a real bar: speed, ETA, pause, cancel
- Detect extracted PS3 ISOs and offer to move them to `/dev_hdd0/PS3ISO/`

> [!WARNING]
> This project is **experimental**. It compiles in CI but has not yet been
> validated on real hardware. See [Limitations](#limitations).

## Features (Phase 1–3)

| Feature | Status |
| --- | --- |
| Device browser (HDD / USB / MS / SD) | ✅ |
| Archive signature detection (ZIP / 7z / TAR / GZ / BZ2 / XZ) | ✅ |
| `.NNN` multi-volume detection & verification | ✅ |
| Missing-part report before extraction | ✅ |
| Streaming extraction (ZIP / 7z, solid + multi-volume) | ✅ |
| CRC-32 verification per entry | ✅ |
| Pause / resume / cancel | ✅ |
| PS3 ISO move prompt | ✅ |
| Deflate / 7z decode (LZMA, LZMA2, BCJ-x86, Delta) | ✅ |
| Archive creation (ZIP / 7z) | 🔜 Phase 4–5 |
| Copy / move / rename / delete | 🔜 Phase 6 |
| Themes, settings, logs | 🔜 Phase 7 |

## Installation

1. Download `PS3-Archive-Manager.pkg` from the
   [latest CI release](../../releases/tag/ci-latest) (or a tagged release).
2. Copy it to a FAT32 USB stick.
3. On your PS3 (HEN active): **Package Manager → Install Package Files**.
4. Launch **PS3 Archive Manager** from the XMB.

## Usage

```
Select archive.zip.001 → EXTRACTION → your ISO
```

- **D-pad**: navigate · **X**: open/confirm · **O**: back/exit
- **Triangle**: extract archive · **L1/R1**: page up/down
- During extraction: **X** pause/resume, **O** cancel

The app refuses to start extraction when a volume of the split set is
missing, and prints which part (e.g. `Missing part: Game.zip.004`).

## Supported split conventions

- `archive.zip.001 … archive.zip.NNN`
- `archive.7z.001 … archive.7z.NNN`
- `archive.001 … archive.NNN`

Detection is **signature-based**: the file type is read from the bytes
(`PK\x03\x04`, `7z\xBC\xAF\x27\x1C`, `ustar`, …), never assumed from the
extension alone. A `.001` file is not necessarily a ZIP.

## Supported formats

| Container | Decode |
| --- | --- |
| ZIP | stored + Deflate entries, CRC-32 verified |
| 7z | Copy, LZMA, LZMA2, Deflate; x86 BCJ and Delta filter chains; solid folders, encoded headers, multi-volume `.7z.001` |
| TAR / GZ / BZ2 / XZ | detected only (unpacking not implemented yet) |

Unsupported 7z coders (PPMd, BZip2, other BCJ variants) and encrypted
archives abort with an explicit status; every extracted file is verified
against its stored CRC-32.

## Build

### Host tests (no toolchain)

```sh
make test
```

### PS3 PKG (PSL1GHT toolchain)

Using the [ps3dev Docker image](https://hub.docker.com/r/ps3dev/ps3dev):

```sh
docker run --rm -v "$PWD":/src -w /src ps3dev/ps3dev:submodules \
    make -C ps3 clean all
```

Output: `ps3/PS3ArchiveManager.pkg` (PPU objects land in `ps3/build/`).

Local toolchain users: set `PS3DEV=/usr/local/ps3dev` (default) and run
`make -C ps3 clean all`.

## Architecture

```
src/core/          Portable C core (host-testable, no PS3 dependencies)
  archive.c        Signature sniffing + split-name parsing
  split.c          Multi-volume set scanning (gapless walk)
  zip_reader.c     Streaming ZIP reader with CRC-32
  inflate.c        Deflate decoder (raw ZIP / 7z streams)
  lzma.c           Resumable LZMA / LZMA2 decoders (7z)
  sevenzip.c       7z container reader + BCJ-x86 / Delta filters
  extract.c        Unified extraction pipeline (ZIP + 7z)
  stream.c         Multi-volume byte stream (".001" … ".NNN")
  crc32.c          CRC-32 (IEEE) for entry verification
ps3/               PSL1GHT application (RSX framebuffer UI + sysFS backend)
tests/             Host test suite + committed fixture archives
.github/workflows  CI: host tests, PKG build, rolling release
```

The core is pure C11: no third-party libraries, no allocations inside the
streaming loops beyond fixed buffers (plus one bounded LZMA dictionary per
open folder): designed for the PS3's tight memory budget and for multi-GB
files.

## Limitations

- **No hardware validation yet** — the SPRX/SELF builds and PKGs assemble in
  CI, but no real HEN console has confirmed loading, rendering or transfers.
- 7z coders outside the supported set (PPMd, BZip2, other BCJ variants)
  and AES-encrypted archives are reported as unsupported/encrypted —
  never silently skipped.
- TAR / GZ / BZ2 / XZ are detected but their unpacking is not
  implemented yet.
- Archive creation is not implemented yet (Phases 4–5).
- The UI is a framebuffer renderer (no RSX shaders): fast, but simple.

## Licence

Project code: **GPL-3.0** — see [LICENSE](LICENSE).

`ps3/src/rsxutil.c|psl1ght_compat.h` derive from PSL1GHT samples
(GPL-3.0, © KaKaRoTo / Youness Alaoui and PSL1GHT contributors).
`font8x8.h` is Daniel Hepper's public-domain 8×8 font.
See [THIRD_PARTY.md](THIRD_PARTY.md) for details.

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
