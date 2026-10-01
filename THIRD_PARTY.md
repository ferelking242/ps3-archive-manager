# Third-party components

| Component | Files | Licence | Source |
| --- | --- | --- | --- |
| PSL1GHT rsxutil sample | `ps3/src/rsxutil.c`, `ps3/src/rsxutil.h` | GPL-3.0 (PSL1GHT) | https://github.com/ps3dev/PSL1GHT |
| PSL1GHT compat shim | `ps3/src/psl1ght_compat.h` | GPL-3.0 (PSL1GHT samples) | https://github.com/ps3dev/PSL1GHT |
| font8x8 (Daniel Hepper) | `ps3/src/font8x8.h` | Public Domain | http://www.github.com/dhepper/font8x8 |

Planned (Phase 3+, not yet vendored):

- zlib (Boost/zlib licence) for ZIP deflate support
- LZMA SDK / 7-Zip (public domain) for 7z support

Each will land in `third_party/<library>/` with its own licence file and
version note. No code has been copied from other homebrew projects.
