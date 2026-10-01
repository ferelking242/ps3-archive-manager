# Contributing

1. Fork, branch (`feat/my-feature`), commit with clear messages.
2. `make test` must pass on the host (no PS3 toolchain needed for core work).
3. Keep `src/core/` free of PS3-specific headers so the host suite stays the
   fast feedback loop.
4. PS3-only changes live under `ps3/` and are validated by CI against the
   `ps3dev/ps3dev:submodules` container.
5. Phases follow the roadmap in the README; open an issue before large
   refactors.
