# PS3 Archive Manager — host + PS3 build
#
# Host build/test (no toolchain needed):
#   make test
# PS3 build (PS3Dev/PSL1GHT container or local toolchain):
#   make ps3

CC ?= cc
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror
CPPFLAGS += -Isrc/core -D_GNU_SOURCE

CORE_SOURCES := src/core/archive.c src/core/split.c src/core/zip_reader.c \
                src/core/crc32.c src/core/stream.c src/core/inflate.c \
                src/core/lzma.c src/core/sevenzip.c src/core/extract.c
CORE_OBJECTS := $(CORE_SOURCES:src/core/%.c=build/%.o)
CORE_TEST := build/test-core
EXTRACT_TEST := build/test-extract

APPID := PS3ARCHMGR
TITLE := PS3 Archive Manager

.PHONY: all clean test ps3 host-smoke

all: $(CORE_TEST)

$(CORE_TEST): tests/test_core.c $(CORE_SOURCES) src/core/archive.h \
              src/core/split.h src/core/zip_reader.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_core.c $(CORE_SOURCES)

$(EXTRACT_TEST): tests/test_extract.c $(CORE_SOURCES) src/core/extract.h \
                 src/core/sevenzip.h src/core/inflate.h src/core/lzma.h
	@mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_extract.c $(CORE_SOURCES)

test: $(CORE_TEST) $(EXTRACT_TEST)
	./$(CORE_TEST)
	./$(EXTRACT_TEST)

host-smoke: tests/test_uistate.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_uistate.c
	./$@

clean:

ps3:
	$(MAKE) -C ps3 all

clean:
	rm -rf build
	-@$(MAKE) -C ps3 clean 2>/dev/null || true
	-@rm -f ps3/pkgfiles/USRDIR/EBOOT.BIN dist/*.pkg 2>/dev/null || true
