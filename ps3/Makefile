# PS3 Archive Manager - PS3 build (PSL1GHT ppu_rules, same layout as
# a standard PSL1GHT application: ELF -> SELF -> PKG with USRDIR payload).
.SUFFIXES:
INSTALLER_DIR := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))

ifeq ($(strip $(PSL1GHT)),)
$(error "Please set PSL1GHT in your environment.")
endif
include $(PSL1GHT)/ppu_rules

TARGET := PS3ArchiveManager
BUILD := build
SOURCES := src
INCLUDES := src

TITLE := PS3 Archive Manager
APPID := PS3ARCHMGR
CONTENTID := UP0001-$(APPID)_00-0000000000000000

INSTALLER_DIR := $(patsubst %/,%,$(dir $(abspath $(firstword $(MAKEFILE_LIST)))))
PKGFILES := $(INSTALLER_DIR)/pkgfiles
ICON0_SRC := $(INSTALLER_DIR)/pkgfiles/ICON0.PNG
ICON0_OUT := $(PKGFILES)/ICON0.PNG

#-------------------------------------------------------------------------------
CFLAGS = -O2 -Wall -mcpu=cell $(MACHDEP) $(INCLUDE) \
	-I../src/core
CXXFLAGS = $(CFLAGS)
LDFLAGS = $(MACHDEP) -Wl,-Map,$(notdir $@).map
LIBS := -lgcm_sys -lrsx -lsysutil -lio -llv2 -lm
LIBDIRS := $(PORTLIBS)
#-------------------------------------------------------------------------------
ifneq ($(BUILD),$(notdir $(CURDIR)))
#-------------------------------------------------------------------------------
export OUTPUT := $(CURDIR)/$(TARGET)
export VPATH := $(foreach dir,$(SOURCES),$(CURDIR)/$(dir)) \
	$(INSTALLER_DIR)/../src/core
export DEPSDIR := $(CURDIR)/$(BUILD)
export BUILDDIR := $(CURDIR)/$(BUILD)
#-------------------------------------------------------------------------------
CFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.c))) \
	archive.c split.c zip_reader.c
CPPFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.cpp)))
sFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.s)))
SFILES := $(foreach dir,$(SOURCES),$(notdir $(wildcard $(dir)/*.S)))
#-------------------------------------------------------------------------------
ifeq ($(strip $(CPPFILES)),)
export LD := $(CC)
else
export LD := $(CXX)
endif
export OFILES := $(CPPFILES:.cpp=.o) $(CFILES:.c=.o) \
$(sFILES:.s=.o) $(SFILES:.S=.o)
#-------------------------------------------------------------------------------
export INCLUDE := $(foreach dir,$(SOURCES), -I$(CURDIR)/$(dir)) \
-I$(INSTALLER_DIR)/../src/core \
$(foreach dir,$(LIBDIRS),-I$(dir)/include) \
$(LIBPSL1GHT_INC) \
-I$(CURDIR)/$(BUILD)
#-------------------------------------------------------------------------------
export LIBPATHS := $(foreach dir,$(LIBDIRS),-L$(dir)/lib) \
$(LIBPSL1GHT_LIB)
#-------------------------------------------------------------------------------
.PHONY: $(BUILD) clean all
#-------------------------------------------------------------------------------
$(BUILD):
	@[ -d $@ ] || mkdir -p $@
#-------------------------------------------------------------------------------
$(ICON0_OUT): $(ICON0_SRC)
	@mkdir -p $(dir $@)
	@cp $< $@
#-------------------------------------------------------------------------------
all: $(ICON0_OUT)
	@[ -d $(BUILD) ] || mkdir -p $(BUILD)
	@$(MAKE) --no-print-directory -C $(BUILD) -f $(INSTALLER_DIR)/Makefile
#-------------------------------------------------------------------------------
clean:
	@echo clean ...
	@rm -fr $(BUILD) $(OUTPUT).elf $(OUTPUT).self $(OUTPUT).fake.self \
		$(OUTPUT).pkg $(OUTPUT).gnpdrm.pkg
#-------------------------------------------------------------------------------
else
DEPENDS := $(OFILES:.o=.d)
#-------------------------------------------------------------------------------
all: $(OUTPUT).pkg
$(OUTPUT).pkg: $(ICON0_OUT)
$(OUTPUT).self: $(OUTPUT).elf
$(OUTPUT).pkg: $(OUTPUT).self
$(OUTPUT).elf: $(OFILES)
#-------------------------------------------------------------------------------
-include $(DEPENDS)
endif
#-------------------------------------------------------------------------------
