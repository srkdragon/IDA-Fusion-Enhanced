# Internal Makefile for Docker builds - no Docker check needed

# Platform detection (via env vars in Docker, uname for native)
PLATFORM ?= $(shell uname -s)

# Default values
USE_COMPILER   := g++
COMPILER_FLAGS := -O3 -std=c++20 -w -Wreturn-type -fpermissive
LINKER_FLAGS   :=

OBJ_DIR        := obj/
CPP_FILES      := $(wildcard ./src/*.cpp)

# Platform-specific settings
ifeq ($(PLATFORM),Linux)
    # Linux
    USE_COMPILER   := g++
    COMPILER_FLAGS += -Isdk/src/include -fPIC -D__LINUX__ -D__EA64__
    LINKER_FLAGS   := -shared
    RELEASE_NAME   := fusion64.so
else ifeq ($(PLATFORM),Darwin)
    # macOS (osxcross)
    ARCH           ?= arm64
    ifeq ($(ARCH),x86_64)
        USE_COMPILER   := o64-clang++
        COMPILER_FLAGS += -Isdk/src/include -D__MAC__ -D__EA64__
        COMPILER_FLAGS += -Lsdk/src/lib/x64_mac_clang_64
        RELEASE_NAME   := fusion64-macos-x64.dylib
    else
        USE_COMPILER   := oa64-clang++
        COMPILER_FLAGS += -Isdk/src/include -D__MAC__ -D__EA64__
        COMPILER_FLAGS += -Lsdk/src/lib/arm64_mac_clang_64
        RELEASE_NAME   := fusion64-macos-arm64.dylib
    endif
    LINKER_FLAGS   := -dynamiclib -undefined dynamic_lookup -lida
else
    # Windows (MinGW cross-compile)
    USE_COMPILER   := x86_64-w64-mingw32-g++
    COMPILER_FLAGS += -Isdk/src/include -D__NT__ -D__X64__
    COMPILER_FLAGS += -Lsdk/src/lib/x64_win_vc_64
    LINKER_FLAGS   := -static -Wl,-exclude-all-symbols,--kill-at -shared
    LINKER_FLAGS   += -l:ida.lib
    RELEASE_NAME   := fusion64.dll
endif

.PHONY: all

all:
	@mkdir -p $(OBJ_DIR)
	@count=0; \
	for file in $(CPP_FILES); do \
	  $(USE_COMPILER) $$file -c -o $(OBJ_DIR)$$count.o $(COMPILER_FLAGS); \
	  count=$$((count + 1)); \
	done
	@mkdir -p release
	@$(USE_COMPILER) -o release/$(RELEASE_NAME) $(COMPILER_FLAGS) $(OBJ_DIR)*.o $(LINKER_FLAGS)
