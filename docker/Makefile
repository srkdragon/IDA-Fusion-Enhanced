# Internal Makefile for Docker builds - no Docker check needed

# Platform detection (via env vars in Docker, uname for native)
PLATFORM ?= $(shell uname -s)

# Default values - IDA SDK requires C++17
USE_COMPILER   := g++
COMPILER_FLAGS := -O2 -std=c++17 -Wreturn-type
LINKER_FLAGS   :=

OBJ_DIR        := obj/
CPP_FILES      := $(wildcard ./src/*.cpp)

# Platform-specific settings
ifeq ($(PLATFORM),Linux)
    # Linux - GCC (official)
    USE_COMPILER   := g++
    COMPILER_FLAGS += -Wno-nontrivial-memcall -Wno-nullability-completeness -Wno-varargs
    COMPILER_FLAGS += -Isdk/src/include
    COMPILER_FLAGS += -fPIC
    COMPILER_FLAGS += -D__LINUX__ -D__EA64__
    LINKER_FLAGS   := -shared
    RELEASE_NAME   := fusion64.so

else ifeq ($(PLATFORM),Darwin)
    # macOS - Clang (official)
    ARCH           ?= arm64
    ifeq ($(ARCH),x86_64)
        USE_COMPILER   := o64-clang++
        COMPILER_FLAGS += -Wno-nullability-completeness -Wno-varargs
        COMPILER_FLAGS += -Isdk/src/include
        COMPILER_FLAGS += -D__MAC__ -D__EA64__
        COMPILER_FLAGS += -mmacosx-version-min=12.0
        COMPILER_FLAGS += -Lsdk/src/lib/x64_mac_clang_64
        RELEASE_NAME   := fusion64-macos-x64.dylib
    else
        USE_COMPILER   := oa64-clang++
        COMPILER_FLAGS += -Wno-nullability-completeness -Wno-varargs
        COMPILER_FLAGS += -Isdk/src/include
        COMPILER_FLAGS += -D__MAC__ -D__EA64__
        COMPILER_FLAGS += -mmacosx-version-min=12.0
        COMPILER_FLAGS += -Lsdk/src/lib/arm64_mac_clang_64
        RELEASE_NAME   := fusion64-macos-arm64.dylib
    endif
    LINKER_FLAGS   := -dynamiclib -undefined dynamic_lookup -lida

else
    # Windows builds not supported via Docker/MinGW due to ABI incompatibility
    # Use Clang with MSVC ABI target (clang-cl + lld-link) instead
    $(error Windows builds require MSVC ABI. Use clang-cl on Windows or cross-compile with xwin)
endif

.PHONY: all clean

all:
	@mkdir -p $(OBJ_DIR)
	@echo "Building for $(PLATFORM) with $(USE_COMPILER)..."
	@count=0; \
	for file in $(CPP_FILES); do \
	  echo "  Compiling: $$file"; \
	  $(USE_COMPILER) $$file -c -o $(OBJ_DIR)$$count.o $(COMPILER_FLAGS); \
	  count=$$((count + 1)); \
	done
	@mkdir -p release
	@echo "  Linking: $(RELEASE_NAME)"
	@$(USE_COMPILER) -o release/$(RELEASE_NAME) $(COMPILER_FLAGS) $(OBJ_DIR)*.o $(LINKER_FLAGS)
	@echo "Done: release/$(RELEASE_NAME)"

clean:
	@rm -rf $(OBJ_DIR) release/
