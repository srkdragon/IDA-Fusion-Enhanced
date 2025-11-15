# Docker Multi-Platform Build

Cross-compile IDA-Fusion for **all platforms** from any host OS using a single multi-stage container.

## Prerequisites

- Docker installed and running
- IDA SDK extracted to `sdk/` directory

## Usage

### Build All Platforms

```bash
make build
```

Builds all 4 platforms in one multi-stage Docker container.

### Cleanup

```bash
make build-clean
```

## Output

Binaries are saved to `release/`:

- `fusion64-linux-x64.so` - Linux x64
- `fusion64-windows-x64.dll` - Windows x64
- `fusion64-macos-arm64.dylib` - macOS ARM64
- `fusion64-macos-x64.dylib` - macOS Intel x64

> **Note**: 32-bit builds are not included (IDA Pro 7.5+ is 64-bit only)

## Implementation

**Files:**
- `Dockerfile` - Multi-stage build for all platforms
- `Makefile` - Platform-specific build logic (no Docker check)

**Build stages:**
- **Linux**: Ubuntu 22.04 with g++
- **Windows**: Ubuntu 22.04 with MinGW cross-compiler
- **macOS ARM64**: Ubuntu 22.04 with osxcross (MacOSX13.3 SDK)
- **macOS x64**: Ubuntu 22.04 with osxcross (MacOSX13.3 SDK)

All artifacts are collected in a final `scratch` stage for extraction. Containers are automatically cleaned up after build.
