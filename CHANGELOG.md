# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [2.1.0] - 2026-04-05

### Added

- XREF signature generation — finds all code XREFs to the target function and generates a unique signature at each call site
- Multi-threaded XREF processing — executable segments are snapshotted into RAM, then all call sites are searched in parallel (one thread per CPU core); no IDA API usage in worker threads
- Vtable hint when no code XREFs are found — shows the data XREF count and explains the function is likely called through virtual dispatch
- User cancellation support during XREF pre-decode phase

### Changed

- XREF results are sorted by signature length (shortest first), shortest is copied to clipboard automatically
- Plugin hooks modernized: replaced deprecated `hook_to_notification_point` with `hook_event_listener` / `DECLARE_LISTENER` (IDA 9.x API)
- "Search for signature" menu option removed — redundant with IDA's built-in search

### Fixed

- Selected byte range signatures no longer get trimmed — wildcards at the edges are preserved when the user explicitly selected the range
- Docker build no longer hardcodes `--platform=linux/amd64`, uses `ARG BUILDPLATFORM` instead

---

## [2.0.1] - 2025-12-21

### Added

**Platform Support**
- ► Linux ARM64 (full support)
- ► Windows x64 cross-compilation (xwin + clang-cl)

**Features**
- Cross-platform clipboard support
  - Windows: Native API (GlobalAlloc/SetClipboardData)
  - macOS: pbcopy integration
  - Linux: xclip integration
- Complete Docker multi-stage build system
  - Builds all 5 platforms in single command
  - Optimized layer caching
  - Automated binary extraction

### Fixed

**Critical**
- Windows crashes during signature generation (format string vulnerabilities)
- Windows settings write permission errors (moved to user directory)
- Windows console output missing (now always prints with timing/match info)

**Quality**
- Format string type safety (`%llX` → `%p` for pointers, `%i` → `%zu` for size_t)
- Clipboard gets clean signature, console gets full diagnostic info
- User directory settings path for cross-platform compatibility

### Changed

- Build system unified with Docker multi-platform support
- Settings location: `%APPDATA%\Hex-Rays\IDA Pro` (Windows) / `~/.idapro` (Unix)
- Console output format: signature + timing + match count

---

## [2.0.0] - 2025-11-15

### Added

**Platform Support**
- ► IDA Pro 9.x with modern SDK APIs
- ► macOS ARM64 (Apple Silicon M1/M2/M3)
- ► macOS Intel x64
- ► Linux x64
- ► Docker multi-platform build system

**Features**
- Context menu integration (right-click → Fusion)
- Performance timing metrics
- Auto-validation of signature uniqueness
- Function boundary detection (optional)
- Wildcard toggle (optional)
- Settings persistence (`fusion_settings.cfg`)
- Platform-specific hotkeys (⌘⌥S / Ctrl+Alt+S)

### Changed

- Migrated to PLUGIN_MULTI architecture (`plugmod_t`)
- Updated API: `bin_search3` → `bin_search`
- Modern action handler system

### Fixed

**Critical**
- Symbol visibility on macOS (plugin loading)
- Memory safety (null pointer checks)
- Format string bugs
- Type safety (u32 return values)

**Quality**
- Code duplication eliminated
- Buffer safety improvements
- Const correctness
- Duplicate console output

---

## [1.x] - Original Release

- Windows x86/x64 support
- IDA Pro 7.x/8.x support
- Signature generation (CODE, IDA, CRC-32, FNV-1A)
- Signature search
- Settings dialog

---

**Original**: [senator715/IDA-Fusion](https://github.com/senator715/IDA-Fusion)
**Fork**: [K4ryuu/IDA-Fusion](https://github.com/K4ryuu/IDA-Fusion)
