# IDA-Fusion - Enhanced

> **Fork Notice**: Maintained fork of [senator715/IDA-Fusion](https://github.com/senator715/IDA-Fusion) with modern IDA Pro support and cross-platform compatibility.

Signature scanner and creator for **IDA Pro 7/8/9+** with support for **Windows**, **Linux**, and **macOS** (Intel + Apple Silicon).

---

## Features

**Core Functionality**

- Signature generation (CODE, IDA, CRC-32, FNV-1A)
- Automatic uniqueness validation
- Performance timing metrics
- Settings persistence

**Platform Support**

- ► IDA Pro 9.x (modern SDK)
- ► macOS ARM64 (Apple Silicon)
- ► macOS x64 (Intel)
- ► Linux x64
- ► Windows x64

**Enhancements**

- Context menu integration (right-click → Fusion)
- Platform-specific hotkeys (⌘⌥S / Ctrl+Alt+S)
- Function boundary detection
- Wildcard toggle for immediate values
- Memory safety & code quality improvements

---

## How It Works

IDA-Fusion wildcards operands containing **immediate values (IMM)** to capture only opcodes:

```
lea rax, [rbx+10h]  →  lea rax, [rbx+?]
```

This makes signatures resilient against anti-reversing techniques. Wildcard behavior is toggleable via dialog checkbox.

![Signature Example](https://user-images.githubusercontent.com/89423559/170587870-133ff3c1-e95a-4a20-a9ca-deb1390cbd40.png)

---

## Installation

**1. Download** the latest release for your platform

**2. Copy** to IDA plugins folder:

- ▪ Windows: `fusion64-windows-x64.dll` → `C:\Program Files\IDA Pro X.X\plugins\`
- ▪ Linux: `fusion64-linux-x64.so` → `/path/to/ida/plugins/`
- ▪ macOS: `fusion64-macos-*.dylib` → `/Applications/IDA Pro X.X.app/Contents/MacOS/plugins/`

**3. Restart** IDA Pro

### Usage

| Method       | Shortcut                                 |
| ------------ | ---------------------------------------- |
| Menu         | `Edit > Plugins > Fusion`                |
| Hotkey       | `Ctrl+Alt+S` (Win/Linux) / `⌘⌥S` (macOS) |
| Context Menu | Right-click in disassembly → `Fusion`    |

---

## Building from Source

### Prerequisites

- **Docker** - Installed and running
- **IDA SDK** - Extract to `sdk/` in project root:
  - IDA 9.x: `ida-sdk-main v9.x.zip` → rename to `sdk`
  - IDA 8.x: `idasdk8.x.zip` → rename to `sdk`

### Build All Platforms

```bash
make build
```

Builds **all 4 platforms** (Linux x64, Windows x64, macOS ARM64, macOS Intel x64) in a single Docker multi-stage container.

**Output:** `release/fusion64-{platform}-{arch}.{ext}`

See [docker/README.md](docker/README.md) for implementation details.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and detailed changes.

## Credits

**Original Author**: [senator715](https://github.com/senator715)
**Original Repository**: [senator715/IDA-Fusion](https://github.com/senator715/IDA-Fusion)

This fork extends the original work with IDA 9.x support and cross-platform compatibility.

## License

Maintains the original license from [senator715/IDA-Fusion](https://github.com/senator715/IDA-Fusion).
