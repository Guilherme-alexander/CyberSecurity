# inject_local.c

> Minimal local shellcode loader for Windows.

## Overview

`inject_local.c` is a simple proof-of-concept (PoC) demonstrating **local shellcode execution** inside the current process.

Unlike remote injection techniques that target external processes, this implementation:

- allocates executable memory locally
- copies position-independent shellcode (PIC)
- changes memory permissions
- directly jumps into the payload

This makes it useful for:

- shellcode debugging
- payload testing
- malware analysis labs
- Windows internals research
- red team development environments

---

## Difference Between Local and Remote Injection

| Feature | inject_local.c | inject.c (remote) |
|---|---|---|
| Injection Target | Current process | External process |
| Complexity | Low | Medium / High |
| Requires PID | No | Yes |
| Requires OpenProcess | No | Yes |
| Uses CreateRemoteThread | No | Yes |
| Debugging | Easier | Harder |
| Real-world simulation | Limited | More realistic |

---

## Execution Flow

```text
Read shellcode from file
            ↓
Allocate RWX memory
            ↓
Copy shellcode into memory
            ↓
Change memory protection to RX
            ↓
Jump to shellcode
            ↓
Execute payload locally
```

---

## Core Windows APIs Used

| API | Purpose |
|---|---|
| `VirtualAlloc` | Allocate executable memory |
| `VirtualProtect` | Change memory permissions |
| `CreateFile` | Read payload from disk |
| `ReadFile` | Load shellcode into memory |
| `memcpy` | Copy shellcode |
| `getchar` | Pause execution for debugging |

---

## Build

### Compile with MinGW GCC

```bash
gcc inject_local.c -o inject_local.exe
```

### Compile with MSVC (Visual Studio)

```bat
cl inject_local.c
```

---

## Usage

```bash
inject_local.exe loader.bin
```

Example:

```bash
inject_local.exe calc.bin
```

---

## Example Loader Logic

```c
cs = VirtualAlloc(
    NULL,
    codeLen,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE
);

memcpy(cs, code, codeLen);

VirtualProtect(
    cs,
    codeLen,
    PAGE_EXECUTE_READ,
    &t
);

((void(*)())cs)();
```

---

## Technical Notes

### Memory Permissions

The loader initially allocates memory as:

```text
PAGE_EXECUTE_READWRITE
```

Then changes it to:

```text
PAGE_EXECUTE_READ
```

This mimics behavior commonly seen in shellcode loaders and reflective execution techniques.

---

### Position Independent Code (PIC)

The payload must be:

- raw shellcode
- position independent
- self-contained

Typically generated from:

- NASM
- Metasploit
- Donut
- custom loaders
- PE-to-shellcode converters

---

## Repository Structure

```text
RedTeam/
└── inject_local/
    ├── inject_local.c
    └── README.md
```

---

## Educational Purpose

This project is intended for:

- malware analysis labs
- shellcode research
- exploit development practice
- defensive research
- Windows internals education

Do not use against systems you do not own or explicitly have permission to test.
