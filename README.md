# WARP SNI Patcher

A small tool that patches Cloudflare WARP's `warp-svc` on disk to override the
MASQUE tunnel SNI and the registration API hostname.

Two builds are provided:

- **Windows** — a Win32 GUI, patches `warp-svc.exe` (PE). Sources at the repo root.
- **Linux** — a CLI, patches `warp-svc` (ELF). Sources in [`linux/`](linux/).

> This is a fork of [Sketchystan1/warp-sni-patcher](https://github.com/Sketchystan1/warp-sni-patcher)
> that adds the Linux port.

## How it works

For each known hostname baked into `warp-svc`, the patcher overwrites the
hostname string in place (keeping its address) and fixes every associated
length value so the runtime reads the new host correctly:

- `mov r32, imm32` length immediates in code, near the `lea` that loads the host;
- fat-pointer length fields in data;
- for the registration host, the parallel pointer/length arrays the service
  indexes at runtime.

MASQUE hostnames are packed Rust string-table literals (`&str` is `(ptr, len)`
with no NUL terminator), so a replacement must fit the original length and the
tail is left untouched — the patched length bounds every read.

The two platforms differ mainly in the binary format and in how the
registration host is handled:

| | Windows (`warp-svc.exe`, PE) | Linux (`warp-svc`, ELF PIE) |
|---|---|---|
| Hostname pointers | absolute values in data | `R_X86_64_RELATIVE` relocations |
| Registration host storage | fixed 32-byte slots (can grow) | packed literals (can't grow) |
| Registration patch strategy | overwrite, up to slot capacity | overwrite in place, repoint to an FQDN already in the binary, **or** relocate into a code cave (no length limit) |
| Front end | Win32 GUI | CLI |

The original binary is preserved as `<target>.bak`, refreshed whenever the
target is still pristine, so re-running after a WARP update stays clean.
Patching breaks the binary's signature, and WARP updates replace the binary, so
re-run the patcher after each update.

## Releases

Pre-built release packages (`.zip`) are available on the
[Releases](../../releases) page. See [CHANGELOG.md](CHANGELOG.md) for details on
each release.

## Building from source

### Windows

Requires Visual Studio with C++ desktop development tools (MSVC x64):

```cmd
build.bat
```

### Linux

Requires a C compiler and glibc headers (no external dependencies):

```sh
cd linux
make              # local build
make STATIC=1     # fully static, portable across distros / libc versions
```

Release binaries are built static, so they run on any x86-64 Linux regardless
of glibc version. See [`linux/README.md`](linux/README.md) for usage and details.
