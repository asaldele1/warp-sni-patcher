# WARP SNI Patcher — Linux

A command-line port of the Windows patcher for the Linux build of Cloudflare
WARP's daemon, `warp-svc` (a Rust ELF64 PIE). It overrides the MASQUE tunnel SNI
and the registration API hostname on disk.

## How it differs from the Windows version

The logic is the same, but the binary format is not:

- **PE → ELF.** Sections and the image layout are read from ELF program/section
  headers; virtual addresses are mapped to file offsets via the `PT_LOAD`
  segments (the RW segment is offset from its VA, so this mapping matters).
- **Pointers are relocations.** Rust `&str` pointers into the hostname table are
  emitted as `R_X86_64_RELATIVE` relocations (target VA in the addend) rather
  than absolute values in data, so the patcher reads/edits `.rela.dyn`.
- **Hostnames are packed.** Both MASQUE and registration hostnames are packed
  string-table literals (no fixed slots). An in-place replacement must be no
  longer than the original; the tail is left intact and the patched length
  bounds every read.

Length metadata is kept consistent across all three places it lives: `mov
r32, imm32` immediates in code (next to the `lea` that loads the host),
fat-pointer length fields in `.data.rel.ro`, and the registration length array
in `.rodata` (indexed in lockstep with a pointer array).

### Registration hostname: in-place **or** repoint

Because registration hosts can't grow in place, the patcher does both:

- **In-place** when the new host fits in the original length (≤ 24 chars) — any
  custom hostname.
- **Repoint** when it doesn't fit but *is* one of the FQDNs already built into
  the binary (e.g. `api.devices.cloudflare.com`, present as an anchor): the
  consumer endpoint's pointer/length references are retargeted to that existing
  string. This is how the default `api.devices.cloudflare.com` is applied.

The original is preserved as `<target>.bak`, refreshed whenever the target is
still pristine, so re-running after a WARP update stays clean. Patching does not
touch the Authenticode-equivalent signing, but WARP updates replace the binary,
so re-run after each update.

## Build

```sh
cd linux
make
```

Needs a C compiler and glibc headers (`<elf.h>`, `memmem`). No external deps.

## Usage

Writing `/usr/bin/warp-svc` and driving systemd requires root:

```sh
sudo ./warp-sni-patcher                      # defaults: speed.cloudflare.com + api.devices.cloudflare.com
sudo ./warp-sni-patcher --sni my.sni.example --reg-sni api.devices.cloudflare.com
sudo ./warp-sni-patcher --restore            # restore from <target>.bak
./warp-sni-patcher --dry-run                 # show what would change, write nothing (no root needed)
```

Options:

| Option | Meaning |
|---|---|
| `--sni <host>` | new MASQUE SNI (default `speed.cloudflare.com`) |
| `--reg-sni <host>` | new registration API hostname (default `api.devices.cloudflare.com`) |
| `--target <path>` | path to `warp-svc` (default: auto-detect in `/usr/bin`, `/bin`, `/usr/lib/warp`, `$PATH`) |
| `--restore` | restore the original binary from `<target>.bak` |
| `--dry-run` | report changes without writing anything or touching the service |
| `--ru` / `--en` | force Russian / English messages (default from `$LANG`) |

The patcher disconnects the tunnel (`warp-cli disconnect`), stops `warp-svc`
(systemd), patches, then restarts the service and reconnects if it was
connected — mirroring the Windows GUI's flow.
