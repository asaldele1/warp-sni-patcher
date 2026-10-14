# Changelog

## [1.3.0] - 2026-10-14
- Linux: code-cave mode — hostnames too long to fit in place are written into
  unused padding in the binary and all references repointed there, lifting the
  length limit for both the MASQUE SNI and the registration hostname
- Linux: CI/release binaries are built fully static, so they run on any x86-64
  Linux regardless of libc version (e.g. glibc 2.33+)

## [1.2.0] - 2026-10-13
- Add Linux port: a CLI patcher for the ELF build of `warp-svc` (`linux/`)
- Linux: handle ELF relocations and packed registration hostnames (in-place or
  repoint to an FQDN already in the binary), and systemd/warp-cli service control
- Add Linux build to CI and release packaging

## [1.1.0] - 2026-10-12
- Add registration API hostname patching
- Add Russian localization
- UI layout refinements
- Add GitHub Actions release workflow

## [1.0.0] - 2026-07-21
- Initial release
