/*
 * WARP SNI Patcher (Linux) -- shared declarations.
 *
 * The program is split into three translation units:
 *   patcher.c   core: ELF parsing, in-place patching, service control
 *   main.c      command-line front end + UiLog()
 *   i18n.c      English / Russian strings
 *
 * The core reports progress through UiLog() (defined in main.c).
 */
#ifndef WARP_SNI_PATCHER_H
#define WARP_SNI_PATCHER_H

#include <stddef.h>
#include "i18n.h"

#define DEFAULT_SNI "speed.cloudflare.com"
#define DEFAULT_REG_SNI "api.devices.cloudflare.com"

/* ---- Core (patcher.c) ---- */

/* When non-zero, patching reports what it would change but writes nothing
   (no binary, no backup) and does not touch the service. Set by main.c. */
extern int g_dryRun;

/* Locate the installed warp-svc (first existing of the usual locations, then
   $PATH). Returns a pointer to a static buffer, or NULL if none was found. */
const char* FindDefaultTarget(void);

/* Patch the target's MASQUE SNI (newSni) and registration API hostname
   (newRegSni). Returns 1 on success. */
int RunPatch(const char* target, const char* newSni, const char* newRegSni);

/* Restore the original binary from its .bak. Returns 1 on success. */
int RunRestore(const char* target);

/* Stop the warp-svc systemd unit, waiting until stopped. Sets *outWasRunning
   to 1 if it was running, so the caller knows whether to restart it. */
int StopWarpService(int* outWasRunning);

/* Start the warp-svc systemd unit, waiting until active. */
int StartWarpService(void);

/* If WARP reports "Connected" via warp-cli, disconnect it so the tunnel is
   down before the service is stopped/patched. Sets *outWasConnected to 1 if it
   was connected. Best-effort: a missing warp-cli or a query failure is not
   treated as fatal. */
int WarpDisconnectIfConnected(const char* target, int* outWasConnected);

/* Reconnect WARP via warp-cli. Best-effort. */
int WarpConnect(const char* target);

/* 1 if path exists and is a regular file. */
int FileExists(const char* path);

/* Build "<target>.bak" into backup. */
void BuildBackupPath(const char* target, char* backup, size_t backupSize);

/* ---- Front end (main.c) ---- */

/* Print a formatted log line. Used by the core for progress. */
void UiLog(const char* fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

#endif /* WARP_SNI_PATCHER_H */
