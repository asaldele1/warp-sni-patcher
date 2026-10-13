/*
 * WARP SNI Patcher (Linux) -- command-line front end.
 *
 * Mirrors the Windows GUI's workflow for a headless Linux client: disconnect
 * the tunnel, stop warp-svc, patch (or restore) the binary on disk, then start
 * the service again. Must run as root to write /usr/bin/warp-svc and drive
 * systemd, unless --dry-run is given.
 */
#include "patcher.h"
#include "i18n.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void UiLog(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

static void PrintUsage(const char* argv0)
{
    printf("%s\n\n", Tr(STR_USAGE_HINT));
    printf("Usage: %s [options]\n\n", argv0);
    printf("  --sni <host>        new MASQUE SNI hostname (default: %s)\n", DEFAULT_SNI);
    printf("  --reg-sni <host>    new registration API hostname (default: %s)\n", DEFAULT_REG_SNI);
    printf("  --target <path>     path to warp-svc (default: auto-detect)\n");
    printf("  --restore           restore the original binary from <target>.bak\n");
    printf("  --dry-run           show what would change without writing anything\n");
    printf("  --ru | --en         force Russian / English messages\n");
    printf("  -h, --help          show this help\n");
}

int main(int argc, char** argv)
{
    const char* sni = DEFAULT_SNI;
    const char* regSni = DEFAULT_REG_SNI;
    const char* target = NULL;
    int restore = 0;
    int wasConnected = 0;
    int ok = 0;
    int i;

    I18nInit(argc, argv);

    for (i = 1; i < argc; ++i)
    {
        const char* a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0)
        {
            PrintUsage(argv[0]);
            return 0;
        }
        else if (strcmp(a, "--restore") == 0)
        {
            restore = 1;
        }
        else if (strcmp(a, "--dry-run") == 0)
        {
            g_dryRun = 1;
        }
        else if (strcmp(a, "--ru") == 0 || strcmp(a, "--en") == 0)
        {
            /* handled by I18nInit */
        }
        else if (strcmp(a, "--sni") == 0 && i + 1 < argc)
        {
            sni = argv[++i];
        }
        else if (strcmp(a, "--reg-sni") == 0 && i + 1 < argc)
        {
            regSni = argv[++i];
        }
        else if (strcmp(a, "--target") == 0 && i + 1 < argc)
        {
            target = argv[++i];
        }
        else
        {
            fprintf(stderr, "Unknown or incomplete option: %s\n\n", a);
            PrintUsage(argv[0]);
            return 2;
        }
    }

    if (!target)
    {
        target = FindDefaultTarget();
        if (!target)
        {
            UiLog(Tr(STR_LOG_ERR_TARGET_NOT_FOUND), "warp-svc");
            UiLog("%s", Tr(STR_LOG_ERR_CHECK_INSTALL));
            return 1;
        }
    }

    if (!g_dryRun && geteuid() != 0)
    {
        UiLog(Tr(STR_LOG_ERR_NEED_ROOT), target);
        return 1;
    }

    if (restore)
    {
        StopWarpService(NULL);
        ok = RunRestore(target);
        StartWarpService();
        UiLog("%s", ok ? Tr(STR_LOG_DONE) : Tr(STR_LOG_ERR_RESTORE_FAILED));
        return ok ? 0 : 1;
    }

    WarpDisconnectIfConnected(target, &wasConnected);
    if (!StopWarpService(NULL))
    {
        return 1;
    }
    ok = RunPatch(target, sni, regSni);
    StartWarpService();
    if (ok && wasConnected)
    {
        WarpConnect(target);
    }
    UiLog("%s", ok ? Tr(STR_LOG_DONE) : Tr(STR_LOG_ERR_PATCH_FAILED));
    return ok ? 0 : 1;
}
