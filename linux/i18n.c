/*
 * WARP SNI Patcher (Linux) -- i18n implementation.
 */
#include "i18n.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
    const char* en;
    const char* ru;
} I18N_ENTRY;

#define ENTRY(id, enStr, ruStr) [id] = { enStr, ruStr }

static const I18N_ENTRY g_table[STR_COUNT] = {
    ENTRY(STR_USAGE_HINT,
        "Patches Cloudflare WARP's warp-svc to override the MASQUE tunnel SNI\n"
        "and the registration API hostname.",
        "Патчит warp-svc в Cloudflare WARP, подменяя SNI туннеля MASQUE\n"
        "и имя хоста API регистрации."),

    ENTRY(STR_LOG_STOP_SERVICE,
        "Stopping warp-svc service...",
        "Остановка службы warp-svc..."),
    ENTRY(STR_LOG_START_SERVICE,
        "Starting warp-svc service...",
        "Запуск службы warp-svc..."),
    ENTRY(STR_LOG_DISCONNECTING,
        "Disconnecting tunnel...",
        "Отключение туннеля..."),
    ENTRY(STR_LOG_RECONNECT_NOTE,
        "Note: reconnect the tunnel with 'warp-cli connect'.",
        "Примечание: подключите туннель заново командой 'warp-cli connect'."),
    ENTRY(STR_LOG_BACKUP,
        "Creating backup...",
        "Создание резервной копии..."),
    ENTRY(STR_LOG_PATCHING,
        "Applying patch...",
        "Применение патча..."),
    ENTRY(STR_LOG_DONE,
        "Done!",
        "Готово!"),
    ENTRY(STR_LOG_RESTORED_OK,
        "Original file restored from backup.",
        "Исходный файл восстановлен из резервной копии."),
    ENTRY(STR_LOG_DRY_RUN,
        "[dry-run] No files were modified.",
        "[dry-run] Файлы не изменялись."),

    ENTRY(STR_LOG_PATCH_MASQUE,
        "  MASQUE %-42s -> %s (len %zu->%zu)",
        "  MASQUE %-42s -> %s (длина %zu->%zu)"),
    ENTRY(STR_LOG_PATCH_REG_INPLACE,
        "  reg    %-42s -> %s (in-place, len %zu->%zu)",
        "  reg    %-42s -> %s (на месте, длина %zu->%zu)"),
    ENTRY(STR_LOG_PATCH_REG_REPOINT,
        "  reg    %-42s -> %s (repoint, len %zu->%zu)",
        "  reg    %-42s -> %s (repoint, длина %zu->%zu)"),

    ENTRY(STR_LOG_ERR_STOP_SERVICE,
        "[!] Could not stop the warp-svc service. Are you root?",
        "[!] Не удалось остановить службу warp-svc. Запущено от root?"),
    ENTRY(STR_LOG_ERR_START_SERVICE,
        "[!] Could not start the warp-svc service.",
        "[!] Не удалось запустить службу warp-svc."),
    ENTRY(STR_LOG_ERR_PATCH_FAILED,
        "[!] Patch could not be applied. Original files left unchanged.",
        "[!] Не удалось применить патч. Исходные файлы остались без изменений."),
    ENTRY(STR_LOG_ERR_RESTORE_FAILED,
        "[!] Restore failed. Check that a .bak backup exists.",
        "[!] Не удалось восстановить. Проверьте наличие резервной копии .bak."),
    ENTRY(STR_LOG_ERR_NO_BACKUP,
        "[!] No backup file found. Nothing to restore.",
        "[!] Файл резервной копии не найден. Нечего восстанавливать."),
    ENTRY(STR_LOG_ERR_BACKUP_DIFF_VER,
        "[!] The backup is from a different version of WARP.",
        "[!] Резервная копия относится к другой версии WARP."),
    ENTRY(STR_LOG_ERR_CURRENT_UNPATCHED,
        "    The current warp-svc is already an original, unpatched version.",
        "    Текущий warp-svc уже является оригинальной непропатченной версией."),
    ENTRY(STR_LOG_ERR_DELETE_BACKUP_FRESH,
        "    Please delete '%s' and re-run against a fresh install.",
        "    Удалите '%s' и запустите повторно на чистой установке."),
    ENTRY(STR_LOG_ERR_BACKUP_NO_ORIG_HOSTS,
        "[!] Could not find original hostnames in the backup file.",
        "[!] Не удалось найти исходные имена хостов в резервной копии."),
    ENTRY(STR_LOG_ERR_NO_ORIG_HOSTS_AND_NO_BACKUP,
        "[!] Could not find original hostnames in warp-svc and no backup exists.",
        "[!] В warp-svc не найдены исходные имена хостов, и резервной копии нет."),
    ENTRY(STR_LOG_ERR_ALREADY_PATCHED_OR_UNSUPPORTED,
        "    The file may already be patched, or this version is not supported.",
        "    Возможно, файл уже пропатчен или эта версия не поддерживается."),
    ENTRY(STR_LOG_ERR_TARGET_NOT_FOUND,
        "[!] Could not find warp-svc at: %s",
        "[!] Не удалось найти warp-svc по адресу: %s"),
    ENTRY(STR_LOG_ERR_CHECK_INSTALL,
        "    Make sure Cloudflare WARP is installed, or pass --target <path>.",
        "    Убедитесь, что Cloudflare WARP установлен, или укажите --target <путь>."),
    ENTRY(STR_LOG_ERR_NEED_ROOT,
        "[!] Writing '%s' needs root. Re-run with sudo.",
        "[!] Для записи в '%s' нужны права root. Запустите через sudo."),
    ENTRY(STR_LOG_ERR_OPEN_FILE,
        "[!] Unable to open '%s'.",
        "[!] Не удалось открыть '%s'."),
    ENTRY(STR_LOG_ERR_INVALID_SIZE,
        "[!] The file '%s' has an invalid size.",
        "[!] Файл '%s' имеет недопустимый размер."),
    ENTRY(STR_LOG_ERR_NOT_ENOUGH_MEM,
        "[!] Not enough memory to read '%s'.",
        "[!] Недостаточно памяти для чтения '%s'."),
    ENTRY(STR_LOG_ERR_READ_FILE,
        "[!] Could not read '%s'.",
        "[!] Не удалось прочитать '%s'."),
    ENTRY(STR_LOG_ERR_WRITE_FILE,
        "[!] Could not write to '%s'.",
        "[!] Не удалось записать в '%s'."),
    ENTRY(STR_LOG_ERR_FILE_TOO_SMALL,
        "[!] The file is too small to be a valid executable.",
        "[!] Файл слишком мал, чтобы быть исполняемым."),
    ENTRY(STR_LOG_ERR_NOT_VALID_ELF,
        "[!] The file is not a valid ELF executable.",
        "[!] Файл не является корректным исполняемым файлом ELF."),
    ENTRY(STR_LOG_ERR_X64_ONLY,
        "[!] Only 64-bit (x86-64) builds of warp-svc are supported.",
        "[!] Поддерживаются только 64-битные (x86-64) сборки warp-svc."),
    ENTRY(STR_LOG_ERR_EMPTY_SNI,
        "[!] MASQUE SNI cannot be empty (e.g. %s).",
        "[!] MASQUE SNI не может быть пустым (например, %s)."),
    ENTRY(STR_LOG_ERR_SNI_TOO_LONG,
        "[!] The MASQUE SNI '%s' is too long (%zu chars; max %zu).",
        "[!] Имя хоста MASQUE SNI '%s' слишком длинное (%zu симв.; максимум %zu)."),
    ENTRY(STR_LOG_TIP_DEFAULT_SNI,
        "    Tip: the default '%s' is recommended.",
        "    Совет: рекомендуется значение по умолчанию '%s'."),
    ENTRY(STR_LOG_ERR_EMPTY_REG_SNI,
        "[!] Registration API hostname cannot be empty (e.g. %s).",
        "[!] Имя хоста API регистрации не может быть пустым (например, %s)."),
    ENTRY(STR_LOG_ERR_REG_HOSTNAME_TOO_LONG,
        "[!] The registration hostname '%s' (%zu) does not fit in place (max %zu)\n"
        "    and is not one of the hostnames already built into warp-svc.",
        "[!] Имя хоста регистрации '%s' (%zu) не помещается на месте (максимум %zu)\n"
        "    и не входит в число хостов, уже встроенных в warp-svc."),
    ENTRY(STR_LOG_TIP_DEFAULT_REG_SNI,
        "    Tip: the default '%s' is recommended.",
        "    Совет: рекомендуется значение по умолчанию '%s'."),
    ENTRY(STR_LOG_ERR_REG_UPDATE_UNSAFE,
        "[!] Could not safely update the registration hostname in this build.",
        "[!] Не удалось безопасно обновить имя хоста регистрации в этой сборке."),
};

static int g_isRussian = 0;

static int looks_russian(const char* s)
{
    return s && (strncasecmp(s, "ru", 2) == 0);
}

void I18nInit(int argc, char** argv)
{
    const char* env;
    int i;

    for (i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "--ru") == 0) { g_isRussian = 1; return; }
        if (strcmp(argv[i], "--en") == 0) { g_isRussian = 0; return; }
    }

    env = getenv("WARP_PATCHER_LANG");
    if (env && *env) { g_isRussian = looks_russian(env); return; }

    env = getenv("LC_ALL");
    if (!env || !*env) env = getenv("LC_MESSAGES");
    if (!env || !*env) env = getenv("LANG");
    if (env && *env) g_isRussian = looks_russian(env);
}

const char* Tr(StringId id)
{
    if ((unsigned)id >= STR_COUNT)
    {
        return "";
    }
    return g_isRussian ? g_table[id].ru : g_table[id].en;
}
