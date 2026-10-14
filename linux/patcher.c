/*
 * WARP SNI Patcher (Linux) -- core (ELF parsing, in-place patching, service
 * control).
 *
 * Standalone on-disk patcher for Cloudflare WARP's warp-svc (the Linux daemon,
 * a Rust ELF64 PIE). It overrides two groups of hostnames baked into the
 * binary:
 *   1. MASQUE tunnel SNI hostnames (consumer-masque / zt-masque ...).
 *   2. The registration API endpoint hostname (api.cloudflareclient.com), the
 *      SNI used for the client-registration HTTPS API.
 *
 * Unlike the Windows PE build, every hostname here is a packed Rust &'static
 * str literal (back-to-back in .rodata, no NUL, no fixed slot), so an in-place
 * replacement must be no longer than the original and the tail is left intact
 * (the patched length bounds every read).
 *
 * Length metadata lives in three kinds of places, all rewritten to match:
 *   1. `mov r32, imm32` length immediates in .text, within a small window
 *      around a `lea reg,[rip+disp32]` that targets the hostname.
 *   2. Fat-pointer length fields in .data.rel.ro: the pointer is emitted as an
 *      R_X86_64_RELATIVE relocation (target VA in r_addend) and the length is
 *      the inline qword right after it.
 *   3. Registration hosts only: a parallel length array in .rodata that code
 *      indexes in lockstep with a pointer-only array (whose pointers are also
 *      R_X86_64_RELATIVE relocations).
 *
 * Registration hostnames additionally support "repoint": when the requested
 * host does not fit in place but IS one of the FQDNs already built into the
 * binary (e.g. api.devices.cloudflare.com, present as an anchor), the consumer
 * endpoint's pointer/length references are retargeted to that existing string
 * instead of overwriting bytes -- no length limit, and the exact FQDN the
 * binary already trusts is reused.
 *
 * The original is preserved as <target>.bak, refreshed whenever the target
 * still contains ALL known hostnames (pristine install or fresh WARP update).
 */

#include "patcher.h"

#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BACKUP_SUFFIX ".bak"
#define RIP_RELATIVE_LEA_SIZE 7
#define STATIC_CODE_PATCH_WINDOW_BEFORE 16
#define STATIC_CODE_PATCH_WINDOW_AFTER 24
#define MAX_OCCURRENCES 64

int g_dryRun = 0;

typedef struct {
    const char* value;
    size_t length;
    int patchTarget;   /* 1: replace/retarget this string; 0: anchor only */
} KNOWN_SNI;

/* MASQUE tunnel hostnames. Packed literals, referenced only by code LEAs with
   immediate lengths (no data fat-pointers on Linux). */
static const KNOWN_SNI g_MasqueHostnames[] = {
    { "consumer-masque.cloudflareclient.com", 36, 1 },
    { "consumer-masque.cloudflareclient.com.", 37, 1 },
    { "consumer-masque-proxy.cloudflareclient.com", 42, 1 },
    { "consumer-masque-proxy.cloudflareclient.com.", 43, 1 },
    { "zt-masque.cloudflareclient.com", 30, 1 },
    { "zt-masque.cloudflareclient.com.", 31, 1 },
    { "zt-masque-proxy.cloudflareclient.com", 36, 1 },
    { "zt-masque-proxy.cloudflareclient.com.", 37, 1 }
};

/* Registration API hosts: trailing-dot FQDNs. Only the consumer endpoint is a
   patch target; the devices/federal entries are anchors that are both verified
   (to find the parallel arrays) and usable as repoint destinations. */
static const KNOWN_SNI g_RegHostnames[] = {
    { "api.cloudflareclient.com.", 25, 1 },
    { "api.cloudflareclient.com", 24, 1 },
    { "api.devices.cloudflare.com.", 27, 0 },
    { "api.devices.cloudflare.com", 26, 0 },
    { "api.devices.fed.cloudflare.com.", 31, 0 },
    { "api.devices.fed.cloudflare.com", 30, 0 }
};

#define MASQUE_HOSTNAME_COUNT (sizeof(g_MasqueHostnames) / sizeof(g_MasqueHostnames[0]))
#define REG_HOSTNAME_COUNT    (sizeof(g_RegHostnames) / sizeof(g_RegHostnames[0]))

typedef struct {
    size_t fileOffset;        /* byte offset within the file buffer */
    unsigned long long va;    /* virtual address (p_vaddr space) */
    size_t originalLength;    /* length of the matched hostname */
    const KNOWN_SNI* known;   /* table entry that matched here */
} OCCURRENCE;

typedef struct {
    unsigned char* base;
    size_t size;
    Elf64_Ehdr* eh;
    Elf64_Phdr* ph;
    Elf64_Half phnum;
    Elf64_Shdr* sh;
    Elf64_Half shnum;
    /* .rela.dyn */
    Elf64_Rela* rela;
    size_t relaCount;
    /* Code cave: a zero-filled, non-writable gap used to store oversized
       hostnames. Allocated lazily on first use. */
    int caveInit;
    unsigned long long caveCursor;   /* next VA to hand out (0 if none) */
    unsigned long long caveEnd;      /* one past the last usable VA */
} ELF_VIEW;

/* ---- File I/O ---- */

static unsigned char* ReadWholeFile(const char* path, size_t* outSize)
{
    FILE* f;
    long sz;
    unsigned char* buf;

    f = fopen(path, "rb");
    if (!f)
    {
        UiLog(Tr(STR_LOG_ERR_OPEN_FILE), path);
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (sz = ftell(f)) < 0)
    {
        UiLog(Tr(STR_LOG_ERR_INVALID_SIZE), path);
        fclose(f);
        return NULL;
    }
    rewind(f);
    if (sz <= 0 || sz > 0x7FFFFFFF)
    {
        UiLog(Tr(STR_LOG_ERR_INVALID_SIZE), path);
        fclose(f);
        return NULL;
    }
    buf = (unsigned char*)malloc((size_t)sz);
    if (!buf)
    {
        UiLog(Tr(STR_LOG_ERR_NOT_ENOUGH_MEM), path);
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz)
    {
        UiLog(Tr(STR_LOG_ERR_READ_FILE), path);
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *outSize = (size_t)sz;
    return buf;
}

/* Write data to path, preserving the existing file's permission bits (so a
   patched warp-svc stays executable). */
static int WriteWholeFile(const char* path, const unsigned char* data, size_t size)
{
    FILE* f;
    struct stat st;
    int haveMode = (stat(path, &st) == 0);

    f = fopen(path, "wb");
    if (!f)
    {
        if (errno == EACCES || errno == EPERM)
        {
            UiLog(Tr(STR_LOG_ERR_NEED_ROOT), path);
        }
        else
        {
            UiLog(Tr(STR_LOG_ERR_WRITE_FILE), path);
        }
        return 0;
    }
    if (fwrite(data, 1, size, f) != size)
    {
        UiLog(Tr(STR_LOG_ERR_WRITE_FILE), path);
        fclose(f);
        return 0;
    }
    fclose(f);
    if (haveMode)
    {
        chmod(path, st.st_mode & 07777);
    }
    return 1;
}

int FileExists(const char* path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

void BuildBackupPath(const char* target, char* backup, size_t backupSize)
{
    snprintf(backup, backupSize, "%s%s", target, BACKUP_SUFFIX);
}

/* ---- ELF parsing ---- */

static int ParseElf(unsigned char* base, size_t size, ELF_VIEW* v)
{
    Elf64_Ehdr* eh;
    Elf64_Half i;

    memset(v, 0, sizeof(*v));
    if (size < sizeof(Elf64_Ehdr))
    {
        UiLog("%s", Tr(STR_LOG_ERR_FILE_TOO_SMALL));
        return 0;
    }
    eh = (Elf64_Ehdr*)base;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0)
    {
        UiLog("%s", Tr(STR_LOG_ERR_NOT_VALID_ELF));
        return 0;
    }
    if (eh->e_ident[EI_CLASS] != ELFCLASS64 || eh->e_machine != EM_X86_64)
    {
        UiLog("%s", Tr(STR_LOG_ERR_X64_ONLY));
        return 0;
    }
    if (eh->e_phoff + (size_t)eh->e_phnum * eh->e_phentsize > size ||
        eh->e_shoff + (size_t)eh->e_shnum * eh->e_shentsize > size ||
        eh->e_phentsize != sizeof(Elf64_Phdr) ||
        eh->e_shentsize != sizeof(Elf64_Shdr))
    {
        UiLog("%s", Tr(STR_LOG_ERR_NOT_VALID_ELF));
        return 0;
    }

    v->base = base;
    v->size = size;
    v->eh = eh;
    v->ph = (Elf64_Phdr*)(base + eh->e_phoff);
    v->phnum = eh->e_phnum;
    v->sh = (Elf64_Shdr*)(base + eh->e_shoff);
    v->shnum = eh->e_shnum;

    for (i = 0; i < v->shnum; ++i)
    {
        Elf64_Shdr* s = &v->sh[i];
        if (s->sh_type == SHT_RELA && s->sh_entsize == sizeof(Elf64_Rela) &&
            s->sh_offset + s->sh_size <= size)
        {
            /* Prefer .rela.dyn (the big one, which carries RELATIVE relocs). */
            if (!v->rela || s->sh_size > v->relaCount * sizeof(Elf64_Rela))
            {
                /* Keep the RELA section with RELATIVE relocations. */
                Elf64_Rela* cand = (Elf64_Rela*)(base + s->sh_offset);
                size_t n = s->sh_size / sizeof(Elf64_Rela);
                size_t j;
                int hasRelative = 0;
                for (j = 0; j < n && j < 16; ++j)
                {
                    if (ELF64_R_TYPE(cand[j].r_info) == R_X86_64_RELATIVE)
                    {
                        hasRelative = 1;
                        break;
                    }
                }
                if (hasRelative)
                {
                    v->rela = cand;
                    v->relaCount = n;
                }
            }
        }
    }
    return 1;
}

/* Translate a virtual address to a file offset using the PT_LOAD segments.
   Returns 1 and sets *outOff on success. */
static int VaToOff(const ELF_VIEW* v, unsigned long long va, size_t* outOff)
{
    Elf64_Half i;
    for (i = 0; i < v->phnum; ++i)
    {
        const Elf64_Phdr* p = &v->ph[i];
        if (p->p_type == PT_LOAD && p->p_filesz > 0 &&
            va >= p->p_vaddr && va < p->p_vaddr + p->p_filesz)
        {
            *outOff = (size_t)(va - p->p_vaddr + p->p_offset);
            return 1;
        }
    }
    return 0;
}

/* Translate a file offset to a virtual address (inverse of VaToOff). */
static int OffToVa(const ELF_VIEW* v, size_t off, unsigned long long* outVa)
{
    Elf64_Half i;
    for (i = 0; i < v->phnum; ++i)
    {
        const Elf64_Phdr* p = &v->ph[i];
        if (p->p_type == PT_LOAD && p->p_filesz > 0 &&
            off >= p->p_offset && off < p->p_offset + p->p_filesz)
        {
            *outVa = (unsigned long long)(off - p->p_offset + p->p_vaddr);
            return 1;
        }
    }
    return 0;
}

/* Return 1 if the offset falls inside an executable PT_LOAD segment. */
static int OffsetIsExecutable(const ELF_VIEW* v, size_t off)
{
    Elf64_Half i;
    for (i = 0; i < v->phnum; ++i)
    {
        const Elf64_Phdr* p = &v->ph[i];
        if (p->p_type == PT_LOAD && (p->p_flags & PF_X) &&
            off >= p->p_offset && off < p->p_offset + p->p_filesz)
        {
            return 1;
        }
    }
    return 0;
}

/* Return 1 if va lies in a loaded, readable, NON-writable segment (safe to
   store a string the runtime only reads, and never clobbered by RELRO). */
static int VaInReadOnlyLoad(const ELF_VIEW* v, unsigned long long va)
{
    Elf64_Half i;
    for (i = 0; i < v->phnum; ++i)
    {
        const Elf64_Phdr* p = &v->ph[i];
        if (p->p_type == PT_LOAD && p->p_filesz > 0 &&
            va >= p->p_vaddr && va < p->p_vaddr + p->p_filesz)
        {
            return (p->p_flags & PF_W) == 0;
        }
    }
    return 0;
}

/* ---- Code cave ----
   Find the largest zero-filled gap between two sections that sits in a
   read-only loaded segment (i.e. inter-section alignment padding -- unused and
   never referenced). Such a gap is a safe place to store an oversized hostname
   whose pointer we then repoint to it. */
static void FindCave(ELF_VIEW* v)
{
    Elf64_Half i, j;
    unsigned long long bestStart = 0;
    size_t bestLen = 0;

    for (i = 0; i < v->shnum; ++i)
    {
        const Elf64_Shdr* a = &v->sh[i];
        unsigned long long gapStart;
        unsigned long long nextAddr = 0;
        size_t gapLen, goff, k;
        int zero = 1;

        if (a->sh_type == SHT_NOBITS || a->sh_addr == 0 || a->sh_size == 0)
        {
            continue;
        }
        gapStart = a->sh_addr + a->sh_size;

        /* Nearest section that starts after this gap. */
        for (j = 0; j < v->shnum; ++j)
        {
            const Elf64_Shdr* b = &v->sh[j];
            if (b->sh_addr > gapStart && (nextAddr == 0 || b->sh_addr < nextAddr))
            {
                nextAddr = b->sh_addr;
            }
        }
        if (nextAddr == 0 || nextAddr <= gapStart)
        {
            continue;
        }
        gapLen = (size_t)(nextAddr - gapStart);
        if (gapLen < 8 || !VaInReadOnlyLoad(v, gapStart))
        {
            continue;
        }
        if (!VaToOff(v, gapStart, &goff) || goff + gapLen > v->size)
        {
            continue;
        }
        for (k = 0; k < gapLen; ++k)
        {
            if (v->base[goff + k] != 0)
            {
                zero = 0;
                break;
            }
        }
        if (zero && gapLen > bestLen)
        {
            bestLen = gapLen;
            bestStart = gapStart;
        }
    }

    if (bestLen >= 8)
    {
        unsigned long long aligned = (bestStart + 7) & ~7ULL;
        if (aligned < bestStart + bestLen)
        {
            v->caveCursor = aligned;
            v->caveEnd = bestStart + bestLen;
        }
    }
}

/* Reserve `bytes` from the cave (8-byte aligned). Returns the VA and sets
   *outOff to its file offset, or 0 if there is no room. */
static unsigned long long CaveAlloc(ELF_VIEW* v, size_t bytes, size_t* outOff)
{
    unsigned long long va;
    size_t need = (bytes + 7) & ~(size_t)7;

    if (!v->caveInit)
    {
        FindCave(v);
        v->caveInit = 1;
    }
    if (v->caveCursor == 0 || need == 0 || v->caveCursor + need > v->caveEnd)
    {
        return 0;
    }
    va = v->caveCursor;
    if (!VaToOff(v, va, outOff))
    {
        return 0;
    }
    v->caveCursor += need;
    return va;
}

/* Write a string into the cave and return the VA it was stored at (0 if full). */
static unsigned long long CaveStoreString(ELF_VIEW* v, const char* s, size_t len)
{
    size_t off;
    unsigned long long va = CaveAlloc(v, len, &off);
    if (va)
    {
        memcpy(v->base + off, s, len);
    }
    return va;
}

/* ---- Hostname discovery ---- */

static void* FindBytes(const unsigned char* hay, size_t hayLen,
                       const void* needle, size_t needleLen)
{
    return memmem(hay, hayLen, needle, needleLen);
}

/* Locate every known hostname in the file. Each packed literal appears once;
   the longest match at a position wins so trailing-dot / -proxy variants beat
   their shorter prefixes. */
static size_t CollectOccurrences(const ELF_VIEW* v, const KNOWN_SNI* list,
                                 size_t listCount, OCCURRENCE* out, size_t maxOut)
{
    size_t count = 0;
    size_t hi;

    for (hi = 0; hi < listCount && count < maxOut; ++hi)
    {
        const KNOWN_SNI* k = &list[hi];
        unsigned char* p = (unsigned char*)FindBytes(v->base, v->size,
                                                     k->value, k->length);
        unsigned long long va;
        size_t j;
        int shadowed = 0;

        if (!p)
        {
            continue;
        }
        /* Skip if this match is a prefix inside an already-recorded, longer
           hostname at the same address. */
        for (j = 0; j < count; ++j)
        {
            if (out[j].fileOffset == (size_t)(p - v->base) &&
                out[j].originalLength >= k->length)
            {
                shadowed = 1;
                break;
            }
        }
        if (shadowed)
        {
            continue;
        }
        if (!OffToVa(v, (size_t)(p - v->base), &va))
        {
            continue;
        }
        out[count].fileOffset = (size_t)(p - v->base);
        out[count].va = va;
        out[count].originalLength = k->length;
        out[count].known = k;
        count++;
    }
    return count;
}

static size_t CountTargets(const OCCURRENCE* occs, size_t n)
{
    size_t i, c = 0;
    for (i = 0; i < n; ++i)
    {
        if (occs[i].known->patchTarget)
        {
            c++;
        }
    }
    return c;
}

/* ---- Length / pointer patching ---- */

/* Resolve `lea reg,[rip+disp32]` (REX.W 8D, modrm mod=00 rm=101) to its target
   VA. Returns 1 on success. */
static int ResolveLeaTargetVa(const ELF_VIEW* v, size_t off, unsigned long long* outVa)
{
    const unsigned char* p = v->base + off;
    Elf64_Sword disp;
    unsigned long long instrVa;

    if (off + RIP_RELATIVE_LEA_SIZE > v->size)
    {
        return 0;
    }
    if ((p[0] != 0x48 && p[0] != 0x49 && p[0] != 0x4C && p[0] != 0x4D) || p[1] != 0x8D)
    {
        return 0;
    }
    if ((p[2] & 0xC7) != 0x05)   /* mod=00, rm=101 (rip-relative) */
    {
        return 0;
    }
    memcpy(&disp, p + 3, sizeof(disp));
    if (!OffToVa(v, off, &instrVa))
    {
        return 0;
    }
    *outVa = instrVa + RIP_RELATIVE_LEA_SIZE + (long long)disp;
    return 1;
}

/* Rewrite the rip-relative displacement of the LEA at off so it targets newVa. */
static void RewriteLeaTargetVa(ELF_VIEW* v, size_t off, unsigned long long newVa)
{
    unsigned long long instrVa;
    Elf64_Sword disp;
    if (!OffToVa(v, off, &instrVa))
    {
        return;
    }
    disp = (Elf64_Sword)((long long)newVa - (long long)(instrVa + RIP_RELATIVE_LEA_SIZE));
    memcpy(v->base + off + 3, &disp, sizeof(disp));
}

/* Patch `mov r32, imm32` immediates equal to origLen -> newLen inside a range. */
static unsigned PatchImmediatesInRange(unsigned char* start, size_t rangeLen,
                                       unsigned origLen, unsigned newLen)
{
    unsigned patched = 0;
    size_t off;
    for (off = 0; off + 5 <= rangeLen; ++off)
    {
        unsigned value;
        if (start[off] >= 0xB8 && start[off] <= 0xBF)     /* mov r32, imm32 */
        {
            memcpy(&value, start + off + 1, 4);
            if (value == origLen)
            {
                memcpy(start + off + 1, &newLen, 4);
                patched++;
                off += 4;
            }
            continue;
        }
        if (off + 6 <= rangeLen && start[off] == 0x41 &&   /* 41 B8..BF: r8d..r15d */
            start[off + 1] >= 0xB8 && start[off + 1] <= 0xBF)
        {
            memcpy(&value, start + off + 2, 4);
            if (value == origLen)
            {
                memcpy(start + off + 2, &newLen, 4);
                patched++;
                off += 5;
            }
        }
    }
    return patched;
}

/* Scan code for LEAs that load origVa. Fix nearby length immediates
   (origLen -> newLen), and when retargetVa != 0 also repoint the LEA to it. */
static unsigned PatchCodeForHost(ELF_VIEW* v, unsigned long long origVa,
                                 size_t origLen, size_t newLen,
                                 unsigned long long retargetVa)
{
    unsigned patched = 0;
    size_t off;

    for (off = 0; off + RIP_RELATIVE_LEA_SIZE <= v->size; ++off)
    {
        unsigned long long targetVa;
        size_t winStart, winEnd;

        if (!OffsetIsExecutable(v, off))
        {
            continue;
        }
        if (!ResolveLeaTargetVa(v, off, &targetVa) || targetVa != origVa)
        {
            continue;
        }

        winStart = off > STATIC_CODE_PATCH_WINDOW_BEFORE
                   ? off - STATIC_CODE_PATCH_WINDOW_BEFORE : 0;
        winEnd = off + RIP_RELATIVE_LEA_SIZE + STATIC_CODE_PATCH_WINDOW_AFTER;
        if (winEnd > v->size)
        {
            winEnd = v->size;
        }
        patched += PatchImmediatesInRange(v->base + winStart, winEnd - winStart,
                                          (unsigned)origLen, (unsigned)newLen);
        if (retargetVa)
        {
            RewriteLeaTargetVa(v, off, retargetVa);
        }
    }
    return patched;
}

/* Walk .rela.dyn for R_X86_64_RELATIVE relocations whose addend == origVa (a
   pointer to the hostname). For each:
     - fix the inline fat-pointer length (qword right after the pointer) when it
       equals origLen;
     - when retargetVa != 0, repoint the pointer by rewriting the addend and the
       stored placeholder value.
   Returns the number of relocations touched. */
static unsigned PatchRelocsForHost(ELF_VIEW* v, unsigned long long origVa,
                                   size_t origLen, size_t newLen,
                                   unsigned long long retargetVa)
{
    unsigned touched = 0;
    size_t i;

    if (!v->rela)
    {
        return 0;
    }
    for (i = 0; i < v->relaCount; ++i)
    {
        Elf64_Rela* r = &v->rela[i];
        size_t ptrOff, lenOff;
        unsigned long long lenWord;

        if (ELF64_R_TYPE(r->r_info) != R_X86_64_RELATIVE ||
            (unsigned long long)r->r_addend != origVa)
        {
            continue;
        }
        if (!VaToOff(v, r->r_offset, &ptrOff) || ptrOff + 16 > v->size)
        {
            continue;
        }

        /* Fat-pointer inline length right after the pointer slot. */
        lenOff = ptrOff + 8;
        memcpy(&lenWord, v->base + lenOff, 8);
        if (lenWord == (unsigned long long)origLen)
        {
            unsigned long long nl = (unsigned long long)newLen;
            memcpy(v->base + lenOff, &nl, 8);
        }

        if (retargetVa)
        {
            unsigned long long rv = retargetVa;
            r->r_addend = (Elf64_Sxword)retargetVa;
            /* The on-disk pointer slot holds the pre-relocation value; for a
               statically-linked relative reloc it is the unrelocated VA. Keep
               it consistent with the new addend. */
            memcpy(v->base + ptrOff, &rv, 8);
        }
        touched++;
    }
    return touched;
}

/* The registration length array parallels a pointer-only array: three qwords
   holding the lengths of api.cloudflareclient.com. / api.devices... / ...fed,
   in that order. Find it by its exact [25, 27, 31] signature and patch the
   consumer entry (index 0). Returns 1 if the array was found and updated. */
static int PatchRegLengthArray(ELF_VIEW* v, size_t consumerOrigLen, size_t newLen)
{
    unsigned long long sig[3];
    unsigned char* p;

    sig[0] = 25; sig[1] = 27; sig[2] = 31;   /* known anchor lengths, with dots */
    p = (unsigned char*)FindBytes(v->base, v->size, sig, sizeof(sig));
    if (!p)
    {
        return 0;
    }
    /* Index 0 must be the consumer host's original length. */
    if (sig[0] != (unsigned long long)consumerOrigLen)
    {
        /* consumerOrigLen might be the undotted 24; the array stores dotted 25.
           Accept either, then write the new length. */
        if (consumerOrigLen != 24 && consumerOrigLen != 25)
        {
            return 0;
        }
    }
    {
        unsigned long long nl = (unsigned long long)newLen;
        memcpy(p, &nl, 8);
    }
    return 1;
}

/* Overwrite a packed string literal in place (newLen <= originalLength); the
   tail is left intact. */
static void OverwriteHostname(ELF_VIEW* v, const OCCURRENCE* occ,
                              const char* value, size_t len)
{
    memcpy(v->base + occ->fileOffset, value, len);
}

/* ---- Service / tunnel control ---- */

static int RunQuiet(const char* cmd)
{
    char full[512];
    int rc;
    snprintf(full, sizeof(full), "%s >/dev/null 2>&1", cmd);
    rc = system(full);
    return rc == 0;
}

static int RunCapture(const char* cmd, char* out, size_t outSize)
{
    FILE* p;
    size_t total = 0;
    out[0] = '\0';
    p = popen(cmd, "r");
    if (!p)
    {
        return 0;
    }
    while (total + 1 < outSize)
    {
        size_t got = fread(out + total, 1, outSize - 1 - total, p);
        if (got == 0)
        {
            break;
        }
        total += got;
    }
    out[total] = '\0';
    pclose(p);
    return 1;
}

int StopWarpService(int* outWasRunning)
{
    if (outWasRunning)
    {
        *outWasRunning = 0;
    }
    if (g_dryRun)
    {
        return 1;
    }
    /* No unit installed -> nothing to control. */
    if (!RunQuiet("systemctl list-unit-files warp-svc.service"))
    {
        return 1;
    }
    if (RunQuiet("systemctl is-active --quiet warp-svc.service"))
    {
        if (outWasRunning)
        {
            *outWasRunning = 1;
        }
        UiLog("%s", Tr(STR_LOG_STOP_SERVICE));
        if (!RunQuiet("systemctl stop warp-svc.service"))
        {
            UiLog("%s", Tr(STR_LOG_ERR_STOP_SERVICE));
            return 0;
        }
    }
    return 1;
}

int StartWarpService(void)
{
    if (g_dryRun)
    {
        return 1;
    }
    UiLog("%s", Tr(STR_LOG_START_SERVICE));
    if (!RunQuiet("systemctl start warp-svc.service"))
    {
        UiLog("%s", Tr(STR_LOG_ERR_START_SERVICE));
        return 0;
    }
    return 1;
}

int WarpDisconnectIfConnected(const char* target, int* outWasConnected)
{
    char out[4096];
    (void)target;
    if (outWasConnected)
    {
        *outWasConnected = 0;
    }
    if (g_dryRun)
    {
        return 1;
    }
    if (!RunCapture("warp-cli --accept-tos status 2>/dev/null", out, sizeof(out)))
    {
        return 1;   /* no CLI / no output: best effort */
    }
    if (strstr(out, "Connected"))
    {
        if (outWasConnected)
        {
            *outWasConnected = 1;
        }
        UiLog("%s", Tr(STR_LOG_DISCONNECTING));
        RunQuiet("warp-cli --accept-tos disconnect");
    }
    return 1;
}

int WarpConnect(const char* target)
{
    (void)target;
    if (g_dryRun)
    {
        return 1;
    }
    if (!RunQuiet("warp-cli --accept-tos connect"))
    {
        UiLog("%s", Tr(STR_LOG_RECONNECT_NOTE));
        return 0;
    }
    return 1;
}

const char* FindDefaultTarget(void)
{
    static const char* candidates[] = {
        "/usr/bin/warp-svc",
        "/bin/warp-svc",
        "/usr/lib/warp/warp-svc",
        "/opt/cloudflare-warp/bin/warp-svc",
    };
    static char found[512];
    size_t i;
    char out[512];

    for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i)
    {
        if (FileExists(candidates[i]))
        {
            snprintf(found, sizeof(found), "%s", candidates[i]);
            return found;
        }
    }
    /* Fall back to $PATH. */
    if (RunCapture("command -v warp-svc 2>/dev/null", out, sizeof(out)) && out[0] == '/')
    {
        char* nl = strchr(out, '\n');
        if (nl)
        {
            *nl = '\0';
        }
        if (FileExists(out))
        {
            snprintf(found, sizeof(found), "%s", out);
            return found;
        }
    }
    return NULL;
}

/* ---- Restore ---- */

int RunRestore(const char* target)
{
    char backup[512];
    unsigned char* data;
    size_t size = 0;

    BuildBackupPath(target, backup, sizeof(backup));
    if (!FileExists(backup))
    {
        UiLog("%s", Tr(STR_LOG_ERR_NO_BACKUP));
        return 0;
    }
    data = ReadWholeFile(backup, &size);
    if (!data)
    {
        return 0;
    }
    if (FileExists(target))
    {
        size_t tsz = 0;
        unsigned char* cur = ReadWholeFile(target, &tsz);
        if (cur)
        {
            free(cur);
            if (tsz != size)
            {
                UiLog("%s", Tr(STR_LOG_ERR_BACKUP_DIFF_VER));
                UiLog("%s", Tr(STR_LOG_ERR_CURRENT_UNPATCHED));
                free(data);
                return 0;
            }
        }
    }
    if (g_dryRun)
    {
        UiLog("%s", Tr(STR_LOG_DRY_RUN));
        free(data);
        return 1;
    }
    if (!WriteWholeFile(target, data, size))
    {
        free(data);
        return 0;
    }
    free(data);
    unlink(backup);
    UiLog("%s", Tr(STR_LOG_RESTORED_OK));
    return 1;
}

/* ---- Patch ---- */

/* Pick the pristine source: inspect the target; if every family's hostnames
   are present it is pristine (refresh the backup from it). Otherwise fall back
   to the backup, provided it is the same size. Returns a freshly allocated
   buffer in *outBuf (caller frees) and its size in *outSize, or 0 on failure. */
static int LoadPristineSource(const char* target, const char* backup,
                              unsigned char** outBuf, size_t* outSize)
{
    unsigned char* tbuf;
    size_t tsize = 0;
    ELF_VIEW tv;
    OCCURRENCE m[MAX_OCCURRENCES], r[MAX_OCCURRENCES];
    size_t mc, rc;

    tbuf = ReadWholeFile(target, &tsize);
    if (!tbuf)
    {
        return 0;
    }
    if (!ParseElf(tbuf, tsize, &tv))
    {
        free(tbuf);
        return 0;
    }
    mc = CollectOccurrences(&tv, g_MasqueHostnames, MASQUE_HOSTNAME_COUNT, m, MAX_OCCURRENCES);
    rc = CollectOccurrences(&tv, g_RegHostnames, REG_HOSTNAME_COUNT, r, MAX_OCCURRENCES);

    if (CountTargets(m, mc) > 0 && CountTargets(r, rc) > 0)
    {
        /* Pristine -> refresh the backup from it (unless dry-run). */
        if (!g_dryRun && !WriteWholeFile(backup, tbuf, tsize))
        {
            free(tbuf);
            return 0;
        }
        if (!g_dryRun)
        {
            UiLog("%s", Tr(STR_LOG_BACKUP));
        }
        *outBuf = tbuf;
        *outSize = tsize;
        return 1;
    }

    /* Already patched -> use the backup as the pristine source. */
    free(tbuf);
    if (!FileExists(backup))
    {
        UiLog("%s", Tr(STR_LOG_ERR_NO_ORIG_HOSTS_AND_NO_BACKUP));
        UiLog("%s", Tr(STR_LOG_ERR_ALREADY_PATCHED_OR_UNSUPPORTED));
        return 0;
    }
    {
        unsigned char* bbuf;
        size_t bsize = 0;
        ELF_VIEW bv;
        OCCURRENCE bm[MAX_OCCURRENCES], br[MAX_OCCURRENCES];

        bbuf = ReadWholeFile(backup, &bsize);
        if (!bbuf)
        {
            return 0;
        }
        if (bsize != tsize)
        {
            UiLog("%s", Tr(STR_LOG_ERR_BACKUP_DIFF_VER));
            UiLog(Tr(STR_LOG_ERR_DELETE_BACKUP_FRESH), backup);
            free(bbuf);
            return 0;
        }
        if (!ParseElf(bbuf, bsize, &bv))
        {
            free(bbuf);
            return 0;
        }
        if (CountTargets(bm, CollectOccurrences(&bv, g_MasqueHostnames,
                MASQUE_HOSTNAME_COUNT, bm, MAX_OCCURRENCES)) == 0 ||
            CountTargets(br, CollectOccurrences(&bv, g_RegHostnames,
                REG_HOSTNAME_COUNT, br, MAX_OCCURRENCES)) == 0)
        {
            UiLog("%s", Tr(STR_LOG_ERR_BACKUP_NO_ORIG_HOSTS));
            UiLog("%s", Tr(STR_LOG_ERR_ALREADY_PATCHED_OR_UNSUPPORTED));
            free(bbuf);
            return 0;
        }
        *outBuf = bbuf;
        *outSize = bsize;
        return 1;
    }
}

/* Find an anchor occurrence (patchTarget == 0) whose hostname equals name,
   accepting both the dotted and undotted forms. Returns NULL if absent. */
static const OCCURRENCE* FindAnchorByName(const OCCURRENCE* occs, size_t n,
                                          const char* name)
{
    size_t i;
    size_t nameLen = strlen(name);
    for (i = 0; i < n; ++i)
    {
        if (occs[i].known->patchTarget)
        {
            continue;
        }
        if (occs[i].originalLength == nameLen &&
            memcmp(occs[i].known->value, name, nameLen) == 0)
        {
            return &occs[i];
        }
        /* Match a dotted request against the dotted anchor and vice versa. */
        if (occs[i].originalLength == nameLen + 1 &&
            occs[i].known->value[nameLen] == '.' &&
            memcmp(occs[i].known->value, name, nameLen) == 0)
        {
            return &occs[i];
        }
    }
    return NULL;
}

int RunPatch(const char* target, const char* newSni, const char* newRegSni)
{
    char backup[512];
    unsigned char* source = NULL;
    size_t sourceSize = 0;
    ELF_VIEW view;
    OCCURRENCE masque[MAX_OCCURRENCES], reg[MAX_OCCURRENCES];
    size_t masqueCount, regCount;
    size_t newLen, regLenPlain;
    unsigned long long caveSniVa = 0;
    size_t i;

    newLen = strlen(newSni);
    regLenPlain = strlen(newRegSni);

    if (newLen == 0)
    {
        UiLog(Tr(STR_LOG_ERR_EMPTY_SNI), DEFAULT_SNI);
        return 0;
    }
    if (regLenPlain == 0)
    {
        UiLog(Tr(STR_LOG_ERR_EMPTY_REG_SNI), DEFAULT_REG_SNI);
        return 0;
    }

    if (!FileExists(target))
    {
        UiLog(Tr(STR_LOG_ERR_TARGET_NOT_FOUND), target);
        UiLog("%s", Tr(STR_LOG_ERR_CHECK_INSTALL));
        return 0;
    }

    BuildBackupPath(target, backup, sizeof(backup));
    if (!LoadPristineSource(target, backup, &source, &sourceSize))
    {
        return 0;
    }
    if (!ParseElf(source, sourceSize, &view))
    {
        free(source);
        return 0;
    }

    masqueCount = CollectOccurrences(&view, g_MasqueHostnames,
                                     MASQUE_HOSTNAME_COUNT, masque, MAX_OCCURRENCES);
    regCount = CollectOccurrences(&view, g_RegHostnames,
                                  REG_HOSTNAME_COUNT, reg, MAX_OCCURRENCES);

    UiLog("%s", Tr(STR_LOG_PATCHING));

    /* ---- MASQUE: overwrite in place when it fits, else relocate to a cave ---- */
    for (i = 0; i < masqueCount; ++i)
    {
        size_t origLen;
        if (!masque[i].known->patchTarget)
        {
            continue;
        }
        origLen = masque[i].originalLength;

        if (newLen <= origLen)
        {
            UiLog(Tr(STR_LOG_PATCH_MASQUE), masque[i].known->value, newSni,
                  origLen, newLen);
            OverwriteHostname(&view, &masque[i], newSni, newLen);
            PatchCodeForHost(&view, masque[i].va, origLen, newLen, 0);
            PatchRelocsForHost(&view, masque[i].va, origLen, newLen, 0);
        }
        else
        {
            if (!caveSniVa)
            {
                caveSniVa = CaveStoreString(&view, newSni, newLen);
            }
            if (!caveSniVa)
            {
                UiLog(Tr(STR_LOG_ERR_NO_CAVE), newSni, newLen);
                free(source);
                return 0;
            }
            UiLog(Tr(STR_LOG_PATCH_MASQUE_CAVE), masque[i].known->value, newSni,
                  origLen, newLen);
            PatchCodeForHost(&view, masque[i].va, origLen, newLen, caveSniVa);
            PatchRelocsForHost(&view, masque[i].va, origLen, newLen, caveSniVa);
        }
    }

    /* ---- Registration: in-place when it fits, else repoint ---- */
    {
        char dotted[256];
        size_t regLenDotted;
        const OCCURRENCE* anchor;

        if (newRegSni[regLenPlain - 1] == '.')
        {
            snprintf(dotted, sizeof(dotted), "%s", newRegSni);
            regLenDotted = regLenPlain;
        }
        else
        {
            snprintf(dotted, sizeof(dotted), "%s.", newRegSni);
            regLenDotted = regLenPlain + 1;
        }

        /* Is the request one of the hostnames already in the binary? */
        anchor = FindAnchorByName(reg, regCount, newRegSni);

        for (i = 0; i < regCount; ++i)
        {
            size_t origLen;
            if (!reg[i].known->patchTarget)
            {
                continue;
            }
            origLen = reg[i].originalLength;

            if (regLenDotted <= origLen || regLenPlain <= origLen)
            {
                /* In-place: prefer the dotted FQDN form when it fits. */
                const char* val = (regLenDotted <= origLen) ? dotted : newRegSni;
                size_t vlen = (regLenDotted <= origLen) ? regLenDotted : regLenPlain;

                UiLog(Tr(STR_LOG_PATCH_REG_INPLACE), reg[i].known->value, val,
                      origLen, vlen);
                OverwriteHostname(&view, &reg[i], val, vlen);
                PatchCodeForHost(&view, reg[i].va, origLen, vlen, 0);
                PatchRelocsForHost(&view, reg[i].va, origLen, vlen, 0);
                PatchRegLengthArray(&view, origLen, vlen);
            }
            else if (anchor)
            {
                /* Repoint: retarget every reference to the existing anchor. */
                UiLog(Tr(STR_LOG_PATCH_REG_REPOINT), reg[i].known->value,
                      anchor->known->value, origLen, anchor->originalLength);
                PatchCodeForHost(&view, reg[i].va, origLen,
                                 anchor->originalLength, anchor->va);
                PatchRelocsForHost(&view, reg[i].va, origLen,
                                   anchor->originalLength, anchor->va);
                PatchRegLengthArray(&view, origLen, anchor->originalLength);
            }
            else
            {
                /* Too long and not already in the binary: store the FQDN in a
                   code cave and repoint every reference to it. */
                unsigned long long caveVa =
                    CaveStoreString(&view, dotted, regLenDotted);
                if (!caveVa)
                {
                    UiLog(Tr(STR_LOG_ERR_NO_CAVE), newRegSni, regLenDotted);
                    free(source);
                    return 0;
                }
                UiLog(Tr(STR_LOG_PATCH_REG_CAVE), reg[i].known->value, dotted,
                      origLen, regLenDotted);
                PatchCodeForHost(&view, reg[i].va, origLen, regLenDotted, caveVa);
                PatchRelocsForHost(&view, reg[i].va, origLen, regLenDotted, caveVa);
                PatchRegLengthArray(&view, origLen, regLenDotted);
            }
        }
    }

    if (g_dryRun)
    {
        UiLog("%s", Tr(STR_LOG_DRY_RUN));
        free(source);
        return 1;
    }

    if (!WriteWholeFile(target, view.base, view.size))
    {
        free(source);
        return 0;
    }
    free(source);
    return 1;
}
