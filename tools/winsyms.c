/* **********************************************************
 * Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
 * Copyright (c) 2009 VMware, Inc.  All rights reserved.
 * **********************************************************/

/* Dr. Memory: the memory debugger
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License, and no later version.

 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Library General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* addr2line for Windows
 *
 * Uses dbghelp.dll, which comes with Windows 2000+ as version 5.0.
 * However, 5.0 does not have SymFromAddr.  Plus, XP's 5.2 has
 * SymFromName but it doesn't work (returns error every time).
 * So, we rely on redistributing 6.x+.
 *
 * Two modes: one that behaves like binutils addr2line, and another that
 * can lookup symbols in multiple modules.  The latter mode takes the
 * full path to the module in every query, to allow for flexibility in
 * how the modules are managed: can unload if running out of space, etc.
 *
 * TODO PR 463897: add a 3rd mode, or a command to the 2nd mode, to
 * take in a pid and load all modules in that process.  Probably
 * simplest for that to be a command-line arg as we need to pass a
 * process handle to SymInitialize().
 *
 * TODO PR 463897: support symbol stores of downloaded Windows system pdbs
 *
 * TODO PR 463897: be more robust about handling failures packing in
 * loaded modules.  E.g., today we will probably fail if passed two
 * .exe's (non-relocatable).  See further comments in load_module()
 * below.
 */

#include <windows.h>
#include <dbghelp.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define ALIGN_FORWARD(x, alignment) \
    ((((UINT_PTR)x) + ((alignment)-1)) & (~((alignment)-1)))

#define EXPANDSTR(x) #x
#define STRINGIFY(x) EXPANDSTR(x)
#define MAX_PATH_STR STRINGIFY(MAX_PATH)

typedef unsigned int uint;

/* forward decls */
static DWORD64 load_module(HANDLE proc, const char *path);
static void unload_module(HANDLE proc, DWORD64 base);
static void query_available(HANDLE proc, DWORD64 base);
static void lookup_address(HANDLE proc, DWORD64 addr);
static void lookup_symbol(HANDLE proc, const char *sym);
static void enumerate_symbols(HANDLE proc, DWORD64 base, const char *match,
                              BOOL search, BOOL searchall);

/* specialized hashtable: strduped string keys, and no synch (single-threaded)
 * (note that all dbghelp routines are un-synchronized as well)
 */
typedef struct _hash_entry_t {
    const char *key;
    DWORD64 payload;
    struct _hash_entry_t *next;
} hash_entry_t;

typedef struct _hashtable_t {
    hash_entry_t **table;
    uint table_bits;
} hashtable_t;

#define HASHTABLE_SIZE(num_bits) (1U << (num_bits))
void hashtable_init(hashtable_t *table, uint num_bits);
DWORD64 hashtable_lookup(hashtable_t *table, const char *key);
void hashtable_add(hashtable_t *table, const char *key, DWORD64 payload);
BOOL hashtable_remove(hashtable_t *table, const char *key);
void hashtable_delete(hashtable_t *table);

/* options */
#define USAGE "Usage:\n%s -e <PE file> [-f] [-v] <absolute addresses on stdin>\n\
OR\n%s [-f] [-v] <pairs of [module_path;address relative to module base] on stdin>\n\
OR\n%s -e <PE file> [-v] [--enum] [--search] [--searchall] -s [<symbol1> <symbol2> ...]\n"
#define PRINT_USAGE(mypath) printf(USAGE, mypath, mypath, mypath)
static BOOL single_target;
static BOOL show_func;
static BOOL verbose;

/* globals */
static DWORD64 next_load = 0x11000000;
#define MODTABLE_BITS 8 /* should have plenty of capacity */

/***************************************************************************
 * MAIN
 */

int
main(int argc, char *argv[])
{
    HANDLE proc = GetCurrentProcess();
    DWORD64 base;
    char *dll;
    char *sym;
    hashtable_t modtable;
    int i;
    /* module + address per line */
    char line[MAX_PATH*2];

    /* options that can be local vars */
    BOOL absolute = FALSE;
    BOOL sym2addr = FALSE;
    BOOL enumerate = FALSE;
    BOOL search = FALSE;
    BOOL searchall = FALSE;

    for (i = 1; i < argc; i++) {
        if (stricmp(argv[i], "-e") == 0) {
            if (i+1 >= argc) {
                PRINT_USAGE(argv[0]);
                return 1;
            }
            i++;
            dll = argv[i];
            single_target = TRUE;
            absolute = TRUE;
        } else if (stricmp(argv[i], "-f") == 0) {
            show_func = TRUE;
        } else if (stricmp(argv[i], "-v") == 0) {
            verbose = TRUE;
        } else if (stricmp(argv[i], "-s") == 0) {
            if (i+1 >= argc) {
                PRINT_USAGE(argv[0]);
                return 1;
            }
            i++;
            sym2addr = TRUE;
            break;
        } else if (stricmp(argv[i], "--enum") == 0) {
            enumerate = TRUE;
        } else if (stricmp(argv[i], "--search") == 0) {
            search = TRUE;
        } else if (stricmp(argv[i], "--searchall") == 0) {
            search = TRUE;
            searchall = TRUE;
        } else {
            /* FIXME: also support addresses as args */
            PRINT_USAGE(argv[0]);
            return 1;
        }
    }
    if (sym2addr && !single_target) {
        /* FIXME: right now sym2addr is a quickly-thrown-in feature:
         * should make it parallel to the others
         */
        PRINT_USAGE(argv[0]);
        return 1;
    }

    SymSetOptions(SYMOPT_LOAD_LINES | SymGetOptions());
    if (!SymInitialize(proc, NULL, FALSE)) {
        printf("SymInitialize error %d\n", GetLastError());
        return 1;
    }

    if (single_target) {
        /* single module: load it now */
        base = load_module(proc, dll);
        if (base == 0) {
            printf("Error loading %s\n", dll);
            return 1;
        }
    } else
        hashtable_init(&modtable, MODTABLE_BITS);

    if (sym2addr) {
        /* kind of a hack: assumes i hasn't changed and that -s is last option */
        for (; i < argc; i++) {
            if (enumerate || search)
                enumerate_symbols(proc, base, argv[i], search, searchall);
            else
                lookup_symbol(proc, argv[i]);
        }
    } else {
        while (!feof(stdin)) {
            DWORD64 addr;
            char modpath[MAX_PATH];
            if (fgets(line, sizeof(line), stdin) == NULL ||
                /* when postprocess.pl closes the pipe, fgets is not
                 * returning, so using an alternative eof code
                 */
                strcmp(line, ";exit\n") == 0)
                break;
            if (single_target) {
                assert(absolute); /* we don't support relative for single_target */
                if (sscanf(line, "%I64x", &addr) == 1) {
                    lookup_address(proc, addr);
                    fflush(stdout); /* ensure flush in case piped */
                } else if (verbose)
                    printf("Error: unknown input %s\n", line);
            } else {
                /* Ensure we support spaces in paths by using ; to split.
                 * Since ; separates PATH, no Windows dll will have ; in its name.
                 */
                assert(!absolute); /* we don't support absolute for multi target */
                if (sscanf(line, "%"MAX_PATH_STR"[^;];%I64x", &modpath, &addr) == 2) {
                    base = hashtable_lookup(&modtable, modpath);
                    if (base == 0) {
                        base = load_module(proc, modpath);
                        if (base == 0) {
                            if (verbose)
                                printf("Error loading %s\n", modpath);
                            else {
                                if (show_func)
                                    printf("?\n");
                                printf("??:0\n");
                                fflush(stdout);
                            }
                        } else
                            hashtable_add(&modtable, modpath, base);
                    }
                    if (base != 0) {
                        lookup_address(proc, base + addr);
                        fflush(stdout); /* ensure flush in case piped */
                    }
                } else if (verbose)
                    printf("Error: unknown input %s\n", line);
            }
        }
    }

    if (single_target)
        unload_module(proc, base);
    else {
        for (i = 0; i < HASHTABLE_SIZE(modtable.table_bits); i++) {
            if (modtable.table[i] != NULL)
                unload_module(proc, modtable.table[i]->payload);
        }
        hashtable_delete(&modtable);
    }

    if (!SymCleanup(proc))
        printf("SymCleanup error %d\n", GetLastError());

    return 0;
}

static DWORD64
load_module(HANDLE proc, const char *path)
{
    DWORD64 base;
    DWORD64 size;
    char ext[_MAX_EXT];

    ext[0] = '\0';
    _splitpath(path, NULL/*drive*/, NULL/*dir*/, NULL/*fname*/, ext);
    /* For single-module, we only need to specify a base for a .pdb file.
     * For multi-module we specify bases and try to pack the address space,
     * except for the .exe which is not relocatable.
     */
    if ((!single_target && stricmp(ext, ".exe") != 0) || stricmp(ext, ".pdb") == 0) {
        /* Any base will do since only loading one, but we need the size */
        HANDLE f = CreateFile(path, GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, 0, NULL);
        if (f == INVALID_HANDLE_VALUE)
            return 0;
        base = next_load;
        size = GetFileSize(f, NULL);
        CloseHandle(f);
        if (size == INVALID_FILE_SIZE)
            return 0;
        next_load += ALIGN_FORWARD(size, 64*1024);
    } else {
        /* Can pass 0 to SymLoadModule64 */
        base = 0;
        size = 0;
    }

    base = SymLoadModule64(proc, NULL, (char *)path, NULL, base, size);
    if (base == 0) {
        /* FIXME PR 463897: for !single_target, we should handle load
         * failure by trying a different address, informed by some
         * memory queries.  For now we assume only one .exe and that
         * it's below our start load address and that we won't fail.
         */
        if (verbose)
            printf("SymLoadModule64 error %d\n", GetLastError());
        return 0;
    }
    if (verbose) {
        printf("loaded %s at 0x%I64x\n", path, base);
        query_available(proc, base);
    }
    return base;
}

static void
unload_module(HANDLE proc, DWORD64 base)
{
    if (!SymUnloadModule64(proc, base)) {
        if (verbose)
            printf("SymUnloadModule64 error %d\n", GetLastError());
    }
}

static void
query_available(HANDLE proc, DWORD64 base)
{
    IMAGEHLP_MODULEW64 info;
    memset(&info, 0, sizeof(info));
    info.SizeOfStruct = sizeof(info);
    if (SymGetModuleInfoW64(proc, base, &info)) {
        switch(info.SymType) {
        case SymNone:
            printf("No symbols found\n");
            break;
        case SymExport:
            printf("Only export symbols found\n");
            break;
        case SymPdb:
            printf("Loaded pdb symbols from %S\n", info.LoadedPdbName);
            break;
        case SymDeferred:
            printf("Symbol load deferred\n");
            break;
        case SymCoff:
        case SymCv:
        case SymSym:
        case SymVirtual:
        case SymDia:
            printf("Symbols in image file loaded\n");
            break;
        default:
            printf("Symbols in unknown format.\n");
            break;
        }

        /* could print out info.ImageName and info.LoadedImageName
         * and whether info.LineNumbers
         * and warn if info.PdbUnmatched or info.DbgUnmatched
         */
    }
}

static void
lookup_address(HANDLE proc, DWORD64 addr)
{
    ULONG64 buf[(sizeof(SYMBOL_INFO) +
                 MAX_SYM_NAME*sizeof(TCHAR) +
                 sizeof(ULONG64) - 1) /
                sizeof(ULONG64)];
    PSYMBOL_INFO info = (PSYMBOL_INFO) buf;
    DWORD64 disp;
    IMAGEHLP_LINE64 line;
    DWORD line_disp;

    info->SizeOfStruct = sizeof(SYMBOL_INFO);
    info->MaxNameLen = MAX_SYM_NAME;
    if (SymFromAddr(proc, addr, &disp, info)) {
        if (show_func)
            printf("%s+0x%x\n", info->Name, disp);
        if (verbose) {
            printf("Symbol 0x%I64x => %s+0x%x (0x%I64x-0x%I64x)\n", addr, info->Name,
                   disp, info->Address, info->Address + info->Size);
        }
    } else {
        if (verbose)
            printf("SymFromAddr error %d\n", GetLastError());
        else if (show_func)
            printf("?\n");
    }

    line.SizeOfStruct = sizeof(line);
    if (SymGetLineFromAddr64(proc, addr, &line_disp, &line)) {
        /* windbg format is file(line#) but we use addr2line format file:line# */
        printf("%s:%u+0x%x\n", line.FileName, line.LineNumber, line_disp);
    } else {
        if (verbose)
            printf("SymGetLineFromAddr64 error %d\n", GetLastError());
        else
            printf("??:0\n");
    }
}

static void
lookup_symbol(HANDLE proc, const char *sym)
{
    ULONG64 buf[(sizeof(SYMBOL_INFO) +
                 MAX_SYM_NAME*sizeof(TCHAR) +
                 sizeof(ULONG64) - 1) /
                sizeof(ULONG64)];
    PSYMBOL_INFO info = (PSYMBOL_INFO) buf;

    info->SizeOfStruct = sizeof(SYMBOL_INFO);
    info->MaxNameLen = MAX_SYM_NAME;
    if (SymFromName(proc, (char *)sym, info)) {
        printf("0x%I64x\n", info->Address);
    } else {
        if (verbose)
            printf("SymFromName error %d %s\n", GetLastError(), sym);
        else
            printf("??\n");
    }
}

static BOOL CALLBACK
enum_cb(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID Context)
{
    const char *match = (const char *) Context;
    if (match == NULL || strcmp(pSymInfo->Name, match) == 0)
        printf("%s 0x%I64x\n", pSymInfo->Name, pSymInfo->Address);
    return TRUE; /* keep iterating */
}

static void
enumerate_symbols(HANDLE proc, DWORD64 base, const char *match, BOOL search,
                  BOOL searchall)
{
    if (search) {
        /* SymSearch is only available in dbghelp 6.3+
         * SYMSEARCH_ALLITEMS is in 6.6+ but we use it to identify
         * whether on VS2005 where headers are for 6.1.
         * Rather than dynamically acquiring SymSearch we just bail
         * if built w/ VS2005.
         */
#ifdef SYMSEARCH_ALLITEMS
        if (!SymSearch(proc, base, 0, 0, match, 0, enum_cb, NULL,
                       searchall ? SYMSEARCH_ALLITEMS : 0)) {
            printf("SymSearch error %d\n", GetLastError());
        }
#else
        printf("compile with VS2008 to get SymSearch\n");
#endif
    } else {
        if (!SymEnumSymbols(proc, base, NULL, enum_cb, (PVOID) match)) {
            printf("SymEnumSymbols error %d\n", GetLastError());
        }
    }
}

/***************************************************************************
 * HASHTABLE
 *
 * Right now only supports fixed-size (no realloc), and only
 * case-insensitive string keys as that's all we need.
 * FIXME: share code with drmemory/utils.c: need to refactor to
 * parametrize dr_mutex_* and global_alloc.
 */

#define HASH_MASK(num_bits) ((~0U)>>(32-(num_bits)))
#define HASH_FUNC_BITS(val, num_bits) ((val) & (HASH_MASK(num_bits)))
#define HASH_FUNC(val, mask) ((val) & (mask))

static uint
hash_key(const char *key, uint num_bits)
{
    uint hash = 0;
    const char *s = key;
    char c;
    for (c = *s; c != '\0'; c = *(s++)) {
        c = tolower(c);
        hash ^= (c << (((s - key) %4) * 8));
    }
    return HASH_FUNC_BITS(hash, num_bits);
}

static BOOL
keys_equal(const char *key1, const char *key2)
{
    return (stricmp(key1, key2) == 0);
}

static void
hashtable_init(hashtable_t *table, uint num_bits)
{
    table->table = (hash_entry_t **)
        malloc(HASHTABLE_SIZE(num_bits) * sizeof(hash_entry_t*));
    memset(table->table, 0, HASHTABLE_SIZE(num_bits) * sizeof(hash_entry_t*));
    table->table_bits = num_bits;
}

static DWORD64
hashtable_lookup(hashtable_t *table, const char *key)
{
    DWORD64 res = 0;
    hash_entry_t *e;
    uint hindex = hash_key(key, table->table_bits);
    for (e = table->table[hindex]; e != NULL; e = e->next) {
        if (keys_equal(e->key, key)) {
            res = e->payload;
            break;
        }
    }
    return res;
}

static void
hashtable_add(hashtable_t *table, const char *key, DWORD64 payload)
{
    uint hindex = hash_key(key, table->table_bits);
    hash_entry_t *e;
    assert(hashtable_lookup(table, key) == 0);
    assert(payload != 0); /* else can't tell from lookup miss */
    e = (hash_entry_t *) malloc(sizeof(*e));
    e->key = strdup(key);
    e->payload = payload;
    e->next = table->table[hindex];
    table->table[hindex] = e;
}

static BOOL
hashtable_remove(hashtable_t *table, const char *key)
{
    BOOL res = FALSE;
    hash_entry_t *e, *prev_e;
    uint hindex = hash_key(key, table->table_bits);
    for (e = table->table[hindex], prev_e = NULL; e != NULL; prev_e = e, e = e->next) {
        if (keys_equal(e->key, key)) {
            if (prev_e == NULL)
                table->table[hindex] = e->next;
            else
                prev_e->next = e->next;
            free((void *)e->key);
            free(e);
            res = TRUE;
            break;
        }
    }
    return res;
}

static void
hashtable_delete(hashtable_t *table)
{
    uint i;
    for (i = 0; i < HASHTABLE_SIZE(table->table_bits); i++) {
        hash_entry_t *e = table->table[i];
        while (e != NULL) {
            hash_entry_t *nexte = e->next;
            free((void *)e->key);
            free(e);
            e = nexte;
        }
    }
    free(table->table);
    table->table = NULL;
}
