/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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

/* Front-end to drsyms for Windows */

#include "dr_api.h"
#include "drsyms.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define MAX_FUNC_LEN 256

#define EXPANDSTR(x) #x
#define STRINGIFY(x) EXPANDSTR(x)
#define MAX_PATH_STR STRINGIFY(MAX_PATH)

#define TEST(mask, var) (((mask) & (var)) != 0)
#define TESTANY TEST
#define TESTALL(mask, var) (((mask) & (var)) == (mask))

/* forward decls */
static void lookup_address(const char *dllpath, size_t modoffs);
static void lookup_symbol(const char *dllpath, const char *sym);
static void enumerate_symbols(const char *dllpath, const char *match,
                              BOOL search, BOOL searchall);

/* options */
#define USAGE "Usage:\n\
Look up addresses for one module:\n\
  %s -e <module> [-f] [-v] -a [<address relative to module base> ...]\n\
Look up addresses for multiple modules:\n\
  %s [-f] [-v] -q <pairs of [module_path;address relative to module base] on stdin>\n\
Look up exact symbols for one module:\n\
  %s -e <module> [-v] [--enum] -s [<symbol1> <symbol2> ...]\n\
Look up symbols matching wildcard patterns (glob-style: *,?) for one module:\n\
  %s -e <module> [-v] --search -s [<symbol1> <symbol2> ...]\n\
Look up private symbols matching wildcard patterns (glob-style: *,?) for one module:\n\
  %s -e <module> [-v] --searchall -s [<symbol1> <symbol2> ...]\n\
List all symbols in a module:\n\
  %s -e <module> [-v] --list\n\
Optional parameters:\n\
  -f = show function name\n\
  -v = verbose\n\
  --enum = look up via external enum rather than drsyms-internal enum\n"
#define PRINT_USAGE(mypath) printf(USAGE, mypath, mypath, mypath, mypath, mypath, mypath)

static BOOL show_func;
static BOOL verbose;

int
main(int argc, char *argv[])
{
    char *dll = NULL;
    char *sym;
    int i;
    /* module + address per line */
    char line[MAX_PATH*2];
    size_t modoffs;

    /* options that can be local vars */
    BOOL addr2sym = FALSE;
    BOOL addr2sym_multi = FALSE;
    BOOL sym2addr = FALSE;
    BOOL enumerate = FALSE;
    BOOL enumerate_all = FALSE;
    BOOL search = FALSE;
    BOOL searchall = FALSE;

    for (i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "-e") == 0) {
            if (i+1 >= argc) {
                PRINT_USAGE(argv[0]);
                return 1;
            }
            i++;
            dll = argv[i];
            if (_access(dll, 4/*read*/) == -1) {
                printf("ERROR: invalid path %s\n", dll);
                return 1;
            }
        } else if (_stricmp(argv[i], "-f") == 0) {
            show_func = TRUE;
        } else if (_stricmp(argv[i], "-v") == 0) {
            verbose = TRUE;
        } else if (_stricmp(argv[i], "-a") == 0 ||
                   _stricmp(argv[i], "-s") == 0) {
            if (i+1 >= argc) {
                PRINT_USAGE(argv[0]);
                return 1;
            }
            if (_stricmp(argv[i], "-a") == 0)
                addr2sym = TRUE;
            else
                sym2addr = TRUE;
            i++;
            /* rest of args read below */
            break;
        } else if (_stricmp(argv[i], "-q") == 0) {
            addr2sym_multi = TRUE;
        } else if (_stricmp(argv[i], "--enum") == 0) {
            enumerate = TRUE;
        } else if (_stricmp(argv[i], "--list") == 0) {
            enumerate_all = TRUE;
        } else if (_stricmp(argv[i], "--search") == 0) {
            search = TRUE;
        } else if (_stricmp(argv[i], "--searchall") == 0) {
            search = TRUE;
            searchall = TRUE;
        } else {
            PRINT_USAGE(argv[0]);
            return 1;
        }
    }
    if (((sym2addr || addr2sym) && dll == NULL) ||
        (addr2sym_multi && dll != NULL) ||
        (!sym2addr && !addr2sym && !addr2sym_multi && !enumerate_all)) {
        PRINT_USAGE(argv[0]);
        return 1;
    }

    dr_standalone_init();

    if (drsym_init(NULL) != DRSYM_SUCCESS) {
        printf("ERROR: unable to initialize symbol library\n");
        return 1;
    }

    if (!addr2sym_multi) {
        if (enumerate_all)
            enumerate_symbols(dll, NULL, search, searchall);
        else {
            /* kind of a hack: assumes i hasn't changed and that -s/-a is last option */
            for (; i < argc; i++) {
                if (addr2sym) {
                    if (sscanf(argv[i], "%I32x", &modoffs) == 1)
                        lookup_address(dll, modoffs);
                    else
                        printf("ERROR: unknown input %s\n", argv[i]);
                } else if (enumerate || search)
                    enumerate_symbols(dll, argv[i], search, searchall);
                else
                    lookup_symbol(dll, argv[i]);
            }
        }
    } else {
        while (!feof(stdin)) {
            char modpath[MAX_PATH];
            if (fgets(line, sizeof(line), stdin) == NULL ||
                /* when postprocess.pl closes the pipe, fgets is not
                 * returning, so using an alternative eof code
                 */
                strcmp(line, ";exit\n") == 0)
                break;
            /* Ensure we support spaces in paths by using ; to split.
             * Since ; separates PATH, no Windows dll will have ; in its name.
             */
            if (sscanf(line, "%"MAX_PATH_STR"[^;];%I32x", &modpath, &modoffs) == 2) {
                lookup_address(modpath, modoffs);
                fflush(stdout); /* ensure flush in case piped */
            } else if (verbose)
                printf("Error: unknown input %s\n", line);
        }
    }

    if (drsym_exit() != DRSYM_SUCCESS)
        printf("WARNING: error cleaning up symbol library\n");

    return 0;
}

static void
print_debug_kind(drsym_debug_kind_t kind)
{
    printf("<debug info: type=%s, %s symbols, %s line numbers>\n",
           TEST(DRSYM_ELF_SYMTAB, kind) ? "ELF symtab" :
           (TEST(DRSYM_PECOFF_SYMTAB, kind) ? "PECOFF symtab" :
            (TEST(DRSYM_PDB, kind) ? "PDB" : "no symbols")),
           TEST(DRSYM_SYMBOLS, kind) ? "has" : "NO",
           TEST(DRSYM_LINE_NUMS, kind) ? "has" : "NO");
}

static void
get_and_print_debug_kind(const char *dllpath)
{
    drsym_debug_kind_t kind;
    drsym_error_t symres = drsym_get_module_debug_kind(dllpath, &kind);
    if (symres == DRSYM_SUCCESS)
        print_debug_kind(kind);
}

static void
lookup_address(const char *dllpath, size_t modoffs)
{
    ssize_t len = 0;
    drsym_error_t symres;
    drsym_info_t *sym;
    char sbuf[sizeof(*sym) + MAX_FUNC_LEN];
    sym = (drsym_info_t *) sbuf;
    sym->struct_size = sizeof(*sym);
    sym->name_size = MAX_FUNC_LEN;
    symres = drsym_lookup_address(dllpath, modoffs, sym, DRSYM_DEMANGLE);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        if (verbose)
            print_debug_kind(sym->debug_kind);
        if (sym->name_available_size >= sym->name_size)
            printf("WARNING: function name longer than max: %s\n", sym->name);
        if (show_func)
            printf("%s+0x%x\n", sym->name, (modoffs - sym->start_offs));

        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            printf("??:0\n");
        } else {
            printf("%s:%"INT64_FORMAT"u+0x%x\n", sym->file, sym->line, sym->line_offs);
        }
    } else {
        if (verbose)
            printf("drsym_lookup_address error %d\n", symres);
        else if (show_func)
            printf("?\n");
    }
}

static void
lookup_symbol(const char *dllpath, const char *sym)
{
    size_t modoffs;
    drsym_error_t symres;
    if (verbose)
        get_and_print_debug_kind(dllpath);
    symres = drsym_lookup_symbol(dllpath, sym, &modoffs, DRSYM_DEMANGLE);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        printf("+0x%x\n", modoffs);
    } else {
        if (verbose)
            printf("drsym error %d looking up \"%s\" in \"%s\"\n", symres, sym, dllpath);
        else
            printf("??\n");
    }
}

static bool
search_cb(const char *name, size_t modoffs, void *data)
{
    const char *match = (const char *) data;
    if (match == NULL || strcmp(name, match) == 0)
        printf("%s +0x%x\n", name, modoffs);
    return true; /* keep iterating */
}

static void
enumerate_symbols(const char *dllpath, const char *match, BOOL search, BOOL searchall)
{
    drsym_error_t symres;
    if (verbose)
        get_and_print_debug_kind(dllpath);
    if (search)
        symres = drsym_search_symbols(dllpath, match, searchall, search_cb, NULL);
    else
        symres = drsym_enumerate_symbols(dllpath, search_cb, (void *)match, 0);
    if (symres != DRSYM_SUCCESS && verbose)
        printf("search/enum error %d\n", symres);
}
