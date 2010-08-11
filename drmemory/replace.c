/* **********************************************************
 * Copyright (c) 2008-2009 VMware, Inc.  All rights reserved.
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

/***************************************************************************
 * replace.c: replacement routines for str* and mem* libc routines that
 * tend to cause false positives due to their optimizations.
 * Ours may be a little slower, but Dr. Memory's general slowdown
 * far outweighs that, and replacing avoids having to use fragile
 * pattern matches (though we still need those for inlined (or static,
 * until we have symbols) copies of these routines).
 * Xref PR 485412.
 */

#include "dr_api.h"
#include "per_thread.h"
#include "utils.h"
#include "heap.h"
#include "drmemory.h"
#ifdef LINUX
# include <unistd.h> /* size_t */
#endif
#ifdef USE_DRSYMS
# include "drsyms.h"
#endif

/* On Windows, keep this updated with drmemory.pl which queries these pre-run */
#define REPLACE_DEFS()     \
    REPLACE_DEF(memset)    \
    REPLACE_DEF(memcpy)    \
    REPLACE_DEF(memchr)    \
    IF_LINUX(REPLACE_DEF(memrchr)) \
    IF_LINUX(REPLACE_DEF(rawmemchr)) \
    REPLACE_DEF(strchr)    \
    REPLACE_DEF(strrchr)   \
    IF_LINUX(REPLACE_DEF(strchrnul)) \
    REPLACE_DEF(strlen)    \
    REPLACE_DEF(strcmp)    \
    REPLACE_DEF(strncmp)   \
    REPLACE_DEF(strcpy)    \
    REPLACE_DEF(strncpy)   \
    REPLACE_DEF(strcat)    \
    REPLACE_DEF(strncat)

static const char *replace_routine_name[] = {
#define REPLACE_DEF(nm) STRINGIFY(nm),
    REPLACE_DEFS()
#undef REPLACE_DEF
};
#define REPLACE_NUM (sizeof(replace_routine_name)/sizeof(replace_routine_name[0]))

/* This table is only written at init time, so no synch needed */
#define REPLACE_TABLE_HASH_BITS 6
static hashtable_t replace_table;

static app_pc replace_routine_start;

/***************************************************************************
 * The replacements themselves.
 * These routines are not static so that under gdb a fault will show
 * up as drmemory!replace_strlen and the user can see it's strlen.
 */

/* To distinguish these routines, we place into a separate page-aligned
 * section.  We assume these will take up no more than one page.
 * We really only use this separate section for debugging purposes, currently.
 * If we later hide client libraries, we should probably move these
 * to a visible library.
 */
#ifdef LINUX
asm(".section .replace, \"ax\", @progbits");
asm(".align 0x1000");
# define IN_REPLACE_SECTION __attribute__ ((section (".replace")))
#else
/* Use special C99 operator _Pragma to generate a pragma from a macro */
# if _MSC_VER <= 1200 /* FIXME: __pragma may work w/ vc6: then don't need #if */
#  define ACTUAL_PRAGMA(p) _Pragma ( #p )
# else
#  define ACTUAL_PRAGMA(p) __pragma ( p )
# endif
ACTUAL_PRAGMA( code_seg(".replace") )
# define IN_REPLACE_SECTION /* nothing */
#endif

IN_REPLACE_SECTION void *
replace_memset(void *dst, int val, size_t size)
{
    register unsigned char *ptr = (unsigned char *) dst;
    while (size-- > 0) /* loop will terminate before underflow */
        *ptr++ = (unsigned char) val;
    return dst;
}

IN_REPLACE_SECTION void *
replace_memcpy(void *dst, const void *src, size_t size)
{
    register unsigned char *d = (unsigned char *) dst;
    register unsigned char *s = (unsigned char *) src;
    while (size-- > 0) /* loop will terminate before underflow */
        *d++ = *s++;
    return dst;
}

IN_REPLACE_SECTION void *
replace_memchr(const void *mem, int find, size_t size)
{
    register const unsigned char *s = (unsigned char *) mem;
    register unsigned char c = (unsigned char) find;
    while (size-- > 0) { /* loop will terminate before underflow */
        if (*s == c)
            return (void *) s;
        s++;
    }
    return NULL;
}

IN_REPLACE_SECTION void *
replace_memrchr(const void *mem, int find, size_t size)
{
    register const unsigned char *s = ((unsigned char *) mem) + size - 1;
    register unsigned char c = (unsigned char) find;
    while (size-- > 0) { /* loop will terminate before underflow */
        if (*s == c)
            return (void *) s;
        s--;
    }
    return NULL;
}

#ifdef LINUX
IN_REPLACE_SECTION void *
replace_rawmemchr(const void *mem, int find)
{
    register unsigned char *s = (unsigned char *) mem;
    register unsigned char c = (unsigned char) find;
    while (*s != c)
        s++;
    return s;
}
#endif

IN_REPLACE_SECTION char *
replace_strchr(const char *str, int find)
{
    register const char *s = str;
    register char c = (char) find;
    /* be sure to match the terminating 0 instead of failing (i#275) */
    while (true) {
        if (*s == c)
            return (char *) s;
        if (*s == '\0')
            return NULL;
        s++;
    }
    return NULL;
}

IN_REPLACE_SECTION char *
replace_strrchr(const char *str, int find)
{
    register const char *s = str;
    register char c = (char) find;
    const char *last = NULL;
    /* be sure to match the terminating 0 instead of failing (i#275) */
    while (true) {
        if (*s == c)
            last = s;
        if (*s == '\0')
            break;
        s++;
    }
    return (char *) last;
}

#ifdef LINUX
IN_REPLACE_SECTION char *
replace_strchrnul(const char *str, int find)
{
    register const char *s = str;
    register char c = (char) find;
    while (*s != '\0') {
        if (*s == c)
            return (char *) s;
        s++;
    }
    return (char *) s;
}
#endif

IN_REPLACE_SECTION size_t
replace_strlen(const char *str)
{
    register char *s = (char *) str;
    while (*s != '\0')
        s++;
    return (s - str);
}

IN_REPLACE_SECTION int
replace_strncmp(const char *str1, const char *str2, size_t size)
{
    register const char *s1 = (char *) str1;
    register const char *s2 = (char *) str2;
    while (size-- > 0) { /* loop will terminate before underflow */
        if (*s1 == '\0') {
            if (*s2 == '\0')
                return 0;
            return -1;
        }
        if (*s2 == '\0')
            return 1;
        if (*s1 < *s2)
            return -1;
        if (*s1 > *s2)
            return 1;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION int
replace_strcmp(const char *str1, const char *str2)
{
    register const char *s1 = (char *) str1;
    register const char *s2 = (char *) str2;
    while (1) {
        if (*s1 == '\0') {
            if (*s2 == '\0')
                return 0;
            return -1;
        }
        if (*s2 == '\0')
            return 1;
        if (*s1 < *s2)
            return -1;
        if (*s1 > *s2)
            return 1;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION char *
replace_strcpy(char *dst, const char *src)
{
    register const char *s = (char *) src;
    register char *d = (char *) dst;
    while (*s != '\0')
        *d++ = *s++;
    *d = '\0';
    return dst;
}

IN_REPLACE_SECTION char *
replace_strncpy(char *dst, const char *src, size_t size)
{
    register const char *s = (char *) src;
    register char *d = (char *) dst;
    while (size > 0 && *s != '\0') {
        *d++ = *s++;
        size--;
    }
    /* if hit size, do not null terminate */
    while (size > 0) {
        *d = '\0';
        size--;
    }
    return dst;
}

IN_REPLACE_SECTION char *
replace_strcat(char *dst, const char *src)
{
    register char *d = (char *) dst;
    while (*d != '\0')
        d++;
    replace_strcpy(d, src);
    return dst;
}

IN_REPLACE_SECTION char *
replace_strncat(char *dst, const char *src, size_t size)
{
    register char *d = (char *) dst;
    while (*d != '\0')
        d++;
    replace_strncpy(d, src, size);
    return dst;
}

#ifdef LINUX
asm(".section .text, \"ax\", @progbits");
asm(".align 0x1000");
#else
ACTUAL_PRAGMA( code_seg() )
#endif

/*
 ***************************************************************************/

static const void *replace_routine_addr[] = {
#define REPLACE_DEF(nm) replace_##nm,
    REPLACE_DEFS()
#undef REPLACE_DEF
};

void
replace_init(void)
{
    if (options.replace_libc) {
        app_pc addr;
        int i;
        char *s;

        hashtable_init(&replace_table, REPLACE_TABLE_HASH_BITS, HASH_INTPTR,
                       false/*!strdup*/);
        /* replace_module_load will be called for each module to populate the hashtable */
        ASSERT(PAGE_START(replace_memset) == PAGE_START(replace_strncat),
               "replace_ routines taking up more than one page");
        replace_routine_start = (app_pc) PAGE_START(replace_memset);
        
        /* PR 485412: we support passing in addresses of libc routines to
         * be replaced if statically included in the executable and if
         * we have no symbols available
         */
        s = options.libc_addrs;
        i = 0;
        while (s != NULL) {
            if (sscanf(s, PIFX, (ptr_uint_t *)&addr) == 1) {
                LOG(2, "replacing %s @"PFX" in executable from options\n",
                    replace_routine_name[i], addr);
                hashtable_add(&replace_table, (void*)addr, (void*)(i+1));
            }
            s = strchr(s, ',');
            if (s != NULL)
                s++;
            i++;
        }
    }
}

void
replace_exit(void)
{
    if (options.replace_libc)
        hashtable_delete(&replace_table);
}

static inline generic_func_t
cast_to_func(void *p)
{
#ifdef WINDOWS
#  pragma warning(push)
#  pragma warning(disable : 4055)
#endif
    return (generic_func_t) p;
#ifdef WINDOWS
#  pragma warning(pop)
#endif
}

static void
replace_in_module(const module_data_t *mod, bool add)
{
    /* We want to replace str/mem in libc, and in the executable if
     * it has statically included libc, and in any library that has done
     * so: so we aggressively apply to all libraries.
     * FIXME: we need symbols to find statically-included libc.
     *
     * It's possible some library exports a routine that is slightly
     * different w/ the same name but that seems very unlikely since it
     * would conflict w/ the libc routine.  On Windows it's more likely
     * since there's no global namespace.
     */
    int i;
    IF_DEBUG(app_pc libc = get_libc_base();)
    IF_DEBUG(const char *modname = dr_module_preferred_name(mod);)
    ASSERT(options.replace_libc, "should not be called if op not on");
    for (i=0; i<REPLACE_NUM; i++) {
        dr_export_info_t info;
        app_pc addr = NULL;
        if (dr_get_proc_address_ex(mod->start, replace_routine_name[i],
                                   &info, sizeof(info))) {
            addr = (app_pc) info.address;
            ASSERT(addr != NULL, "can't succeed yet have NULL addr!");
            if (info.is_indirect_code) {
                /* i#248/PR 510905: new ELF indirect code object type.
                 * We have to call the export to get the real impl.
                 * This could be unsafe: but we're already trusting the app and
                 * assuming it's not trying to intentionally subvert us.
                 */
                app_pc (*indir)(void) = (app_pc (*)(void)) cast_to_func(addr);
                addr = (*indir)();
                LOG(2, "export %s indirected from "PFX" to "PFX"\n",
                    replace_routine_name[i], info.address, addr);
            }
        }
#ifdef USE_DRSYMS
        else {
            /* PR 486382: look up these symbols online for all modules.
             * We rely on drsym_init() having been called during init.
             */
            addr = lookup_symbol(mod, replace_routine_name[i]);
        }
#endif
        if (addr != NULL) {
            LOG(2, "%s %s @"PFX" in %s (base "PFX")\n",
                add ? "replacing" : "removing replacement",
                replace_routine_name[i], addr,
                modname == NULL ? "<noname>" : modname, mod->start);
            /* We can't store 0 in the table (==miss) so we store index + 1 */
            if (add)
                hashtable_add(&replace_table, (void*)addr, (void*)(i+1));
            else
                hashtable_remove(&replace_table, (void*)addr);
        } else {
            /* We should find every single routine in libc */
            ASSERT(mod->start != libc, "can't find libc routine to replace");
        }
    }
}

void
replace_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    /* Skip DR (its forwarders raise a curiosity in module_shared.c, plus
     * we don't want to replace its or client uses)
     */
    if (options.replace_libc &&
        !dr_memory_is_dr_internal(info->start) &&
        !dr_memory_is_in_client(info->start))
        replace_in_module(info, true/*add*/);
}

void
replace_module_unload(void *drcontext, const module_data_t *info)
{
    /* Skip DR (its forwarders raise a curiosity in module_shared.c, plus
     * we don't want to replace its or client uses)
     */
    if (options.replace_libc &&
        !dr_memory_is_dr_internal(info->start) &&
        !dr_memory_is_in_client(info->start))
        replace_in_module(info, false/*remove*/);
}

bool
in_replace_routine(app_pc pc)
{
    return (pc >= replace_routine_start &&
            pc < replace_routine_start + PAGE_SIZE);
}

/* Replacement strategy: we assume these routines will always be entered in
 * a new bb (we're not going to request elision or indcall2direct from DR).
 * We want to interpret our own routines, so we replace the whole bb with
 * a jump to the replacement routine.  This avoids having faults in
 * our lib, for which DR will abort.
 */
void
replace_instrument(void *drcontext, instrlist_t *bb)
{
    app_pc pc, replacement;
    int idx;
    instr_t *inst = instrlist_first(bb);
    if (!options.replace_libc)
        return;
    if (inst == NULL)
        return;
    pc = instr_get_app_pc(inst);
    ASSERT(pc != NULL, "can't get app pc for instr");
    idx = (int) hashtable_lookup(&replace_table, (void*)pc);
    if (idx != 0) {
        idx--; /* index + 1 is stored in the table */
        replacement = (app_pc) replace_routine_addr[idx];
        LOG(2, "replacing %s at "PFX"\n", replace_routine_name[idx], pc);
        instrlist_clear(drcontext, bb);
        instrlist_append(bb, INSTR_XL8(INSTR_CREATE_jmp
                                       (drcontext, opnd_create_pc(replacement)), pc));
    }
}
