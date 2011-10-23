/* **********************************************************
 * Copyright (c) 2010-2011 Google, Inc.  All rights reserved.
 * Copyright (c) 2008-2010 VMware, Inc.  All rights reserved.
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

#ifdef LINUX
/* avoid depending on __isoc99_sscanf */
# undef sscanf
# define _GNU_SOURCE 1
# include <stdio.h>
# undef _GNU_SOURCE
#endif

#include "dr_api.h"
#include "per_thread.h"
#include "utils.h"
#include "heap.h"
#include "drmemory.h"
#ifdef USE_DRSYMS
# include "symcache.h"
#endif
#ifdef LINUX
# include <unistd.h> /* size_t */
#endif
#ifdef USE_DRSYMS
# include "drsyms.h"
#endif

#undef sscanf /* eliminate warning from utils.h b/c we have _GNU_SOURCE above */

/* On Windows, keep this updated with drmemory.pl which queries these pre-run.
 *
 * When adding, make sure the regexs passed to find_syms_regex() cover
 * the new name!
 */
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
    REPLACE_DEF(strncat)   \
    REPLACE_DEF(memmove)   \
    /* DO NOT ADD ABOVE HERE w/o updating drmemory.pl -libc_addrs */ \
    REPLACE_DEF(memcmp)    \
    REPLACE_DEF(wmemset)   \
    REPLACE_DEF(wmemcpy)   \
    REPLACE_DEF(wmemchr)   \
    REPLACE_DEF(wcslen)    \
    REPLACE_DEF(wcscmp)    \
    REPLACE_DEF(wcsncmp)   \
    REPLACE_DEF(wmemcmp)

/* TODO(timurrrr): add wrappers for wcschr, wcsrchr, wcscpy, wcsncpy, wcscat,
 * wcsncat, wmemmove.
 */

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

#ifdef USE_DRSYMS
/* for passing data to sym enum callback */
typedef struct _sym_enum_data_t {
    bool add;
    bool processed[REPLACE_NUM];
    const module_data_t *mod;
} sym_enum_data_t;

/* for considering wildcard symbols */
#define REPLACE_NAME_TABLE_HASH_BITS 6
static hashtable_t replace_name_table;
#endif

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
ACTUAL_PRAGMA( code_seg(".replace") )
# define IN_REPLACE_SECTION /* nothing */
#endif

/* prevent cl from replacing our loop with a call to ntdll!memset,
 * which we replace with this routine, which results an infinite loop!
 */
DO_NOT_OPTIMIZE
IN_REPLACE_SECTION void *
replace_memset(void *dst, int val_in, size_t size)
{
    register unsigned char *ptr = (unsigned char *) dst;
    unsigned char val = (unsigned char) val_in;
    unsigned int val4 = (val << 24) | (val << 16) | (val << 8) | val;
    while (!ALIGNED(ptr, 4) && size > 0) {
        *ptr++ = val;
        size--;
    }
    while (size > 3) {
        *((unsigned int *)ptr) = val4;
        ptr += 4;
        size -= 4;
    }
    while (size > 0) {
        *ptr++ = val;
        size--;
    }
    return dst;
}

IN_REPLACE_SECTION wchar_t *
replace_wmemset(wchar_t *dst, wchar_t val_in, size_t size)
{
    wchar_t *ret = dst;
    while (size-- > 0)
        *dst++ = val_in;
    return ret;
}
END_DO_NOT_OPTIMIZE

IN_REPLACE_SECTION void *
replace_memcpy(void *dst, const void *src, size_t size)
{
    register unsigned char *d = (unsigned char *) dst;
    register unsigned char *s = (unsigned char *) src;
    if (((ptr_uint_t)dst & 3) == ((ptr_uint_t)src & 3)) {
        /* same alignment, so we can do 4 aligned bytes at a time and stay
         * on fastpath.  when not same alignment, I'm assuming it's faster
         * to have all 1-byte moves on fastpath rather than half 4-byte
         * (aligned) on fastpath and half 4-byte (unaligned) on slowpath.
         */
        while (!ALIGNED(d, 4) && size > 0) {
            *d++ = *s++;
            size--;
        }
        while (size > 3) {
            *((unsigned int *)d) = *((unsigned int *)s);
            s += 4;
            d += 4;
            size -= 4;
        }
        while (size > 0) {
            *d++ = *s++;
            size--;
        }
    } else {
        while (size-- > 0) /* loop will terminate before underflow */
            *d++ = *s++;
    }
    return dst;
}

IN_REPLACE_SECTION wchar_t *
replace_wmemcpy(wchar_t *dst, const wchar_t *src, size_t size)
{
    return (wchar_t*)replace_memcpy(dst, src, size * sizeof(wchar_t));
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

IN_REPLACE_SECTION wchar_t *
replace_wmemchr(wchar_t *s, wchar_t c, size_t size)
{
    while (size-- > 0) { /* loop will terminate before underflow */
        if (*s == c)
            return s;
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
    register const char *s = str;
    while (*s != '\0')
        s++;
    return (s - str);
}

IN_REPLACE_SECTION size_t
replace_wcslen(const wchar_t *str)
{
    register const wchar_t *s = str;
    while (*s != L'\0')
        s++;
    return (s - str);
}

IN_REPLACE_SECTION int
replace_strncmp(const char *str1, const char *str2, size_t size)
{
    register const unsigned char *s1 = (const unsigned char *) str1;
    register const unsigned char *s2 = (const unsigned char *) str2;
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
replace_wcsncmp(const wchar_t *s1, const wchar_t *s2, size_t size)
{
    while (size-- > 0) { /* loop will terminate before underflow */
        if (*s1 == L'\0') {
            if (*s2 == L'\0')
                return 0;
            return -1;
        }
        if (*s2 == L'\0')
            return 1;
        if ((unsigned int)*s1 < (unsigned int)*s2)
            return -1;
        if ((unsigned int)*s1 > (unsigned int)*s2)
            return 1;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION int
replace_strcmp(const char *str1, const char *str2)
{
    register const unsigned char *s1 = (const unsigned char *) str1;
    register const unsigned char *s2 = (const unsigned char *) str2;
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

IN_REPLACE_SECTION int
replace_wcscmp(const wchar_t *s1, const wchar_t *s2)
{
    while (1) {
        if (*s1 == L'\0') {
            if (*s2 == L'\0')
                return 0;
            return -1;
        }
        if (*s2 == L'\0')
            return 1;
        if ((unsigned int)*s1 < (unsigned int)*s2)
            return -1;
        if ((unsigned int)*s1 > (unsigned int)*s2)
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
    /* we can't easily use replace_strncpy b/c we don't want
     * to fill to size, and we want to null-terminate
     */
    register const char *s = (char *) src;
    register char *d = (char *) dst;
    while (*d != '\0')
        d++;
    while (size > 0 && *s != '\0') {
        *d++ = *s++;
        size--;
    }
    *d = '\0';
    return dst;
}

IN_REPLACE_SECTION void *
replace_memmove(void *dst, const void *src, size_t size)
{
    if (((ptr_uint_t)dst) - ((ptr_uint_t)src) >= size) {
        /* forward walk won't clobber: either no overlap or dst < src */
        register const char *s = (const char *) src;
        register char *d = (char *) dst;
        if (((ptr_uint_t)dst & 3) == ((ptr_uint_t)src & 3)) {
            /* same alignment, so we can do 4 aligned bytes at a time and stay
             * on fastpath.  when not same alignment, I'm assuming it's faster
             * to have all 1-byte moves on fastpath rather than half 4-byte
             * (aligned) on fastpath and half 4-byte (unaligned) on slowpath.
             */
            while (!ALIGNED(d, 4) && size > 0) {
                *d++ = *s++;
                size--;
            }
            while (size > 3) {
                *((unsigned int *)d) = *((unsigned int *)s);
                s += 4;
                d += 4;
                size -= 4;
            }
            while (size > 0) {
                *d++ = *s++;
                size--;
            }
        } else {
            while (size > 0) {
                *d++ = *s++;
                size--;
            }
        }
    } else {
        /* walk backward to avoid clobbering since overlaps and src < dst */
        register const char *s = ((const char *) src) + size;
        register char *d = ((char *) dst) + size;
        if (((ptr_uint_t)dst & 3) == ((ptr_uint_t)src & 3)) {
            /* same alignment, so we can do 4 aligned bytes at a time and stay
             * on fastpath.  we want to do 4 aligned on mod 3 since backward.
             */
            while (!ALIGNED(d, 4) && size > 0) {
                *(--d) = *(--s);
                size--;
            }
            while (size > 3) {
                *((unsigned int *)(d-4)) = *((unsigned int *)(s-4));
                s -= 4;
                d -= 4;
                size -= 4;
            }
            while (size > 0) {
                *(--d) = *(--s);
                size--;
            }
        } else {
            while (size > 0) {
                *(--d) = *(--s);
                size--;
            }
        }
    }
    return dst;
}

IN_REPLACE_SECTION int
replace_memcmp(const void *p1, const void *p2, size_t size)
{
    register const unsigned char *s1 = (unsigned char *) p1;
    register const unsigned char *s2 = (unsigned char *) p2;
    ssize_t diff;
    while (size-- > 0) { /* loop will terminate before underflow */
        diff = (*s1 - *s2);
        if (diff != 0)
            return diff;
        s1++;
        s2++;
    }
    return 0;
}

IN_REPLACE_SECTION int
replace_wmemcmp(const wchar_t *s1, const wchar_t *s2, size_t count)
{
    ssize_t diff;
    while (count-- > 0) { /* loop will terminate before underflow */
        diff = (*s1 - *s2);
        if (diff != 0)
            return diff;
        s1++;
        s2++;
    }
    return 0;
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

static app_pc
get_function_entry(app_pc C_var)
{
    void *drcontext = dr_get_current_drcontext();
    byte *pc;
    instr_t inst;
    instr_init(drcontext, &inst);
    pc = decode(drcontext, C_var, &inst);
    ASSERT(pc != NULL, "invalid instr at function entry");
    if (instr_get_opcode(&inst) == OP_jmp) {
        /* skip jmp in ILT */
        ASSERT(opnd_is_pc(instr_get_target(&inst)), "decoded jmp should have pc tgt");
        pc = opnd_get_pc(instr_get_target(&inst));
    } else
        pc = C_var;
    instr_free(drcontext, &inst);
    return pc;
}

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
        ASSERT(PAGE_START(get_function_entry((app_pc)replace_memset)) ==
               PAGE_START(get_function_entry((app_pc)replace_memmove)),
               "replace_ routines taking up more than one page");
        ASSERT(sizeof(int) >= sizeof(wchar_t),
               "wchar_t replacement functions assume wchar_t is not larger than int");
        replace_routine_start = (app_pc)
            PAGE_START(get_function_entry((app_pc)replace_memset));
        
        /* PR 485412: we support passing in addresses of libc routines to
         * be replaced if statically included in the executable and if
         * we have no symbols available
         */
        s = options.libc_addrs;
        i = 0;
        while (s != NULL) {
            if (sscanf(s, PIFX, (ptr_uint_t *)&addr) == 1 ||
                /* we save option space by having no 0x prefix but assuming hex */
                sscanf(s, PIFMT, (ptr_uint_t *)&addr) == 1) {
                LOG(2, "replacing %s @"PFX" in executable from options\n",
                    replace_routine_name[i], addr);
                hashtable_add(&replace_table, (void*)addr, (void*)(i+1));
            }
            s = strchr(s, ',');
            if (s != NULL)
                s++;
            i++;
        }

#ifdef USE_DRSYMS
        hashtable_init(&replace_name_table, REPLACE_NAME_TABLE_HASH_BITS, HASH_STRING,
                       false/*!strdup*/);
        for (i=0; i<REPLACE_NUM; i++) {
            hashtable_add(&replace_name_table, (void *) replace_routine_name[i],
                          (void *)(ptr_int_t)(i+1)/*since 0 is "not found"*/);
        }
#endif
    }
}

void
replace_exit(void)
{
    if (options.replace_libc) {
        hashtable_delete(&replace_table);
#ifdef USE_DRSYMS
        hashtable_delete(&replace_name_table);
#endif
    }
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
replace_routine(bool add, const module_data_t *mod,
                app_pc addr, int index)
{
    IF_DEBUG(const char *modname = dr_module_preferred_name(mod);)
    LOG(2, "%s %s @"PFX" in %s (base "PFX")\n",
        add ? "replacing" : "removing replacement",
        replace_routine_name[index], addr,
        modname == NULL ? "<noname>" : modname, mod->start);
    /* We can't store 0 in the table (==miss) so we store index + 1 */
    if (add) {
#ifdef USE_DRSYMS
        if (options.use_symcache)
            symcache_add(mod, replace_routine_name[index], addr - mod->start);
#endif
        hashtable_add(&replace_table, (void*)addr, (void*)(index+1));
    } else
        hashtable_remove(&replace_table, (void*)addr);
}

/* Modern glibc uses an ELF indirect code object to enable strlen to
 * dynamically resolve to an arch-specific optimized version.
 * However, some internal glibc routines like fputs have
 * hardcoded calls to strlen that sometimes target the version
 * that is not the one resolved at runtime, and these versions
 * are not exported.  If we had full debug information we could
 * find them as they are named __strlen_ia32 and __strlen_sse2.
 * This routine tries to identify all such routines and replace
 * them all.  It assumes the strlen() resolution routine first
 * does the typical "call thunk to get retaddr in ebx, add immed to ebx"
 * to find the GOT, and then has "lea <offs of func>+GOT into eax"
 * for each return possibility.  Xref PR 623449.
 */
static void
replace_all_strlen(bool add, const module_data_t *mod,
                   int index, app_pc indir, app_pc resolved)
{
    void *drcontext = dr_get_current_drcontext();
    instr_t inst;
    app_pc pc = indir, prev_pc;
    bool last_was_call = false, first_call = false;
    app_pc addr_got = NULL;
    instr_init(drcontext, &inst);
    do {
        instr_reset(drcontext, &inst);
        prev_pc = pc;
        pc = decode(drcontext, pc, &inst);
        if (pc == NULL || !instr_valid(&inst)) {
            LOG(1, "WARNING: invalid instr at indir func %s "PFX"\n",
                replace_routine_name[index], prev_pc);
            break;
        }
        if (last_was_call) {
            /* At instr after call to thunk: should be add of immed to ebx */
            first_call = true;
            if (instr_get_opcode(&inst) == OP_add &&
                opnd_is_immed_int(instr_get_src(&inst, 0)) &&
                opnd_is_reg(instr_get_dst(&inst, 0)) &&
                opnd_get_reg(instr_get_dst(&inst, 0)) == REG_XBX) {
                addr_got = opnd_get_immed_int(instr_get_src(&inst, 0)) + prev_pc;
                LOG(2, "\tfound GOT "PFX" for indir func %s\n",
                    addr_got, replace_routine_name[index]);
                if (addr_got < mod->start || addr_got > mod->end)
                    addr_got = NULL;
            }
        }
        if (addr_got != NULL &&
            instr_get_opcode(&inst) == OP_lea &&
            opnd_get_reg(instr_get_dst(&inst, 0)) == REG_XAX &&
            opnd_is_base_disp(instr_get_src(&inst, 0)) &&
            opnd_get_base(instr_get_src(&inst, 0)) == REG_XBX &&
            opnd_get_index(instr_get_src(&inst, 0)) == REG_NULL &&
            opnd_get_scale(instr_get_src(&inst, 0)) == 0) {
            app_pc addr = addr_got + opnd_get_disp(instr_get_src(&inst, 0));
            LOG(2, "\tfound return value "PFX" for indir func %s @"PFX"\n",
                addr, replace_routine_name[index], prev_pc);
            if (addr < mod->start || addr > mod->end) {
                LOG(1, "WARNING: unknown code in indir func %s @"PFX"\n",
                    replace_routine_name[index], prev_pc);
                break;
            }
            if (addr != resolved)
                replace_routine(add, mod, addr, index);
        }
        if (!first_call && instr_is_call_direct(&inst))
            last_was_call = true;
    } while (!instr_is_return(&inst));
    instr_reset(drcontext, &inst);

}

#ifdef USE_DRSYMS
/* It's faster to search for multiple symbols at once via regex
 * and strcmp to identify precise targets (i#315).
 */
static bool
enumerate_syms_cb(const char *name, size_t modoffs, void *data)
{
    uint i;
    sym_enum_data_t *edata = (sym_enum_data_t *) data;
    ASSERT(edata != NULL && edata->processed != NULL, "invalid param");
    LOG(2, "%s: %s "PIFX"\n", __FUNCTION__, name, modoffs);
    /* Using hashtable lookup to avoid linear walk of strcmp.
     * Linear walk isn't much slower now, but will become worse
     * as we add more routines.
     */
    i = (uint) hashtable_lookup(&replace_name_table, (void *)name);
    /* XXX: some modules have multiple addresses for one symbol: e.g., unit_tests.exe 
     * strlen, strchr, and strrchr
     */
    if (i != 0 && !edata->processed[i-1]) {
        i--;
        edata->processed[i] = true;
        replace_routine(edata->add, edata->mod, edata->mod->start + modoffs, i);
    }
    return true; /* keep iterating */
}

static void
find_syms_regex(sym_enum_data_t *edata, const char *regex)
{
    if (!lookup_all_symbols(edata->mod, regex, enumerate_syms_cb, (void *)edata))
        LOG(2, "WARNING: failed to look up symbols: %s\n", regex);
}
#endif /* USE_DRSYMS */


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
    app_pc libc = get_libc_base();
    void *drcontext = dr_get_current_drcontext();
#ifdef USE_DRSYMS
    sym_enum_data_t edata = {add, {0,}, mod};
    bool missing_export = false;
#endif
    ASSERT(options.replace_libc, "should not be called if op not on");
    for (i=0; i<REPLACE_NUM; i++) {
        dr_export_info_t info;
        app_pc addr = NULL;
        if (dr_get_proc_address_ex(mod->start, replace_routine_name[i],
                                   &info, sizeof(info))) {
            addr = (app_pc) info.address;
            ASSERT(addr != NULL, "can't succeed yet have NULL addr!");
#ifdef USE_DRSYMS
            edata.processed[i] = true;
#endif
            if (info.is_indirect_code) {
                /* i#248/PR 510905: new ELF indirect code object type.
                 * We have to call the export to get the real impl.
                 * This could be unsafe: but we're already trusting the app and
                 * assuming it's not trying to intentionally subvert us.
                 */
                app_pc (*indir)(void) = (app_pc (*)(void)) cast_to_func(addr);
                app_pc orig_addr = addr;
                DR_TRY_EXCEPT(drcontext, {
                    addr = (*indir)();
                }, { /* EXCEPT */
                    addr = NULL;
                });
                LOG(2, "export %s indirected from "PFX" to "PFX"\n",
                    replace_routine_name[i], info.address, addr);
                if (mod->start == libc)
                    replace_all_strlen(add, mod, i, orig_addr, addr);
            }
        }
#ifdef USE_DRSYMS
        else {
            size_t modoffs;
            uint count;
            uint idx;
            LOG(3, "did not find export %s\n", replace_routine_name[i]);
            if (options.use_symcache && symcache_module_is_cached(mod)) {
                for (idx = 0, count = 1;
                     idx < count && symcache_lookup(mod, replace_routine_name[i],
                                                    idx, &modoffs, &count); idx++) {
                    STATS_INC(symbol_search_cache_hits);
                    edata.processed[i] = true;
                    if (modoffs != 0)
                        replace_routine(add, mod, mod->start + modoffs, i);
                }
            }
            if (!edata.processed[i]) {
                LOG(2, "did not find %s in symcache\n", replace_routine_name[i]);
                missing_export = true;
            }
        }
#endif
        if (addr != NULL) {
            replace_routine(add, mod, addr, i);
        } else {
            /* We should find every single routine in libc on linux: on windows
             * the wide-char ones aren't always there
             */
            IF_LINUX(ASSERT(mod->start != libc, "can't find libc routine to replace"));
        }
    }

#ifdef USE_DRSYMS
    if (missing_export) {
        /* PR 486382: look up these symbols online for all modules.
         * We rely on drsym_init() having been called during init.
         * It's faster to look up multiple via regex (xref i#315)
         * when most modules don't have any of the replacement syms.
         */
        /* add 0, which will be replaced if we find it */
        if (options.use_symcache) {
            for (i = 0; i < REPLACE_NUM; i++) {
                if (!edata.processed[i])
                    symcache_add(mod, replace_routine_name[i], 0);
            }
        }
        /* These regex cover all function names we replace.  Both
         * number of syms and number of queries count.  This is a good
         * compromise.  "*mem*" has too many matches, while
         * "mem[scrm]*", "*wmem*", "str[crln]*", and "wcs*" is too
         * many queries.  Note that dbghelp does not support a regex
         * symbol for "0 or 1 chars".
         */
        /* N.B.: if you change these regexes, bump SYMCACHE_VERSION! */
        find_syms_regex(&edata, "[msw]?????");
        find_syms_regex(&edata, "[msw]??????");
# ifdef LINUX
        find_syms_regex(&edata, "strchrnul");
        find_syms_regex(&edata, "rawmemchr");
# endif
    }
#endif
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

bool
in_replace_memset(app_pc pc)
{
    /* we assume the layout for memset is all in one spot (optimizations
     * are disabled) and that memcpy follows it.  it wouldn't be
     * disastrous to include another routine since only used for
     * heap-unaddr checks.
     */
    static app_pc memset_entry, memcpy_entry;
    if (memset_entry == NULL) {
        memset_entry = get_function_entry((app_pc)replace_memset);
        memcpy_entry = get_function_entry((app_pc)replace_memcpy);
    }
    return (pc >= (app_pc)memset_entry && pc < (app_pc)memcpy_entry);
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
