/* **********************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
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

#include "dr_api.h"
#include <string.h>
#include "options.h"
#include "utils.h"
#include "fuzzer.h"

#ifdef WINDOWS
# include "dbghelp.h"
#endif

/* prefix for loading the descriptor from a file -- XXX i#1734: NYI */
#define DESCRIPTOR_PREFIX_FILE "file:"
#define DESCRIPTOR_PREFIX_FILE_LEN strlen(DESCRIPTOR_PREFIX_FILE)

#define MODULE_SEP '!'
#define OFFSET_SEP '+'
#define AT_ESCAPE '-'
#define TEMP_SPACE_CHAR '\1'

#define LOG_PREFIX "[fuzzer]"
#define FUZZ_ERROR(...) \
do { \
    ELOG(0, "ERROR: "LOG_PREFIX" "); \
    ELOG(0, __VA_ARGS__); \
} while (0)

#define FUZZ_REG_ERROR(...) \
do { \
    ELOG(0, "ERROR: "LOG_PREFIX" failed to register the fuzz target: "); \
    ELOG(0, __VA_ARGS__); \
} while (0)

#define FUZZ_WARN(...) \
do { \
    WARN("WARNING: "LOG_PREFIX" "); \
    WARN(__VA_ARGS__); \
} while (0)

typedef enum _fuzz_target_type_t {
    FUZZ_TARGET_NONE,
    FUZZ_TARGET_OFFSET,
    FUZZ_TARGET_SYMBOL
} fuzz_target_type_t;

typedef struct _fuzz_target_t {
    fuzz_target_type_t type;
    bool enabled;
    bool registered; /* XXX i#1734: NYI multiple instances of the target module */
    bool repeat;
    const char *raw_descriptor; /* cached reference -- not allocated */
    generic_func_t pc;
    char *module_name;
    union {
        size_t offset;
        char *symbol;
    };
    uint arg_count;
    uint buffer_arg;
    uint size_arg;
    uint repeat_count;
    uint repeat_index;
} fuzz_target_t;

static fuzz_target_t fuzz_target;

static void
module_loaded(void *drcontext, const module_data_t *module, bool loaded);

static void
module_unloaded(void *drcontext, const module_data_t *module);

static bool
register_fuzz_target(const module_data_t *module);

static bool
user_input_parse(char *descriptor);

static void
free_fuzz_target();

void
fuzzer_init(client_id_t client_id _IF_WINDOWS(bool fuzz_mangled_names))
{
    drmgr_init();
    if (drfuzz_init(client_id) != DRMF_SUCCESS)
        ASSERT(false, "fail to init Dr. Fuzz");

    if (!drmgr_register_module_load_event(module_loaded))
        ASSERT(false, "fail to register module load event");
    if (!drmgr_register_module_unload_event(module_unloaded))
        ASSERT(false, "fail to register module unload event");

#ifdef WINDOWS
    if (fuzz_mangled_names)
        SymSetOptions(SymGetOptions() & ~SYMOPT_UNDNAME);
#endif
}

void
fuzzer_exit()
{
    free_fuzz_target();

    if (drfuzz_exit() != DRMF_SUCCESS)
        ASSERT(false, "fail to exit Dr. Fuzz");
    drmgr_exit();
}

bool
fuzzer_fuzz_target(const char *target_descriptor)
{
    char *descriptor_copy; /* writable working copy */
    module_data_t *module;

    if (fuzz_target.enabled && fuzz_target.type != FUZZ_TARGET_NONE) {
        if (!fuzzer_unfuzz_target())
            FUZZ_WARN("failed to unfuzz the current target. Replacing it anyway.\n");
    }

    if (strlen(target_descriptor) > DESCRIPTOR_PREFIX_FILE_LEN &&
        strncmp(target_descriptor, DESCRIPTOR_PREFIX_FILE,
                DESCRIPTOR_PREFIX_FILE_LEN) == 0) {
        /* XXX i#1734: NYI */
        FUZZ_ERROR("File-based fuzz descriptor is not implemented yet\n");
        ASSERT(false, "File-based fuzz descriptor is not implemented yet\n");
        return false;
    } else {
        fuzz_target.raw_descriptor = target_descriptor;
    }

    descriptor_copy = drmem_strdup(target_descriptor, HEAPSTAT_MISC);
    if (user_input_parse(descriptor_copy)) {
        /* register the target now if the module is loaded */
        module = dr_lookup_module_by_name(fuzz_target.module_name);
        if (module == NULL) {
            LOG(1, LOG_PREFIX" Skipping fuzz target for now because "
                "module %s is not loaded now.\n", fuzz_target.module_name);
        } else {
            fuzz_target.enabled = register_fuzz_target(module);
            dr_free_module_data(module);
        }
    }

    if (!fuzz_target.enabled)
        free_fuzz_target();

    global_free(descriptor_copy, strlen(descriptor_copy) + 1/*null-term*/, HEAPSTAT_MISC);
    return fuzz_target.enabled;
}

bool
fuzzer_unfuzz_target()
{
    if (fuzz_target.enabled) {
        drmf_status_t res = drfuzz_unfuzz_target(fuzz_target.pc);
        if (res != DRMF_SUCCESS)
            FUZZ_ERROR("failed to unfuzz the target "PIFX"\n", fuzz_target.pc);
        free_fuzz_target();
        return (res == DRMF_SUCCESS);
    } else {
        return false;
    }
}

static void
pre_fuzz(void *fuzzcxt, generic_func_t target_pc)
{
    LOG(4, LOG_PREFIX" executing pre-fuzz for "PIFX"\n", target_pc);

    if (fuzz_target.repeat_index < fuzz_target.repeat_count && !fuzz_target.repeat)
        fuzz_target.repeat_index = 0; /* new entry to the target */

    /* FIXME i#1734: NYI save and restore the drmemory shadow state */
}

static bool
post_fuzz(void *fuzzcxt, generic_func_t target_pc)
{
    if (!fuzz_target.enabled)
        return false; /* in case someone unfuzzed while a target was looping */

    LOG(4, LOG_PREFIX" executing post-fuzz for "PIFX"\n", target_pc);

    /* FIXME i#1734: NYI save and restore the drmemory shadow state */

    fuzz_target.repeat = (fuzz_target.repeat_index++ < fuzz_target.repeat_count);
    return fuzz_target.repeat;
}

static void
module_loaded(void *drcontext, const module_data_t *module, bool loaded)
{
    const char *name = dr_module_preferred_name(module);

    ASSERT_NOT_TESTED("Registration of fuzz target on module load");

    if (fuzz_target.enabled && !fuzz_target.registered &&
        name != NULL && strcmp(name, fuzz_target.module_name) == 0)
        register_fuzz_target(module);
}

static void
module_unloaded(void *drcontext, const module_data_t *module)
{
    const char *name = dr_module_preferred_name(module);

    ASSERT_NOT_TESTED("Unregistration of fuzz target on module unload");

    if (fuzz_target.enabled && !fuzz_target.registered &&
        name != NULL && strcmp(name, fuzz_target.module_name) == 0)
        free_fuzz_target();
}

static bool
register_fuzz_target(const module_data_t *module)
{
    drmf_status_t res;

    if (fuzz_target.type == FUZZ_TARGET_SYMBOL) {
        drsym_debug_kind_t kind;
        drsym_error_t result;
        size_t symbol_offset;

        /* give a meaningful log message if the module doesn't have symbols */
        if (drsym_get_module_debug_kind(module->full_path, &kind) != DRSYM_SUCCESS) {
            FUZZ_REG_ERROR("module %s does not have symbols.\n", module->full_path);
            return false;
        }

        result = drsym_lookup_symbol(module->full_path, fuzz_target.symbol,
                                     &symbol_offset, 0);
        if (result == DRSYM_SUCCESS && symbol_offset > 0) {
            fuzz_target.pc = (generic_func_t) (module->start + symbol_offset);
            LOG(1, LOG_PREFIX" Successfully resolved symbol %s in module %s to "PIFX"\n",
                fuzz_target.symbol, module->full_path, fuzz_target.pc);
        } else {
            FUZZ_REG_ERROR("failed to locate symbol '%s' in module '%s'.\n",
                fuzz_target.symbol, module->full_path);
            return false;
        }
    } else {
        ASSERT(fuzz_target.type == FUZZ_TARGET_OFFSET, "unsupported fuzz target type");
        ASSERT(fuzz_target.offset < (module->end - module->start), "offset out of range");
        fuzz_target.pc = (generic_func_t) (module->start + fuzz_target.offset);
        LOG(1, LOG_PREFIX" Successfully resolved module %s offset "PIFX" to "PIFX"\n",
            module->full_path, fuzz_target.offset, fuzz_target.pc);
    }

    LOG(1, LOG_PREFIX" Attempting to register fuzz target at pc "PIFX" with %d args\n",
        fuzz_target.pc, fuzz_target.arg_count);

    res = drfuzz_fuzz_target(fuzz_target.pc, fuzz_target.arg_count, DRFUZZ_CALLCONV_CDECL,
                             pre_fuzz, post_fuzz);
    if (res == DRMF_SUCCESS) {
        LOG(1, LOG_PREFIX" Successfully registered fuzz target at pc "PIFX"\n",
            fuzz_target.pc);
        fuzz_target.registered = true;
        return true;
    } else {
        FUZZ_REG_ERROR("drfuzz_fuzz_target returned %d.\n", res);
        return false;
    }
}

static void
free_fuzz_target()
{
    if (fuzz_target.module_name != NULL) {
        global_free(fuzz_target.module_name, strlen(fuzz_target.module_name) + 1,
                    HEAPSTAT_MISC);
    }
    if (fuzz_target.type == FUZZ_TARGET_SYMBOL && fuzz_target.symbol != NULL) {
        global_free(fuzz_target.symbol, strlen(fuzz_target.symbol) + 1, HEAPSTAT_MISC);
    }
    memset(&fuzz_target, 0, sizeof(fuzz_target_t));
}

/***************************************************************************************
 * STRING TOKENIZER
 */

/* Simple string tokenizer that copies space-delimited tokens from a string. */

typedef struct _tokenizer_t {
    bool start;          /* whether any tokens have been copied from this tokenizer yet */
    const char *raw_src; /* original head of the src string (not moved by tokenization) */
    const char *src;     /* tokenizer src string (tokenizer does not write to it) */
    heapstat_t type;     /* allocation type */
} tokenizer_t;

#define RAW_SNIPPET_FORMAT "'%.32s%s'"
#define RAW_SNIPPET_ARGS(s) (s), strlen(s) > 32 ? "..." : ""

static void
tokenizer_init(tokenizer_t *t, const char *src, heapstat_t type)
{
    t->start = true;
    t->raw_src = src;
    t->src = src;
    t->type = type;
}

static void
tokenizer_exit_with_usage_error()
{
    NOTIFY_ERROR("Failed to configure the fuzz target. Exiting now."NL);
    dr_abort();
}

static bool
tokenizer_copy_to(IN tokenizer_t *t, IN const char *to, OUT size_t *len,
                  OUT char **token)
{
    *len = (to + 1/*null-term*/ - t->src);
    *token = global_alloc(*len, t->type);
    t->src = dr_get_token(t->src, *token, *len);
    ASSERT(t->src != NULL, "failed to parse a token from the user input");
    t->start = false;
    if (t->src == NULL) {
        global_free(*token, *len, t->type);
        return false;
    }
    return true;
}

static bool
tokenizer_copy_next(IN tokenizer_t *t, OUT size_t *len, OUT char **token,
                    IN char delimiter, IN const char *field_name)
{
    const char *src_ptr = NULL;

    if (*t->src != '\0')
        src_ptr = strchr(t->start ? t->src : ++t->src, ' ');
    if (src_ptr == NULL) {
        uint len = strlen(t->src);
        if (len == 0) { /* is there a tail on the string? */
            NOTIFY_ERROR("Missing %s in descriptor:"NL, field_name);
            NOTIFY_ERROR("did not find '%c' at position %d in "RAW_SNIPPET_FORMAT"."NL,
                         delimiter, t->src - t->raw_src,
                         RAW_SNIPPET_ARGS(fuzz_target.raw_descriptor));
            tokenizer_exit_with_usage_error();
            return false;
        }
        src_ptr = t->src + len; /* ok, copy the tail */
    }
    return tokenizer_copy_to(t, src_ptr, len, token);
}

static bool
tokenizer_next_uint(IN tokenizer_t *t, OUT uint *dst,
                    IN char delimiter, IN const char *field_name)
{
    size_t len;
    char *src;

    if (!tokenizer_copy_next(t, &len, &src, delimiter, field_name))
        return false;
    if (dr_sscanf(src, "%d", dst) != 1) {
        NOTIFY_ERROR("Failed to parse '%s' as the %s."NL, src, field_name);
        global_free(src, len, t->type);
        tokenizer_exit_with_usage_error();
    }
    global_free(src, len, t->type);
    return true;
}

/* Search `t->src` for the first instance of any character in the null-terminated array
 * `chrs`. If found, return true and point `res` to that character within `t->src`.
 */
static bool
tokenizer_strchrs(IN tokenizer_t *t, OUT const char **res, IN const char *chrs)
{
    const char *c, *c_ptr, *first_match = NULL;
    uint first_match_len = 0xffffffff;
    bool found = false;

    for (c = chrs; *c != '\0'; c++) {
        c_ptr = strchr(t->src, *c);
        if (c_ptr == NULL)
            continue;
        found = true;
        if ((c_ptr - t->src) < first_match_len) {
            first_match_len = (c_ptr - t->src);
            first_match = c_ptr;
        }
    }
    if (found)
        *res = first_match;
    return found;
}

/***************************************************************************************
 * DESCRIPTOR PARSER
 */

/* Parses the fuzz target descriptor specified by the user into `fuzz_target`. */

static bool
is_module_extension(const char *str)
{
#ifdef WINDOWS
    return strcasecmp(str, ".exe") == 0 || strcasecmp(str, ".dll") == 0;
#else
    return strcasecmp(str, ".so") == 0;
#endif
}

static inline void
replace_char(char *dst, char old, char new)
{
    char *next_old = strchr(dst, old);

    for (; next_old != NULL; next_old = strchr(next_old + 1, old))
        *next_old = new;
}

static bool
user_input_parse(char *descriptor)
{
    char *desc_ptr = NULL, *module_name, *function /*symbol or offset*/;
    const char function_separators[] = {MODULE_SEP, OFFSET_SEP, '\0'};
    size_t module_name_len, function_len;
    tokenizer_t tokens;

    LOG(1, LOG_PREFIX" Attempting to register fuzz target descriptor %s\n", descriptor);

    replace_char(descriptor, ' ', TEMP_SPACE_CHAR); /* replace spaces with placeholder */
    replace_char(descriptor, '|', ' '); /* replace pipes with spaces for dr_get_token() */

    tokenizer_init(&tokens, (const char *) descriptor /*tokenizer will not modify it*/,
                   HEAPSTAT_MISC);

    if (!tokenizer_strchrs(&tokens, (const char **) &desc_ptr, function_separators)) {
        NOTIFY_ERROR("Missing symbol or offset in descriptor:"NL);
        NOTIFY_ERROR("    did not find '!' or '+' in "RAW_SNIPPET_FORMAT"."NL,
                     RAW_SNIPPET_ARGS(fuzz_target.raw_descriptor));
        tokenizer_exit_with_usage_error();
    }
    switch (*desc_ptr) { /* must be one of `function_separators` */
    case MODULE_SEP:
        fuzz_target.type = FUZZ_TARGET_SYMBOL;
        break;
    case OFFSET_SEP:
        fuzz_target.type = FUZZ_TARGET_OFFSET;
        break;
    }
    *desc_ptr = ' '; /* change to a space for dr_get_token() */

    if (!tokenizer_copy_to(&tokens, desc_ptr, &module_name_len, &module_name))
        return false;

    if (strcmp(module_name, FUZZER_MAIN_MODULE_ALIAS) == 0) { /* if using <main> alias */
        module_data_t *main_module = dr_get_main_module();
        const char *main_module_name = dr_module_preferred_name(main_module);

        global_free(module_name, module_name_len, HEAPSTAT_MISC);
        if (main_module_name == NULL) {
            FUZZ_ERROR("Cannot resolve <main> alias in fuzz descriptor because "
                       "the main module name cannot be found.\n");
            return false;
        }
        module_name_len = strlen(main_module_name) + 1; /* resolve the <main> alias */
        fuzz_target.module_name = drmem_strdup(main_module_name, HEAPSTAT_MISC);
        dr_free_module_data(main_module);
    } else { /* copy the module name */
        fuzz_target.module_name = module_name;
    } /* end of obligation for module_name: it's either parked on fuzz_target or freed */

    if (!tokenizer_copy_next(&tokens, &function_len, &function, '|', "argument count"))
        return false;

    if (fuzz_target.type == FUZZ_TARGET_OFFSET) { /* XXX: it would be nice to test this */
        uint res = dr_sscanf(function, PIFX, &fuzz_target.offset);

        if (res != 1) {
            NOTIFY_ERROR("Failed to parse '%s' as an offset."NL, function);
            global_free(function, function_len, HEAPSTAT_MISC);
            tokenizer_exit_with_usage_error();
        }
        global_free(function, function_len, HEAPSTAT_MISC);
    } else {
        if (function[0] == '?') { /* for MSVC symbol, the module name is not needed */
            fuzz_target.symbol = function;
            replace_char(fuzz_target.symbol, AT_ESCAPE, '@'); /* restore escaped '@' */
        } else { /* rebuild "<module>!<symbol>" (without the module's file extension) */
            IF_DEBUG(uint len;)
            size_t alloc_size, module_symbol_len;
            char *module_symbol_name, *tail;

            /* copy out the part of the module name that is used in the symbol */
            module_symbol_len = module_name_len - 1/*null-term*/;
            tail = strrchr(fuzz_target.module_name, '.');
            if (tail != NULL && is_module_extension(tail))
                module_symbol_len = (tail - fuzz_target.module_name);
            module_symbol_name = drmem_strndup(fuzz_target.module_name,
                                               module_symbol_len, HEAPSTAT_MISC);

            /* allocate and construct the symbol */
            alloc_size = (function_len - 1/*null-term*/) + module_symbol_len +
                         1/*sep*/ + 1/*null-term*/;
            fuzz_target.symbol = global_alloc(alloc_size, HEAPSTAT_MISC);
            IF_DEBUG(len =)
                dr_snprintf(fuzz_target.symbol, alloc_size,
                            "%s%c%s", module_symbol_name, MODULE_SEP, function);
            ASSERT(len == (alloc_size - 1/*null-term*/),
                   "failed to construct the symbol name");

            global_free(module_symbol_name, module_symbol_len + 1/*null-term*/,
                        HEAPSTAT_MISC);
            global_free(function, function_len, HEAPSTAT_MISC);
        }
        replace_char(fuzz_target.symbol, TEMP_SPACE_CHAR, ' '); /* put the spaces back */
    } /* end of obligation for `function`: it's either parked on fuzz_target or freed */

    if (!tokenizer_next_uint(&tokens, &fuzz_target.arg_count, '|', "buffer arg"))
        return false;
    if (!tokenizer_next_uint(&tokens, &fuzz_target.buffer_arg, '|', "size arg"))
        return false;
    if (!tokenizer_next_uint(&tokens, &fuzz_target.size_arg, '|', "repeat count"))
        return false;
    if (!tokenizer_next_uint(&tokens, &fuzz_target.repeat_count, '|', "repeat count"))
        return false;

    return true;
}
