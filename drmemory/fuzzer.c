/* **********************************************************
 * Copyright (c) 2015-2017 Google, Inc.  All rights reserved.
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
#include "umbra.h"
#include "shadow.h"
#include "report.h"
#include "drwrap.h"
#include "drx.h"
#include "drfuzz_mutator.h"
#include "fuzzer.h"
#include "drmemory.h"
#include "drvector.h"
#include "alloc.h"

#ifdef UNIX
# include <dirent.h> /* opendir, readdir */
#else
# include <windows.h>
# include "dbghelp.h"
#endif

/* prefix for loading the descriptor from a file -- XXX i#1734: NYI */
#define DESCRIPTOR_PREFIX_FILE "file:"
#define DESCRIPTOR_PREFIX_FILE_LEN strlen(DESCRIPTOR_PREFIX_FILE)

#define MODULE_SEP '!'
#define OFFSET_SEP '+'
#define AT_ESCAPE '-'
#define TEMP_SPACE_CHAR '\1'
/* XXX i#1734: move this to drwrap.h */
#define CALLCONV_FLAG_SHIFT 0x18  /* offset of drwrap_callconv_t in drwrap_wrap_flags_t */
#define TARGET_BUFFER_TRUNC "..."
#define TARGET_BUFFER_TRUNC_LEN strlen(TARGET_BUFFER_TRUNC)
#define LOG_LEVEL_ELOG 0xffffffff

#define LOG_PREFIX "[fuzzer]"
#define FUZZ_ERROR(...) \
do { \
    ELOG(1, "ERROR: "LOG_PREFIX" "); \
    ELOG(1, __VA_ARGS__); \
} while (0)

#define FUZZ_REG_ERROR(...) \
do { \
    ELOG(1, "ERROR: "LOG_PREFIX" failed to register the fuzz target: "); \
    ELOG(1, __VA_ARGS__); \
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

typedef struct _callconv_args_t callconv_args_t; /* defined under shadow banner */

/* Maintains fuzzing data and state during a fuzz pass. One instance per thread. */
typedef struct _fuzz_state_t {
    bool repeat;
    uint repeat_index;
    uint skip_initial;       /* number of target invocations remaining to skip */
    thread_id_t thread_id;   /* always safe to access without lock */
    drfuzz_mutator_t *mutator;
    uint64 num_bbs;          /* number of basic blocks seen */

    /* fields for corpus based mutation */
    /* index in corpus_vec indicating which input file has been executed */
    uint   corpus_index;
    /* index in mutator_vec indicating which mutator to be used */
    uint   mutator_index;
    bool   should_mutate;    /* perform mutation on mutators from mutator_vec */
    bool   use_orig_input;   /* run with original input from app */

    /* While fields below are thread-local like the others, they may be read
     * by another thread at any time, i.e., during error reporting.
     * For error reporting code (e.g., fuzz_error_report) that may access other
     * thread's fuzz_state, fuzz_state_lock must be acquired before accessing them.
     * For code that accesses its own thread's fuzz_state, (e.g., pre_fuzz, post_fuzz,
     * load_fuzz_input, shadow_state_init, etc.) fuzz_state_lock is only required
     * before updating those fields.
     */
    byte *input_buffer;      /* reference to the fuzz target's buffer arg */
    size_t input_size;       /* size of the fuzz target's buffer arg */
} fuzz_state_t;

/* start of mutation region within the input_buffer */
#define MUTATION_START(buffer) ((buffer) + fuzz_target.buffer_offset)

/* List of the fuzz states for all process threads. Protected by fuzz_state_lock.
 * Xref comment above about which fuzz_state fields are safe to access with/without lock.
 */
typedef struct _fuzz_state_list_t {
    fuzz_state_t *state;
    struct _fuzz_state_list_t *next;
} fuzz_state_list_t;

static fuzz_state_list_t *state_list = NULL;

/* Definition of the fuzz target and its global state of registration and fuzzing. */
typedef struct _fuzz_target_t {
    fuzz_target_type_t type;
    bool enabled;
    generic_func_t pc;   /* start of the target instance that is being fuzzed */
    char *module_name;   /* when NULL, indicates no fuzzer target is active or pending */
    app_pc module_start; /* start pc of the module instance that is being fuzzed */
                         /* XXX i#1734: NYI multiple instances of the target module */
    union {
        size_t offset;
        char *symbol;
    };
    uint arg_count;         /* total number of arguments to the target */
    uint arg_count_regs;    /* number of target function arguments in registers */
    uint arg_count_stack;   /* number of target function arguments on the stack */
    uint buffer_arg;
    uint size_arg;
    uint buffer_fixed_size; /* constrains mutation to a fixed number of bytes */
    uint buffer_offset;     /* constrains mutation to start at an offset in the buffer */
     int repeat_count;      /* number of times to fuzz the target (-1 means indefinite) */
    uint skip_initial;      /* number of target invocations each thread should skip */
    uint stat_freq;
    const char *singleton_input;
    drwrap_callconv_t callconv;
    const callconv_args_t *callconv_args;
    bool use_coverage;      /* use basic block coverage info for mutation */
    /* fields that need fuzz_target_lock for synchronized update */
    thread_id_t tid;        /* the thread that performs fuzzing */
} fuzz_target_t;

static fuzz_target_t fuzz_target;

/* Synchronize the fuzz_target fields update */
static void *fuzz_target_lock;


/* Tables for corpus based fuzzing.
 * FIXME i#1842: we do not support multiple threads fuzzing the same target function.
 */
/* The corpus_vec stores corpus input file names.
 * All its operations are synchronized.
 */
drvector_t corpus_vec;
/* The mutator_vec stores created mutators.
 * All its operations are synchronized.
 */
drvector_t mutator_vec;
#define CORPUS_VEC_INIT_SIZE 64
#define MUTATOR_VEC_INIT_SIZE 64

static drfuzz_mutator_api_t mutator_api = {sizeof(mutator_api),};
static int mutator_argc;
static char **mutator_argv;

static bool fuzzer_initialized;

/* Protects the fuzz_state_t fields input_buffer and input_size for access from
 * other threads while the fuzz_state_t owner thread is fuzzing its target. Also
 * protects the state_list during thread init/exit and error reporting.
 */
static void *fuzz_state_lock;

static int tls_idx_fuzzer;

static void
module_loaded(void *drcontext, const module_data_t *module, bool loaded);

static void
module_unloaded(void *drcontext, const module_data_t *module);

static bool
register_fuzz_target(const module_data_t *module);

static void
tokenizer_exit_with_usage_error();

static bool
user_input_parse_target(char *descriptor, const char *raw_descriptor);

static void
free_fuzz_target();

static void
thread_init(void *dcontext);

static void
thread_exit(void *dcontext);

static bool
fuzzer_fuzz_target_callconv_arg_init();

static void
fuzzer_option_init();

static void
fuzzer_mutator_option_exit(void);

static drfuzz_mutator_t *
fuzzer_mutator_copy(void *dcontext, fuzz_state_t *state);

static ssize_t
load_fuzz_corpus_input(void *dcontext, const char *fname, fuzz_state_t *state);

static bool
dump_fuzz_corpus_input(void *dcontext, fuzz_state_t *state);

static void
mutator_vec_entry_free(void *entry)
{
    mutator_api.drfuzz_mutator_stop(entry);
}

static void
corpus_vec_entry_free(void *entry)
{
    global_free(entry, strlen(entry) + 1, HEAPSTAT_MISC);
}

/* Called once at initialization to read the corpus file list for loading later. */
#ifdef UNIX
static bool
fuzzer_read_corpus_list(void)
{
    DIR *dir;
    struct dirent *ent;

    LOG(2, "Reading corpus directory %s\n", options.fuzz_corpus);
    dir = opendir(options.fuzz_corpus);
    if (dir == NULL) {
        /* could not open directory */
        FUZZ_ERROR("Failed to open directory '%s'"NL, options.fuzz_corpus);
        return false;
    }
    for (ent = readdir(dir); ent != NULL; ent = readdir(dir)) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        /* add corpus into the vector for later execution */
        drvector_append(&corpus_vec, drmem_strdup(ent->d_name, HEAPSTAT_MISC));
    }
    closedir(dir);
    return true;
}
#else
static bool
fuzzer_read_corpus_list(void)
{
    HANDLE h_find = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA ffd;
    char path[MAXIMUM_PATH];

    /* append \* to the end */
    dr_snprintf(path, BUFFER_SIZE_ELEMENTS(path), "%s\\*", options.fuzz_corpus);
    NULL_TERMINATE_BUFFER(path);
    LOG(2, "Reading corpus directory %s\n", path);
    h_find = FindFirstFile(path, &ffd);
    if (h_find == INVALID_HANDLE_VALUE) {
        ASSERT(false, "Failed to read corpus directory\n");
        return false;
    }
    do {
        if (!TESTANY(ffd.dwFileAttributes, FILE_ATTRIBUTE_DIRECTORY))
            drvector_append(&corpus_vec, drmem_strdup(ffd.cFileName, HEAPSTAT_MISC));
    } while (FindNextFile(h_find, &ffd) != 0);
    FindClose(h_find);
    return true;
}
#endif

static inline void
replace_char(char *dst, char old, char new)
{
    char *next_old = strchr(dst, old);

    for (; next_old != NULL; next_old = strchr(next_old + 1, old))
        *next_old = new;
}

void
fuzzer_init(client_id_t client_id)
{
    fuzz_state_lock = dr_mutex_create();
    fuzz_target_lock = dr_mutex_create();

    drmgr_init();
    if (drfuzz_init(client_id) != DRMF_SUCCESS)
        ASSERT(false, "fail to init Dr. Fuzz");

    tls_idx_fuzzer = drmgr_register_tls_field();
    if (tls_idx_fuzzer < 0) {
        NOTIFY_ERROR("Fuzzer failed to reserve a TLS slot."NL);
        dr_abort();
    }

    if (!drmgr_register_thread_init_event(thread_init))
        ASSERT(false, "fail to register thread init event");
    if (!drmgr_register_thread_exit_event(thread_exit))
        ASSERT(false, "fail to register thread exit event");
    if (!drmgr_register_module_load_event(module_loaded))
        ASSERT(false, "fail to register module load event");
    if (!drmgr_register_module_unload_event(module_unloaded))
        ASSERT(false, "fail to register module unload event");

#ifdef WINDOWS
    if (option_specified.fuzz_mangled_names)
        SymSetOptions(SymGetOptions() & ~SYMOPT_UNDNAME);
#endif

    fuzzer_initialized = true;
    fuzzer_option_init();
    if (option_specified.fuzz_corpus) {
        drvector_init(&corpus_vec, CORPUS_VEC_INIT_SIZE, true/*sync*/,
                      corpus_vec_entry_free);
        drvector_init(&mutator_vec, MUTATOR_VEC_INIT_SIZE, true/*sync*/,
                      mutator_vec_entry_free);
        if (!dr_directory_exists(options.fuzz_corpus) || !fuzzer_read_corpus_list()) {
            NOTIFY_ERROR("Fuzzer failed to read corpus list."NL);
            dr_abort();
        }
        if (option_specified.fuzz_corpus_out &&
            !dr_directory_exists(options.fuzz_corpus_out)) {
            NOTIFY_ERROR("Corpus output directory %s does not exist."NL,
                         options.fuzz_corpus_out);
            dr_abort();
        }
    }
}

void
fuzzer_exit()
{
    uint64 num_bbs;

    if (option_specified.fuzz_corpus) {
        drvector_delete(&mutator_vec);
        drvector_delete(&corpus_vec);
    }
    fuzzer_mutator_option_exit();

    free_fuzz_target();

    dr_mutex_destroy(fuzz_state_lock);
    dr_mutex_destroy(fuzz_target_lock);

    drfuzz_get_target_num_bbs(NULL, &num_bbs);
    LOG(1, LOG_PREFIX" "SZFMT" basic blocks seen during execution.\n", num_bbs);

    if (drfuzz_exit() != DRMF_SUCCESS)
        ASSERT(false, "fail to exit Dr. Fuzz");
    drmgr_exit();
}

static void
fuzzer_fuzz_target_init()
{
    module_data_t *module;
    /* module */
    if (!option_specified.fuzz_module) {
        module = dr_get_main_module();
        fuzz_target.module_name = drmem_strdup(dr_module_preferred_name(module),
                                               HEAPSTAT_MISC);
        dr_free_module_data(module);
    } else {
        fuzz_target.module_name = drmem_strdup(options.fuzz_module, HEAPSTAT_MISC);
    }
    /* function/offset */
    if (option_specified.fuzz_offset) {
        fuzz_target.type = FUZZ_TARGET_OFFSET;
        fuzz_target.offset = options.fuzz_offset;
    } else {
        fuzz_target.type = FUZZ_TARGET_SYMBOL;
        fuzz_target.symbol = drmem_strdup(options.fuzz_function, HEAPSTAT_MISC);
        /* We replaced '@' with '-' in MSVC symbol for testing, now replace it back. */
        if (fuzz_target.symbol[0] == '?') /* for MSVC symbol */
            replace_char(fuzz_target.symbol, AT_ESCAPE, '@'); /* restore escaped '@' */
    }
    /* args */
    fuzz_target.arg_count    = options.fuzz_num_args;
    fuzz_target.buffer_arg   = options.fuzz_data_idx;
    fuzz_target.size_arg     = options.fuzz_size_idx;
    fuzz_target.repeat_count = options.fuzz_num_iters;
    if (!option_specified.fuzz_call_convention)
        fuzz_target.callconv = DRWRAP_CALLCONV_DEFAULT;
    else {
        if (strcmp(options.fuzz_call_convention, "stdcall") == 0)
            fuzz_target.callconv = DRWRAP_CALLCONV_CDECL;
        else if (strcmp(options.fuzz_call_convention, "fastcall") == 0)
            fuzz_target.callconv = DRWRAP_CALLCONV_FASTCALL;
        else if (strcmp(options.fuzz_call_convention, "thiscall") == 0)
            fuzz_target.callconv = DRWRAP_CALLCONV_THISCALL;
#ifdef X64
# ifdef UNIX
        else if (strcmp(options.fuzz_call_convention, "amd64") == 0)
            fuzz_target.callconv = DRWRAP_CALLCONV_AMD64;
# else
        else if (strcmp(options.fuzz_call_convention, "ms64") == 0)
            fuzz_target.callconv = DRWRAP_CALLCONV_MICROSOFT_X64;
# endif /* UNIX/WINDOWS */
#endif
#ifdef ARM
        else if (strcmp(options.fuzz_call_convention, "arm32") == 0)
            fuzz_target.callconv = DRWRAP_CALLCONV_ARM;
#endif
        else
            FUZZ_WARN("Unknown calling convention, using default value instead.\n");
    }
    fuzzer_fuzz_target_callconv_arg_init();
}

static bool
fuzzer_mutator_option_init(void)
{
    drvector_t vec;
    int i;
#   define MAX_TOKEN_SIZE 1024
    char buf[MAX_TOKEN_SIZE];

    if (option_specified.fuzz_mutator_lib) {
        if (drfuzz_mutator_load(options.fuzz_mutator_lib, &mutator_api) !=
            DRMF_SUCCESS) {
            NOTIFY_ERROR("Failed to load mutator library '%s'"NL,
                         options.fuzz_mutator_lib);
            dr_abort();
            return false; /* won't be reached */
        }
        NOTIFY("Using custom fuzz mutator '%s'"NL, options.fuzz_mutator_lib);
    } else {
        if (drfuzz_mutator_load(NULL, &mutator_api) != DRMF_SUCCESS) {
            NOTIFY_ERROR("Failed to load default mutator library"NL);
            dr_abort();
            return false; /* won't be reached */
        }
    }

    if (!drvector_init(&vec, 16, false/*!synch*/, NULL)) {
        NOTIFY_ERROR("Failed to initialize vector"NL);
        dr_abort();
        return false; /* won't be reached */
    }
    if (option_specified.fuzz_mutator_ops) {
        const char *s;
        s = dr_get_token(options.fuzz_mutator_ops, buf, BUFFER_SIZE_ELEMENTS(buf));
        do {
            drvector_append(&vec, drmem_strdup(buf, HEAPSTAT_MISC));
            s = dr_get_token(s, buf, BUFFER_SIZE_ELEMENTS(buf));
        } while (s != NULL);
    }

    if (option_specified.fuzz_mutator_alg) {
        drvector_append(&vec, drmem_strdup("-alg", HEAPSTAT_MISC));
        drvector_append(&vec, drmem_strdup(options.fuzz_mutator_alg, HEAPSTAT_MISC));
    }
    if (option_specified.fuzz_mutator_unit) {
        drvector_append(&vec, drmem_strdup("-unit", HEAPSTAT_MISC));
        drvector_append(&vec, drmem_strdup(options.fuzz_mutator_unit, HEAPSTAT_MISC));
    }
    if (option_specified.fuzz_mutator_flags) {
        dr_snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), "0x%x", options.fuzz_mutator_flags);
        NULL_TERMINATE_BUFFER(buf);
        drvector_append(&vec, drmem_strdup("-flags", HEAPSTAT_MISC));
        drvector_append(&vec, drmem_strdup(buf, HEAPSTAT_MISC));
    }
    if (option_specified.fuzz_mutator_sparsity) {
        dr_snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), "%d", options.fuzz_mutator_sparsity);
        NULL_TERMINATE_BUFFER(buf);
        drvector_append(&vec, drmem_strdup("-sparsity", HEAPSTAT_MISC));
        drvector_append(&vec, drmem_strdup(buf, HEAPSTAT_MISC));
    }
    if (option_specified.fuzz_mutator_max_value) {
        dr_snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), UINT64_FORMAT_STRING,
                    options.fuzz_mutator_max_value);
        NULL_TERMINATE_BUFFER(buf);
        drvector_append(&vec, drmem_strdup("-max_value", HEAPSTAT_MISC));
        drvector_append(&vec, drmem_strdup(buf, HEAPSTAT_MISC));
    }
    if (option_specified.fuzz_mutator_random_seed) {
        dr_snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), UINT64_FORMAT_STRING,
                    options.fuzz_mutator_random_seed);
        NULL_TERMINATE_BUFFER(buf);
        drvector_append(&vec, drmem_strdup("-random_seed", HEAPSTAT_MISC));
        drvector_append(&vec, drmem_strdup(buf, HEAPSTAT_MISC));
    }
    if (option_specified.fuzz_dictionary) {
        drvector_append(&vec, drmem_strdup("-unit", HEAPSTAT_MISC));
        drvector_append(&vec, drmem_strdup("token", HEAPSTAT_MISC));
        drvector_append(&vec, drmem_strdup("-dictionary", HEAPSTAT_MISC));
        drvector_append(&vec, drmem_strdup(options.fuzz_dictionary, HEAPSTAT_MISC));
    }

    mutator_argc = vec.entries;
    mutator_argv = (char **) global_alloc((mutator_argc+1) * sizeof(char*), HEAPSTAT_MISC);
    for (i = 0; i < mutator_argc; i++)
        mutator_argv[i] = (char *) drvector_get_entry(&vec, i);
    mutator_argv[i] = NULL;
    drvector_delete(&vec);

    return true;
}

static void
fuzzer_mutator_option_exit(void)
{
    int i;
    for (i = 0; i < mutator_argc; i++)
        global_free(mutator_argv[i], strlen(mutator_argv[i]) + 1, HEAPSTAT_MISC);
    global_free(mutator_argv, (mutator_argc+1) * sizeof(char*), HEAPSTAT_MISC);
}

static void
fuzzer_option_init()
{
    if (option_specified.fuzz_target)
        fuzzer_fuzz_target(options.fuzz_target);
    else
        fuzzer_fuzz_target_init();
    fuzzer_mutator_option_init();
    if (option_specified.fuzz_one_input)
        fuzzer_set_singleton_input(options.fuzz_one_input);

    if (options.fuzz_coverage)
        fuzz_target.use_coverage = true;
    fuzz_target.buffer_fixed_size = options.fuzz_buffer_fixed_size;
    fuzz_target.buffer_offset = options.fuzz_buffer_offset;
    fuzz_target.skip_initial = options.fuzz_skip_initial;
    fuzz_target.stat_freq = options.fuzz_stat_freq;
}

bool
fuzzer_fuzz_target(const char *target_descriptor)
{
    char *descriptor_copy; /* writable working copy */
    module_data_t *module;

    if (!fuzzer_initialized)
        return false;

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
    }

    descriptor_copy = drmem_strdup(target_descriptor, HEAPSTAT_MISC);
    if (user_input_parse_target(descriptor_copy, target_descriptor)) {
        /* register the target now if the module is loaded */
        module = dr_lookup_module_by_name(fuzz_target.module_name);
        if (module == NULL) {
            LOG(1, LOG_PREFIX" Skipping fuzz target for now because "
                "module %s is not loaded now.\n", fuzz_target.module_name);
        } else {
            if (register_fuzz_target(module))
                fuzz_target.enabled = true;
            dr_free_module_data(module);
        }
    }

    if (!fuzz_target.enabled)
        free_fuzz_target();

    global_free(descriptor_copy, strlen(descriptor_copy) + 1/*null-term*/, HEAPSTAT_MISC);
    return fuzz_target.module_name != NULL;
}

bool
fuzzer_unfuzz_target()
{
    bool success = false;

    if (fuzz_target.enabled) {
        drmf_status_t res = drfuzz_unfuzz_target(fuzz_target.pc);
        if (res != DRMF_SUCCESS)
            FUZZ_ERROR("failed to unfuzz the target "PIFX"\n", fuzz_target.pc);
        free_fuzz_target();
        success = (res == DRMF_SUCCESS);
    }

    return success;
}

void
fuzzer_set_singleton_input(const char *input_value)
{
    fuzz_target.singleton_input = input_value;
}

static byte *
drfuzz_reallocate_buffer(void *drcontext, size_t size, app_pc caller)
{
    void *ptr = client_app_malloc(drcontext, size, caller);
    if (ptr == NULL)
        FUZZ_ERROR("Failed to allocate fuzz input buffer."NL);
    return (byte *)ptr;
}

static void
drfuzz_free_reallocated_buffer(void *drcontext, void *ptr, app_pc caller)
{
    client_app_free(drcontext, ptr, caller);
}

static ssize_t
load_fuzz_input(void *dcontext, const char *fname, fuzz_state_t *state)
{
    file_t data;
    ssize_t read_size;
    uint64 file_size;
    byte *input_buffer = NULL, *to_free = NULL;

    data = dr_open_file(fname, DR_FILE_READ);
    if (data == INVALID_FILE) {
        FUZZ_ERROR("Failed to open fuzz input file."NL);
        return 0;
    }

    /* We need to hold fuzz_state_lock for updating input_buffer/input_size fields
     * but cannot hold a lock when we alloc/free application memory, so we split
     * the code and put the memory alloc/free code outside.
     */
    /* alloc if necessary */
    if (options.fuzz_replace_buffer) {
        if (!dr_file_size(data, &file_size)) {
            FUZZ_ERROR("Failed to get input file size."NL);
            file_size = (uint64)state->input_size;
        } else if (file_size == 0) {
            FUZZ_WARN("Empty file."NL);
            return 0;
        } else if (state->input_size < (size_t)file_size) {
            /* We only reallocate the buffer if we cannot fit the input data into
             * the current input buffer.
             * By doing that, we are able to support multiple mutators without
             * keeping track of the input size of each mutator.
             * Xref pre_fuzz_corpus() about pick a mutator for fuzzing.
             */
            input_buffer = drfuzz_reallocate_buffer(dcontext, (size_t)file_size,
                                                    (app_pc)fuzz_target.pc);
        }
    }
    /* update input_buffer/input_size */
    dr_mutex_lock(fuzz_state_lock);
    if (options.fuzz_replace_buffer && input_buffer != NULL) {
        to_free = state->input_buffer;
        state->input_size = (size_t)file_size;
        state->input_buffer = input_buffer;
    }
    /* read at most input_size */
    read_size = dr_read_file(data, state->input_buffer, state->input_size);
    dr_mutex_unlock(fuzz_state_lock);
    LOG(2, LOG_PREFIX" Load %d bytes from %s to "PFX"."NL,
        read_size, fname, state->input_buffer);
    /* free if necessary */
    if (to_free != NULL)
        drfuzz_free_reallocated_buffer(dcontext, to_free, (app_pc)fuzz_target.pc);

    if (read_size <= 0) {
        FUZZ_ERROR("Failed to read fuzz input file."NL);
        return 0;
    }
    /* FIXME i#1734: we may need to update shadow state for loaded data */
    return read_size;
}

static ssize_t
load_fuzz_corpus_input(void *dcontext, const char *fname, fuzz_state_t *state)
{
    char path[MAXIMUM_PATH];
    if (dr_snprintf(path, BUFFER_SIZE_ELEMENTS(path),
                    "%s%c%s", options.fuzz_corpus, DIRSEP, fname) <= 0) {
        FUZZ_WARN("Failed to get full path of log file %s\n", fname);
        return -1;
    }
    return load_fuzz_input(dcontext, path, state);
}

static bool
dump_fuzz_input(fuzz_state_t *state, const char *logdir, char *suffix,
                char *path, size_t size)
{
    file_t data = drx_open_unique_appid_file(logdir,
                                             dr_get_process_id(),
                                             "fuzz", suffix, 0, path, size);
    if (data == INVALID_FILE) {
        FUZZ_ERROR("Failed to create/dump fuzz input to file."NL);
        return false;
    }
    if (dr_write_file(data, state->input_buffer, state->input_size) !=
        state->input_size) {
        FUZZ_ERROR("Partial fuzz input is dumped to file."NL);
    }
    dr_close_file(data);
    LOG(2, LOG_PREFIX" Dumped input to file %s."NL, path);
    return true;
}

/* dump current fuzz input data into corpus directory */
#define CORPUS_FILE_SUFFIX "corpus.dat"
static bool
dump_fuzz_corpus_input(void *dcontext, fuzz_state_t *state)
{
    char suffix[32];
    char *logdir;
    char path[MAXIMUM_PATH];
    logdir = option_specified.fuzz_corpus_out ?
        options.fuzz_corpus_out : options.fuzz_corpus;
    dr_snprintf(suffix, BUFFER_SIZE_ELEMENTS(suffix), CORPUS_FILE_SUFFIX);
    NULL_TERMINATE_BUFFER(suffix);
    return dump_fuzz_input(state, logdir, suffix, path, BUFFER_SIZE_ELEMENTS(path));
}

static bool
dump_fuzz_error_input(fuzz_state_t *state, char *buffer, size_t buffer_size,
                      size_t *sofar, ssize_t *len, char *prefix, int eid)
{
    char suffix[32];
    char path[MAXIMUM_PATH];
    const char *dump_dir;
    dr_snprintf(suffix, BUFFER_SIZE_ELEMENTS(suffix), "error.%d.dat", eid);
    NULL_TERMINATE_BUFFER(suffix);
    /* we prefer corpus directory over log directory */
    dump_dir = option_specified.fuzz_corpus_out ?
        options.fuzz_corpus_out :
        (option_specified.fuzz_corpus ? options.fuzz_corpus : logsubdir);
    if (dump_fuzz_input(state, dump_dir, suffix, path, BUFFER_SIZE_ELEMENTS(path))) {
        BUFPRINT(buffer, buffer_size, *sofar, *len,
                 "%sfuzz input for error #%d is stored in file %s\n",
                 prefix, eid, path);
        return true;
    } else {
        BUFPRINT(buffer, buffer_size, *sofar, *len,
                 "%sfailed to dump fuzz input for error #%d to file %s\n",
                 prefix, eid, path);
    }
    return false;
}

static void
print_fuzz_input(fuzz_state_t *state, char *buffer, size_t buffer_size,
                 size_t *sofar, ssize_t *len, const char *prefix)
{
    uint i;

    BUFPRINT(buffer, buffer_size, *sofar, *len, NL"%s"NL"%s", prefix, prefix);
#define MAX_DWORD_PER_LINE 8
#define MAX_PRINT_PER_LINE \
    (strlen(prefix) + (8/*char*/+1/*space*/)*MAX_DWORD_PER_LINE + 2/*NL*/)
    ASSERT(state->input_size < (4/*byte*/*MAX_DWORD_PER_LINE) /* small input */||
           (buffer_size - *sofar) > MAX_PRINT_PER_LINE,
           "buffer too small");
    for (i = 0; i < state->input_size; i++) { /* print in lexical byte order */
        BUFPRINT(buffer, buffer_size, *sofar, *len, "%02x", state->input_buffer[i]);
        if ((i % (4*MAX_DWORD_PER_LINE)) == (4*MAX_DWORD_PER_LINE-1) &&
            i < (state->input_size - 1)) /* avoid extra newline when it ends flush */ {
            if (buffer_size - *sofar > MAX_PRINT_PER_LINE) {
                /* start a new line */
                BUFPRINT(buffer, buffer_size, *sofar, *len, NL"%s", prefix);
            } else {
                /* not enough to print a new line, backtrack and print "..." */
                *sofar -= TARGET_BUFFER_TRUNC_LEN + 1/*NULL TERM*/;
                BUFPRINT(buffer, buffer_size, *sofar, *len, TARGET_BUFFER_TRUNC);
                break;
            }
        } else if ((i % 4) == 3)
            BUFPRINT(buffer, buffer_size, *sofar, *len, " "); /* space between dwords */
    }
    BUFPRINT(buffer, buffer_size, *sofar, *len, NL"%s"NL, prefix);
}

static inline void
log_target_buffer(void *dcontext, uint loglevel, fuzz_state_t *thread)
{
    char *buffer;
    ssize_t len = 0;
    size_t sofar = 0, buffer_size;

    buffer_size = (thread->input_size * 2) /*two chars per byte*/ +
                  (thread->input_size / 4) /*space between dwords*/ +
                  ((thread->input_size / 32) * sizeof(NL)) /*internal newline*/ +
                  (sizeof(NL) * 4) /*newlines top and bottom*/ + 1 /*null-term*/;
    buffer = thread_alloc(dcontext, buffer_size, HEAPSTAT_MISC);
    print_fuzz_input(thread, buffer, buffer_size, &sofar, &len, ""/*no prefix*/);
    ASSERT(sofar <= buffer_size, "buffer overflowed the expected size");
    if (loglevel == LOG_LEVEL_ELOG)
        ELOG(1, buffer);
    else
        LOG(loglevel, buffer);
    thread_free(dcontext, buffer, buffer_size, HEAPSTAT_MISC);
}

size_t
fuzzer_error_report(IN void *dcontext, OUT char *notify, IN size_t notify_size, int eid)
{
    ssize_t len = 0;
    size_t sofar = 0;
    fuzz_state_t *this_thread, *report_thread = NULL;
    uint fuzzing_thread_count = 0;
    fuzz_state_list_t *next;

    if (!fuzzer_initialized)
        return 0;

    if (dcontext == NULL)
        dcontext = dr_get_current_drcontext();
    this_thread = drmgr_get_tls_field(dcontext, tls_idx_fuzzer);

    /* If TLS is cleaned up already, the process must be exiting, so skip the fuzzer
     * state report b/c fuzz state is irrelevant to all errors reported at exit time.
     */
    if (this_thread == NULL)
        return 0;

    dr_mutex_lock(fuzz_state_lock);

    if (this_thread->input_size > 0)
        report_thread = this_thread;
    next = state_list;
    while (next != NULL) {
        if (next->state->input_size > 0) {
            fuzzing_thread_count++;

            ELOG(1, "Thread %d was executing a fuzz target with buffer value:");
            log_target_buffer(dcontext, LOG_LEVEL_ELOG, this_thread);

            if (report_thread == NULL)       /* look for a single other thread fuzzing */
                report_thread = next->state; /* (ignored if fuzzing_thread_count > 1)  */
        }
        next = next->next;
    }

    if (fuzzing_thread_count > 0) {
        if (options.fuzz_dump_on_error) {
            dump_fuzz_error_input(this_thread, notify, notify_size, &sofar,
                                  &len, INFO_PFX, eid);
        } else {
            BUFPRINT(notify, notify_size, sofar, len,
                     INFO_PFX"%d threads were executing fuzz targets."NL""INFO_PFX,
                     fuzzing_thread_count);
            if (report_thread == this_thread || fuzzing_thread_count == 1) {
                if (report_thread == this_thread) {
                    BUFPRINT(notify, notify_size, sofar, len, "The error thread");
                } else { /* XXX i#1734: would like to have a test for this case */
                    BUFPRINT(notify, notify_size, sofar, len,
                             "Thread id %d", report_thread->thread_id);
                }
                BUFPRINT(notify, notify_size, sofar, len,
                         " was executing the fuzz target with input value:");
                print_fuzz_input(this_thread, notify, notify_size, &sofar, &len, INFO_PFX);
                ASSERT(sofar <= notify_size, "buffer overflowed the expected size");
            }
        }
    }

    dr_mutex_unlock(fuzz_state_lock);
    return sofar;
}

/***************************************************************************************
 * SHADOW MEMORY SAVE/RESTORE
 */

/* Save shadow state at the beginning of each fuzz pass, and restore it on each
 * subsequent iteration of the fuzz target during the pass.
 *
 * XXX i#1734: assumes cdecl calling convention and shadow memory density
 * of 2 bits per byte. Code requires update when alternatives are implemented.
 */

struct _callconv_args_t { /* forward declared at top */
    const reg_t *regs;
    uint reg_count;
    uint stack_offset; /* retaddr (1) and/or reserved slots */
};

#ifdef ARM /* 32-bit */
# ifdef X64
#  error NYI ARM X64
# else /* 32-bit */
static const reg_t arg_regs_arm[] = {
    DR_REG_R0,
    DR_REG_R1,
    DR_REG_R2,
    DR_REG_R3
};
static const callconv_args_t callconv_args_arm = { arg_regs_arm, 4, 0 };
# endif
#else /* Intel x86 */
# ifdef X64 /* UNIX or WINDOWS */
static const reg_t arg_regs_amd64[] = {
    DR_REG_XDI,
    DR_REG_XSI,
    DR_REG_XDX,
    DR_REG_XCX,
    DR_REG_R8,
    DR_REG_R9
};
static const reg_t arg_regs_ms64[] = {
    DR_REG_XCX,
    DR_REG_XDX,
    DR_REG_R8,
    DR_REG_R9
};
static const callconv_args_t callconv_args_amd64 = { arg_regs_amd64, 6, 1 };
static const callconv_args_t callconv_args_ms64 = { arg_regs_ms64, 4, 1 + 4/*reserved*/ };
# endif /* x64 */
static const reg_t arg_regs_fastcall[] = {
    DR_REG_XCX,
    DR_REG_XDX
};
static const reg_t arg_regs_thiscall[] = {
    DR_REG_XCX
};
static const callconv_args_t callconv_args_fastcall = { arg_regs_fastcall, 2, 1 };
static const callconv_args_t callconv_args_thiscall = { arg_regs_thiscall, 1, 1 };
static const callconv_args_t callconv_args_cdecl = { NULL, 0, 1 };
#endif

static const callconv_args_t *
map_callconv_args(drwrap_callconv_t callconv)
{
    switch (callconv) {
#ifdef ARM
    case DRWRAP_CALLCONV_ARM:
        return &callconv_args_arm;
#else /* Intel x86 */
# ifdef X64
    case DRWRAP_CALLCONV_AMD64:
        return &callconv_args_amd64;
    case DRWRAP_CALLCONV_MICROSOFT_X64:
        return &callconv_args_ms64;
# endif
    case DRWRAP_CALLCONV_CDECL:
        return &callconv_args_cdecl;
    case DRWRAP_CALLCONV_FASTCALL:
        return &callconv_args_fastcall;
    case DRWRAP_CALLCONV_THISCALL:
        return &callconv_args_thiscall;
#endif
    default: return NULL;
    }
}

static bool
fuzzer_fuzz_target_callconv_arg_init()
{
    fuzz_target.callconv_args = map_callconv_args(fuzz_target.callconv);
    if (fuzz_target.callconv_args == NULL) {
        NOTIFY_ERROR("Descriptor specifies unknown calling convention id %d"NL,
                     fuzz_target.callconv);
        FUZZ_ERROR("Descriptor specifies unknown calling convention id %d\n",
                   fuzz_target.callconv);
        return false;
    }
    fuzz_target.arg_count_regs = MIN(fuzz_target.arg_count,
                                     fuzz_target.callconv_args->reg_count);
    fuzz_target.arg_count_stack = fuzz_target.arg_count - fuzz_target.arg_count_regs;
    IF_DEBUG({
        if (fuzz_target.callconv_args->regs != NULL)
            ASSERT_NOT_TESTED("Save and restore shadow registers");
    });
    return true;
}

/* simple heuristic to detect incorrect buffer arg index */
#define MAX_EXPECTED_BUFFER_SIZE (64*1024*1024) /* 64MB */

/* stores shadow memory state for an instance of the fuzz target (per thread) */
typedef struct _shadow_state_t {
    uint *reg_args;   /* saved shadow memory state of the register args */
    byte *app_start;  /* reference to the fuzz target's buffer arg */
    size_t app_size;  /* size of the fuzz target's buffer arg */
    shadow_buffer_t *buffer_shadow; /* shadow memory state of the target's buffer arg */
    shadow_buffer_t *stack_shadow;  /* shadow memory state of the target's stack args */
} shadow_state_t;

#define SIZEOF_SHADOW_STATE() \
    (sizeof(shadow_state_t) + (fuzz_target.callconv_args->reg_count * sizeof(uint)))

/* Save shadow state for the arg registers and stack frame. */
static inline void
shadow_state_save_stack_frame(dr_mcontext_t *mc, shadow_state_t *shadow)
{
    uint i;

    for (i = 0; i < fuzz_target.arg_count_regs; i++)
        shadow->reg_args[i] = get_shadow_register(fuzz_target.callconv_args->regs[i]);
    if (fuzz_target.arg_count > fuzz_target.callconv_args->reg_count ||
        fuzz_target.callconv_args->stack_offset > 0) {
        size_t stack_ret_size = fuzz_target.callconv_args->stack_offset * sizeof(reg_t);
        size_t stack_arg_size = (fuzz_target.arg_count_stack * sizeof(reg_t));
        /* save shadow state for arg and return addr */
        shadow->stack_shadow = shadow_save_region((app_pc)(mc->xsp),
                                                  stack_ret_size + stack_arg_size);
    }
}

/* Restore shadow state for the arg registers and stack frame. */
static inline void
shadow_state_restore_stack_frame(dr_mcontext_t *mc, shadow_state_t *shadow)
{
    uint i;

    for (i = 0; i < fuzz_target.arg_count_regs; i++) {
        register_shadow_set_ptrsz(fuzz_target.callconv_args->regs[i],
                                  shadow->reg_args[i]);
    }
    if (shadow->stack_shadow != NULL)
        shadow_restore_region(shadow->stack_shadow);
}

static void
free_shadow_buffers(shadow_state_t *shadow)
{
    if (shadow->buffer_shadow != NULL) {
        shadow_free_buffer(shadow->buffer_shadow);
        shadow->buffer_shadow = NULL;
    }
    if (shadow->stack_shadow != NULL) {
        shadow_free_buffer(shadow->stack_shadow);
        shadow->stack_shadow = NULL;
    }
}

static void
free_shadow_state(void *dcontext, shadow_state_t *shadow)
{
    free_shadow_buffers(shadow); /* in case fuzzing was interrupted by an error */
    thread_free(dcontext, shadow, SIZEOF_SHADOW_STATE(), HEAPSTAT_MISC);
}

/* `fuzzcxt` may be NULL */
static void
free_shadow_state_per_target(void *fuzzcxt, void *p)
{
    free_shadow_state(drfuzz_get_drcontext(fuzzcxt), (shadow_state_t *) p);
}

static inline shadow_state_t *
create_shadow_state(void *dcontext)
{
    size_t size = SIZEOF_SHADOW_STATE();
    shadow_state_t *shadow = thread_alloc(dcontext, size, HEAPSTAT_MISC);
    memset(shadow, 0, sizeof(shadow_state_t));
    if (fuzz_target.callconv_args->reg_count > 0)
        shadow->reg_args = (uint *) ((byte *) shadow + sizeof(shadow_state_t));
    else
        shadow->reg_args = NULL;
    return shadow;
}

static bool
init_thread_shadow_state(OUT shadow_state_t **shadow_out)
{
    drmf_status_t res;
    shadow_state_t *shadow;
    void *fuzzcxt = drfuzz_get_fuzzcxt();
    void *dcontext = drfuzz_get_drcontext(fuzzcxt);

    res = drfuzz_get_target_per_thread_user_data(fuzzcxt, fuzz_target.pc,
                                                 (void **) &shadow);
    if (res != DRMF_SUCCESS) {
        FUZZ_WARN("Failed to acquire the shadow memory state on thread 0x%x. "
                  "Replacing it."NL, dr_get_thread_id(dcontext));
        ASSERT(false, "missing shadow state");
        shadow = NULL;
    }

    if (shadow == NULL) {
        shadow = create_shadow_state(dcontext);
        res = drfuzz_set_target_per_thread_user_data(fuzzcxt, fuzz_target.pc, shadow,
                                                     free_shadow_state_per_target);
        if (res != DRMF_SUCCESS) {
            FUZZ_ERROR("Failed to set the shadow memory state on thread 0x%x. "
                       "Cannot fuzz test on this thread."NL, dr_get_thread_id(dcontext));
            ASSERT(false, "failed to set shadow state");
            free_shadow_state(dcontext, shadow);
            return false;
        }
    }

    *shadow_out = shadow;
    return true;
}

static void
shadow_state_init(void *dcontext, fuzz_state_t *state, dr_mcontext_t *mc, bool save_input)
{
    shadow_state_t *shadow;
    /* We only need to save shadow state for uninit check. */
    if (!options.check_uninitialized)
        return;
    ASSERT(options.shadowing, "shadow is disabled");

    if (!init_thread_shadow_state(&shadow)) {
        FUZZ_ERROR("Failed to initialize the shadow memory state for target "PIFX
                   "on thread 0x%x. Disabling the fuzz target."NL,
                   fuzz_target.pc, state->thread_id);
        fuzz_target.enabled = false;
        return;
    }

    /* We save shadow state for arguments, arg/ret on stack, and input buffers.
     * We do not save shadow state for the redzone because the redzone shadow state
     * should not be changed.
     */
    shadow_state_save_stack_frame(mc, shadow);
    if (save_input) {
        shadow->buffer_shadow = shadow_save_region(state->input_buffer,
                                                   state->input_size);
    } else {
        shadow->buffer_shadow = NULL;
        shadow_set_range(state->input_buffer,
                         state->input_buffer + state->input_size,
                         SHADOW_DEFINED);
    }
 }

static void
shadow_state_restore(void *dcontext, void *fuzzcxt,
                     fuzz_state_t *state, dr_mcontext_t *mc)
{
    drmf_status_t res;
    shadow_state_t *shadow;

    /* We only need to restore shadow state for uninit check. */
    if (!options.check_uninitialized)
        return;
    ASSERT(options.shadowing, "shadow is disabled");

    res = drfuzz_get_target_per_thread_user_data(fuzzcxt, fuzz_target.pc,
                                                 (void **) &shadow);
    if (res != DRMF_SUCCESS) {
        FUZZ_ERROR("Failed to acquire the shadow memory state for target "PIFX
                   "on thread 0x%x. Disabling the fuzz target."NL,
                   fuzz_target.pc, dr_get_thread_id(dcontext));
        fuzz_target.enabled = false;
        return;
    }
    shadow_state_restore_stack_frame(mc, shadow);
    if (shadow->buffer_shadow != NULL)
        shadow_restore_region(shadow->buffer_shadow);
    else {
        shadow_set_range(state->input_buffer,
                         state->input_buffer + state->input_size,
                         SHADOW_DEFINED);
    }
}

static void
shadow_state_exit(void *dcontext, void *fuzzcxt)
{
    drmf_status_t res;
    shadow_state_t *shadow;

    /* We only need to save shadow state for uninit check. */
    if (!options.check_uninitialized)
        return;
    ASSERT(options.shadowing, "shadow is disabled");

    res = drfuzz_get_target_per_thread_user_data(fuzzcxt, fuzz_target.pc,
                                                 (void **) &shadow);
    if (res != DRMF_SUCCESS) {
        FUZZ_ERROR("Failed to acquire the shadow memory state for target "PIFX
                   "on thread 0x%x. Disabling the fuzz target."NL,
                   fuzz_target.pc, dr_get_thread_id(dcontext));
        fuzz_target.enabled = false;
        return;
    }

    free_shadow_buffers(shadow);
}

/***************************************************************************************
 * FUZZER PRIVATE
 */

static inline void
apply_singleton_input(fuzz_state_t *fuzz_state)
{
    uint len = MIN(fuzz_state->input_size * 2, strlen(fuzz_target.singleton_input));
    uint i, b, singleton_byte_count = (len / 2);

    ASSERT(len % 2 == 0, "Singleton input must have 2 digits per byte");

    for (i = 0; i < singleton_byte_count; i++) {
        if (dr_sscanf(fuzz_target.singleton_input + (i * 2), "%02x", &b) != 1) {
            NOTIFY_ERROR("Failed to parse '%c%c' as a hexadecimal byte."NL,
                         fuzz_target.singleton_input[i * 2],
                         fuzz_target.singleton_input[(i * 2) + 1]);
            tokenizer_exit_with_usage_error();
        }
        fuzz_state->input_buffer[i] = b;
    }
    for (; i < fuzz_state->input_size; i++) /* fill remainder with zeros */
        fuzz_state->input_buffer[i] = 0;
}

static inline bool
find_target_buffer(fuzz_state_t *fuzz_state, void *fuzzcxt, generic_func_t target_pc)
{
    byte *input_buffer;
    drmf_status_t res;
    size_t input_size;

    ASSERT(fuzz_target.pc == target_pc, "fuzz target pc miss match");
    res = drfuzz_get_arg(fuzzcxt, fuzz_target.pc, fuzz_target.size_arg,
                         true/*original*/, (void **) &input_size);
    if (res != DRMF_SUCCESS) {
        NOTIFY_ERROR("Failed to obtain the buffer size for the fuzz target"NL);
        ASSERT(false, "Failed to obtain the buffer size");
        fuzz_target.enabled = false;
        return false;
    }

    /* Validate that the arg index for the buffer size given by the user appears to be
     * reasonable. If not, exit with an error instead of crashing with alloc problems.
     */
    if (input_size > MAX_EXPECTED_BUFFER_SIZE) {
        FUZZ_WARN("buffer size is too large: %d"NL, input_size);
    }

    if (fuzz_target.buffer_offset >= input_size) {
        FUZZ_WARN("buffer offset is larger than input size: %d >= %d -> skip fuzzing"NL,
                  fuzz_target.buffer_offset, input_size);
        fuzz_state->skip_initial++;
        return false;
    }

    res = drfuzz_get_arg(fuzzcxt, fuzz_target.pc, fuzz_target.buffer_arg,
                         true/*original*/, (void **) &input_buffer);
    if (res != DRMF_SUCCESS) {
        NOTIFY_ERROR("Failed to obtain reference to the buffer arg for the fuzz target"
                     NL);
        ASSERT(false, "Failed to obtain reference to the original buffer arg\n");
        fuzz_target.enabled = false;
        return false;
    }

    if (options.fuzz_replace_buffer) {
        void *drcontext = drfuzz_get_drcontext(fuzzcxt);
        byte *buffer;
        /* We always replace buffer at beginning for simplicity, so that other code
         * like load_fuzz_input can call free_fuzz_input_buffer when necessary.
         */
        buffer = drfuzz_reallocate_buffer(drcontext, input_size, (app_pc)target_pc);
        if (buffer == NULL) {
            NOTIFY_ERROR("Failed to allocate fuzz input buffer."NL);
            ASSERT(false, "Failed to allocate fuzz input buffer\n");
            fuzz_target.enabled = false;
            return false;
        }
        memcpy(buffer, input_buffer, input_size);
        /* XXX: we replace the original input_buffer with newly allocated memory,
         * which may cause problems if other pointers pointing to the original buffer,
         * or the replaced buffer is used after fuzzing iterations.
         */
        input_buffer = buffer;
    }

    dr_mutex_lock(fuzz_state_lock);
    fuzz_state->input_size = input_size;
    fuzz_state->input_buffer = input_buffer;
    dr_mutex_unlock(fuzz_state_lock);

    return fuzz_target.enabled;
}

static inline void
free_target_buffer(fuzz_state_t *fuzz_state, void *fuzzcxt)
{
    byte *buffer;
    dr_mutex_lock(fuzz_state_lock);
    fuzz_state->input_size = 0;
    buffer = fuzz_state->input_buffer;
    fuzz_state->input_buffer = NULL;
    fuzz_state->repeat_index = 0;
    dr_mutex_unlock(fuzz_state_lock);
    if (options.fuzz_replace_buffer && buffer != NULL) {
        drfuzz_free_reallocated_buffer(drfuzz_get_drcontext(fuzzcxt), buffer,
                                       (app_pc)fuzz_target.pc);
    }
}

static void
fuzzer_mutator_init(void *dcontext, fuzz_state_t *fuzz_state)
{
    drmf_status_t res;
    size_t mutation_size = fuzz_state->input_size - fuzz_target.buffer_offset;

    if (fuzz_target.buffer_fixed_size > 0 &&
        fuzz_target.buffer_fixed_size < mutation_size)
        mutation_size = fuzz_target.buffer_fixed_size;

    if (fuzz_target.repeat_count < 0)
        LOG(1, LOG_PREFIX" Repeating until mutator is exhausted.\n");

    DOLOG(1, {
        LOG(1, "Initializing mutator with buffer:\n\n");
        log_target_buffer(dcontext, 1, fuzz_state);
        LOG(1, "\n\n");
    });

    if (fuzz_state->mutator != NULL) {
        mutator_api.drfuzz_mutator_stop(fuzz_state->mutator);
        fuzz_state->mutator = NULL;
    }

    res = mutator_api.drfuzz_mutator_start
        (&fuzz_state->mutator, MUTATION_START(fuzz_state->input_buffer),
         mutation_size, mutator_argc, (const char **)mutator_argv);
    if (res != DRMF_SUCCESS) {
        NOTIFY_ERROR("Failed to start the mutator with the specified options."NL);
        dr_abort();
    }
}

/* create new mutator with existing mutator's current value as input seed */
static drfuzz_mutator_t *
fuzzer_mutator_copy(void *dcontext, fuzz_state_t *state)
{
    drmf_status_t res;
    drfuzz_mutator_t *mutator;
    void *input = global_alloc(state->input_size, HEAPSTAT_MISC);
    ASSERT(state->input_size > fuzz_target.buffer_offset,
           "buffer offset is too large");
    res = mutator_api.drfuzz_mutator_get_current_value(state->mutator, input);
    if (res != DRMF_SUCCESS) {
        FUZZ_ERROR("Failed to get current mutator value."NL);
        global_free(input, state->input_size, HEAPSTAT_MISC);
        return NULL;
    }
    res = mutator_api.drfuzz_mutator_start
        (&mutator, MUTATION_START((byte *)input), state->input_size,
         mutator_argc, (const char **)mutator_argv);
    global_free(input, state->input_size, HEAPSTAT_MISC);
    if (res != DRMF_SUCCESS) {
        FUZZ_ERROR("Failed to copy the mutator."NL);
        return NULL;
    }
    return mutator;
}

static void
fuzzer_mutator_next(void *dcontext, fuzz_state_t *fuzz_state)
{
    if (fuzz_target.singleton_input == NULL) {
        mutator_api.drfuzz_mutator_get_next_value
            (fuzz_state->mutator, MUTATION_START(fuzz_state->input_buffer));
    } else {
        apply_singleton_input(fuzz_state);
    }
    DOLOG(3, {
        LOG(3, "\n"LOG_PREFIX" Executing target with mutated buffer:\n");
        log_target_buffer(dcontext, 3, fuzz_state);
    });
}

static void
fuzzer_mutator_feedback(void *dcontext, generic_func_t target_pc,
                        fuzz_state_t *fuzz_state)
{
    uint64 num_bbs;
    if (!fuzz_target.use_coverage ||
        drfuzz_get_target_num_bbs(target_pc, &num_bbs) != DRMF_SUCCESS)
        return;
    if (fuzz_state->repeat && (num_bbs - fuzz_state->num_bbs) > 0) {
        mutator_api.drfuzz_mutator_feedback(fuzz_state->mutator,
                                            num_bbs - fuzz_state->num_bbs);
    }
    fuzz_state->num_bbs = num_bbs;
    LOG(2, LOG_PREFIX" "UINT64_FORMAT_STRING" basic blocks seen during fuzzing.\n",
        num_bbs);
}

static void
fuzzer_mutator_exit(fuzz_state_t *fuzz_state)
{
    if (fuzz_state->mutator != NULL) {
        mutator_api.drfuzz_mutator_stop(fuzz_state->mutator);
        fuzz_state->mutator = NULL;
    }
}

/* Pre fuzz function for corpus based fuzzing.
 * We have two phases: corpus phase and mutate phase.
 * In the corpus phase (if state->should_mutate is false), we load corpus inputs
 * from corpus_vec for execution and create mutators for future fuzzing.
 * The newly created mutators will be added into mutator_vec in post_fuzz_corpus.
 * In the mutate phase (if state->should_mutate is true), we pick a mutator from
 * the mutator_vec, perform mutation on it, and then execute the mutated input.
 */
static void
pre_fuzz_corpus(void *fuzzcxt, generic_func_t target_pc, dr_mcontext_t *mc)
{
    void *dcontext = drfuzz_get_drcontext(fuzzcxt);
    fuzz_state_t *state = drmgr_get_tls_field(dcontext, tls_idx_fuzzer);

    /* corpus phase */
    if (!state->should_mutate) {
        bool has_corpus = false;
        while (state->corpus_index < corpus_vec.entries) {
            char *fname = drvector_get_entry(&corpus_vec, state->corpus_index++);
            ssize_t read_size;
            read_size = load_fuzz_corpus_input(dcontext, fname, state);
            if (read_size > 0) {
                state->mutator = NULL;
                fuzzer_mutator_init(dcontext, state);
                if (state->repeat)
                    shadow_state_restore(dcontext, fuzzcxt, state, mc);
                else /* first fuzz loop */
                    shadow_state_init(dcontext, state, mc, false);
                has_corpus = true;
                break;
            }
        }
        if (!has_corpus &&
            /* no corpus or all empty corpus, use current input */
            (corpus_vec.entries == 0 || mutator_vec.entries == 0)) {
            state->use_orig_input = true;
            ASSERT(state->mutator == NULL, "mutator should be NULL");
            fuzzer_mutator_init(dcontext, state);
            shadow_state_init(dcontext, state, mc, false);
        }
        state->should_mutate = !has_corpus;
    }

    /* mutate phase */
    if (state->should_mutate && mutator_vec.entries > 0) {
        /* pick a mutator for fuzzing */
        /* Assuming we only increase the buffer size with -fuzz_replace_buffer.
         * The current buffer can be used for any mutator we have seen,
         * Xref load_fuzz_input() for when the buffer is replaced.
         */
        state->mutator = drvector_get_entry(&mutator_vec, state->mutator_index);
        state->mutator_index++;
        if (state->mutator_index >= mutator_vec.entries)
            state->mutator_index = 0;
        ASSERT(state->mutator != NULL, "corpus mutator must not be NULL");
        fuzzer_mutator_next(dcontext, state);
        shadow_state_restore(dcontext, fuzzcxt, state, mc);
    }

    if (options.fuzz_replace_buffer) {
        ASSERT(state->input_buffer != NULL,
               "fuzz input buffer must not be NULL");
        drfuzz_set_arg(fuzzcxt, fuzz_target.buffer_arg, state->input_buffer);
        drfuzz_set_arg(fuzzcxt, fuzz_target.size_arg, (void *)state->input_size);
    }
}

static void
pre_fuzz(void *fuzzcxt, generic_func_t target_pc, dr_mcontext_t *mc)
{
    void *dcontext = drfuzz_get_drcontext(fuzzcxt);
    fuzz_state_t *fuzz_state = drmgr_get_tls_field(dcontext, tls_idx_fuzzer);

    LOG(2, LOG_PREFIX" executing pre-fuzz (repeat=%d) for "PIFX"\n",
        fuzz_state->repeat, target_pc);

    /* i#1782: pick the first thread that hit target function for fuzzing */
    dr_mutex_lock(fuzz_target_lock);
    if (fuzz_target.tid == 0)
        fuzz_target.tid = dr_get_thread_id(dcontext);
    dr_mutex_unlock(fuzz_target_lock);

    if (!fuzz_target.enabled || fuzz_state->skip_initial > 0 ||
        /* FIXME i#1782: no multiple threads fuzzing support */
        fuzz_target.tid != dr_get_thread_id(dcontext))
        return;

    /* find buffer arg and size arg */
    if (!fuzz_state->repeat && !find_target_buffer(fuzz_state, fuzzcxt, target_pc))
        return;

    if (option_specified.fuzz_corpus) {
        /* separate handling for fuzzing with corpus */
        pre_fuzz_corpus(fuzzcxt, target_pc, mc);
        return;
    }

    if (!fuzz_state->repeat) {
        if (option_specified.fuzz_input_file) {
            if (load_fuzz_input(dcontext, options.fuzz_input_file, fuzz_state) == 0) {
                /* fail to load input, do not fuzz */
                NOTIFY_ERROR("Failed to load input data from %s."NL,
                             options.fuzz_input_file);
                fuzz_target.enabled = false;
                free_target_buffer(fuzz_state, fuzzcxt);
                return;
            }
        }
        shadow_state_init(dcontext, fuzz_state, mc,
                          options.fuzz_replace_buffer ?
                          false /* do not save the shadow state of the input data */:
                          true  /* save the shadow state of the input data */);
        fuzzer_mutator_init(dcontext, fuzz_state);
        if (fuzz_target.repeat_count == 0)
            goto pre_fuzz_done;
        if (fuzz_target.use_coverage) {
            /* no mutation for the base input if using coverage */
            goto pre_fuzz_done;
        }
        LOG(2, LOG_PREFIX" re-starting mutator\n");
    } else
        shadow_state_restore(dcontext, fuzzcxt, fuzz_state, mc);
    fuzzer_mutator_next(dcontext, fuzz_state);
 pre_fuzz_done:
    if (options.fuzz_replace_buffer) {
        ASSERT(fuzz_state->input_buffer != NULL,
               "fuzz input buffer must not be NULL");
        drfuzz_set_arg(fuzzcxt, fuzz_target.buffer_arg, fuzz_state->input_buffer);
        drfuzz_set_arg(fuzzcxt, fuzz_target.size_arg, (void *)fuzz_state->input_size);
    }
}

/* Post fuzz function for corpus based fuzzing.
 * This is where any mutator is added into mutator_vec for future fuzzing.
 */
static bool
post_fuzz_corpus(void *fuzzcxt, generic_func_t target_pc)
{
    uint64 num_bbs;
    void *dcontext = drfuzz_get_drcontext(fuzzcxt);
    fuzz_state_t *state = drmgr_get_tls_field(dcontext, tls_idx_fuzzer);

    if (drfuzz_get_target_num_bbs(target_pc, &num_bbs) == DRMF_SUCCESS) {
        if (!state->should_mutate) {
            /* corpus phase: simply add the mutator into mutator_vec */
            drvector_append(&mutator_vec, (void *)state->mutator);
            if (option_specified.fuzz_corpus_out && num_bbs > state->num_bbs)
                dump_fuzz_corpus_input(dcontext, state);
        } else if (num_bbs > state->num_bbs) {
            /* mutate phase: dump and add the mutator if we discover new bbs */
            dump_fuzz_corpus_input(dcontext, state);
            drvector_append(&mutator_vec,
                            state->use_orig_input ?
                            state->mutator : fuzzer_mutator_copy(dcontext, state));
            state->use_orig_input = false;
        }
        state->num_bbs = num_bbs;
    }

    if (fuzz_target.repeat_count > 0 &&
        ++state->repeat_index < fuzz_target.repeat_count) {
        state->repeat = true;
        return true;
    }

    state->repeat = false;
    shadow_state_exit(dcontext, fuzzcxt);
    free_target_buffer(state, fuzzcxt);
    /* for corpus fuzzing, we stop fuzzing even if we see the fuzz function again */
    fuzz_target.enabled = false;
    return false; /* stop fuzzing */
}

static bool
post_fuzz(void *fuzzcxt, generic_func_t target_pc)
{
    void *dcontext = drfuzz_get_drcontext(fuzzcxt);
    fuzz_state_t *fuzz_state = (fuzz_state_t *) drmgr_get_tls_field(dcontext,
                                                                    tls_idx_fuzzer);

    if (!fuzz_target.enabled ||
        /* FIXME i#1782: no multiple threads fuzzing support */
        fuzz_target.tid != dr_get_thread_id(dcontext))
        return false; /* in case someone unfuzzed while a target was looping */
    if (fuzz_state->skip_initial > 0) {
        fuzz_state->skip_initial--;
        return false;
    }

    LOG(2, LOG_PREFIX" executing post-fuzz for "PIFX"\n", target_pc);

    if (option_specified.fuzz_corpus)
        return post_fuzz_corpus(fuzzcxt, target_pc);

    fuzzer_mutator_feedback(dcontext, target_pc, fuzz_state);

    fuzz_state->repeat_index++;
    if (fuzz_target.stat_freq > 0 && fuzz_state->repeat_index % fuzz_target.stat_freq) {
        LOG(1, LOG_PREFIX" mutation for iteration #%d:\n", fuzz_state->repeat_index);
        log_target_buffer(dcontext, 1, fuzz_state);
    }
    if (fuzz_target.singleton_input == NULL) {
        bool has_next = mutator_api.drfuzz_mutator_has_next_value(fuzz_state->mutator);
        if (fuzz_target.repeat_count > 0) {
            fuzz_state->repeat = (fuzz_state->repeat_index < fuzz_target.repeat_count) &&
                /* If the mutator ran out we do end early */
                has_next;
        } else if (fuzz_target.repeat_count < 0)
            fuzz_state->repeat = has_next;
    } else
        fuzz_state->repeat = false;

    if (fuzz_state->repeat)
        return true;

    /* do not repeat, clean-up */
    shadow_state_exit(dcontext, fuzzcxt);
    fuzzer_mutator_exit(fuzz_state);
    free_target_buffer(fuzz_state, fuzzcxt);
    return false;
}

static void
thread_init(void *dcontext)
{
    fuzz_state_t *state = thread_alloc(dcontext, sizeof(fuzz_state_t), HEAPSTAT_MISC);
    fuzz_state_list_t *list_item = thread_alloc(dcontext, sizeof(fuzz_state_list_t),
                                                HEAPSTAT_MISC);
    memset(state, 0, sizeof(fuzz_state_t));
    drmgr_set_tls_field(dcontext, tls_idx_fuzzer, (void *) state);

    dr_mutex_lock(fuzz_state_lock);
    list_item->state = state;
    list_item->next = state_list;
    state_list = list_item;
    dr_mutex_unlock(fuzz_state_lock);

    state->thread_id = dr_get_thread_id(dcontext);
    state->skip_initial = fuzz_target.skip_initial;
}

static void
thread_exit(void *dcontext)
{
    fuzz_state_t *state = drmgr_get_tls_field(dcontext, tls_idx_fuzzer);
    fuzz_state_list_t *state_item = NULL;

    dr_mutex_lock(fuzz_state_lock);
    if (state_list != NULL) {
        fuzz_state_list_t *prev = NULL, *next = state_list;
        while (next != NULL) {
            if (next->state == state) {
                state_item = next;  /* found this thread's state,  */
                if (prev == NULL)   /* now remove it from the list */
                    state_list = state_list->next;
                else
                    prev->next = next->next;
                break;
            }
            prev = next;
            next = next->next;
        }
    }
    dr_mutex_unlock(fuzz_state_lock);

    thread_free(dcontext, state, sizeof(fuzz_state_t), HEAPSTAT_MISC);
    if (state_item == NULL)
        LOG(1, "Error: failed to find an exiting thread in the fuzz state list.\n");
    else
        thread_free(dcontext, state_item, sizeof(fuzz_state_list_t), HEAPSTAT_MISC);
}

static void
module_loaded(void *drcontext, const module_data_t *module, bool loaded)
{
    const char *name = dr_module_preferred_name(module);

    if (fuzz_target.module_start == 0 && name != NULL &&
        fuzz_target.module_name != NULL && strcmp(name, fuzz_target.module_name) == 0)
        fuzz_target.enabled = register_fuzz_target(module);
}

static void
module_unloaded(void *drcontext, const module_data_t *module)
{
    ASSERT_NOT_TESTED("Unregistration of fuzz target on module unload");

    if (fuzz_target.enabled && fuzz_target.module_start == module->start)
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

    res = drfuzz_fuzz_target(fuzz_target.pc, fuzz_target.arg_count, 0,
                             fuzz_target.callconv, pre_fuzz, post_fuzz);
    if (res == DRMF_SUCCESS) {
        LOG(1, LOG_PREFIX" Successfully registered fuzz target at pc "PIFX"\n",
            fuzz_target.pc);
        fuzz_target.module_start = module->start;
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
    fuzz_target.module_start = 0;
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
    bool start;           /* whether any tokens have been copied from the tokenizer yet */
    const char *src_head; /* head of the src string (not moved by tokenization) */
    const char *src;      /* tokenizer src string (tokenizer does not write to it) */
    const char *raw_src;  /* raw user input, for reference in error messages */
    heapstat_t type;      /* allocation type */
} tokenizer_t;

typedef enum _tokenizer_char_type_t {
    TOKENIZER_CHAR_SINGLETON,
    TOKENIZER_CHAR_SET
} tokenizer_char_type_t;

#define RAW_SNIPPET_FORMAT "'%.32s%s'"
#define RAW_SNIPPET_ARGS(s) (s), strlen(s) > 32 ? "..." : ""

static void
tokenizer_init(tokenizer_t *t, const char *src, const char *raw_src, heapstat_t type)
{
    t->start = true;
    t->src_head = src;
    t->src = src;
    t->raw_src = raw_src;
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
tokenizer_has_next(IN tokenizer_t *t, IN char delimiter)
{
    const char *next_ptr = NULL;

    if (*t->src == '\0')
        return false;
    next_ptr = strchr(t->start ? t->src : t->src + 1, ' ');
    return (next_ptr != NULL || strlen(t->src) > 0); /* found delimiter or a tail */
}

static bool
tokenizer_find_next(IN tokenizer_t *t, OUT const char **src_ptr_out, IN char delim,
                    IN char raw_delim, IN const char *field_name)
{
    const char *src_ptr = NULL;

    if (*t->src != '\0')
        src_ptr = strchr(t->start ? t->src : ++t->src, delim);
    if (src_ptr == NULL) {
        uint tail_len = strlen(t->src);
        if (tail_len == 0) { /* is there a tail on the string? */
            NOTIFY_ERROR("Missing %s delimiter in descriptor:"NL, field_name);
            NOTIFY_ERROR("did not find '%c' at position %d in "RAW_SNIPPET_FORMAT"."NL,
                         raw_delim, t->src - t->src_head, RAW_SNIPPET_ARGS(t->raw_src));
            tokenizer_exit_with_usage_error();
            *src_ptr_out = NULL;
            return false;
        }
        src_ptr = t->src + tail_len; /* use the trailing token */
    }
    *src_ptr_out = src_ptr;
    return true;
}

static bool
tokenizer_copy_next(IN tokenizer_t *t, OUT size_t *len, OUT char **token,
                    IN char delimiter, IN const char *field_name)
{
    const char *src_ptr = NULL;

    if (tokenizer_find_next(t, &src_ptr, ' ', delimiter, field_name))
        return tokenizer_copy_to(t, src_ptr, len, token);
    else
        return false;
}

static bool
tokenizer_next_int(IN tokenizer_t *t, OUT byte *dst, IN char delimiter,
                   IN bool hex, IN bool is_64, IN const char *field_name)
{
    size_t len;
    char *src;
    const char *format = hex ? (is_64 ? "0x%llx" : "0x%x") : (is_64 ? "%lld" : "%d");

    if (!tokenizer_copy_next(t, &len, &src, delimiter, field_name))
        return false;
    if (dr_sscanf(src, format, dst) != 1) {
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

static bool
user_input_parse_target(char *descriptor, const char *raw_descriptor)
{
    char *desc_ptr = NULL, *module_name, *function /*symbol or offset*/;
    const char function_separators[] = {MODULE_SEP, OFFSET_SEP, '\0'};
    size_t module_name_len, function_len;
    tokenizer_t tokens;

    LOG(1, LOG_PREFIX" Attempting to register fuzz target descriptor %s\n", descriptor);

    replace_char(descriptor, ' ', TEMP_SPACE_CHAR); /* replace spaces with placeholder */
    replace_char(descriptor, '|', ' '); /* replace pipes with spaces for dr_get_token() */

    tokenizer_init(&tokens, (const char *) descriptor, raw_descriptor, HEAPSTAT_MISC);

    if (!tokenizer_strchrs(&tokens, (const char **) &desc_ptr, function_separators)) {
        NOTIFY_ERROR("Missing symbol or offset in descriptor:"NL);
        NOTIFY_ERROR("    did not find '!' or '+' in "RAW_SNIPPET_FORMAT"."NL,
                     RAW_SNIPPET_ARGS(raw_descriptor));
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
                       "the main module name cannot be found."NL);
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

    if (!tokenizer_next_int(&tokens, (byte *) &fuzz_target.arg_count,
                            '|', false, false, "number of args"))
        return false;
    if (!tokenizer_next_int(&tokens, (byte *) &fuzz_target.buffer_arg,
                            '|', false, false, "buffer arg"))
        return false;
    if (!tokenizer_next_int(&tokens, (byte *) &fuzz_target.size_arg,
                            '|', false, false, "size arg"))
        return false;
    if (!tokenizer_next_int(&tokens, (byte *) &fuzz_target.repeat_count,
                            '|', false, false, "repeat count"))
        return false;
    if (tokenizer_has_next(&tokens, '|')) {
        uint callconv;
        if (!tokenizer_next_int(&tokens, (byte *) &callconv,
                                '|', false, false, "calling convention"))
            return false;
        fuzz_target.callconv = (callconv << CALLCONV_FLAG_SHIFT);
    } else {
        fuzz_target.callconv = DRWRAP_CALLCONV_DEFAULT;
    }
    if (!fuzzer_fuzz_target_callconv_arg_init())
        tokenizer_exit_with_usage_error();

    return true;
}
