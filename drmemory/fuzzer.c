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
#include "umbra.h"
#include "shadow.h"
#include "report.h"
#include "drwrap.h"
#include "drfuzz_mutator.h"
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
    byte *input_buffer;      /* reference to the fuzz target's buffer arg */
    /* While these two fields are thread-local like the others, they may be accessed
     * by another thread at any time, e.g. during error reporting. Acquire the
     * fuzz_state_lock before accessing or updating them.
     */
    byte *input_buffer_copy; /* threadsafe copy of the fuzz target's buffer arg */
    size_t input_size;       /* size of the fuzz target's buffer arg */
    drfuzz_mutator_t *mutator;
} fuzz_state_t;

/* List of the fuzz states for all process threads. Protected by fuzz_state_lock. It
 * is safe to access the input_buffer_copy and input_size fields of each state while
 * holding the fuzz_state_lock, and it is always safe to access the thread_id, but it
 * is only safe to access the repeat, repeat_index, and input_buffer fields when the
 * owning thread is known to be suspended (e.g., when all threads are suspended).
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
    uint repeat_count;      /* number of times to fuzz the target (0 means indefinite) */
    uint skip_initial;      /* number of target invocations each thread should skip */
    uint stat_freq;
    const char *singleton_input;
    drwrap_callconv_t callconv;
    const callconv_args_t *callconv_args;
    drfuzz_mutator_options_t *mutator_options;
} fuzz_target_t;

static fuzz_target_t fuzz_target;

/* Global configuration of the shadow memory and related handling options. */
typedef struct _shadow_config_t {
    bool save_restore_enabled;
    uint redzone_size;
    bool pattern_enabled;
    uint pattern;
} shadow_config_t;

static shadow_config_t shadow_config;

static bool fuzzer_initialized;

/* Protects the fuzz_state_t fields input_buffer_copy and input_size for access from
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

static bool
user_input_parse_mutator(char *descriptor, const char *raw_descriptor);

static void
free_fuzz_target();

static void
thread_init(void *dcontext);

static void
thread_exit(void *dcontext);

void
fuzzer_init(client_id_t client_id)
{
    shadow_config.save_restore_enabled = options.shadowing && options.check_uninitialized;
    shadow_config.pattern = options.pattern;
    shadow_config.redzone_size = options.redzone_size;
#ifdef X64
    if (shadow_config.save_restore_enabled) {
        ASSERT_NOT_IMPLEMENTED(); /* XXX i#1734: NYI */
        NOTIFY_ERROR("Shadow memory save/restore is not implemented in x64."NL);
        tokenizer_exit_with_usage_error();
    }
#endif
    if (options.pattern != 0 && !shadow_config.save_restore_enabled)
        FUZZ_WARN("pattern mode not fully supported--redzone will not be reset\n");

    fuzz_state_lock = dr_mutex_create();

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
}

void
fuzzer_exit()
{
    free_fuzz_target();

    dr_mutex_destroy(fuzz_state_lock);

    if (drfuzz_exit() != DRMF_SUCCESS)
        ASSERT(false, "fail to exit Dr. Fuzz");
    drmgr_exit();
}

void
fuzzer_fuzz_option_target()
{
    fuzzer_fuzz_target(options.fuzz_target);
    if (option_specified.fuzz_mutator) {
        if (option_specified.fuzz_one_input) {
            NOTIFY_ERROR("Cannot specify both a mutator configuration and a single "
                         "input to fuzz"NL);
            dr_abort();
        }
        fuzzer_set_mutator_descriptor(options.fuzz_mutator);
    }
    if (option_specified.fuzz_one_input)
        fuzzer_set_singleton_input(options.fuzz_one_input);

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

/* XXX i#1734: could define the mutator as a set of callbacks for extensibility */
bool
fuzzer_set_mutator_descriptor(const char *mutator_descriptor)
{
    bool res;
    char *descriptor_copy;

    if (fuzz_target.module_name == NULL)
        return false;

    descriptor_copy = drmem_strdup(mutator_descriptor, HEAPSTAT_MISC);
    res = user_input_parse_mutator(descriptor_copy, mutator_descriptor);
    global_free(descriptor_copy, strlen(descriptor_copy) + 1/*null-term*/, HEAPSTAT_MISC);
    return res;
}

void
fuzzer_set_singleton_input(const char *input_value)
{
    fuzz_target.singleton_input = input_value;
}

static void
print_target_buffer(fuzz_state_t *state, char *buffer, size_t buffer_size,
                    size_t *sofar, ssize_t *len, const char *prefix)
{
    uint i;

    BUFPRINT(buffer, buffer_size, *sofar, *len, NL"%s"NL"%s", prefix, prefix);
    for (i = 0; i < state->input_size; i++) { /* print in lexical byte order */
        BUFPRINT(buffer, buffer_size, *sofar, *len,
                 "%02x", state->input_buffer[i]);
        if ((buffer_size - *sofar) <= (TARGET_BUFFER_TRUNC_LEN + 1/*null-term*/)) {
            BUFPRINT(buffer, buffer_size, *sofar, *len, TARGET_BUFFER_TRUNC);
            break;
        }
        if ((i % 32) == 31 &&            /* 8 dwords on each line, and             */
            i < (state->input_size - 1)) /* avoid extra newline when it ends flush */
            BUFPRINT(buffer, buffer_size, *sofar, *len, NL"%s", prefix);
        else if ((i % 4) == 3)
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
    print_target_buffer(thread, buffer, buffer_size, &sofar, &len, ""/*no prefix*/);
    ASSERT(sofar <= buffer_size, "buffer overflowed the expected size");
    if (loglevel == LOG_LEVEL_ELOG)
        ELOG(1, buffer);
    else
        LOG(loglevel, buffer);
    thread_free(dcontext, buffer, buffer_size, HEAPSTAT_MISC);
}

size_t
fuzzer_error_report(IN void *dcontext, OUT char *notify, IN size_t notify_size)
{
    ssize_t len = 0;
    size_t sofar = 0;
    fuzz_state_t *this_thread, *report_thread = NULL;
    uint fuzzing_thread_count = 0;
    fuzz_state_list_t *next = state_list;

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
            print_target_buffer(this_thread, notify, notify_size, &sofar, &len, INFO_PFX);
            ASSERT(sofar <= notify_size, "buffer overflowed the expected size");
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

#define MAX_BUFFER_SIZE 0x1000 /* heuristic to detect incorrect buffer arg index */

/* stores shadow memory state for an instance of the fuzz target (per thread) */
typedef struct _shadow_state_t {
    reg_t xsp;        /* stack pointer, saved when first entering a fuzz target */
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

    shadow->xsp = mc->xsp;

    for (i = 0; i < fuzz_target.arg_count_regs; i++)
        shadow->reg_args[i] = get_shadow_register(fuzz_target.callconv_args->regs[i]);
    if (fuzz_target.arg_count > fuzz_target.callconv_args->reg_count) {
        size_t stack_arg_offset = fuzz_target.callconv_args->stack_offset * sizeof(reg_t);
        app_pc stack_arg_start = (app_pc) (mc->xsp + stack_arg_offset);
        size_t stack_arg_size = (fuzz_target.arg_count_stack * sizeof(reg_t));
        shadow->stack_shadow = shadow_save_region(stack_arg_start, stack_arg_size);
    }
}

static inline void
shadow_state_reset_redzone(fuzz_state_t *fuzz_state, shadow_state_t *shadow)
{
    byte *tail = fuzz_state->input_buffer + fuzz_state->input_size;

    shadow_set_range(fuzz_state->input_buffer - shadow_config.redzone_size,
                     fuzz_state->input_buffer, SHADOW_UNADDRESSABLE);
    shadow_set_range(tail, tail + shadow_config.redzone_size, SHADOW_UNADDRESSABLE);
}

/* Restore shadow state for the arg registers and stack frame. */
static inline void
shadow_state_restore_stack_frame(dr_mcontext_t *mc, shadow_state_t *shadow)
{
    uint i;

    ASSERT((app_pc)(shadow->xsp) != NULL, "stack pointer was not saved");
    shadow_set_range((app_pc)shadow->xsp, (app_pc)mc->xsp, SHADOW_DEFINED);

    for (i = 0; i < fuzz_target.arg_count_regs; i++)
        register_shadow_set_dword(fuzz_target.callconv_args->regs[i],
                                  shadow->reg_args[i]);
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

static inline void
pattern_reset_redzone()
{
    /* XXX i#1734: NYI */
}

/***************************************************************************************
 * FUZZER PRIVATE
 */

static inline void
apply_singleton_input(fuzz_state_t *fuzz_state)
{
    uint i, b, len = strlen(fuzz_target.singleton_input), byte_count = (len / 2);

    ASSERT(len % 2 == 0, "Singleton input must have 2 digits per byte");
    ASSERT(fuzz_state->input_size == byte_count, "Singleton input has incorrect size");

    for (i = 0; i < byte_count; i++) {
        if (dr_sscanf(fuzz_target.singleton_input + (i * 2), "%02x", &b) != 1) {
            NOTIFY_ERROR("Failed to parse '%c%c' as a hexadecimal byte."NL,
                         fuzz_target.singleton_input[i * 2],
                         fuzz_target.singleton_input[(i * 2) + 1]);
            tokenizer_exit_with_usage_error();
        }
        fuzz_state->input_buffer[i] = b;
    }
}

static inline void
find_target_buffer(fuzz_state_t *fuzz_state, void *fuzzcxt)
{
    byte *input_buffer;
    drmf_status_t res;

    dr_mutex_lock(fuzz_state_lock);

    res = drfuzz_get_arg(fuzzcxt, fuzz_target.pc, fuzz_target.buffer_arg,
                         true/*original*/, (void **) &input_buffer);
    if (res != DRMF_SUCCESS) {
        NOTIFY_ERROR("Failed to obtain reference to the buffer arg for the fuzz target"NL);
        ASSERT(false, "Failed to obtain reference to the original buffer arg\n");
        fuzz_target.enabled = false;
        goto unlock;
    }

    res = drfuzz_get_arg(fuzzcxt, fuzz_target.pc, fuzz_target.size_arg,
                         true/*original*/, (void **) &fuzz_state->input_size);
    if (res != DRMF_SUCCESS) {
        NOTIFY_ERROR("Failed to obtain the buffer size for the fuzz target"NL);
        ASSERT(false, "Failed to obtain the buffer size");
        fuzz_target.enabled = false;
        goto unlock;
    }

    /* Validate that the arg index for the buffer size given by the user appears to be
     * reasonable. If not, exit with an error instead of crashing with alloc problems.
     */
    if (fuzz_state->input_size > MAX_BUFFER_SIZE) {
        NOTIFY_ERROR("Buffer size of the fuzz target is out of range: %d. "
                     "Max allowed is %d."NL, fuzz_state->input_size, MAX_BUFFER_SIZE);
        ASSERT(false, "Target's buffer size too large");
        fuzz_target.enabled = false;
        goto unlock;
    }

    fuzz_state->input_buffer = input_buffer;
    fuzz_state->input_buffer_copy = global_alloc(fuzz_state->input_size, HEAPSTAT_MISC);
    memcpy(fuzz_state->input_buffer_copy, input_buffer, fuzz_state->input_size);

unlock:
    dr_mutex_unlock(fuzz_state_lock);
}

static inline void
free_target_buffer(fuzz_state_t *fuzz_state, void *fuzzcxt)
{
    dr_mutex_lock(fuzz_state_lock);
    global_free(fuzz_state->input_buffer_copy, fuzz_state->input_size, HEAPSTAT_MISC);
    fuzz_state->input_size = 0;
    dr_mutex_unlock(fuzz_state_lock);
}

static void
pre_fuzz(void *fuzzcxt, generic_func_t target_pc, dr_mcontext_t *mc)
{
    drmf_status_t res;
    shadow_state_t *shadow;
    void *dcontext = drfuzz_get_drcontext(fuzzcxt);
    fuzz_state_t *fuzz_state = drmgr_get_tls_field(dcontext, tls_idx_fuzzer);
    bool is_fuzz_entry = !fuzz_state->repeat;

    LOG(4, LOG_PREFIX" executing pre-fuzz for "PIFX"\n", target_pc);

    if (!fuzz_target.enabled || fuzz_state->skip_initial > 0)
        return;

    if (is_fuzz_entry)
        find_target_buffer(fuzz_state, fuzzcxt);

    if (shadow_config.save_restore_enabled) {
        if (is_fuzz_entry) {
            if (!init_thread_shadow_state(&shadow)) {
                FUZZ_ERROR("Failed to initialize the shadow memory state for target "PIFX
                           "on thread 0x%x. Disabling the fuzz target."NL,
                           fuzz_target.pc, fuzz_state->thread_id);
                fuzz_target.enabled = false;
                return;
            }
            shadow->buffer_shadow = shadow_save_region(fuzz_state->input_buffer,
                                                       fuzz_state->input_size);
            shadow_state_save_stack_frame(mc, shadow);
        } else {
            res = drfuzz_get_target_per_thread_user_data(fuzzcxt, fuzz_target.pc,
                                                         (void **) &shadow);
            if (res != DRMF_SUCCESS) {
                FUZZ_ERROR("Failed to acquire the shadow memory state for target "PIFX
                           "on thread 0x%x. Disabling the fuzz target."NL,
                           fuzz_target.pc, fuzz_state->thread_id);
                fuzz_target.enabled = false;
                return;
            }
            shadow_restore_region(shadow->buffer_shadow);
            shadow_state_reset_redzone(fuzz_state, shadow);
        }
    } else if (shadow_config.pattern != 0) {
        pattern_reset_redzone();
    }
    /* XXX i#1734: May want to consider an option to not reset redzone state.  */

    if (is_fuzz_entry) {
        const drfuzz_mutator_options_t *mutator_options;
        byte *mutation_start = fuzz_state->input_buffer + fuzz_target.buffer_offset;
        size_t mutation_size = fuzz_state->input_size - fuzz_target.buffer_offset;

        if (fuzz_target.buffer_fixed_size > 0 &&
            fuzz_target.buffer_fixed_size < mutation_size)
            mutation_size = fuzz_target.buffer_fixed_size;

        fuzz_state->repeat_index = 0;
        if (fuzz_target.repeat_count == 0)
            LOG(1, LOG_PREFIX" Repeating until mutator is exhausted.\n");

        DOLOG(1, {
            LOG(1, "Initializing mutator with buffer:\n\n");
            log_target_buffer(dcontext, 1, fuzz_state);
            LOG(1, "\n\n");
        });

        if (fuzz_state->mutator != NULL) {
            drfuzz_mutator_stop(fuzz_state->mutator); /* in case a target was aborted */
            fuzz_state->mutator = NULL;
        }

        if (fuzz_target.mutator_options == NULL)
            mutator_options = &DRFUZZ_MUTATOR_DEFAULT_OPTIONS;
        else
            mutator_options = fuzz_target.mutator_options;
        res = drfuzz_mutator_start(&fuzz_state->mutator, mutation_start,
                                   mutation_size, mutator_options);
        if (res != DRMF_SUCCESS) {
            NOTIFY_ERROR("Failed to start the mutator with the specified options."NL);
            dr_abort();
        }
    }

    if (fuzz_target.singleton_input == NULL) {
        drfuzz_mutator_get_next_value(fuzz_state->mutator, fuzz_state->input_buffer);
        if (fuzz_target.repeat_count == 0) /* repeating until mutator exhausts */
            fuzz_state->repeat = drfuzz_mutator_has_next_value(fuzz_state->mutator);
    } else {
        apply_singleton_input(fuzz_state);
        fuzz_state->repeat = false;
    }

    DOLOG(3, {
        LOG(3, "\n"LOG_PREFIX" Executing target with mutated buffer:\n");
        log_target_buffer(dcontext, 3, fuzz_state);
    });
}

static bool
post_fuzz(void *fuzzcxt, generic_func_t target_pc)
{
    void *dcontext = drfuzz_get_drcontext(fuzzcxt);
    fuzz_state_t *fuzz_state = (fuzz_state_t *) drmgr_get_tls_field(dcontext,
                                                                    tls_idx_fuzzer);

    if (!fuzz_target.enabled)
        return false; /* in case someone unfuzzed while a target was looping */

    if (fuzz_state->skip_initial > 0) {
        fuzz_state->skip_initial--;
        return false;
    }

    LOG(2, LOG_PREFIX" executing post-fuzz for "PIFX"\n", target_pc);

    fuzz_state->repeat_index++;
    if (fuzz_target.stat_freq > 0 && fuzz_state->repeat_index % fuzz_target.stat_freq) {
        LOG(1, LOG_PREFIX" mutation for iteration #%d:\n", fuzz_state->repeat_index);
        log_target_buffer(dcontext, 1, fuzz_state);
    }
    if (fuzz_target.repeat_count > 0 && fuzz_target.singleton_input == NULL)
        fuzz_state->repeat = (fuzz_state->repeat_index < fuzz_target.repeat_count);

    if (shadow_config.save_restore_enabled) {
        drmf_status_t res;
        shadow_state_t *shadow;
        void *dcontext = drfuzz_get_drcontext(fuzzcxt);

        res = drfuzz_get_target_per_thread_user_data(fuzzcxt, fuzz_target.pc,
                                                     (void **) &shadow);
        if (res != DRMF_SUCCESS) {
            FUZZ_ERROR("Failed to acquire the shadow memory state for target "PIFX
                       "on thread 0x%x. Disabling the fuzz target."NL,
                       fuzz_target.pc, fuzz_state->thread_id);
            fuzz_target.enabled = false;
            return false;
        }

        if (fuzz_state->repeat) {
            dr_mcontext_t mc;

            mc.size = sizeof(dr_mcontext_t);
            mc.flags = DR_MC_INTEGER | DR_MC_CONTROL;
            dr_get_mcontext(dcontext, &mc);
            shadow_state_restore_stack_frame(&mc, shadow);
        } else {
            free_shadow_buffers(shadow);
        }
    }

    if (!fuzz_state->repeat) {
        if (fuzz_state->mutator != NULL) {
            drfuzz_mutator_stop(fuzz_state->mutator);
            fuzz_state->mutator = NULL;
        }
        free_target_buffer(fuzz_state, fuzzcxt);
    }
    return fuzz_state->repeat;
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

    ASSERT_NOT_TESTED("Registration of fuzz target on module load");

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
    if (fuzz_target.mutator_options != NULL) {
        global_free(fuzz_target.mutator_options, sizeof(drfuzz_mutator_options_t),
                    HEAPSTAT_MISC);
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

static char
tokenizer_peek_next(IN tokenizer_t *t)
{
    if (*t->src == '\0')
        return '\0';
    else
        return *(t->start ? t->src : t->src + 1);
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
tokenizer_next_char(IN tokenizer_t *t, OUT char *c, IN char delimiter,
                    IN const char *accepted_codes, IN const char *field_name,
                    tokenizer_char_type_t char_type)
{
    size_t len;
    const char *src_ptr = NULL;
    bool valid = false;

    if (tokenizer_find_next(t, &src_ptr, ' ', delimiter, field_name)) {
        len = src_ptr - t->src;
        if (len == 0) {
            if (char_type == TOKENIZER_CHAR_SET)
                return false; /* end of set */
            *c = ' ';
            valid = true;
        } else if (char_type == TOKENIZER_CHAR_SET || len == 1) {
            const char *next_code;

            for (next_code = accepted_codes; *next_code != '\0'; next_code++) {
                if (*next_code == *t->src) {
                    valid = true;
                    *c = *t->src;
                    break;
                }
            }
        }
    }

    if (!valid) {
        NOTIFY_ERROR("Failed to understand '%.1s' as a %s."NL, t->src, field_name);
        NOTIFY_ERROR("Expected one of '{%s}' at position %d in "RAW_SNIPPET_FORMAT"."NL,
                     accepted_codes, t->src - t->src_head, RAW_SNIPPET_ARGS(t->raw_src));
        tokenizer_exit_with_usage_error();
        return false;
    }

    if (char_type == TOKENIZER_CHAR_SINGLETON)
        t->src += len;
    t->start = false;
    return true;
}

static bool
tokenizer_next_uint(IN tokenizer_t *t, OUT byte *dst, IN char delimiter,
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

static inline void
replace_char(char *dst, char old, char new)
{
    char *next_old = strchr(dst, old);

    for (; next_old != NULL; next_old = strchr(next_old + 1, old))
        *next_old = new;
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

    if (!tokenizer_next_uint(&tokens, (byte *) &fuzz_target.arg_count,
                             '|', false, false, "buffer arg"))
        return false;
    if (!tokenizer_next_uint(&tokens, (byte *) &fuzz_target.buffer_arg,
                             '|', false, false, "size arg"))
        return false;
    if (!tokenizer_next_uint(&tokens, (byte *) &fuzz_target.size_arg,
                             '|', false, false, "repeat count"))
        return false;
    if (!tokenizer_next_uint(&tokens, (byte *) &fuzz_target.repeat_count,
                             '|', false, false, "repeat count"))
        return false;
    if (tokenizer_has_next(&tokens, '|')) {
        uint callconv;
        if (!tokenizer_next_uint(&tokens, (byte *) &callconv,
                                 '|', false, false, "calling convention"))
            return false;
        fuzz_target.callconv = (callconv << CALLCONV_FLAG_SHIFT);
    } else {
        fuzz_target.callconv = DRWRAP_CALLCONV_DEFAULT;
    }
    fuzz_target.callconv_args = map_callconv_args(fuzz_target.callconv);
    if (fuzz_target.callconv_args == NULL) {
        NOTIFY_ERROR("Descriptor specifies unknown calling convention id %d"NL,
                     fuzz_target.callconv);
        FUZZ_ERROR("Descriptor specifies unknown calling convention id %d\n",
                   fuzz_target.callconv);
        tokenizer_exit_with_usage_error();
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

static void
log_flag(drfuzz_mutator_options_t *options, drfuzz_mutator_flags_t flag,
         const char *display_name)
{
    if (TEST(flag, options->flags))
        LOG(1, LOG_PREFIX" Set mutator flag '%s'\n", display_name);
    else
        LOG(1, LOG_PREFIX" Cleared mutator flag '%s'\n", display_name);
}

static bool
user_input_parse_mutator(char *descriptor, const char *raw_descriptor)
{
    char code;
    uint64 time_millis;
    bool user_specified_time_seed = false;
    tokenizer_t tokens;
    drfuzz_mutator_options_t *options;

    if (fuzz_target.mutator_options == NULL)
        options = global_alloc(sizeof(drfuzz_mutator_options_t), HEAPSTAT_MISC);
    else
        options = fuzz_target.mutator_options; /* will overwrite all values */
    memcpy(options, &DRFUZZ_MUTATOR_DEFAULT_OPTIONS, sizeof(drfuzz_mutator_options_t));
    options->flags = 0; /* no default flags when user specifies a descriptor */

    replace_char(descriptor, '|', ' '); /* replace pipes with spaces for dr_get_token() */
    tokenizer_init(&tokens, (const char *) descriptor, raw_descriptor, HEAPSTAT_MISC);

    if (!tokenizer_next_char(&tokens, &code, '|', "or\0", "mutator algorithm",
                             TOKENIZER_CHAR_SINGLETON)) {
        global_free(options, sizeof(drfuzz_mutator_options_t), HEAPSTAT_MISC);
        return false;
    }
    switch (code) {
    case 'o':
        options->alg = MUTATOR_ALG_ORDERED;
        LOG(1, LOG_PREFIX" Set mutator algorithm to 'ordered'\n");
        break;
    case 'r':
        options->alg = MUTATOR_ALG_RANDOM;
        LOG(1, LOG_PREFIX" Set mutator algorithm to 'random'\n");
        break;
    default: break; /* use the default value */
    }

    if (!tokenizer_next_char(&tokens, &code, '|', "nb\0", "mutator unit",
                             TOKENIZER_CHAR_SINGLETON)) {
        global_free(options, sizeof(drfuzz_mutator_options_t), HEAPSTAT_MISC);
        return false;
    }
    switch (code) {
    case 'n':
        options->unit = MUTATOR_UNIT_NUM;
        LOG(1, LOG_PREFIX" Set mutator unit to 'numeric'\n");
        break;
    case 'b':
        options->unit = MUTATOR_UNIT_BITS;
        LOG(1, LOG_PREFIX" Set mutator unit to 'bit-flip'\n");
        break;
    default: break; /* use the default value */
    }

    while (tokenizer_next_char(&tokens, &code, '|', "rt\0", "mutator flag",
                               TOKENIZER_CHAR_SET)) {
        switch (code) {
        case 'r':
            options->flags |= MUTATOR_FLAG_BITFLIP_SEED_CENTRIC;
            break;
        case 't': /* report the specific seed to stderr for release visibility */
            time_millis = dr_get_milliseconds();
            LOG(1, "Initialize mutator's random seed with time 0x%llx\n", time_millis);
            NOTIFY("Dr. Fuzz mutator random seed: 0x%llx"NL, time_millis);
            options->random_seed = time_millis;
            user_specified_time_seed = true;
            break;
        default:
            NOTIFY_ERROR("Unknown mutator flag '%c'"NL, code);
            FUZZ_ERROR("Unknown mutator flag '%c'"NL, code);
            global_free(options, sizeof(drfuzz_mutator_options_t), HEAPSTAT_MISC);
            tokenizer_exit_with_usage_error();
            return false;
        }
    }
    log_flag(options, MUTATOR_FLAG_BITFLIP_SEED_CENTRIC, "seed-centric");

    if (!tokenizer_next_uint(&tokens, (byte *) &options->sparsity,
                             '|', false, false, "mutator sparsity"))
        return false;

    if (tokenizer_peek_next(&tokens) != '\0') { /* optional mutator random seed */
        if (user_specified_time_seed) {
            NOTIFY_ERROR("Cannot specify both a random seed and a randomized random seed "
                         "for the same mutator."NL);
            FUZZ_ERROR("Cannot specify both a random seed and a randomized random seed "
                       "for the same mutator."NL);
            global_free(options, sizeof(drfuzz_mutator_options_t), HEAPSTAT_MISC);
            tokenizer_exit_with_usage_error();
            return false;
        }
        if (!tokenizer_next_uint(&tokens, (byte *) &options->random_seed,
                                 '|', true, true, "mutator random seed")) {
            NOTIFY_ERROR("Failed to parse the mutator random seed."NL);
            FUZZ_ERROR("Failed to parse the mutator random seed."NL);
            global_free(options, sizeof(drfuzz_mutator_options_t), HEAPSTAT_MISC);
            tokenizer_exit_with_usage_error();
            return false;
        }
    }

    fuzz_target.mutator_options = options;
    return true;
}
