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
 * callstack.h: callstack recording
 */

#ifndef _CALLSTACK_H_
#define _CALLSTACK_H_ 1

#include "dr_api.h"
#include "crypto.h"

/****************************************************************************
 * Application locations
 */

typedef enum {
    APP_LOC_PC,
    APP_LOC_SYSCALL,
    /* for future use of perhaps replacing data addr, where I'm passing
     * a low int for uninit error in register
     */
    APP_LOC_REGISTER,
} app_loc_type_t;

/* Structure to represent a location within an application such as
 * an instruction's program counter or a system call number
 */
typedef struct _app_loc_t {
    app_loc_type_t type;
    union {
        /* Normally the error is at a particular instruction.  For PR 494769
         * we may not have translated the cache pc yet so the pc field
         * is not valid unless the valid field is true.
         */
        struct { 
            bool valid;
            app_pc pc;
        } addr;
        /* An error in a system call has the syscall number and an
         * additional string describing which parameter (PR 525269).
         */
        struct { 
            uint sysnum;
            const char *syscall_aux;
        } syscall;
    } u;
} app_loc_t;

void
pc_to_loc(app_loc_t *loc, app_pc pc);

void
syscall_to_loc(app_loc_t *loc, uint sysnum, const char *aux);

/* needs to be defined by the tool-specific code */
app_pc
loc_to_pc(app_loc_t *loc);

/* needs to be defined by the tool-specific code */
app_pc
loc_to_print(app_loc_t *loc);

/****************************************************************************
 * Callstacks
 */

/* Values for the flags parameter to callstack_init.  These control
 * how our callstack walking looks for frame pointers when it
 * encounters a discontinuity in the frame links.  We arrange these
 * such that 0 is a good default.
 */
enum {
    /* Showing non module works fine, but there are issues with suppression -
     * FIXME: PR 464809.
     */
    FP_SHOW_NON_MODULE_FRAMES         = 0x0001,
    FP_STOP_AT_BAD_NONZERO_FRAME      = 0x0002,
    FP_STOP_AT_BAD_ZERO_FRAME         = 0x0004,
    FP_SEARCH_MATCH_SINGLE_FRAME      = 0x0008, /* only valid w/ FP_SEARCH_REQUIRE_FP */
    /* Whether to look for fp,ra pairs during scan, which doesn't work with FPO */
    FP_SEARCH_REQUIRE_FP              = 0x0010,
    /* For more speed but less accuracy (esp with FPO) can not check whether
     * retaddr candidates during scan are post-OP_call
     */
    FP_SEARCH_DO_NOT_DISASM           = 0x0020,
    /* For more speed, optionally can not check retaddrs during fp chain walk */
    FP_DO_NOT_CHECK_RETADDR           = 0x0040,
    /* By default, avoid 40% perf hit (on cfrac and roboop) by not checking
     * retaddr during fp chain walk until have to do a scan: should be
     * safe to assume fp's are genuine up to any scan.
     */
    FP_CHECK_RETADDR_PRE_SCAN         = 0x0080,
    /* We do want to check the very first retaddr since ebp might point at
     * some stack var that happens to look like another fp,ra pair
     */
    FP_DO_NOT_CHECK_FIRST_RETADDR     = 0x0100,
    FP_SEARCH_AGGRESSIVE              = (FP_SHOW_NON_MODULE_FRAMES |
                                         FP_SEARCH_MATCH_SINGLE_FRAME),
};

/* Options for how to display callstacks.
 * N.B.: postprocess.pl has a duplicate copy (once we have linux online syms
 * that will go away) so keep them in sync
 */
enum {
    PRINT_FRAME_NUMBERS        = 0x0001,
    PRINT_ABS_ADDRESS          = 0x0002,
    PRINT_MODULE_OFFSETS       = 0x0004,
    PRINT_SYMBOL_OFFSETS       = 0x0008,
    PRINT_LINE_OFFSETS         = 0x0010,
    PRINT_SRCFILE_NEWLINE      = 0x0020,
    PRINT_SRCFILE_NO_COLON     = 0x0040,
    PRINT_SYMBOL_FIRST         = 0x0080,
    PRINT_ALIGN_COLUMNS        = 0x0100,

    PRINT_FOR_POSTPROCESS      = (PRINT_FRAME_NUMBERS | PRINT_ABS_ADDRESS |
                                  PRINT_MODULE_OFFSETS),
    PRINT_FOR_LOG              = (PRINT_ABS_ADDRESS | PRINT_MODULE_OFFSETS |
                                  PRINT_SYMBOL_OFFSETS | PRINT_LINE_OFFSETS),
};

/* length of strings identifying module+offset addresses:
 * e.g., "0x7d61f78c <ntdll.dll+0x1f78c>"
 */
#define MAX_MODULE_LEN IF_WINDOWS_ELSE(32,52)
/* this can't be an expression since we STRINGIFY it */
#define MAX_MODOFF_LEN IF_WINDOWS_ELSE(34,54) /* for '<' and '>' */
#define MAX_PFX_LEN (3/*'+0x'*/ + IF_X64_ELSE(16,8)/*%08x*/)
#define MAX_ADDR_LEN (MAX_MODULE_LEN + MAX_PFX_LEN)
/* max lengths for symbols */
#define MAX_FUNC_LEN 256 /* C++ templates get pretty long */
#define MAX_SYMBOL_LEN (MAX_MODULE_LEN + 1/*!*/ + MAX_FUNC_LEN)
#define MAX_FILENAME_LEN 128
#define MAX_LINENO_DIGITS 6
#define MAX_FILE_LINE_LEN (MAX_FILENAME_LEN + 1/*:*/ + MAX_LINENO_DIGITS)

/* if a zero or bad fp is within this threshold of the lowest frame,
 * do not scan further.  i#246.
 * XXX: could turn into an option if becomes important
 */
#define FP_NO_SCAN_NEAR_LOW_THRESH 64

/* Max length of error report lines prior to callstack.
 * Since disass is separate, this is title + timestamp + info
 * from PR 535568.  Here is an example of how large it can get:
 *   Error #1: UNADDRESSABLE ACCESS  reading 0x0835b39b-0x0835b39c 1 byte(s)
 *   Elapsed time = 0:00:00.109 in thread 18436
 *   Note: prev lower malloc:  0x0835b358-0x0835b38b
 *   Note: next higher malloc: 0x0835b3b8-0x0835b3bb
 *   Note: 0x0835b39b-0x0835b39c overlaps freed memory 0x0835b398-0x0835b3ac
 */
#define MAX_ERROR_INITIAL_LINES 512

#ifdef STATISTICS
extern uint find_next_fp_scans;
extern uint symbol_names_truncated;
extern uint cstack_is_retaddr;
extern uint cstack_is_retaddr_backdecode;
extern uint cstack_is_retaddr_unreadable;
#endif

void
callstack_init(uint callstack_max_frames, uint stack_swap_threshold,
               uint fp_flags, size_t fp_scan_sz, uint print_flags,
               const char *(*get_syscall_name)(uint),
               bool (*is_dword_defined)(byte *));

void
callstack_exit(void);

void
callstack_thread_init(void *drcontext);

void
callstack_thread_exit(void *drcontext);

size_t
max_callstack_size(void);

/****************************************************************************
 * Binary callstacks for storing callstacks of allocation sites
 */

struct _packed_callstack_t;
typedef struct _packed_callstack_t packed_callstack_t;

void
packed_callstack_record(packed_callstack_t **pcs_out/*out*/, dr_mcontext_t *mc,
                        app_loc_t *loc);

void
packed_callstack_first_frame_retaddr(packed_callstack_t *pcs);

void
packed_callstack_print(packed_callstack_t *pcs, uint num_frames,
                       char *buf, size_t bufsz, size_t *sofar);

#ifdef DEBUG
void
packed_callstack_log(packed_callstack_t *pcs, file_t f);
#endif

uint
packed_callstack_free(packed_callstack_t *pcs);

void
packed_callstack_add_ref(packed_callstack_t *pcs);

packed_callstack_t *
packed_callstack_clone(packed_callstack_t *src);

uint
packed_callstack_hash(packed_callstack_t *pcs);

bool
packed_callstack_cmp(packed_callstack_t *pcs1, packed_callstack_t *pcs2);

void
packed_callstack_md5(packed_callstack_t *pcs, byte digest[MD5_RAW_BYTES]);

void
packed_callstack_crc32(packed_callstack_t *pcs, uint crc[2]);

/* The user must call this from a DR dr_register_module_load_event() event */
void
callstack_module_load(void *drcontext, const module_data_t *info, bool loaded);

/* The user must call this from a DR dr_register_module_unload_event() event */
void
callstack_module_unload(void *drcontext, const module_data_t *info);

bool
is_in_module(byte *pc);

/****************************************************************************
 * Symbolized callstacks
 */

struct _symbolized_frame_t;
typedef struct _symbolized_frame_t symbolized_frame_t;

typedef struct _symbolized_callstack_t {
    ushort num_frames;
    symbolized_frame_t *frames;
} symbolized_callstack_t;

void
packed_callstack_to_symbolized(packed_callstack_t *pcs IN,
                               symbolized_callstack_t *scs OUT);

void
symbolized_callstack_print(const symbolized_callstack_t *scs IN,
                           char *buf, size_t bufsz, size_t *sofar);

void
symbolized_callstack_free(symbolized_callstack_t *scs);

bool
symbolized_callstack_frame_is_module(const symbolized_callstack_t *scs, uint frame);

char *
symbolized_callstack_frame_modname(const symbolized_callstack_t *scs, uint frame);

char *
symbolized_callstack_frame_modoffs(const symbolized_callstack_t *scs, uint frame);

char *
symbolized_callstack_frame_func(const symbolized_callstack_t *scs, uint frame);

/****************************************************************************
 * Printing routines
 */

/* Returns whether a new frame was added (won't be if module_only and pc
 * is not in a module)
 */
bool
print_address(char *buf, size_t bufsz, size_t *sofar,
              app_pc pc, module_data_t *mod_in /*optional*/,
              bool omit_non_module, bool sub1_sym, bool for_log);

void
print_callstack(char *buf, size_t bufsz, size_t *sofar, dr_mcontext_t *mc, 
                bool print_fps, packed_callstack_t *pcs, int num_frames_printed,
                bool for_log);

void
print_buffer(file_t f, char *buf);

#ifdef DEBUG
void
print_callstack_to_file(void *drcontext, dr_mcontext_t *mc, app_pc pc, file_t f);
#endif


#endif /* _CALLSTACK_H_ */
