/* **********************************************************
 * Copyright (c) 2010-2015 Google, Inc.  All rights reserved.
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
 * readwrite.c: Dr. Memory memory read/write slowpath handling
 */

#include "dr_api.h"
#include "drutil.h"
#include "drmemory.h"
#include "instru.h"
#include "readwrite.h"
#include "spill.h"
#include "fastpath.h"
#include "stack.h"
#include "alloc_drmem.h"
#include "heap.h"
#include "alloc.h"
#include "report.h"
#include "shadow.h"
#include "syscall.h"
#include "replace.h"
#include "perturb.h"
#include "annotations.h"
#ifdef TOOL_DR_HEAPSTAT
# include "../drheapstat/staleness.h"
#endif
#include "pattern.h"
#include <stddef.h>
#include "asm_utils.h"

/* pusha/popa need 8 dwords, as does a ymm data xfer */
#define MAX_DWORDS_TRANSFER 8
#define OPND_SHADOW_ARRAY_LEN (MAX_DWORDS_TRANSFER * sizeof(uint))

typedef struct _shadow_combine_t {
    /* Array of shadow vals from sources to dests: each uint entry in the
     * array is a shadow for one byte being transferred from source(s) to dest.
     * Larger mem refs either have no transfer (e.g., fxsave), or if
     * they do (rep movs) we handle them specially.
     */
    uint raw[OPND_SHADOW_ARRAY_LEN];
    /* Indirection, to support laying out all srcs side-by-side and not combining any.
     * All references to the array should go through dst instead of raw.
     */
    uint *dst;
    /* Shadow value to write to eflags */
    uint eflags;
    /* The instr we're processing.  This is optional: it can be NULL, but then
     * the code using this struct needs to handle all special data movement
     * on its own, must still set the opcode, and must propagate shadow eflags.
     */
    instr_t *inst;
    /* Must be set */
    uint opcode;
    /* These must be set when processing sources, and thus when calling
     * check_mem_opnd() or integrate_register_shadow() for non-eflag sources.
     * These exist to support artificial constructions.  They should not be
     * extract from inst (it's a little fragile -- we kind of rely on only
     * accessing inst for certain types of instrs that we never fake).
     */
#ifdef DEBUG
    bool opnd_valid; /* whether opnd and opsz are set */
#endif
    opnd_t opnd;
    size_t opsz; /* in bytes */
    /* For handling OP_movs */
    byte *movs_addr;
} shadow_combine_t;

#ifdef STATISTICS
/* per-opcode counts */
uint64 slowpath_count[OP_LAST+1];
/* per-opsz counts */
uint64 slowpath_sz1;
uint64 slowpath_sz2;
uint64 slowpath_sz4;
uint64 slowpath_sz8;
uint64 slowpath_sz10;
uint64 slowpath_sz16;
uint64 slowpath_szOther;

/* PR 423757: periodic stats dump */
uint next_stats_dump;

uint num_faults;
uint num_slowpath_faults;
#endif

#ifdef STATISTICS
uint slowpath_executions;
uint medpath_executions;
uint read_slowpath;
uint write_slowpath;
uint push_slowpath;
uint pop_slowpath;
uint read_fastpath;
uint write_fastpath;
uint push_fastpath;
uint pop_fastpath;
uint read4_fastpath;
uint write4_fastpath;
uint push4_fastpath;
uint pop4_fastpath;
uint slow_instead_of_fast;
uint heap_header_exception;
uint tls_exception;
uint alloca_exception;
uint strlen_exception;
uint strlen_uninit_exception;
uint strcpy_exception;
uint rawmemchr_exception;
uint strmem_unaddr_exception;
uint strrchr_exception;
uint andor_exception;
uint bitfield_const_exception;
uint bitfield_xor_exception;
uint loader_DRlib_exception;
uint cppexcept_DRlib_exception;
uint fldfst_exception;
uint heap_func_ref_ignored;
uint reg_dead;
uint reg_xchg;
uint reg_spill;
uint reg_spill_slow;
uint reg_spill_own;
uint reg_spill_used_in_bb;
uint reg_spill_unused_in_bb;
uint addressable_checks_elided;
uint aflags_saved_at_top;
uint xl8_shared;
uint xl8_not_shared_reg_conflict;
uint xl8_not_shared_scratch_conflict;
uint xl8_not_shared_disp_too_big;
uint xl8_not_shared_unaligned;
uint xl8_not_shared_mem2mem;
uint xl8_not_shared_offs;
uint xl8_not_shared_slowpaths;
uint xl8_shared_slowpath_instrs;
uint xl8_shared_slowpath_count;
uint slowpath_unaligned;
uint slowpath_8_at_border;
uint app_instrs_fastpath;
uint app_instrs_no_dup;
uint xl8_app_for_slowpath;
uint movs4_src_unaligned;
uint movs4_dst_unaligned;
uint movs4_src_undef;
uint movs4_med_fast;
uint cmps1_src_undef;
uint cmps1_med_fast;
uint num_bbs;
#endif

#ifdef TOOL_DR_MEMORY
static void
register_shadow_mark_defined(reg_id_t reg, size_t sz);
#endif /* TOOL_DR_MEMORY */

static bool
check_mem_opnd(uint opc, uint flags, app_loc_t *loc, opnd_t opnd, uint sz,
               dr_mcontext_t *mc, int opnum, shadow_combine_t *comb INOUT);

/***************************************************************************
 * Registers
 */

/* To relocate restores to the common slowpath yet still support
 * site-specific scratch registers we have restore patterns for
 * every possible combination
 */
/* variable-reg: reg1 and reg2 */
enum {
    SPILL_REG_NONE, /* !used and !dead */
    SPILL_REG_EAX,  /* this reg is spilled to tls */
    SPILL_REG_ECX,
    SPILL_REG_EDX,
    SPILL_REG_EBX,
    SPILL_REG_EAX_DEAD, /* this reg is dead */
    SPILL_REG_ECX_DEAD,
    SPILL_REG_EDX_DEAD,
    SPILL_REG_EBX_DEAD,
    SPILL_REG_NUM,
};
enum {
    SPILL_REG3_NOSPILL,
    SPILL_REG3_SPILL,
    SPILL_REG3_NUM,
};
enum {
    SPILL_EFLAGS_NOSPILL,
    SPILL_EFLAGS_5_NOEAX,
    SPILL_EFLAGS_6_NOEAX,
    SPILL_EFLAGS_5_EAX,
    SPILL_EFLAGS_6_EAX,
    SPILL_EFLAGS_NUM,
};
#define SPILL_REG3_REG   DR_REG_XCX

/* The 4 indices are: reg1, reg2, reg3, eflags */
byte *shared_slowpath_entry_local[SPILL_REG_NUM][SPILL_REG_NUM][SPILL_REG3_NUM][SPILL_EFLAGS_NUM];
/* For whole-bb spilling, we do not restore eflags, but reg3 can be anything */
byte *shared_slowpath_entry_global[SPILL_REG_NUM][SPILL_REG_NUM][SPILL_REG_NUM];
byte *shared_slowpath_region;
byte *shared_slowpath_entry;
/* adjust_esp's shared fast and slow paths pointers are below */

/* Lock for updating gencode later */
static void *gencode_lock;

/***************************************************************************
 * ISA
 */

#if 0 /* currently unused */
static bool
reg_is_caller_saved(reg_id_t reg)
{
    return (reg == DR_REG_XAX || reg == DR_REG_XDX || reg == DR_REG_XCX);
}
#endif

bool
reg_is_gpr(reg_id_t reg)
{
    return (reg >= REG_RAX && reg <= REG_DIL);
}

bool
reg_is_8bit(reg_id_t reg)
{
    return (reg >= REG_START_8 && reg <= REG_STOP_8);
}

bool
reg_is_8bit_high(reg_id_t reg)
{
    return (reg >= REG_AH && reg <= REG_BH);
}

bool
reg_is_16bit(reg_id_t reg)
{
    return (reg >= REG_START_16 && reg <= REG_STOP_16);
}

bool
reg_offs_in_dword(reg_id_t reg)
{
    if (reg_is_8bit_high(reg))
        return 1;
    else
        return 0;
}

bool
opc_is_push(uint opc)
{
    return (opc == OP_push || opc == OP_push_imm ||
            opc == OP_call || opc == OP_call_ind ||
            opc == OP_call_far || opc == OP_call_far_ind ||
            opc == OP_pushf || opc == OP_pusha || opc == OP_enter);
    /* We ignore kernel stack changes: OP_int, OP_int3, and OP_into */
}

bool
opc_is_pop(uint opc)
{
    return (opc == OP_pop || opc == OP_popf || opc == OP_popa || opc == OP_leave ||
            opc == OP_ret || opc == OP_ret_far || opc == OP_iret);
    /* DRi#537 made the post-sysenter ret visible so we no
     * longer need to treat OP_sysenter as a ret.
     */
}

bool
opc_is_stringop_loop(uint opc)
{
    return (opc == OP_rep_ins || opc == OP_rep_outs || opc == OP_rep_movs ||
            opc == OP_rep_stos || opc == OP_rep_lods || opc == OP_rep_cmps ||
            opc == OP_repne_cmps || opc == OP_rep_scas || opc == OP_repne_scas);
}

bool
opc_is_stringop(uint opc)
{
    return (opc_is_stringop_loop(opc) ||
            opc == OP_ins || opc == OP_outs || opc == OP_movs ||
            opc == OP_stos || opc == OP_lods || opc == OP_cmps ||
            opc == OP_cmps || opc == OP_scas || opc == OP_scas);
}

bool
opc_is_loopcc(uint opc)
{
    return (opc == OP_loop || opc == OP_loope || opc == OP_loopne);
}

static bool
opc_is_loop(uint opc)
{
    return (opc == OP_jecxz || opc == OP_loop || opc == OP_loope || opc == OP_loopne);
}

static bool
opc_is_move(uint opc)
{
    return (opc == OP_mov_ld || opc == OP_mov_st || opc == OP_xchg ||
            opc == OP_movzx || opc == OP_movsx ||
            opc == OP_push || opc == OP_pop || opc == OP_pusha || opc == OP_popa ||
            opc == OP_ins || opc == OP_outs || opc == OP_movs ||
            opc == OP_stos || opc == OP_lods ||
            opc == OP_rep_ins || opc == OP_rep_outs || opc == OP_rep_movs ||
            opc == OP_rep_stos || opc == OP_rep_lods);
}

static bool
opc_is_load_seg(uint opc)
{
    return (opc == OP_les || opc == OP_lds || opc == OP_lss ||
            opc == OP_lfs || opc == OP_lgs);
}

#ifdef TOOL_DR_MEMORY
/* count is in src #0 */
static bool
opc_is_shift_src0(uint opc)
{
    switch (opc) {
    case OP_shl:      case OP_shr:
    case OP_sar:
    case OP_rol:      case OP_ror:
    case OP_rcl:      case OP_rcr:
    case OP_psrlw:    case OP_psrld:   case OP_psrlq:
    case OP_psraw:    case OP_psrad:
    case OP_psrldq:
    case OP_psllw:    case OP_pslld:   case OP_psllq:
    case OP_pslldq:
        return true;
    default:
        return false;
    }
}

# ifdef DEBUG
/* count is in src #1 */
static bool
opc_is_shift_src1(uint opc)
{
    switch (opc) {
    case OP_shld:      case OP_shrd:
    case OP_vpsrlw:   case OP_vpsrld:  case OP_vpsrlq:
    case OP_vpsraw:   case OP_vpsrad:
    case OP_vpsrldq:
    case OP_vpsravd:
    case OP_vpsrlvd:  case OP_vpsrlvq:
    case OP_vpsllw:   case OP_vpslld:  case OP_vpsllq:
    case OP_vpslldq:
    case OP_vpsllvd:  case OP_vpsllvq:
        return true;
    default:
        return false;
    }
}
# endif
#endif /* TOOL_DR_MEMORY */

/* count is in src #0 */
static bool
opc_is_gpr_shift_src0(uint opc)
{
    return (opc == OP_shl || opc == OP_shr || opc == OP_sar ||
            opc == OP_rol || opc == OP_ror ||
            opc == OP_rcl || opc == OP_rcr);
}

/* count is in src #1 */
static bool
opc_is_gpr_shift_src1(uint opc)
{
    return (opc == OP_shld || opc == OP_shrd);
}

bool
opc_is_gpr_shift(uint opc)
{
    return (opc_is_gpr_shift_src0(opc) || opc_is_gpr_shift_src1(opc));
}

bool
opc_is_jcc(uint opc)
{
    return ((opc >= OP_jo && opc <= OP_jnle) ||
            (opc >= OP_jo_short && opc <= OP_jnle_short));
}

bool
opc_is_cmovcc(uint opc)
{
    return (opc >= OP_cmovo && opc <= OP_cmovnle);
}

bool
opc_is_fcmovcc(uint opc)
{
    return (opc >= OP_fcmovb && opc <= OP_fcmovnu);
}

static bool
opc_loads_into_eip(uint opc)
{
    return (opc == OP_ret || opc == OP_ret_far || opc == OP_iret ||
            opc == OP_call_ind || opc == OP_jmp_ind ||
            opc == OP_call_far_ind || opc == OP_jmp_far_ind);
    /* DRi#537 made the post-sysenter ret visible so we no
     * longer need to treat OP_sysenter as a ret.
     */
}

/* can 2nd dst be treated as simply an extension of the 1st */
bool
opc_2nd_dst_is_extension(uint opc)
{
    return (opc == OP_rdtsc || opc == OP_rdmsr || opc == OP_rdpmc ||
            opc == OP_cpuid /*though has 4 dsts*/ ||
            opc == OP_div || opc == OP_idiv ||
            opc == OP_mul || opc == OP_imul);
}

bool
reg_is_shadowed(int opc, reg_id_t reg)
{
    /* i#471: we don't yet shadow floating-point regs */
    return (reg_is_gpr(reg) ||
            /* i#243: we don't yet shadow ymm regs */
            (reg_is_xmm(reg) && !reg_is_ymm(reg)) ||
            /* i#1473: propagate mmx */
            reg_is_mmx(reg));
}

static bool
instr_propagatable_dsts(instr_t *inst)
{
    int i;
    bool res = false;
    int opc = instr_get_opcode(inst);
    for (i = 0; i < instr_num_dsts(inst); i++) {
        opnd_t opnd = instr_get_dst(inst, i);
        /* i#1543, i#243: we now shadow xmm regs and propagate and mirror xmm
         * operations (at least most of them: work in progress).
         */
        if ((opnd_is_reg(opnd) && reg_is_shadowed(opc, opnd_get_reg(opnd))) ||
            opnd_is_memory_reference(opnd)) {
            res = true;
        } else {
            res = false;
            break;
        }
    }
    return res;
}

bool
xax_is_used_subsequently(instr_t *inst)
{
    while (inst != NULL) {
        if (instr_uses_reg(inst, DR_REG_XAX))
            return true;
        inst = instr_get_next(inst);
    }
    return false;
}

#ifdef TOOL_DR_MEMORY
/* drcontext can be NULL if the operand is an immed int.
 *
 * For mmx, xmm, or ymm sources, returns just the lower reg_t bits.
 * XXX: we'll need to return the full value for handling OP_pand, etc.!
 * For now we only use this to get shift amounts for which we can ignore
 * all high bits.
 */
static bool
get_cur_src_value(void *drcontext, instr_t *inst, uint i, reg_t *val)
{
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    opnd_t src = instr_get_src(inst, i);
    if (val == NULL)
        return false;
    if (opnd_is_immed_int(src)) {
        *val = (reg_t) opnd_get_immed_int(src);
        return true;
    }
    ASSERT(drcontext != NULL, "need drcontext for non-immed opnd");
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */
    dr_get_mcontext(drcontext, &mc);
    if (opnd_is_memory_reference(src)) {
        app_pc addr = opnd_compute_address(src, &mc);
        size_t sz = opnd_size_in_bytes(opnd_get_size(src));
        if (sz > sizeof(*val))
            return false;
        return (safe_read(addr, sz, val));
    } else if (opnd_is_reg(src)) {
        byte val32[sizeof(dr_ymm_t)];
        reg_id_t reg = opnd_get_reg(src);
        if (!reg_is_gpr(reg)) {
            mc.flags |= DR_MC_MULTIMEDIA;
            dr_get_mcontext(drcontext, &mc);
        }
        if (!reg_get_value_ex(reg, &mc, val32))
            return false;
        *val = *(reg_t*)val32;
        return true;
    }
    return false;
}

static inline bool
opnds_overlap(opnd_t op1, opnd_t op2)
{
    /* XXX: should we check overlap on memory opnd? */
    return (opnd_same(op1, op2) ||
            (opnd_is_reg(op1) && opnd_is_reg(op2) && opnd_share_reg(op1, op2)));
}

static bool
instrs_share_opnd(instr_t *in1, instr_t *in2)
{
    int i, j;
    for (i = 0; i < instr_num_srcs(in1); i++) {
        for (j = 0; j < instr_num_srcs(in2); j++) {
            if (opnds_overlap(instr_get_src(in1, i), instr_get_src(in2, j)))
                return true;
        }
        for (j = 0; j < instr_num_dsts(in2); j++) {
            if (opnds_overlap(instr_get_src(in1, i), instr_get_dst(in2, j)))
                return true;
        }
    }
    for (i = 0; i < instr_num_dsts(in1); i++) {
        for (j = 0; j < instr_num_srcs(in2); j++) {
            if (opnds_overlap(instr_get_dst(in1, i), instr_get_src(in2, j)))
                return true;
        }
        for (j = 0; j < instr_num_dsts(in2); j++) {
            if (opnds_overlap(instr_get_dst(in1, i), instr_get_dst(in2, j)))
                return true;
        }
    }
    return false;
}
#endif /* TOOL_DR_MEMORY */

uint
adjust_memop_push_offs(instr_t *inst)
{
    /* DR's IR now properly encodes push sizes (DRi#164), except for OP_enter */
    if (instr_get_opcode(inst) == OP_enter) {
        /* OP_enter's esp adjust (1st immed) is handled in
         * instrument_esp_adjust, as it doesn't write those bytes
         */
        uint extra_pushes = (uint) opnd_get_immed_int(instr_get_src(inst, 1));
        uint sz = opnd_size_in_bytes(opnd_get_size(instr_get_dst(inst, 1)));
        ASSERT(opnd_is_immed_int(instr_get_src(inst, 1)), "internal error");
        return sz*extra_pushes;
    }
    return 0;
}

opnd_t
adjust_memop(instr_t *inst, opnd_t opnd, bool write, uint *opsz, bool *pushpop_stackop)
{
    /* DR's IR now properly encodes push sizes (DRi#164), except for OP_enter */
    uint opc = instr_get_opcode(inst);
    uint sz = opnd_size_in_bytes(opnd_get_size(opnd));
    bool push = opc_is_push(opc);
    bool pop = opc_is_pop(opc);
    bool pushpop = false; /* is mem ref on stack for push/pop */
    if (opnd_uses_reg(opnd, DR_REG_XSP) || opc == OP_leave/*(ebp) not (esp)*/) {
        if (write && push && opnd_is_base_disp(opnd)) {
            uint extra_push_sz = adjust_memop_push_offs(inst);
            pushpop = true;
            if (extra_push_sz > 0) {
                sz += extra_push_sz;
                opnd_set_disp(&opnd, opnd_get_disp(opnd) - sz);
            }
        } else if (!write && pop && opnd_is_base_disp(opnd)) {
            if (!instr_pop_into_esp(inst))
                pushpop = true;
            if (opc == OP_leave) {
                /* OP_leave's ebp->esp is handled in instrument_esp_adjust; here we
                 * treat it as simply a pop into ebp, though using the esp value
                 * copied from ebp, which we emulate here since we're doing it
                 * before the adjust instead of after: FIXME we'll report
                 * errors in both in the wrong order.
                 */
                ASSERT(opnd_get_base(opnd) == DR_REG_XBP, "OP_leave opnd wrong");
            }
            /* OP_ret w/ immed is treated as single pop here; its esp
             * adjustment is handled separately, as it doesn't read those bytes.
             */
        }
    }
    /* we assume only +w ref for push (-w for pop) is the stack adjust */
    ASSERT(pushpop || (!(write && push) && !(!write && pop)) || instr_pop_into_esp(inst),
           "internal stack op bad assumption");
    *opsz = sz;
    *pushpop_stackop = pushpop;
    return opnd;
}

/* Some source operands we always check.  Note that we don't need to explicitly
 * list stack pointers or stringop bases as our basedisp checks already
 * look at those registers.
 */
bool
always_check_definedness(instr_t *inst, int opnum)
{
    uint opc = instr_get_opcode(inst);
    return ((opc == OP_leave && opnum == 0) /* ebp */ ||
            /* count of loop is important: check it */
            (opc_is_stringop_loop(opc) && opnd_is_reg(instr_get_src(inst, opnum)) &&
             reg_overlap(opnd_get_reg(instr_get_src(inst, opnum)), DR_REG_XCX)) ||
            /* the comparison operands only: the others are moves */
            (opc == OP_cmpxchg && opnum > 0/*dst, eax*/) ||
            (opc == OP_cmpxchg8b && opnum <= 2/*memop, eax, edx*/) ||
            /* always check %cl.  FIXME PR 408549: Valgrind propagates it (if undefined,
             * dest is always undefined), but for us to propagate we need
             * special checks to avoid calling adjust_source_shadow()
             */
            ((opc_is_gpr_shift_src0(opc) && opnum == 0) ||
             (opc_is_gpr_shift_src1(opc) && opnum == 1)));
}

/* For some instructions we check all source operands for definedness. */
bool
instr_check_definedness(instr_t *inst)
{
    uint opc = instr_get_opcode(inst);
    return
        /* always check conditional jumps */
        instr_is_cbr(inst) ||
        (options.check_uninit_non_moves && !opc_is_move(opc)) ||
        options.check_uninit_all ||
        (options.check_uninit_cmps &&
         /* a compare writes eflags but nothing else, or is a loop, cmps, or cmovcc.
          * for cmpxchg* only some operands are compared: see always_check_definedness.
          */
         ((instr_num_dsts(inst) == 0 &&
           TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL))) ||
          opc_is_loop(opc) || opc_is_cmovcc(opc) || opc_is_fcmovcc(opc) ||
          opc == OP_cmps || opc == OP_rep_cmps || opc == OP_repne_cmps)) ||
        /* if eip is a destination we have to check the corresponding
         * source.  for ret or call, the other dsts/srcs are just esp, which
         * has to be checked as an addressing register anyway. */
        opc_loads_into_eip(opc) ||
        opc_is_load_seg(opc) || /* we could not check the offs part */
        /* We consider arith flags as enough to transfer definedness to.
         * Note that we don't shadow the floating-point status word, so
         * most float ops should hit this. */
        (!instr_propagatable_dsts(inst) &&
         !TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)) &&
         /* though prefetch has nowhere to propagate uninit shadow vals to, we
          * do not want to raise errors.  so we ignore, under the assumption
          * that a real move will happen soon enough to propagate: if not,
          * little harm done.  i#244.
          */
         !instr_is_prefetch(inst));
}

/***************************************************************************
 * Definedness and Addressability Checking
 */

bool
result_is_always_defined(instr_t *inst, bool natively)
{
    /* Even if source operands are undefined, don't consider this instr as
     * reading undefined values if:
     * 1) clearing/setting all bits via:
     *   - and with 0
     *   - or with ~0
     *   - xor with self
     *   - packed subtract with self
     *   - sbb with self (PR 425498): now handled via num_true_srcs since must
     *     propagate eflags (PR 425622)
     */
    int opc = instr_get_opcode(inst);

#ifdef TOOL_DR_MEMORY
    /* i#1529: mark an entire module defined */
    if (!natively && options.check_uninit_blacklist[0] != '\0') {
        /* Fastpath should have already checked the cached value in
         * bb_info_t.mark_defined, so we should only be paying this
         * cost for each slowpath entry.
         */
        app_pc pc = instr_get_app_pc(inst) != NULL ?
            instr_get_app_pc(inst) : instr_get_raw_bits(inst);
        if (module_is_on_check_uninit_blacklist(pc)) {
            LOG(3, "module is on uninit blacklist: always defined\n");
            return true;
        }
    }
#endif

    /* Though our general non-const per-byte 0/1 checking would cover this,
     * we optimize by looking for entire-dword consts up front
     */
    if ((opc == OP_and &&
         opnd_is_immed_int(instr_get_src(inst, 0)) &&
         opnd_get_immed_int(instr_get_src(inst, 0)) == 0) ||
        (opc == OP_test &&
         opnd_is_immed_int(instr_get_src(inst, 1)) &&
         opnd_get_immed_int(instr_get_src(inst, 1)) == 0) ||
        (opc == OP_or &&
         opnd_is_immed_int(instr_get_src(inst, 0)) &&
         opnd_get_immed_int(instr_get_src(inst, 0)) == ~0) ||
        ((opc == OP_xor || opc == OP_pxor || opc == OP_xorps || opc == OP_xorpd ||
          opc == OP_psubq || opc == OP_subps || opc == OP_subpd) &&
         opnd_same(instr_get_src(inst, 0), instr_get_src(inst, 1)))) {
        STATS_INC(andor_exception);
        return true;
    }
    return false;
}

#ifdef TOOL_DR_MEMORY
# ifdef UNIX
static bool
is_rawmemchr_uninit(void *drcontext, app_pc pc, reg_id_t reg,
                    dr_mcontext_t *mc, instr_t *inst)
{
    char buf[16]; /* for safe_read */
    /* PR 406535: glibc's rawmemchr does some bit tricks that can end up using
     * undefined or unaddressable values:
     * <rawmemchr+113>:
     *   0x0046b0d1  8b 48 08             mov    0x08(%eax) -> %ecx
     *   0x0046b0d4  bf ff fe fe fe       mov    $0xfefefeff -> %edi
     *   0x0046b0d9  31 d1                xor    %edx %ecx -> %ecx
     *   0x0046b0db  01 cf                add    %ecx %edi -> %edi
     *   0x0046b0dd  73 2c                jnb    $0x0046b10b
     * we have two different checks: one for !options.check_uninit_non_moves where
     * the error isn't raised until the jnb and one for error on xor.
     * FIXME: share code w/ is_rawmemchr_pattern() in alloc_drmem.c
     */
    if (options.check_uninit_non_moves ||
        options.check_uninit_all) {
        static const byte RAWMEMCHR_PATTERN_NONMOVES[5] = {0xbf, 0xff, 0xfe, 0xfe, 0xfe};
        ASSERT(sizeof(RAWMEMCHR_PATTERN_NONMOVES) <= BUFFER_SIZE_BYTES(buf),
               "buf too small");
        if (reg == DR_REG_XCX &&
            instr_get_opcode(inst) == OP_xor &&
            safe_read(pc - sizeof(RAWMEMCHR_PATTERN_NONMOVES),
                      sizeof(RAWMEMCHR_PATTERN_NONMOVES), buf) &&
            memcmp(buf, RAWMEMCHR_PATTERN_NONMOVES,
                   sizeof(RAWMEMCHR_PATTERN_NONMOVES)) == 0) {
            LOG(3, "suppressing positive from glibc rawmemchr pattern\n");
            register_shadow_set_dword(DR_REG_XCX, SHADOW_DWORD_DEFINED);
            STATS_INC(rawmemchr_exception);
            return true;
        }
    } else {
        /* FIXME PR 406535: verify there's no chance of a true positive */
        static const byte RAWMEMCHR_PATTERN[9] =
            {0xbf, 0xff, 0xfe, 0xfe, 0xfe, 0x31, 0xd1, 0x01, 0xcf};
        ASSERT(sizeof(RAWMEMCHR_PATTERN) <= BUFFER_SIZE_BYTES(buf), "buf too small");
        if (reg == REG_EFLAGS &&
            (instr_get_opcode(inst) == OP_jnb ||
             instr_get_opcode(inst) == OP_jnb_short) &&
            safe_read(pc - sizeof(RAWMEMCHR_PATTERN), sizeof(RAWMEMCHR_PATTERN), buf) &&
            memcmp(buf, RAWMEMCHR_PATTERN, sizeof(RAWMEMCHR_PATTERN)) == 0) {
            uint val = get_shadow_register(DR_REG_XCX);
            /* We want to only allow the end of the search to be suppressed,
             * to avoid suppressing a real positive.  We assume going in
             * forward direction (there is no rawmemrchr).
             * Not easy to compute whether done w/ search: for now just
             * going to require bottom byte to be defined to at least
             * not suppress the entire byte being undefined.
             * FIXME: do better: similarly w/ the strlen exceptions.
             */
            if ((val & 0x3) == 0) {
                LOG(3, "suppressing positive from glibc rawmemchr pattern\n");
                set_shadow_eflags(SHADOW_DWORD_DEFINED);
                STATS_INC(rawmemchr_exception);
                return true;
            } else
                LOG(3, "NOT suppressing glibc rawmemchr w/ val 0x%x\n", val);
        }
    }
    return false;
}

static bool
is_strrchr_uninit(void *drcontext, app_pc pc, reg_id_t reg,
                  dr_mcontext_t *mc, instr_t *inst)
{
    bool match = false;
    char buf[16]; /* for safe_read */
    /* glibc's strrchr:
     *   +0    L3  8b 56 08             mov    0x08(%esi) -> %edx
     *   +3    L3  bf ff fe fe fe       mov    $0xfefefeff -> %edi
     *   +8    L3  01 d7                add    %edx %edi -> %edi
     *   +10   L3  73 66                jnb    $0x00466986
     * glibc's strlen has several of these, for offsets 0, 4, 8, and 0xc:
     *   +0    L3  8b 48 0c             mov    0x0c(%eax) -> %ecx
     *   +3    L3  ba ff fe fe fe       mov    $0xfefefeff -> %edx
     *   +8    L3  01 ca                add    %ecx %edx -> %edx
     *   +10   L3  73 0b                jnb    $0x0046640e
     */
    /* FIXME PR 406535: verify there's no chance of a true positive */
    /* we skip the modrm of the add since it varies */
    static const uint skip = 1;
    /* we stop prior to the mov-imm opcode since it varies */
    static const byte STR_ROUTINE_PATTERN[5] =
        {0xff, 0xfe, 0xfe, 0xfe, 0x01};
    ASSERT(sizeof(STR_ROUTINE_PATTERN) <= BUFFER_SIZE_BYTES(buf), "buf too small");
    if (reg == REG_EFLAGS &&
        (instr_get_opcode(inst) == OP_jnb ||
         instr_get_opcode(inst) == OP_jnb_short) &&
        safe_read(pc - skip - sizeof(STR_ROUTINE_PATTERN),
                  sizeof(STR_ROUTINE_PATTERN), buf) &&
        memcmp(buf, STR_ROUTINE_PATTERN, sizeof(STR_ROUTINE_PATTERN)) == 0) {
        uint val;
        /* See above notes on only end of search.  For these patterns,
         * the load is into the 1st source of the add.
         */
        instr_t add;
        instr_init(drcontext, &add);
        if (safe_decode(drcontext, pc - 2, &add, NULL) &&
            instr_valid(&add) && opnd_is_reg(instr_get_src(&add, 0))) {
            val = get_shadow_register(opnd_get_reg(instr_get_src(&add, 0)));
            if ((val & 0x3) == 0) {
                LOG(3, "suppressing positive from glibc strrchr/strlen pattern\n");
                set_shadow_eflags(SHADOW_DWORD_DEFINED);
                STATS_INC(strrchr_exception);
                match = true;
            } else
                LOG(3, "NOT suppressing glibc strrchr/strlen w/ val 0x%x\n", val);
        } else {
            ASSERT(false, "strrchr/strlen pattern: invalid/unexpected instr");
        }
        instr_free(drcontext, &add);
    }
    /* strrchr again, w/ some variations on what registers are xor'd:
     *   +0    L3  31 d7                xor    %edx %edi -> %edi
     *   +2    L3  81 cf ff fe fe fe    or     $0xfefefeff %edi -> %edi
     *   +8    L3  47                   inc    %edi -> %edi
     *   +9    L3  0f 85 cb 00 00 00    jnz    $0x0046698c
     * variation:
     *   +0    L3  31 ca                xor    %ecx %edx -> %edx
     *   +2    L3  81 ca ff fe fe fe    or     $0xfefefeff %edx -> %edx
     *   +8    L3  42                   inc    %edx -> %edx
     *   +9    L3  75 4e                jnz    $0x00466417
     */
    /* FIXME PR 406535: verify there's no chance of a true positive */
    static const byte STRRCHR_PATTERN_1[7] =
        {0x81, 0xcf, 0xff, 0xfe, 0xfe, 0xfe, 0x47};
    static const byte STRRCHR_PATTERN_2[7] =
        {0x81, 0xca, 0xff, 0xfe, 0xfe, 0xfe, 0x42};
    ASSERT(sizeof(STRRCHR_PATTERN_1) == sizeof(STRRCHR_PATTERN_2), "size changed");
    ASSERT(sizeof(STRRCHR_PATTERN_1) <= BUFFER_SIZE_BYTES(buf), "buf too small");
    if (reg == REG_EFLAGS &&
        /* I've seen OP_je_short as well (in esxi glibc) => allowing any jcc */
        instr_is_cbr(inst) &&
        safe_read(pc - sizeof(STRRCHR_PATTERN_1), sizeof(STRRCHR_PATTERN_1), buf) &&
        (memcmp(buf, STRRCHR_PATTERN_1, sizeof(STRRCHR_PATTERN_1)) == 0 ||
         memcmp(buf, STRRCHR_PATTERN_2, sizeof(STRRCHR_PATTERN_2)) == 0)) {
        uint val;
        if (memcmp(buf, STRRCHR_PATTERN_2, sizeof(STRRCHR_PATTERN_2)) == 0)
            val = get_shadow_register(DR_REG_XDX);
        else
            val = get_shadow_register(DR_REG_XDI);
        if ((val & 0x3) == 0) {
            LOG(3, "suppressing positive from glibc strrchr pattern\n");
            set_shadow_eflags(SHADOW_DWORD_DEFINED);
            STATS_INC(strrchr_exception);
            match = true;
        } else
            LOG(3, "NOT suppressing glibc strrchr/strlen w/ val 0x%x\n", val);
    }
    return match;
}
# endif /* UNIX */

static bool
is_strlen_uninit(void *drcontext, app_pc pc, reg_id_t reg,
                 dr_mcontext_t *mc, instr_t *inst)
{
    char buf[16]; /* for safe_read */
    /* i#1505: mingw inlines strlen:
     *   +0    L3              8b 13                mov    (%ebx)[4byte] -> %edx
     *   +2    L3              83 c3 04             add    $0x00000004 %ebx -> %ebx
     *   +5    L3              8d 82 ff fe fe fe    lea    0xfefefeff(%edx) -> %eax
     *   +11   L3              f7 d2                not    %edx -> %edx
     *   +13   L3              21 d0                and    %edx %eax -> %eax
     *   +15   L3              25 80 80 80 80       and    $0x80808080 %eax -> %eax
     *   +20   L3              74 ea                jz     $0x0040f7b0
     */
    static const byte STRLEN_PATTERN[] =
        {0xfe, 0xfe, 0xfe, 0xf7, 0xd2, 0x21, 0xd0, 0x25, 0x80, 0x80, 0x80, 0x80};
    ASSERT(sizeof(STRLEN_PATTERN) <= BUFFER_SIZE_BYTES(buf), "buf too small");
    if (reg == REG_EFLAGS &&
        (instr_get_opcode(inst) == OP_jz ||
         instr_get_opcode(inst) == OP_jz_short) &&
        safe_read(pc - sizeof(STRLEN_PATTERN),
                  sizeof(STRLEN_PATTERN), buf) &&
        memcmp(buf, STRLEN_PATTERN, sizeof(STRLEN_PATTERN)) == 0) {
        STATS_INC(strlen_uninit_exception);
        return true;
    }
    return false;
}

/* All current non-syscall uses already have inst decoded so we require it
 * for efficiency
 */
static bool
check_undefined_reg_exceptions(void *drcontext, app_loc_t *loc, reg_id_t reg,
                               dr_mcontext_t *mc, instr_t *inst)
{
    bool match = false;
    byte *pc;
    if (loc->type != APP_LOC_PC)
        return false; /* syscall */
    ASSERT(inst != NULL, "must pass in inst if non-syscall");
    pc = loc_to_pc(loc);
    ASSERT(instr_valid(inst), "unknown suspect instr");

#ifdef UNIX
    match = is_rawmemchr_uninit(drcontext, pc, reg, mc, inst);
    if (!match) {
        match = is_strrchr_uninit(drcontext, pc, reg, mc, inst);
    }
#endif
    if (!match) {
        match = is_strlen_uninit(drcontext, pc, reg, mc, inst);
    }

    return match;
}

static bool
instr_is_load_to_nongpr(instr_t *inst)
{
    int opc = instr_get_opcode(inst);
    if (opc == OP_fld)
        return true;
    /* With the initial i#243 implementation we no longer need to look for
     * movq/movdqu/movdqa here.
     */
    return false;
}

static bool
instr_is_store_from_nongpr(instr_t *inst)
{
    int opc = instr_get_opcode(inst);
    /* With the initial i#243 implementation we no longer need to look for
     * movq/movdqu/movdqa here.
     */
    if (opc == OP_fstp) {
        return opnd_is_memory_reference(instr_get_dst(inst, 0)) &&
            opnd_is_reg(instr_get_src(inst, 0));
    }
    return false;
}

/* i#471/i#931 heuristic: match "fld;fstp" to avoid false pos until we have proper
 * floating point register shadowing and propagation.
 *
 * i#1453: generalized to handle "load memory from address A into
 * xmmN; store xmmN into address B".
 *
 * Should only be called on an uninit memory read.  The general
 * approach is to mark B as bitlevel so we come back to the slowpath
 * on the store, where we perform the shadow copy A->B.
 *
 * An alternative to this uninit-exception-based approach would be to recognize
 * "fld;fstp" during instrumentation, special-case the fld to check
 * addressability and not definedness, and special-case the fstp to do a mem2mem
 * propagation with a fake src taken from the fld -- but, we'd need the slowpath
 * to recognize that too, which requires decode-backward or a hashtable; and,
 * the current fastpath doesn't support 8-byte+ mem2mem propagation.  Thus, this
 * approach here seems simpler and not much slower.
 */
static bool
check_mem_copy_via_nongpr(app_loc_t *loc, app_pc addr, uint sz, dr_mcontext_t *mc,
                          uint *idx)
{
    void *drcontext = dr_get_current_drcontext();
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
    app_pc pc, next_pc;
    opnd_t fstp_mem;
    byte *store_addr = NULL;
    app_pc load_pc, store_pc = NULL;
    reg_id_t xfer_reg = DR_REG_NULL;
    instr_t inst;
    umbra_shadow_memory_info_t info;
    int num_regs;
    bool allow_base_write, writes_ebp;
    opnd_t overlap_write;

    /* Handle subsequent calls from handle_mem_ref() (one per byte).
     * We don't short-circuit b/c we want to ensure they're all addressable.
     * This also avoid mixups on a double load;load;store;store.
     */
    if (cpt->mem2fpmm_source != NULL)
        return true;

    if (!options.fpxmm_mem2mem_prop)
        return false;
    if (loc->type == APP_LOC_SYSCALL)
        return false;
    if (addr == NULL) /* equals our sentinel value in cpt->mem2fpmm_source */
        return false;
    instr_init(drcontext, &inst);
    pc = loc_to_pc(loc);
    if (!safe_decode(drcontext, pc, &inst, &next_pc))
        return false;
    if (!instr_is_load_to_nongpr(&inst)) {
        instr_free(drcontext, &inst);
        return false;
    }
    load_pc = pc;
    xfer_reg = opnd_get_reg(instr_get_dst(&inst, 0));
    /* We support instructions in between the load and store, as we see
     * such patterns with several different compilers.
     */
#   define NONGPR_MEMCOPY_MAX_DISTANCE 128
    DOLOG(3, {
        LOG(3, "%s: found load @"PFX", looking for store:\n", __FUNCTION__, load_pc);
        disassemble_with_info(drcontext, pc, LOGFILE_GET(drcontext), true, true);
    });
    do {
        instr_reset(drcontext, &inst);
        pc = next_pc;
        DOLOG(3, {
            disassemble_with_info(drcontext, pc, LOGFILE_GET(drcontext), true, true);
        });
        if (!safe_decode(drcontext, pc, &inst, &next_pc))
            break;
        if (instr_is_cti(&inst) || instr_is_syscall(&inst) || !instr_opcode_valid(&inst))
            break;
        /* XXX: we could check for overlap with the src to ensure it doesn't
         * change, but it gets complex with our allowance of changes to the
         * base reg of the store.  We live w/ the risk for now.
         */
        if (instr_is_store_from_nongpr(&inst) &&
            opnd_get_reg(instr_get_src(&inst, 0)) == xfer_reg) {
            store_pc = pc;
            break;
        }
    } while (next_pc < pc + NONGPR_MEMCOPY_MAX_DISTANCE);
    if (store_pc == NULL) {
        instr_free(drcontext, &inst);
        return false;
    }
    fstp_mem = instr_get_dst(&inst, 0);
    ASSERT(opnd_is_memory_reference(fstp_mem), "fstp must write to mem");
    instr_free(drcontext, &inst);
    /* Second pass to ensure we can identify the memory address of the store.
     * We're aggressive here and we risk corner cases with aliases in order to
     * avoid having to go to suppressions to deal with these.
     * We'll do the wrong thing if something in between the load and store
     * writes to memory overlapping the load address: we'll then propagate
     * the wrong shadow value.
     */
    pc = load_pc;
    num_regs = opnd_num_regs_used(fstp_mem);
    allow_base_write = num_regs == 1 && opnd_is_base_disp(fstp_mem);
    writes_ebp = false;
    overlap_write = opnd_create_null();
    while (pc < store_pc) {
        /* Bail if in-between instr writes to any reg used to construct fstp address */
        int i;
        instr_reset(drcontext, &inst);
        if (!safe_decode(drcontext, pc, &inst, &pc))
            return false;
        if (!writes_ebp && instr_writes_to_reg(&inst, DR_REG_XBP, DR_QUERY_INCLUDE_ALL))
            writes_ebp = true;
        for (i = 0; i < num_regs; i++) {
            if (instr_writes_to_reg(&inst, opnd_get_reg_used(fstp_mem, i),
                                    DR_QUERY_INCLUDE_ALL)) {
                /* We do support a write to a reg if that's the sole addressing
                 * reg and if the write comes from an ebp-based slot where
                 * ebp does not change.  This is to handle cases like this
                 * gcc code:
                 *   dd 40 04        fld    0x04(%eax) -> %st0
                 *   8b 45 08        mov    0x08(%ebp) -> %eax
                 *   dd 58 04        fstp   %st0 -> 0x04(%eax)
                 * And this VS2013 Chromium Release code:
                 *   f30f6f00        movdqu  xmm0,xmmword ptr [eax]
                 *   8b4508          mov     eax,dword ptr [ebp+8]
                 *   f30f7f00        movdqu  xmmword ptr [eax],xmm0
                 */
                if (allow_base_write && opnd_is_null(overlap_write) &&
                    instr_num_srcs(&inst) == 1 &&
                    instr_num_dsts(&inst) == 1 && opnd_is_reg(instr_get_dst(&inst, 0)) &&
                    opnd_get_reg(instr_get_dst(&inst, 0)) == opnd_get_base(fstp_mem)) {
                    overlap_write = instr_get_src(&inst, 0);
                } else {
                    instr_free(drcontext, &inst);
                    return false;
                }
            }
        }
    }
    instr_free(drcontext, &inst);
    if (!opnd_is_null(overlap_write)) {
        LOG(3, "%s: checking overlap with xmm/fp store\n", __FUNCTION__);
        if (opnd_is_base_disp(overlap_write) &&
            opnd_get_base(overlap_write) == DR_REG_XBP &&
            opnd_get_index(overlap_write) == DR_REG_NULL &&
            !writes_ebp) {
            reg_t baseval;
            reg_t *slot = (reg_t *) opnd_compute_address(overlap_write, mc);
            if (safe_read(slot, sizeof(baseval), &baseval)) {
                reg_id_t basereg = opnd_get_base(fstp_mem);
                reg_t save = reg_get_value(basereg, mc);
                LOG(3, "%s: old %s = "PFX", new="PFX"\n", __FUNCTION__,
                    get_register_name(basereg), save, baseval);
                reg_set_value(basereg, mc, baseval);
                store_addr = opnd_compute_address(fstp_mem, mc);
                LOG(3, "%s: store addr computed to be "PFX"\n", __FUNCTION__, store_addr);
                reg_set_value(basereg, mc, save);
            }
        }
    } else
        store_addr = opnd_compute_address(fstp_mem, mc);
    if (store_addr == NULL ||
        /* overlap is ok, but we require the same size */
        opnd_size_in_bytes(opnd_get_size(fstp_mem)) != sz) {
        return false;
    }
    LOG(3, "%s: matched pattern for store addr="PFX"\n", __FUNCTION__, store_addr);
    /* Now disable the fstp instru fastpath by marking the dest mem as bitlevel.
     * We'll propagate the shadow values in the fstp slowpath.
     * Otherwise, fstp's fastpath will blindly mark the dest memory as defined.
     * Note that we can't instead propagate here and mark base reg as
     * undefined, as that check may be optimized out.
     */
    umbra_shadow_memory_info_init(&info);
    cpt->mem2fpmm_prev_shadow = shadow_get_byte(&info, store_addr);
    cpt->mem2fpmm_dest = store_addr;
    cpt->mem2fpmm_pc = store_pc;
    DODEBUG({
        /* used for a debug check in slow_path() */
        cpt->mem2fpmm_load_pc = load_pc;
    });
    shadow_set_byte(&info, store_addr, SHADOW_DEFINED_BITLEVEL);
    ASSERT(cpt->mem2fpmm_source == NULL, "mem2fpmm_source wasn't cleared");
    /* Point at the start addr, as we're going to propagate the whole thing
     * (we might be midway through if the first few bytes are defined and we
     * hit uninit bytes in the middle).
     */
    cpt->mem2fpmm_source = addr - *idx;
    STATS_INC(fldfst_exception);
    return true;
}

static bool
check_undefined_exceptions(bool pushpop, bool write, app_loc_t *loc, app_pc addr,
                           uint sz, uint *shadow, dr_mcontext_t *mc, uint *idx)
{
    bool match = false;
    /* I used to have an exception for uninits in heap headers, but w/
     * proper operation headers should be unaddr.  Plus, the exception here,
     * which marked as defined, was only in slowpath: in fastpath the uninit
     * bits are propagated and won't be recognized as heap headers when
     * they bubble up.  Thus it was removed since no longer necessary.
     */
    /* We now check for result_is_always_defined() up front in the
     * slow path to avoid the redundant decode here, which can be a
     * noticeable performance hit (PR 622253)
     */
    if (!match && !pushpop && !write)
        match = check_mem_copy_via_nongpr(loc, addr, sz, mc, idx);
    return match;
}

static inline uint
combine_shadows(uint shadow1, uint shadow2)
{
    /* This routine only looks at two one-byte values.
     * We ignore BITLEVEL for now.
     * We assume UNADDR will be reported, and we want to propagate
     * defined afterward in any case to avoid chained errors (xref i#1476).
     */
    ASSERT((shadow1 & ~0xf) == 0 && (shadow2 & ~0xf) == 0, "non-byte shadows");
    return (shadow1 == SHADOW_UNDEFINED || shadow2 == SHADOW_UNDEFINED) ?
        SHADOW_UNDEFINED : SHADOW_DEFINED;
}

static inline void
accum_shadow(uint *shadow1, uint shadow2)
{
    *shadow1 = combine_shadows(*shadow1, shadow2);
}

/* Opcodes that write to subreg at locations not fixed in the low part of the reg */
static inline bool
opc_dst_subreg_nonlow(int opc)
{
    switch (opc) {
    case OP_pextrb:
    case OP_pextrw:
    case OP_pextrd:
    case OP_vpextrb:
    case OP_vpextrw:
    case OP_vpextrd:
    case OP_extractps:
    case OP_pinsrb:
    case OP_pinsrw:
    case OP_pinsrd:
    case OP_vpinsrb:
    case OP_vpinsrw:
    case OP_vpinsrd:
    case OP_insertps:
    case OP_movhps:
    case OP_movhpd:
        return true;
    }
    return false;
}

static void
shadow_combine_init(shadow_combine_t *comb, instr_t *inst, uint opcode, uint max)
{
    uint i;
    uint init_shadow = SHADOW_DEFINED;
    if (opc_dst_subreg_nonlow(opcode) &&
        inst != NULL && instr_num_dsts(inst) == 1) {
        opnd_t dst = instr_get_dst(inst, 0);
        if (opnd_is_reg(dst)) {
            reg_id_t reg = opnd_get_reg(dst);
            uint opsz = opnd_size_in_bytes(opnd_get_size(dst));
            uint regsz = opnd_size_in_bytes(reg_get_size(reg));
            if (opsz < regsz) {
                /* For opcodes that write to only part of the reg and leave the
                 * rest unchanged and don't write to just the bottom of the reg,
                 * we have to pass every byte of the register shadow to
                 * map_src_to_dst().  We need to incorporate the prior reg
                 * shadow values, which we can't solely do later as we need to
                 * distinguish what was written by the opcode.  By using
                 * BITLEVEL we ensure that shadow_combine() will clobber this
                 * rather than OR it in.
                 */
                init_shadow = SHADOW_DEFINED_BITLEVEL;
            }
        }
    }
    comb->dst = comb->raw;
    /* Initialize to defined so we can aggregate operands as we go.
     * This works with no-source instrs (rdtsc, etc.)
     * This also makes small->large work out w/o any special processing
     * (movsz, movzx, cwde, etc.): but XXX: are there any src/dst size
     * mismatches where we do NOT want to set dst bytes beyond count
     * of src bytes to defined?
     */
    for (i = 0; i < max; i++)
        comb->dst[i] = init_shadow;
    comb->eflags = SHADOW_DEFINED;
    comb->inst = inst;
    comb->opcode = opcode;
}

static inline void
shadow_combine_set_opnd(shadow_combine_t *comb, opnd_t opnd, uint opsz)
{
    comb->opnd = opnd;
    comb->opsz = opsz;
#ifdef DEBUG
    comb->opnd_valid = true;
#endif
}

#ifdef DEBUG
# define SHADOW_COMBINE_CHECK_OPND(comb, bytenum) do {\
    ASSERT((comb)->opnd_valid, "have to set opnd");   \
    if ((bytenum) + 1 == (comb)->opsz)                \
        (comb)->opnd_valid = false;                   \
} while (0)
#else
# define SHADOW_COMBINE_CHECK_OPND(comb, bytenum) /* nothing */
#endif

/* Same base interface as map_src_to_dst(), but this one takes in an
 * arbitrary opcode that can differ from comb->opcode, a per-element
 * src_bytenum, an offset for the dst bytenum, and a per-element opsz,
 * allowing for use on packed shifts as well as GPR shifts.
 */
static bool
map_src_to_dst_shift(shadow_combine_t *comb INOUT, uint opc, int opnum, int src_bytenum,
                     uint src_offs, uint opsz, uint shadow)
{
    reg_t shift;
    /* Be sure to use opsz, the element size, NOT comb->opsz; similarly, use
     * the passed-in opc, NOT comb->opcode, for the operation.
     */
    ASSERT(comb->inst != NULL, "need inst for shifts");
    ASSERT(opc_is_shift_src0(comb->opcode) || opc_is_shift_src1(comb->opcode),
           "unknown shift");
    if (!get_cur_src_value(dr_get_current_drcontext(), comb->inst,
                           opc_is_shift_src0(comb->opcode) ? 0 : 1, &shift)) {
        ASSERT(false, "failed to get shift amount");
        /* graceful failure */
        return false;
    }
    LOG(4, " src bytenum %d, offs %d, opsz %d, shift %d\n", src_bytenum, src_offs,
        opsz, shift);
    if (shift > opsz*8)
        shift = opsz*8; /* XXX i#101: for a rotate we want shift % (opsz*8) */
    if (shift == 0) {
        /* no flags are changed for shift==0 */
        accum_shadow(&comb->dst[src_offs + src_bytenum], shadow);
        return true;
    }
    if (opc == OP_shl) {
        /* If shift % 8 != 0 we touch two bytes: */
        int map1 = src_bytenum + shift/8;
        int map2 = src_bytenum + (shift-1)/8 + 1;
        if (map1 >= opsz) {
            if (map1 == opsz) {
                /* bit shifted off goes to CF */
                LOG(4, "  accum eflags %d + %d\n", comb->eflags, shadow);
                accum_shadow(&comb->eflags, shadow);
            }
            /* shifted off the end */
            return true;
        }
        LOG(4, "  accum @%d %d + %d\n", src_offs + map1, comb->dst[src_offs + map1],
            shadow);
        accum_shadow(&comb->dst[src_offs + map1], shadow);
        if (map1 != map2 && map2 < opsz) {
            LOG(4, "  accum @%d %d + %d\n", src_offs + map2, comb->dst[src_offs + map2],
                shadow);
            accum_shadow(&comb->dst[src_offs + map2], shadow);
        }
        accum_shadow(&comb->eflags, shadow);
        return true;
    } else if (opc == OP_shr || opc == OP_sar) {
        /* If shift % 8 != 0 we touch two bytes: */
        int map1 = src_bytenum - shift/8;
        int map2 = src_bytenum - ((shift-1)/8 + 1);
        if (opc == OP_sar && src_bytenum == opsz - 1) {
            /* Top bit is what's shifted in */
            int i;
            for (i = 0; i <= shift/8 && i < opsz; i ++)
                accum_shadow(&comb->dst[src_offs + opsz - 1 - i], shadow);
            accum_shadow(&comb->eflags, shadow);
            return true;
        }
        if (map1 >= 0) { /* if not shifted off the end */
            LOG(4, "  accum @%d %d + %d\n", src_offs + map1, comb->dst[src_offs + map1],
                shadow);
            accum_shadow(&comb->dst[src_offs + map1], shadow);
        }
        if (map1 != map2 && map2 >= 0) {
            LOG(4, "  accum @%d %d + %d\n", src_offs + map2, comb->dst[src_offs + map2],
                shadow);
            accum_shadow(&comb->dst[src_offs + map2], shadow);
        }
        accum_shadow(&comb->eflags, shadow);
        /* We assume we don't need to proactively mark the top now-0 bits
         * as defined for OP_shr b/c our method of combining starts w/ defined
         */
        return true;
    } else {
        /* FIXME i#101: add rotate opcodes + shrd/shld */
    }
    return false; /* unhandled */
}

/* Takes the shadow value \p shadow for the \p src_bytenum-th byte in
 * the source operand ordinal \p opnum of instruction \p inst and
 * places it into comb's dst and eflags repositories, combining with
 * what's already there.
 */
static void
map_src_to_dst(shadow_combine_t *comb INOUT, int opnum, int src_bytenum, uint shadow)
{
    int opc = comb->opcode;
    uint opsz = comb->opsz;
    uint shift = 0;
    if (opc_is_gpr_shift(opc)) {
        if (map_src_to_dst_shift(comb, comb->opcode, opnum, src_bytenum, 0,
                                 comb->opsz, shadow)) {
            SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
            return; /* handled */
        }
    }
    /* XXX PR 408551: for now we are not considering propagation to
     * more-significant bytes from arithmetic ops.
     */
    /* For instrs w/ multiple GPR/mem dests, or concatenated sources,
     * we need to make sure we lay out the dests side by side in the array.
     *
     * Here we check for srcs that do NOT simply go into the lowest slot:
     */
    switch (opc) {
    case OP_xchg:
    case OP_xadd:
        SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
        accum_shadow(&comb->dst[opsz*(1 - opnum) + src_bytenum], shadow);
        break;
    case OP_cmpxchg8b:
        SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
        /* opnds: cmpxchg8b mem8 %eax %edx %ecx %ebx -> mem8 %eax %edx
         * operation: if (edx:eax == mem8) mem8 = ecx:ebx; else edx:eax = mem8
         * we just combine all 3 sources and write the result to both dests.
         */
        switch (opnum) {
        case 0: shift = 0; break;
        case 1: shift = 0; break;
        case 2: shift = 1; break;
        case 3: shift = 1; break;
        case 4: shift = 0; break;
        default: ASSERT(false, "invalid opnum");
        }
        accum_shadow(&comb->dst[opsz*shift + src_bytenum], shadow);
        break;
    case OP_bswap:
        ASSERT(opsz == 4, "invalid bswap opsz");
        accum_shadow(&comb->dst[3 - src_bytenum], shadow);
        return;
#ifndef X64
    case OP_pusha:
        SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
        if (opnd_is_reg(comb->opnd)) {
            reg_id_t reg = opnd_get_reg(comb->opnd);
            shift = opsz*(reg_to_pointer_sized(reg) - DR_REG_EAX);
            accum_shadow(&comb->dst[shift + src_bytenum], shadow);
        }
        break;
#endif
    case OP_punpcklbw:
    case OP_vpunpcklbw:
        /* Dst is opnum==1 and its 0-n/2 => 0, 2, 4, 6, ....
         * Src is opnum==0 and its 0-n/2 => 1, 3, 5, 7, ...
         */
        if (src_bytenum < opsz/2)
            accum_shadow(&comb->dst[src_bytenum*2 + (1 - opnum)], shadow);
        break;
    case OP_punpcklwd:
    case OP_vpunpcklwd:
        if (src_bytenum < opsz/2) {
            accum_shadow(&comb->dst[(src_bytenum/2) *4 + (src_bytenum % 2) +
                                    2*(1 - opnum)], shadow);
        }
        break;
    case OP_punpckldq:
    case OP_vpunpckldq:
    case OP_unpcklps:
    case OP_vunpcklps:
        if (src_bytenum < opsz/2) {
            accum_shadow(&comb->dst[(src_bytenum/4) *8 + (src_bytenum % 4) +
                                    4*(1 - opnum)], shadow);
        }
        break;
    case OP_punpcklqdq:
    case OP_vpunpcklqdq:
    case OP_unpcklpd:
    case OP_vunpcklpd:
        if (src_bytenum < opsz/2) {
            accum_shadow(&comb->dst[(src_bytenum/8) *16 + (src_bytenum % 8) +
                                    8*(1 - opnum)], shadow);
        }
        break;
    case OP_punpckhbw:
    case OP_vpunpckhbw:
        if (src_bytenum >= opsz/2) {
            accum_shadow(&comb->dst[(src_bytenum-opsz/2)*2 + (1 - opnum)], shadow);
        }
        break;
    case OP_punpckhwd:
    case OP_vpunpckhwd:
        if (src_bytenum >= opsz/2) {
            accum_shadow(&comb->dst[((src_bytenum-opsz/2)/2) *4 + (src_bytenum % 2) +
                                    2*(1 - opnum)], shadow);
        }
        break;
    case OP_punpckhdq:
    case OP_vpunpckhdq:
    case OP_unpckhps:
    case OP_vunpckhps:
        if (src_bytenum >= opsz/2) {
            accum_shadow(&comb->dst[((src_bytenum-opsz/2)/4) *8 + (src_bytenum % 4) +
                                    4*(1 - opnum)], shadow);
        }
        break;
    case OP_punpckhqdq:
    case OP_vpunpckhqdq:
    case OP_unpckhpd:
    case OP_vunpckhpd:
        if (src_bytenum >= opsz/2) {
            accum_shadow(&comb->dst[((src_bytenum-opsz/2)/8) *16 + (src_bytenum % 8) +
                                    8*(1 - opnum)], shadow);
        }
        break;
    case OP_shufps:
    case OP_shufpd:
    case OP_vshufps:
    case OP_vshufpd: {
        ptr_uint_t immed = 0;
        ASSERT(comb->inst != NULL, "need inst for OP_shuf*");
        if (!get_cur_src_value(NULL, comb->inst,
                               (opc == OP_vshufps || opc == OP_vshufpd) ? 2 : 1,
                               &immed))
            ASSERT(false, "failed to get immed"); /* rel build: keep going */
        switch (opc) {
        case OP_shufps:
        case OP_vshufps: {
            uint mod = src_bytenum % 4;
            uint shift = src_bytenum >= 16 ? 16 : 0;
            if (opnum == 0) { /* the src */
                uint dst2 = (immed >> 4) & 0x3;
                uint dst3 = (immed >> 6) & 0x3;
                if (dst2 == (src_bytenum % 16)/4)
                    accum_shadow(&comb->dst[shift + 8 + mod], shadow);
                if (dst3 == (src_bytenum % 16)/4)
                    accum_shadow(&comb->dst[shift + 12 + mod], shadow);
            } else { /* the dst, or 2nd src for vshufps */
                uint dst0 = immed & 0x3;
                uint dst1 = (immed >> 2) & 0x3;
                if (dst0 == (src_bytenum % 16)/4)
                    accum_shadow(&comb->dst[shift + mod], shadow);
                if (dst1 == (src_bytenum % 16)/4)
                    accum_shadow(&comb->dst[shift + 4 + mod], shadow);
            }
            break;
        }
        case OP_shufpd:
        case OP_vshufpd: {
            uint mod = src_bytenum % 8;
            uint shift = src_bytenum >= 16 ? 16 : 0;
            if (opnum == 0) { /* the src */
                if (immed == (src_bytenum % 16)/8)
                    accum_shadow(&comb->dst[shift + 8 + mod], shadow);
            } else { /* the dst, or 2nd src for vshufps */
                if (immed == (src_bytenum % 16)/8)
                    accum_shadow(&comb->dst[shift + mod], shadow);
            }
            break;
        }
        }
        break;
    }
    case OP_pshufw:
    case OP_pshufd:
    case OP_pshufhw:
    case OP_pshuflw:
    case OP_vpshufhw:
    case OP_vpshufd:
    case OP_vpshuflw:
        /* FIXME i#1484: fill in proper shuffling */
        accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_pshufb:
    case OP_vpshufb:
        /* FIXME i#1484: this one is complex, bailing for now */
        accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_psrlw:
    case OP_vpsrlw:
        if (map_src_to_dst_shift(comb, OP_shr, opnum, src_bytenum % 2,
                                 ALIGN_BACKWARD(src_bytenum, 2), 2, shadow)) {
            SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
            return; /* handled */
        } else /* gracefully continue */
            accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_psrld:
    case OP_vpsrld:
        if (map_src_to_dst_shift(comb, OP_shr, opnum, src_bytenum % 4,
                                 ALIGN_BACKWARD(src_bytenum, 4), 4, shadow)) {
            SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
            return; /* handled */
        } else /* gracefully continue */
            accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_psrlq:
    case OP_vpsrlq:
        if (map_src_to_dst_shift(comb, OP_shr, opnum, src_bytenum % 8,
                                 ALIGN_BACKWARD(src_bytenum, 8), 8, shadow)) {
            SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
            return; /* handled */
        } else /* gracefully continue */
            accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_psraw:
    case OP_vpsraw:
        if (map_src_to_dst_shift(comb, OP_sar, opnum, src_bytenum % 2,
                                 ALIGN_BACKWARD(src_bytenum, 2), 2, shadow)) {
            SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
            return; /* handled */
        } else /* gracefully continue */
            accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_psrad:
    case OP_vpsrad:
        if (map_src_to_dst_shift(comb, OP_sar, opnum, src_bytenum % 4,
                                 ALIGN_BACKWARD(src_bytenum, 4), 4, shadow)) {
            SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
            return; /* handled */
        } else /* gracefully continue */
            accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_psrldq:
    case OP_vpsrldq: {
        /* These shift by *bytes*, not *bits*! */
        reg_t shift;
        if (get_cur_src_value(dr_get_current_drcontext(), comb->inst,
                              opc_is_shift_src0(opc) ? 0 : 1, &shift)) {
            if (shift > opsz)
                shift = opsz;
            if (src_bytenum >= shift)
                accum_shadow(&comb->dst[src_bytenum - shift], shadow);
        } else /* gracefully continue */
            accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    }
    case OP_psllw:
    case OP_vpsllw:
        if (map_src_to_dst_shift(comb, OP_shl, opnum, src_bytenum % 2,
                                 ALIGN_BACKWARD(src_bytenum, 2), 2, shadow)) {
            SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
            return; /* handled */
        } else /* gracefully continue */
            accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_pslld:
    case OP_vpslld:
        if (map_src_to_dst_shift(comb, OP_shl, opnum, src_bytenum % 4,
                                 ALIGN_BACKWARD(src_bytenum, 4), 4, shadow)) {
            SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
            return; /* handled */
        } else /* gracefully continue */
            accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_psllq:
    case OP_vpsllq:
        if (map_src_to_dst_shift(comb, OP_shl, opnum, src_bytenum % 8,
                                 ALIGN_BACKWARD(src_bytenum, 8), 8, shadow)) {
            SHADOW_COMBINE_CHECK_OPND(comb, src_bytenum);
            return; /* handled */
        } else /* gracefully continue */
            accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_pslldq:
    case OP_vpslldq: {
        /* These shift by *bytes*, not *bits*! */
        reg_t shift;
        if (get_cur_src_value(dr_get_current_drcontext(), comb->inst,
                              opc_is_shift_src0(opc) ? 0 : 1, &shift)) {
            if (shift > opsz)
                shift = opsz;
            if (src_bytenum + shift < opsz)
                accum_shadow(&comb->dst[src_bytenum + shift], shadow);
        } else /* gracefully continue */
            accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    }
    case OP_vpsravd:
    case OP_vpsrlvd:
    case OP_vpsrlvq:
    case OP_vpsllvd:
    case OP_vpsllvq:
        /* FIXME i#1484: these are complex, bailing for now */
        accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;
    case OP_pextrb:
    case OP_pextrw:
    case OP_pextrd:
    case OP_vpextrb:
    case OP_vpextrw:
    case OP_vpextrd:
    case OP_extractps:
    case OP_pinsrb:
    case OP_pinsrw:
    case OP_pinsrd:
    case OP_insertps: {
        ptr_uint_t immed = 0;
        ASSERT(comb->inst != NULL, "need inst for OP_pextr*");
        /* zero-extended so we only write bottom */
        /* we get passed the entire xmm reg (reg_get_size, not opnd_get_size) */
        if (!get_cur_src_value(NULL, comb->inst, 1, &immed))
            ASSERT(false, "failed to get shift amount"); /* rel build: keep going */
        switch (opc) {
        case OP_pextrb:
        case OP_vpextrb:
            if (src_bytenum == immed)
                accum_shadow(&comb->dst[0], shadow);
            break;
        case OP_pextrw:
        case OP_vpextrw:
            if (src_bytenum >= immed*2 && src_bytenum < (immed+1)*2)
                accum_shadow(&comb->dst[src_bytenum % 2], shadow);
            break;
        case OP_pextrd:
        case OP_vpextrd:
        case OP_extractps:
            if (src_bytenum >= immed*4 && src_bytenum < (immed+1)*4)
                accum_shadow(&comb->dst[src_bytenum % 4], shadow);
            break;
        case OP_pinsrb:
            if (src_bytenum == 0) /* DRi#1388: we'll iterate >1 byte for reg */
                accum_shadow(&comb->dst[immed], shadow);
            break;
        case OP_vpinsrb:
            if (src_bytenum == 0) /* DRi#1388: we'll iterate >1 byte for reg */
                accum_shadow(&comb->dst[immed], shadow);
            break;
        case OP_pinsrw:
            if (src_bytenum < 2) /* DRi#1388: we'll iterate >2 bytes for reg */
                accum_shadow(&comb->dst[immed*2 + (src_bytenum % 2)], shadow);
            break;
        case OP_pinsrd:
            accum_shadow(&comb->dst[immed*4 + (src_bytenum % 4)], shadow);
            break;
        case OP_insertps: {
            uint count_s = opnd_is_reg(comb->opnd) ? (immed >> 6) : 0;
            uint count_d = (immed >> 4) & 0x3;
            uint zmask = immed & 0xf;
            uint i;
            if (src_bytenum >= count_s*4 && src_bytenum < (count_s+1)*4)
                accum_shadow(&comb->dst[count_d*4 + (src_bytenum % 4)], shadow);
            if (src_bytenum == 0) { /* arbitrary, just do it once */
                for (i = 0; i < 3; i++) {
                    if (TEST(0x1, zmask))
                        accum_shadow(&comb->dst[i], SHADOW_DEFINED);
                    if (TEST(0x2, zmask))
                        accum_shadow(&comb->dst[4+i], SHADOW_DEFINED);
                    if (TEST(0x4, zmask))
                        accum_shadow(&comb->dst[8+i], SHADOW_DEFINED);
                    if (TEST(0x8, zmask))
                        accum_shadow(&comb->dst[12+i], SHADOW_DEFINED);
                }
            }
        }
        }
        break;
    }
    case OP_vpinsrb:
    case OP_vpinsrw:
    case OP_vpinsrd: {
        ptr_uint_t immed = 0;
        ASSERT(comb->inst != NULL, "need inst for OP_vpinsr*");
        /* we get passed the entire xmm reg (reg_get_size, not opnd_get_size) */
        if (!get_cur_src_value(NULL, comb->inst, 2, &immed))
            ASSERT(false, "failed to get shift amount"); /* rel build: keep going */
        switch (opc) {
        case OP_vpinsrb:
            if (opnum == 0) {
                if (src_bytenum != immed)
                    accum_shadow(&comb->dst[src_bytenum], shadow);
            } else if (src_bytenum == 0) /* DRi#1388: we'll iterate >1 byte */
                accum_shadow(&comb->dst[immed], shadow);
            break;
        case OP_vpinsrw:
            if (opnum == 0) {
                if (src_bytenum < immed*2 || src_bytenum >= (immed+1)*2)
                    accum_shadow(&comb->dst[src_bytenum], shadow);
            } else if (src_bytenum < 2) /* DRi#1388: we'll iterate >2 bytes */
                accum_shadow(&comb->dst[immed*2 + (src_bytenum % 2)], shadow);
            break;
        case OP_vpinsrd:
            if (opnum == 0) {
                if (src_bytenum < immed*4 || src_bytenum >= (immed+1)*4)
                    accum_shadow(&comb->dst[src_bytenum], shadow);
            } else
                accum_shadow(&comb->dst[immed*4 + (src_bytenum % 4)], shadow);
            break;
        }
        break;
    }
    case OP_movhps:
    case OP_movhpd:
        ASSERT(comb->inst != NULL, "need comb->inst for movhps");
        if (opnd_is_memory_reference(comb->opnd)) {
            accum_shadow(&comb->dst[src_bytenum + (opsz - 8)], shadow);
        } else if (opnd_is_reg(instr_get_dst(comb->inst, 0))) {
            /* reg-reg is OP_movlhps */
            if (src_bytenum < 8)
                accum_shadow(&comb->dst[src_bytenum + (opsz - 8)], shadow);
        } else {
            if (src_bytenum >= opsz - 8) /* high quadword */
                accum_shadow(&comb->dst[src_bytenum - (opsz - 8)], shadow);
        }
        break;
    case OP_movlps:
        ASSERT(comb->inst != NULL, "need comb->inst for movlps");
        if (opnd_is_reg(comb->opnd) && opnd_is_reg(instr_get_dst(comb->inst, 0))) {
            /* reg-reg is OP_movhlps */
            if (src_bytenum >= opsz - 8) /* high quadword */
                accum_shadow(&comb->dst[src_bytenum - (opsz - 8)], shadow);
        } else if (src_bytenum < 8)
            accum_shadow(&comb->dst[src_bytenum], shadow);
        break;

    /* XXX i#1484/i#243: add more xmm opcodes here.  Also add to either
     * set_check_definedness_pre_regs() (if check_definedness is
     * enough) or instr_ok_for_instrument_fastpath() if fastpath
     * can't handle them.
     *
     * See all the "FIXME i#1484" comments above as well.
     *
     * Opcodes that need extra handling: and + or operations with constants;
     * widening/narrowing (OP_cvt*); conditional moves (OP_*blend*);
     * shifting and selecting (OP_palignr, OP_phminposuw, OP_pcmpestr*).
     *
     * For now we mark these as defined to avoid false negatives.
     * OP_por, OP_pand, and OP_pand are not yet listed here b/c it should
     * be much rarer to and or or with a constant in xmm vs gpr and we'd
     * rather not have false negatives on common operations.
     */
    /* conversions that shrink */
    case OP_cvttpd2pi:
    case OP_cvttsd2si:
    case OP_cvtpd2pi:
    case OP_cvtsd2si:
    case OP_cvtpd2ps:
    case OP_cvtsd2ss:
    case OP_cvtdq2pd:
    case OP_cvttpd2dq:
    case OP_cvtpd2dq:
    /* blend and other complex operations */
    case OP_pblendvb:
    case OP_blendvps:
    case OP_blendvpd:
    case OP_blendps:
    case OP_blendpd:
    case OP_pblendw:
    case OP_vpblendvb:
    case OP_vblendvps:
    case OP_vblendvpd:
    case OP_vblendps:
    case OP_vblendpd:
    case OP_vpblendw:
    case OP_vpblendd:
    case OP_palignr:
    case OP_phminposuw:
    case OP_pcmpestrm:
    case OP_pcmpestri:
        /* FIXME i#1484: implement proper handling */
        accum_shadow(&comb->dst[src_bytenum], SHADOW_DEFINED);
        break;

    /* cpuid: who cares if collapse to eax */
    /* rdtsc, rdmsr, rdpmc: no srcs, so can use bottom slot == defined */
    /* mul, imul, div, idiv: FIXME PR 408551: should split: for now we collapse */

    default:
        accum_shadow(&comb->dst[src_bytenum], shadow);
       break;
    }

    /* By default all source bytes influence eflags.  If an opcode wants to do
     * otherwise it needs to return prior to here.
     */
    if (comb->inst != NULL &&
        TESTANY(EFLAGS_WRITE_6, instr_get_eflags(comb->inst, DR_QUERY_INCLUDE_ALL)))
        accum_shadow(&comb->eflags, shadow);
    return;
}
#endif /* TOOL_DR_MEMORY */

bool
instr_needs_all_srcs_and_vals(instr_t *inst)
{
    /* For bitwise and + or we need to know the shadow value and the real value
     * of all sources before we can decide whether any one source's
     * undefinedness is an issue!
     */
    int opc = instr_get_opcode(inst);
    return (opc == OP_and || opc == OP_test || opc == OP_or);
}

#ifdef TOOL_DR_MEMORY
/* i#489: handle the "mov C->B, xor A->B, and D->B, xor B->C" sequence
 * used by optimizing compilers (cl /GL in particular) to set a sequence of
 * bits within a word to a given non-constant value.
 * We don't want to spend the time scanning for this pattern up front in
 * the bb events b/c of overhead and extra complexity of passing data
 * to the instrumentation code (or of an app2app xform).  We leverage
 * the fact that OP_and w/ undef srcs comes to slowpath (just like i#849
 * relies on it).  It's painful to go backward though (we'd have to walk
 * the bb table to find start of bb) so we just look for "and D->B, xor B->C"
 * and mark B and C defined which is a reasonable compromise.
 *
 * i#878: handle the "mov C->B, xor A->B, and D->B, xor C->B" sequence, for
 * which we look for "and D->B, xor C->B"
 *
 * i#1523: we also handle a double intertwined mov;xor;and;xor.
 */

static void
xor_bitfield_mark_defined(opnd_t op, dr_mcontext_t *mc, opnd_t and_src, opnd_t and_dst)
{
    if (opnd_is_reg(op)) {
        register_shadow_mark_defined(opnd_get_reg(op),
                                     opnd_size_in_bytes(opnd_get_size(op)));
    } else {
        ASSERT(opnd_is_memory_reference(op), "invalid xor dst");
        /* No need for adjust_memop: not a push or pop */
        /* Rule out OP_and's operands affecting base/index of xor (so we can
         * rely on opnd_compute_address() below), or D==C.
         */
        if (((opnd_is_memory_reference(op) &&
              opnd_is_memory_reference(and_src)) ||
             !opnd_share_reg(op, and_src)) &&
            ((opnd_is_memory_reference(op) &&
              opnd_is_memory_reference(and_dst)) ||
             !opnd_share_reg(op, and_dst))) {
            shadow_set_non_matching_range(opnd_compute_address(op, mc),
                                          opnd_size_in_bytes(opnd_get_size(op)),
                                          SHADOW_DEFINED, SHADOW_UNADDRESSABLE);
        }
    }
}

static bool
xor_bitfield_check_instr(void *drcontext, dr_mcontext_t *mc, instr_t *and, instr_t *xor,
                         shadow_combine_t *comb INOUT, size_t sz)
{
    bool matches = false;
    /* While someone could construct an L4 OP_and where src0==dst0 (or
     * with 30 sources, for that matter), it won't encode, so we go ahead
     * and assume it matches the canonical form.
     */
    opnd_t and_src = instr_get_src(and, 0);
    opnd_t and_dst = instr_get_dst(and, 0);
    opnd_t xor_src = instr_get_src(xor, 0);
    opnd_t xor_dst = instr_get_dst(xor, 0);
    ASSERT(instr_get_opcode(xor) == OP_xor, "caller should check");
    if ((opnd_same(xor_src, and_dst) || opnd_same(xor_dst, and_dst)) &&
        /* Rule out: 1) nop; 2) xor where B and C are not completely separate */
        !opnd_share_reg(xor_dst, xor_src)) {
        int i;
        /* XXX: in debug build try to go backward and verify the prior mov,xor
         * instrs to find out whether any other patterns match this tail end.
         */
        LOG(4, "%s: matched @"PFX"\n", __FUNCTION__, instr_get_app_pc(and));
        matches = true;
        STATS_INC(bitfield_xor_exception);
        /* Caller already collapsed the 2nd src so we just set bottom indices */
        for (i = 0; i < sz; i++) {
            if (comb->dst[i] == SHADOW_UNDEFINED)
                comb->dst[i] = SHADOW_DEFINED;
        }
        /* Eflags will be marked defined since comb->dst is all defined */
        /* i#878: we mark both xor dst and xor src b/c this pattern match code
         * is executed at the OP_and and marking dst defined doesn't help b/c
         * the xor then executes and propagates the uninit bits from the src.
         */
        xor_bitfield_mark_defined(xor_src, mc, and_src, and_dst);
        xor_bitfield_mark_defined(xor_dst, mc, and_src, and_dst);
    }
    return matches;
}

static bool
check_xor_bitfield(void *drcontext, dr_mcontext_t *mc, instr_t *inst,
                   shadow_combine_t *comb INOUT, size_t sz, app_pc next_pc)
{
    bool matches = false;
    instr_t xor;
    byte *pc = next_pc;
    ASSERT(instr_get_opcode(inst) == OP_and, "caller should check");
    if (options.strict_bitops) /* not worth separate option */
        return false;
    instr_init(drcontext, &xor);
    if (!safe_decode(drcontext, pc, &xor, &pc) || !instr_valid(&xor))
        goto check_xor_bitfield_done;
    if (instr_get_opcode(&xor) != OP_xor) {
        /* Try the next instr, to handle double intertwined patterns (i#1523)
         * or just a random instr in between (i#1530, i#1542).
         */
        instr_t *between = instr_clone(drcontext, &xor);
        instr_reset(drcontext, &xor);
        if (!safe_decode(drcontext, pc, &xor, &pc) || !instr_valid(&xor) ||
            /* Bail if the instr in between has any non-memory-alias overlap */
            /* i#1542: the instr in between could have shared reg
             *   mov     al,[edi+0x20]
             *   xor     al,[ebp+0x10]           ss:002b:0018e110=00
             *   and     al,0x1
             *   mov     dword ptr [edi],0x103356c8
             *   xor     [edi+0x20],al
             */
            instrs_share_opnd(between, &xor)) {
            instr_destroy(drcontext, between);
            goto check_xor_bitfield_done;
        }
        instr_destroy(drcontext, between);
    }
    if (instr_get_opcode(&xor) == OP_xor) {
        matches = xor_bitfield_check_instr(drcontext, mc, inst, &xor, comb, sz);
        if (!matches) {
            /* Try the next instr, to handle double intertwined patterns (i#1523) */
            instr_reset(drcontext, &xor);
            if (!safe_decode(drcontext, pc, &xor, &pc) || !instr_valid(&xor))
                goto check_xor_bitfield_done;
            if (instr_get_opcode(&xor) == OP_xor) {
                matches = xor_bitfield_check_instr(drcontext, mc, inst, &xor, comb, sz);
            }
        }
    }
 check_xor_bitfield_done:
    instr_free(drcontext, &xor);
    return matches;
}

/* Caller has already checked that "val" is defined */
static bool
check_andor_vals(int opc, reg_t val, uint i, bool bitmask_immed)
{
    if (options.strict_bitops) {
        bool def = ((opc != OP_or && DWORD2BYTE(val, i) == 0) ||
                    (opc == OP_or && DWORD2BYTE(val, i) == ~0));
        DOSTATS({
            if (def)
                STATS_INC(bitfield_const_exception);
        });
        return def;
    } else {
        /* i#849: we relax typical bitfield operations:
         * + OP_or with a defined value (not enough to just allow non-0 value)
         *   used to set a bitfield var to a non-const-zero value
         *   XXX: could put this on fastpath for perf.
         *   XXX i#489: another sequence used to set is a double xor
         *   sequence which will require pattern matching.
         * + OP_and with a constant that has only one sequence of 0's and at
         *   least a few 1's, used to set a bitfield var to zero
         */
        return (opc != OP_or && DWORD2BYTE(val, i) == 0) ||
            (opc == OP_and && bitmask_immed) ||
            opc == OP_or;
    }
}

static bool
check_and_not_test(void *drcontext, dr_mcontext_t *mc, instr_t *and, app_pc next_pc)
{
    /* i#1520: we expand our bitfield heuristics to handle single-bit fields as
     * well as multiple contiguous bitfield variables.  These end up initialized
     * using OP_and with constants like 0x80000000 or 0xf3009000 that don't
     * meet the original i#849 requirements.  Here, we allow any OP_and constant
     * so long as there's no eflags-reading instr soon after, to rule out
     * non-assignment uses like testing that are using OP_and instead of OP_test
     * for some reason.
     */
    bool matches = false;
    instr_t inst;
    uint count;
    byte *pc = next_pc;
#   define AND_NOT_TEST_INSTRS_TO_CHECK 3
    ASSERT(instr_get_opcode(and) == OP_and, "caller should check");
    if (options.strict_bitops) /* not worth separate option */
        return false;
    instr_init(drcontext, &inst);
    for (count = 0; count < AND_NOT_TEST_INSTRS_TO_CHECK; count++) {
        if (!safe_decode(drcontext, pc, &inst, &pc) ||
            !instr_valid(&inst))
            break;
        /* for case like: and %ecx 0x80; jecxz */
        if (instr_is_cbr(&inst))
            break;
        if (TESTANY(EFLAGS_READ_6, instr_get_eflags(&inst, DR_QUERY_DEFAULT)))
            break;
        if (/* report match on aflags written by other following instr */
            TESTALL(EFLAGS_WRITE_6, instr_get_eflags(&inst, DR_QUERY_DEFAULT)) ||
            /* i#1576, i#1586: report match on non-cbr-cti */
            instr_is_cti(&inst)) {
            count = AND_NOT_TEST_INSTRS_TO_CHECK;
            break;
        }
        instr_reset(drcontext, &inst);
    }
    if (count == AND_NOT_TEST_INSTRS_TO_CHECK) {
        matches = true;
        LOG(4, "%s: no eflags-reading instrs after and-with-const @"PFX"\n",
            __FUNCTION__, next_pc);
        STATS_INC(bitfield_const_exception);
    }
    instr_free(drcontext, &inst);
    return matches;
}


static bool
check_andor_bitmask_immed(int opc, size_t sz, reg_t immed, bool *byte_bounds OUT)
{
    /* For i#849, we're looking for OP_and with a constant that sets a contiguous
     * sequence of bits to 0 and leaves the rest alone: used to initialize
     * a bitfield var to zero.
     * We look for one set of 0's and more than 2 1's (to rule out testing
     * just one or two bits w/ OP_and instead of OP_test).
     */
    bool bitmask_immed = false;
    bool byte_only = false;
    if (!options.strict_bitops && opc == OP_and/*no OP_test*/) {
        uint num_contig_1bits = 0;
        /* Also look for byte-aligned and byte-length sequences */
        uint sequence_0 = 0, sequence_1 = 0;
        reg_t curval = immed;
        bool found_zero = false, last_zero = false, two_zeroes = false;
        uint i;
        byte_only = true;
        for (i = 0; i < sz*8; i++) {
            /* XXX perf: per-byte table lookup would be better though
             * need logic to stitch bytes together
             */
            if (TEST(1, curval)) {
                num_contig_1bits++;
                last_zero = false;
                if (sequence_0 % 8 != 0)
                    byte_only = false;
                sequence_0 = 0;
                sequence_1++;
            } else {
                if (!last_zero && found_zero) {
                    /* two sets of zeros: but we can't break b/c of sequence* */
                    two_zeroes = true;
                } else {
                    found_zero = true;
                    last_zero = true;
                }
                if (sequence_1 % 8 != 0)
                    byte_only = false;
                sequence_1 = 0;
                sequence_0++;
            }
            curval = curval >> 1;
        }
        if (!two_zeroes && i == sz*8 && num_contig_1bits > 2) {
            STATS_INC(bitfield_const_exception);
            bitmask_immed = true;
        }
    }
    *byte_bounds = byte_only;
    return bitmask_immed;
}

/* Returns whether the definedness values changed at all */
static bool
check_andor_sources(void *drcontext, dr_mcontext_t *mc, instr_t *inst,
                    shadow_combine_t *comb INOUT, app_pc next_pc)
{
    /* The two sources have been laid out side-by-side in comb->dst.
     * We need to combine, with special rules that suppress undefinedness
     * based on 0 or 1 values.
     */
    int opc = instr_get_opcode(inst);
    reg_t val0, val1, immed = 0;
    uint i, immed_opnum, nonimmed_opnum;
    bool changed = false;
    bool have_vals = (get_cur_src_value(drcontext, inst, 0, &val0) &&
                      get_cur_src_value(drcontext, inst, 1, &val1));
    bool have_immed = false;
    bool bitmask_immed = false;
    size_t sz;
    ASSERT(instr_needs_all_srcs_and_vals(inst) &&
           (opc == OP_and || opc == OP_test || opc == OP_or), "must be OP_{and,test,or}");
    if (opnd_is_immed_int(instr_get_src(inst, 0))) {
        immed_opnum = 0;
        nonimmed_opnum = 1;
        have_immed = true;
        immed = val0;
        sz = opnd_size_in_bytes(opnd_get_size(instr_get_src(inst, 1)));
    } else {
        immed_opnum = 1;
        nonimmed_opnum = 0;
        sz = opnd_size_in_bytes(opnd_get_size(instr_get_src(inst, 0)));
        if (opnd_is_immed_int(instr_get_src(inst, 1))) {
            have_immed = true;
            immed = val1;
        }
        ASSERT(opnd_is_immed_int(instr_get_src(inst, 1)) ||
               sz == opnd_size_in_bytes(opnd_get_size(instr_get_src(inst, 1))),
               "check_andor_sources assumption error");
    }
    ASSERT(instr_needs_all_srcs_and_vals(inst), "check_andor_sources called incorrectly");

    /* Check for intl\strlen.asm case where it reads 4 bytes for efficiency,
     * but only if aligned.  while it does look at the extra bytes the string
     * should terminate in the valid bytes.  We assume that these constants are
     * enough to avoid false positives and don't check surrounding instrs.
     *    hello!strlen [F:\SP\vctools\crt_bld\SELF_X86\crt\src\intel\strlen.asm]:
     *       00405f91 a900010181       test    eax,0x81010100
     *       00405f96 74e8             jz      hello!strlen+0x30 (00405f80)
     *    cygwin1!strcpy:
     *       610deb96 a980808080       test    eax,0x80808080
     *       610deb9b 74e3             jz      cygwin1!strcpy+0x20 (610deb80)
     *    cygwin1!strchr+0x37:
     *       610ded17 f7c280808080     test    edx,0x80808080
     *    cygwin1!cygwin_internal+0xe7f:
     *       6101a79f 81e280808080     and     edx,0x80808080
     *       6101a7a5 74e9             jz      cygwin1!cygwin_internal+0xe70 (6101a790)
     *       6101a7a7 f7c280800000     test    edx,0x8080
     *       6101a7ad 7506             jnz     cygwin1!cygwin_internal+0xe95 (6101a7b5)
     *    crafty+0x246dd:
     *       00424706 81e100010181     and     ecx,0x81010100
     *       0042470c 751c             jnz     crafty+0x2472a (0042472a)
     *       0042470e 2500010181       and     eax,0x81010100
     *       00424713 74d3             jz      crafty+0x246e8 (004246e8)
     *     (haven't yet needed these ones, haven't analyzed whether might)
     *       00424715 2500010101       and     eax,0x1010100
     *       0042471a 7508             jnz     crafty+0x24724 (00424724)
     *       0042471c 81e600000080     and     esi,0x80000000
     *       00424722 75c4             jnz     crafty+0x246e8 (004246e8)
     *
     * We can't do these checks solely on reported undefined instances b/c of the
     * OP_and (and OP_test if -no_check_uninit_cmps) so we must mark defined.
     * Of course this leaves us open to false negatives.
     */
    if (opc != OP_or && sz == 4 &&
        opnd_is_reg(instr_get_src(inst, nonimmed_opnum)) &&
        (opnd_get_reg(instr_get_src(inst, nonimmed_opnum)) == DR_REG_XAX ||
         opnd_get_reg(instr_get_src(inst, nonimmed_opnum)) == DR_REG_XCX ||
         opnd_get_reg(instr_get_src(inst, nonimmed_opnum)) == DR_REG_XDX) &&
        opnd_is_immed_int(instr_get_src(inst, immed_opnum)) &&
        (opnd_get_immed_int(instr_get_src(inst, immed_opnum)) == 0x81010100 ||
         opnd_get_immed_int(instr_get_src(inst, immed_opnum)) == 0x80808080 ||
         opnd_get_immed_int(instr_get_src(inst, immed_opnum)) == 0x00008080)) {
        LOG(3, "strlen/strcpy magic constant @"PFX"\n", instr_get_app_pc(inst));
#ifdef STATISTICS
        if (opnd_get_immed_int(instr_get_src(inst, immed_opnum)) == 0x81010100)
            STATS_INC(strlen_exception);
        else
            STATS_INC(strcpy_exception);
#endif
        for (i = 0; i < sz; i++) {
            comb->dst[i] = SHADOW_DEFINED;
            comb->dst[i+sz] = SHADOW_DEFINED;
        }
        return true;
    }

    if (!options.strict_bitops && have_immed) {
        bool byte_bounds;
        bitmask_immed = check_andor_bitmask_immed(opc, sz, immed, &byte_bounds);
        /* XXX i#1520c#8: we'd like to set bitmask_immed to false if
        * byte_bounds is true, but that leads to false positives.
        * So for now we ignore it and prefer to err on the false neg side
        * until we add true per-bit tracking.
        */
        if (!bitmask_immed && opc == OP_and)
            bitmask_immed = check_and_not_test(drcontext, mc, inst, next_pc);
    }

    for (i = 0; i < sz; i++) {
        LOG(4, "%s: have_vals=%d i=%d def=%d %d val=%d %d\n",
            __FUNCTION__, have_vals, i, comb->dst[i], comb->dst[i+sz],
            DWORD2BYTE(val1, i), DWORD2BYTE(val0, i));
        if (comb->dst[i] == SHADOW_UNDEFINED) {
            if (have_vals && comb->dst[i+sz] == SHADOW_DEFINED &&
                check_andor_vals(opc, val1, i, bitmask_immed)) {
                /* The 0/1 byte makes the source undefinedness not matter */
                comb->dst[i] = SHADOW_DEFINED;
                changed = true;
                STATS_INC(andor_exception);
                LOG(3, "0/1 byte %d suppresses undefined and/or source\n", i);
            }
        } else {
            ASSERT(comb->dst[i] == SHADOW_DEFINED, "shadow val inconsistency");
            if (comb->dst[i+sz] == SHADOW_UNDEFINED) {
                if (have_vals && check_andor_vals(opc, val0, i, bitmask_immed)) {
                    /* The 0/1 byte makes the source undefinedness not matter */
                    STATS_INC(andor_exception);
                    LOG(3, "0/1 byte %d suppresses undefined and/or source\n", i);
                    changed = true;
                } else {
                    /* We probably don't need this as map_src_to_dst() should
                     * already have propagated i+sz to eflags?
                     */
                    changed = true;
                    comb->dst[i] = SHADOW_UNDEFINED;
                }
            } else
                ASSERT(comb->dst[i+sz] == SHADOW_DEFINED, "shadow val inconsistency");
        }
        /* Throw out the 2nd source vals now that we've integrated */
        comb->dst[i+sz] = SHADOW_DEFINED;
    }

    if (opc == OP_and && check_xor_bitfield(drcontext, mc, inst, comb, sz, next_pc))
        changed = true;

    return changed;
}

/* Adds a new source operand's value to the array of shadow vals in
 * comb->dst to be assigned to the destination.
 */
static void
integrate_register_shadow(shadow_combine_t *comb INOUT, int opnum,
                          reg_id_t reg, uint shadow, bool pushpop)
{
    uint i, sz;
    uint opc = comb->opcode;

    if (reg == REG_EFLAGS) {
        /* eflags propagates to all bytes */
        uint dstsz;
        accum_shadow(&comb->eflags, SHADOW_DWORD2BYTE(shadow, 0));
        if (instr_num_dsts(comb->inst) == 0)
            return;
        dstsz = opnd_size_in_bytes(opnd_get_size(instr_get_dst(comb->inst, 0)));
        for (i = 0; i < dstsz; i++)
            accum_shadow(&comb->dst[i], SHADOW_DWORD2BYTE(shadow, i));
        return;
    }

    /* PR 426162: ignore stack register source if instr also has memref
     * using same register as addressing register, since memref will do a
     * definedness check for us, and if the reg is undefined we do NOT want
     * to propagate it as it will end up in a regular dest, say pop into a
     * reg, when that dest should only depend on the memref (since on
     * reported error we set addressing register to defined).
     */
    if ((pushpop && reg_overlap(reg, DR_REG_XSP)) ||
        ((opc == OP_leave || opc == OP_enter) && reg_overlap(reg, DR_REG_XBP)))
        return;

    if (opc_dst_subreg_nonlow(comb->opcode)) {
        /* Deliberately bypassing opnd_get_size() so we can pick the right bits out
         * of the reg for opcodes that are sub-xmm but pull from higher than offset
         * 0 (e.g., pextr*).
         */
        ASSERT(comb->opnd_valid, "need opnd valid for subreg-nonzero opcodes");
        sz = opnd_size_in_bytes(reg_get_size(reg));
    } else
        sz = opnd_size_in_bytes(opnd_get_size(comb->opnd));
    for (i = 0; i < sz; i++)
        map_src_to_dst(comb, opnum, i, SHADOW_DWORD2BYTE(shadow, i));
}

/* Assigns the array of source shadow_vals to the destination register shadow */
static void
assign_register_shadow(shadow_combine_t *comb INOUT, int opnum, opnd_t opnd,
                       reg_id_t reg, bool pushpop)
{
    uint shift = 0;
    uint sz, i;
    int opc = comb->opcode;

    /* Here we need to de-mux from the side-by-side dests in the array
     * into individual register dests.
     * We ignore some dests:
     * - push/pop esp (or enter/leave ebp): we checked esp (ebp) source
     * - string ops ecx/esi/edi: we checked ecx/esi/edi source
     * Some instrs w/ GPR dests we'll naturally mark as defined:
     * - les, lds, lss, lfs, lgs: seg part should be checked up front,
     *                            for simplicity we check the whole thing
     * We also have to shift dsts that do NOT simply go into the lowest slot.
     */
    if (opc_is_stringop(opc)) {
        if (reg_overlap(reg, DR_REG_XDI) || reg_overlap(reg, DR_REG_XSI) ||
            reg_overlap(reg, DR_REG_XCX))
            return;
    } else if ((pushpop && reg_overlap(reg, DR_REG_XSP)) ||
               ((opc == OP_leave || opc == OP_enter) &&
                reg_overlap(reg, DR_REG_XBP))) {
        return;
    } else {
        /* We need special handling for multi-dest opcodes */
        switch (opc) {
        case OP_popa:
            shift = (reg_to_pointer_sized(reg) - DR_REG_XAX);
            break;
        case OP_xchg:
        case OP_xadd:
            shift = opnum;
            break;
        case OP_cmpxchg8b:
            /* opnds: cmpxchg8b mem8 %eax %edx %ecx %ebx -> mem8 %eax %edx
             * operation: if (edx:eax == mem8) mem8 = ecx:ebx; else edx:eax = mem8
             * we just combine all 3 sources and write the result to both dests.
             */
            switch (opnum) {
            case 0: shift = 0; break;
            case 1: shift = 0; break;
            case 2: shift = 1; break;
            default: ASSERT(false, "invalid opnum");
            }
            break;
        }
    }

    if (comb->inst != NULL && proc_avx_enabled() && instr_zeroes_ymmh(comb->inst)) {
        if (opnd_is_reg(instr_get_dst(comb->inst, 0))) {
            reg_id_t reg = opnd_get_reg(instr_get_dst(comb->inst, 0));
            if (reg_is_xmm(reg) && !reg_is_ymm(reg)) {
                /* If instr doesn't zero (i.e., not VEX_encoded), and DR
                 * presents its dst as just xmm, we'll naturally leave the
                 * ymmh shadow as-is.  But if it zeroes we need to explicitly
                 * define the ymmh shadow.
                 */
                int i;
                reg = reg - DR_REG_XMM0 + DR_REG_YMM0;
                for (i = 0; i < 16; i++)
                    register_shadow_set_byte(reg, 16 + i, SHADOW_DEFINED);
            }
        }
    }

    if (opc_dst_subreg_nonlow(comb->opcode)) {
        uint shadow = get_shadow_register(reg);
        /* Deliberately bypassing opnd_get_size() so we can pick the right bits out
         * of the reg for opcodes that are sub-xmm but pull from higher than offset
         * 0 (e.g., pextr*).
         */
        sz = opnd_size_in_bytes(reg_get_size(reg));
        /* Replace the BITLEVEL markers with the register's prior shadow value */
        for (i = 0; i < sz; i++) {
            if (comb->dst[i] == SHADOW_DEFINED_BITLEVEL)
                comb->dst[i] = SHADOW_DWORD2BYTE(shadow, i);
        }
    } else
        sz = opnd_size_in_bytes(opnd_get_size(opnd));

    shift *= sz;
    register_shadow_set_byte(reg, reg_offs_in_dword(reg), comb->dst[shift + 0]);
    if (sz > 1) {
        ASSERT(reg_offs_in_dword(reg) == 0, "invalid reg offs");
        for (i = 1; i < sz; i++) {
            ASSERT(shift + i < OPND_SHADOW_ARRAY_LEN, "shadow_vals overflow");
            register_shadow_set_byte(reg, i, comb->dst[shift + i]);
        }
    }
}

static void
register_shadow_mark_defined(reg_id_t reg, size_t sz)
{
    uint i;
    if (sz == 4 && reg_is_gpr(reg))
        register_shadow_set_dword(reg, SHADOW_DWORD_DEFINED);
    else {
        for (i = 0; i < sz; i++)
            register_shadow_set_byte(reg, i, SHADOW_DEFINED);
    }
}
#endif /* TOOL_DR_MEMORY */

/* PR 530902: cmovcc should ignore src+dst unless eflags matches.  For both
 * cmovcc and fcmovcc we treat an unmatched case as though the source and
 * dest do not exist: certainly source should not propagate to dest, whether
 * we should check for addressability of source is debatable: not doing it
 * for now.  We do have to check whether eflags is defined though.
 *
 * FIXME: what about cmpxchg* where the register (or ecx:ebx for 8b)
 * is not read if the cmp fails?  For now we go ahead and propagate
 * but perhaps we shouldn't be: we'll wait for a false positive to
 * take any action though, seems pretty unlikely, unlike cmovcc.
 */
/* XXX i#1649: handle other predication: OP_bsf, OP_bsr, OP_*maskmov*, etc. */
int
num_true_srcs(instr_t *inst, dr_mcontext_t *mc /*optional*/)
{
    int opc = instr_get_opcode(inst);
    if (opc_is_cmovcc(opc) || opc_is_fcmovcc(opc)) {
        /* PR 530902: cmovcc should ignore src+dst unless eflags matches */
        if (mc != NULL && !instr_cmovcc_triggered(inst, mc->xflags))
            return 0;
        else {
            /* i#1456: ignore the dst-as-src added by DR, since we model the
             * conditional nature ourselves, and don't want a false pos on an uninit
             * dst.
             */
            return 1;
        }
    }
    /* sbb with self should consider all srcs except eflags defined (thus can't
     * be in result_is_always_defined) (PR 425498, PR 425622)
     */
    if (opc == OP_sbb && opnd_same(instr_get_src(inst, 0), instr_get_src(inst, 1)))
        return 0;
    return instr_num_srcs(inst);
}

int
num_true_dsts(instr_t *inst, dr_mcontext_t *mc /*optional*/)
{
    int opc = instr_get_opcode(inst);
    if (opc_is_cmovcc(opc) || opc_is_fcmovcc(opc)) {
        /* PR 530902: cmovcc should ignore src+dst unless eflags matches */
        if (mc != NULL && !instr_cmovcc_triggered(inst, mc->xflags))
            return 0;
    }
    return instr_num_dsts(inst);
}

#ifdef TOOL_DR_MEMORY
/* It turns out that it's not the clean call that's the bottleneck: it's
 * the decode and all the IR processing in the slow path proper.  So for a
 * common slowpath case, 4-byte OP_movs, we have an easy-to-write
 * "medium-speed-path".  Because it's mem2mem, we do not have fastpath
 * support for it yet when check_definedness fails, and maybe we never will
 * need it since this medium-path works fairly well.
 */
void
medium_path_movs4(app_loc_t *loc, dr_mcontext_t *mc)
{
    /* since esi and edi are used as base regs, we are checking
     * definedness, so we ignore the reg operands
     */
    int i;
    shadow_combine_t comb;
    umbra_shadow_memory_info_t info;
    umbra_shadow_memory_info_init(&info);
    LOG(3, "medium_path movs4 "PFX" src="PFX" %d%d%d%d dst="PFX" %d%d%d%d\n",
        loc_to_pc(loc), mc->xsi,
        shadow_get_byte(&info, (app_pc)mc->xsi),
        shadow_get_byte(&info, (app_pc)mc->xsi+1),
        shadow_get_byte(&info, (app_pc)mc->xsi+2),
        shadow_get_byte(&info, (app_pc)mc->xsi+3),
        mc->xdi,
        shadow_get_byte(&info, (app_pc)mc->xdi),
        shadow_get_byte(&info, (app_pc)mc->xdi+1),
        shadow_get_byte(&info, (app_pc)mc->xdi+2),
        shadow_get_byte(&info, (app_pc)mc->xdi+3));
#ifdef STATISTICS
    if (!ALIGNED(mc->xsi, 4))
        STATS_INC(movs4_src_unaligned);
    if (!ALIGNED(mc->xdi, 4))
        STATS_INC(movs4_dst_unaligned);
    if (shadow_get_byte(&info, (app_pc)mc->xsi) != SHADOW_DEFINED ||
        shadow_get_byte(&info, (app_pc)mc->xsi+1) != SHADOW_DEFINED ||
        shadow_get_byte(&info, (app_pc)mc->xsi+2) != SHADOW_DEFINED ||
        shadow_get_byte(&info, (app_pc)mc->xsi+3) != SHADOW_DEFINED)
        STATS_INC(movs4_src_undef);
#endif
    STATS_INC(medpath_executions);

    if (!options.check_uninitialized) {
        if ((!options.check_alignment ||
             (ALIGNED(mc->xsi, 4) && ALIGNED(mc->xdi, 4))) &&
            shadow_get_byte(&info, (app_pc)mc->xsi) != SHADOW_UNADDRESSABLE &&
            shadow_get_byte(&info, (app_pc)mc->xdi) != SHADOW_UNADDRESSABLE) {
            STATS_INC(movs4_med_fast);
            return;
        }
        /* no need to pass shadow_combine_t for MEMREF_CHECK_ADDRESSABLE */
        check_mem_opnd(OP_movs, MEMREF_CHECK_ADDRESSABLE, loc,
                       opnd_create_far_base_disp(SEG_DS, DR_REG_XSI,
                                                 REG_NULL, 0, 0, OPSZ_PTR),
                       4, mc, 0, NULL);
        check_mem_opnd(OP_movs, MEMREF_CHECK_ADDRESSABLE, loc,
                       opnd_create_far_base_disp(SEG_ES, DR_REG_XDI
                                                 , REG_NULL, 0, 0, OPSZ_PTR),
                       4, mc, 0, NULL);
        return;
    }

    /* The generalized routines below are just a little too slow.  The
     * common case is an unaligned movs4 whose source is fully
     * defined, or aligned or unaligned but with source undefined, and
     * with eflags defined, so we have a fastpath here.  This has been
     * good enough so no need for a real fastpath in gencode.
     * i#i#237.
     */
    /* XXX: assuming SEG_DS and SEG_ES are flat+full */
    if (is_shadow_register_defined(get_shadow_register(DR_REG_XSI)) &&
        is_shadow_register_defined(get_shadow_register(DR_REG_XDI)) &&
        get_shadow_eflags() == SHADOW_DEFINED) {
        uint src0 = shadow_get_byte(&info, (app_pc)mc->xsi+0);
        uint src1 = shadow_get_byte(&info, (app_pc)mc->xsi+1);
        uint src2 = shadow_get_byte(&info, (app_pc)mc->xsi+2);
        uint src3 = shadow_get_byte(&info, (app_pc)mc->xsi+3);
        if ((src0 == SHADOW_DEFINED || src0 == SHADOW_UNDEFINED) &&
            (src1 == SHADOW_DEFINED || src1 == SHADOW_UNDEFINED) &&
            (src2 == SHADOW_DEFINED || src2 == SHADOW_UNDEFINED) &&
            (src3 == SHADOW_DEFINED || src3 == SHADOW_UNDEFINED) &&
            shadow_get_byte(&info, (app_pc)mc->xdi+0) != SHADOW_UNADDRESSABLE &&
            shadow_get_byte(&info, (app_pc)mc->xdi+1) != SHADOW_UNADDRESSABLE &&
            shadow_get_byte(&info, (app_pc)mc->xdi+2) != SHADOW_UNADDRESSABLE &&
            shadow_get_byte(&info, (app_pc)mc->xdi+3) != SHADOW_UNADDRESSABLE) {
            shadow_set_byte(&info, (app_pc)mc->xdi+0, src0);
            shadow_set_byte(&info, (app_pc)mc->xdi+1, src1);
            shadow_set_byte(&info, (app_pc)mc->xdi+2, src2);
            shadow_set_byte(&info, (app_pc)mc->xdi+3, src3);
            STATS_INC(movs4_med_fast);
            return;
        }
    }

    shadow_combine_init(&comb, NULL, OP_movs, 4);
    check_mem_opnd(OP_movs, MEMREF_USE_VALUES, loc,
                   opnd_create_far_base_disp(SEG_DS, DR_REG_XSI,
                                             REG_NULL, 0, 0, OPSZ_4),
                   4, mc, 0, &comb);
    for (i = 0; i < 4; i++)
        accum_shadow(&comb.dst[i], get_shadow_eflags());
    check_mem_opnd(OP_movs, MEMREF_WRITE | MEMREF_USE_VALUES, loc,
                   opnd_create_far_base_disp(SEG_ES, DR_REG_XDI,
                                             REG_NULL, 0, 0, OPSZ_4),
                   4, mc, 0, &comb);
}

/* See comments for medium_path_movs4().  For cmps1, because it has 2 memory
 * refs, it only stays on the fastpath if both dwords are fully defined:
 * which fails at the end of strings and other locations.
 */
void
medium_path_cmps1(app_loc_t *loc, dr_mcontext_t *mc)
{
    /* since esi and edi are used as base regs, we are checking
     * definedness, so we ignore the reg operands
     */
    uint flags;
    shadow_combine_t comb;
    umbra_shadow_memory_info_t info;
    umbra_shadow_memory_info_init(&info);
    LOG(3, "medium_path cmps1 "PFX" src1="PFX" %d%d%d%d src2="PFX" %d%d%d%d\n",
        loc_to_pc(loc), mc->xsi,
        shadow_get_byte(&info, (app_pc)mc->xsi),
        shadow_get_byte(&info, (app_pc)mc->xsi+1),
        shadow_get_byte(&info, (app_pc)mc->xsi+2),
        shadow_get_byte(&info, (app_pc)mc->xsi+3),
        mc->xdi,
        shadow_get_byte(&info, (app_pc)mc->xdi),
        shadow_get_byte(&info, (app_pc)mc->xdi+1),
        shadow_get_byte(&info, (app_pc)mc->xdi+2),
        shadow_get_byte(&info, (app_pc)mc->xdi+3));
#ifdef STATISTICS
    if (shadow_get_byte(&info, (app_pc)mc->xsi) != SHADOW_DEFINED ||
        shadow_get_byte(&info, (app_pc)mc->xsi+1) != SHADOW_DEFINED ||
        shadow_get_byte(&info, (app_pc)mc->xsi+2) != SHADOW_DEFINED ||
        shadow_get_byte(&info, (app_pc)mc->xsi+3) != SHADOW_DEFINED ||
        shadow_get_byte(&info, (app_pc)mc->xdi) != SHADOW_DEFINED ||
        shadow_get_byte(&info, (app_pc)mc->xdi+1) != SHADOW_DEFINED ||
        shadow_get_byte(&info, (app_pc)mc->xdi+2) != SHADOW_DEFINED ||
        shadow_get_byte(&info, (app_pc)mc->xdi+3) != SHADOW_DEFINED)
        STATS_INC(cmps1_src_undef);
#endif
    STATS_INC(medpath_executions);

    if (!options.check_uninitialized) {
        if (shadow_get_byte(&info, (app_pc)mc->xsi) != SHADOW_UNADDRESSABLE &&
            shadow_get_byte(&info, (app_pc)mc->xdi) != SHADOW_UNADDRESSABLE) {
            STATS_INC(cmps1_med_fast);
            return;
        }
        /* no need to initialize shadow_vals for MEMREF_CHECK_ADDRESSABLE */
        check_mem_opnd(OP_cmps, MEMREF_CHECK_ADDRESSABLE, loc,
                       opnd_create_far_base_disp(SEG_DS, DR_REG_XSI,
                                                 REG_NULL, 0, 0, OPSZ_1),
                       1, mc, 0, NULL);
        check_mem_opnd(OP_cmps, MEMREF_CHECK_ADDRESSABLE, loc,
                       opnd_create_far_base_disp(SEG_ES, DR_REG_XDI,
                                                 REG_NULL, 0, 0, OPSZ_1),
                       1, mc, 0, NULL);
        return;
    }

    /* The generalized routines are just a little too slow.
     * Xref i#i#237 for movs4.
     */
    /* XXX: assuming SEG_DS and SEG_ES are flat+full */
    if (is_shadow_register_defined(get_shadow_register(DR_REG_XSI)) &&
        is_shadow_register_defined(get_shadow_register(DR_REG_XDI)) &&
        get_shadow_eflags() == SHADOW_DEFINED) {
        uint src0 = shadow_get_byte(&info, (app_pc)mc->xsi);
        uint src1 = shadow_get_byte(&info, (app_pc)mc->xdi);
        if ((src0 == SHADOW_DEFINED ||
             (!options.check_uninit_cmps && src0 == SHADOW_UNDEFINED)) &&
            (src1 == SHADOW_DEFINED ||
             (!options.check_uninit_cmps && src1 == SHADOW_UNDEFINED))) {
            set_shadow_eflags(combine_shadows(src0, src1));
            STATS_INC(cmps1_med_fast);
            return;
        }
    }

    flags = MEMREF_USE_VALUES;
    if (options.check_uninit_cmps)
        flags |= MEMREF_CHECK_DEFINEDNESS;
    if (options.check_uninit_blacklist[0] != '\0') {
        /* i#1529: mark an entire module defined */
        /* XXX: this is the wrong pc if decode_pc != pc.  For now we live with it. */
        if (module_is_on_check_uninit_blacklist(loc_to_pc(loc)))
            flags = 0; /* w/o MEMREF_USE_VALUES, handle_mem_ref() uses SHADOW_DEFINED */
    }
    shadow_combine_init(&comb, NULL, OP_cmps, 1);
    check_mem_opnd(OP_cmps, flags, loc,
                   opnd_create_far_base_disp(SEG_DS, DR_REG_XSI,
                                             REG_NULL, 0, 0, OPSZ_1),
                   1, mc, 0, &comb);
    check_mem_opnd(OP_cmps, flags, loc,
                   opnd_create_far_base_disp(SEG_ES, DR_REG_XDI,
                                             REG_NULL, 0, 0, OPSZ_1),
                   1, mc, 1, &comb);
    /* b/c we set inst to NULL, map_src_to_dst won't do this for us */
    accum_shadow(&comb.dst[0], get_shadow_eflags());
    set_shadow_eflags(comb.dst[0]);
}

bool
opnd_uses_nonignorable_memory(opnd_t opnd)
{
    /* XXX: we could track ebp and try to determine when not used as frame ptr */
    return (opnd_is_memory_reference(opnd) &&
            /* pattern mode */
            (options.pattern == 0 ? true : pattern_opnd_needs_check(opnd)) &&
            /* stack access */
            (options.check_stack_access ||
             !opnd_is_base_disp(opnd) ||
             (reg_to_pointer_sized(opnd_get_base(opnd)) != REG_XSP &&
              reg_to_pointer_sized(opnd_get_base(opnd)) != REG_XBP) ||
             opnd_get_index(opnd) != REG_NULL ||
             opnd_is_far_memory_reference(opnd)));
}

/* Called by slow_path() after initial decode.  Expected to free inst. */
bool
slow_path_without_uninitialized(void *drcontext, dr_mcontext_t *mc, instr_t *inst,
                                app_loc_t *loc, size_t instr_sz)
{
    opnd_t opnd, memop = opnd_create_null();
    int opc, i, num_srcs, num_dsts;
    uint sz;
    bool pushpop_stackop;
    uint flags;
    ASSERT(!options.check_uninitialized, "should not be called");

    opc = instr_get_opcode(inst);
    num_srcs = (opc == OP_lea) ? 0 : num_true_srcs(inst, mc);
    for (i = 0; i < num_srcs; i++) {
        opnd = instr_get_src(inst, i);
        if (opnd_uses_nonignorable_memory(opnd)) {
            opnd = adjust_memop(inst, opnd, false, &sz, &pushpop_stackop);
            if (pushpop_stackop && options.check_stack_bounds)
                flags = MEMREF_PUSHPOP | MEMREF_IS_READ;
            else
                flags = MEMREF_CHECK_ADDRESSABLE | MEMREF_IS_READ;
            memop = opnd;
            check_mem_opnd_nouninit(opc, flags, loc, opnd, sz, mc);
        }
    }

    num_dsts = num_true_dsts(inst, mc);
    for (i = 0; i < num_dsts; i++) {
        opnd = instr_get_dst(inst, i);
        if (opnd_uses_nonignorable_memory(opnd)) {
            opnd = adjust_memop(inst, opnd, true, &sz, &pushpop_stackop);
            if (pushpop_stackop && options.check_stack_bounds)
                flags = MEMREF_PUSHPOP | MEMREF_WRITE;
            else
                flags = MEMREF_CHECK_ADDRESSABLE;
            memop = opnd;
            check_mem_opnd_nouninit(opc, flags, loc, opnd, sz, mc);
        }
    }

    instr_free(drcontext, inst);

    /* call this last after freeing inst in case it does a synchronous flush */
    slow_path_xl8_sharing(loc, instr_sz, memop, mc);

    return true;
}
#endif /* TOOL_DR_MEMORY */

/* Does everything in C code, except for handling non-push/pop writes to esp.
 *
 * General design:
 * + comb.dest[] array holds the shadow values for the destinations.
 *   If there are multiple dests, they are laid out side-by-side.
 * + Shadow values are combined via combine_shadows() which does OR-combining.
 *
 * First we walk the sources and add each in turn to the shadow array via:
 * + integrate_register_shadow() for regs
 * + handle_mem_ref() with MEMREF_USE_VALUES for memrefs
 * Both call map_src_to_dst() which determines where in
 * the dst shadow array to put each source, thus handling arbitrary
 * opcodes with weird data movements.
 *
 * Then we walk the dests and call handle_mem_ref() or
 * assign_register_shadow() on each, which pulls from comb.dest[]'s shadow vals.
 *
 * XXX: can we change handle_mem_ref() and map_src_to_dst() to not operate on
 * one byte at a time, so we can make the slowpath more closely match the
 * fastpath code, and thus make it easier to transition opcodes to the fastpath?
 */
bool
slow_path_with_mc(void *drcontext, app_pc pc, app_pc decode_pc, dr_mcontext_t *mc)
{
    instr_t inst;
    int opc;
#ifdef TOOL_DR_MEMORY
    opnd_t opnd;
    int i, num_srcs, num_dsts;
    uint sz;
    shadow_combine_t comb;
    bool check_definedness, pushpop, pushpop_stackop;
    bool check_srcs_after;
    bool always_defined;
    opnd_t memop = opnd_create_null();
    size_t instr_sz;
    cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
#endif
    app_loc_t loc;

#if defined(STATISTICS) && defined(TOOL_DR_MEMORY)
    /* PR 423757: periodic stats dump, both for server apps that don't
     * close cleanly and to get stats out prior to overflow.
     */
    int execs = atomic_add32_return_sum((volatile int *)&slowpath_executions, 1);
    if (execs == next_stats_dump) {
        /* still racy: could skip a dump, but that's ok */
        ATOMIC_ADD32(next_stats_dump, options.stats_dump_interval);
        dr_fprintf(f_global, "\n**** per-%dK-slowpath stats dump:\n",
                   options.stats_dump_interval/1000);
        dump_statistics();
    }
#endif

    pc_to_loc(&loc, pc);

    /* Locally-spilled and whole-bb-spilled (PR 489221) registers have
     * already been restored in shared_slowpath, so we can properly
     * emulate addresses referenced.  We can't restore whole-bb-spilled
     * here b/c we don't have the bb tag.  Eflags may not be restored
     * but we don't rely on them here.
     */

    /* for jmp-to-slowpath optimization where we xl8 to get app pc (PR 494769)
     * we always pass NULL for decode_pc
     */
    if (decode_pc == NULL) {
        /* not using safe_read since in cache */
        byte *ret_pc = (byte *) get_own_tls_value(SPILL_SLOT_2);
        ASSERT(pc == NULL, "invalid params");
        ASSERT(options.single_arg_slowpath, "only used for single_arg_slowpath");
        /* If the ret pc is a jmp, we know to walk forward, bypassing
         * spills, to find the app instr (we assume app jmp never
         * needs slowpath).  If using a cloned app instr, then ret pc
         * points directly there.  Since we want to skip the clone and
         * the jmp, we always skip the instr at ret pc when returning.
         */
        pc = decode_next_pc(drcontext, ret_pc);
        ASSERT(pc != NULL, "invalid stored app instr");
        set_own_tls_value(SPILL_SLOT_2, (reg_t) pc);
        if (*ret_pc == 0xe9) {
            /* walk forward to find the app pc */
            instr_init(drcontext, &inst);
            do {
                instr_reset(drcontext, &inst);
                decode_pc = pc;
                pc = decode(drcontext, decode_pc, &inst);
                ASSERT(pc != NULL, "invalid app instr copy");
            } while (instr_is_spill(&inst) || instr_is_restore(&inst));
            instr_reset(drcontext, &inst);
        } else
            decode_pc = ret_pc;
        /* if we want the app addr later, we'll have to translate to get it */
        loc.u.addr.valid = false;
        loc.u.addr.pc = decode_pc;
        pc = NULL;
    } else
        ASSERT(!options.single_arg_slowpath, "single_arg_slowpath error");

#ifdef TOOL_DR_MEMORY
    if (decode_pc != NULL) {
        if (*decode_pc == MOVS_4_OPCODE ||
            /* we now pass original pc from -repstr_to_loop including rep.
             * ignore other prefixes here: data16 most likely and then not movs4.
             */
            (options.repstr_to_loop && *decode_pc == REP_PREFIX &&
             *(decode_pc + 1) == MOVS_4_OPCODE)) {
            /* see comments for this routine: common enough it's worth optimizing */
            medium_path_movs4(&loc, mc);
            /* no sharing with string instrs so no need to call
             * slow_path_xl8_sharing
             */
            return true;
        } else if (*decode_pc == CMPS_1_OPCODE ||
                   (options.repstr_to_loop &&
                    (*decode_pc == REP_PREFIX || *decode_pc == REPNE_PREFIX) &&
                    *(decode_pc + 1) == CMPS_1_OPCODE)) {
            medium_path_cmps1(&loc, mc);
            return true;
        }
    }
#endif /* TOOL_DR_MEMORY */

    instr_init(drcontext, &inst);
#ifdef TOOL_DR_MEMORY
    instr_sz = decode(drcontext, decode_pc, &inst) - decode_pc;
#else
    decode(drcontext, decode_pc, &inst);
#endif
    ASSERT(instr_valid(&inst), "invalid instr");
    opc = instr_get_opcode(&inst);

    if (options.repstr_to_loop && opc == OP_loop) {
        /* to point at an OP_loop but use app's repstr pc we use this table (i#391) */
        byte *rep_pc;
        dr_mutex_lock(stringop_lock);
        rep_pc = (byte *) hashtable_lookup(&stringop_us2app_table, decode_pc);
        dr_mutex_unlock(stringop_lock);
        if (rep_pc != NULL) {
            ASSERT(dr_memory_is_dr_internal(decode_pc), "must be drmem heap");
            /* use this as app pc if we report an error */
            pc_to_loc(&loc, rep_pc);
        }
    }

#ifdef STATISTICS
    STATS_INC(slowpath_count[opc]);
    {
        uint bytes = instr_memory_reference_size(&inst);
        if (bytes == 0) {
            if (instr_num_dsts(&inst) > 0 &&
                !opnd_is_pc(instr_get_dst(&inst, 0)) &&
                !opnd_is_instr(instr_get_dst(&inst, 0)))
                bytes = opnd_size_in_bytes(opnd_get_size(instr_get_dst(&inst, 0)));
            else if (instr_num_srcs(&inst) > 0 &&
                     !opnd_is_pc(instr_get_src(&inst, 0)) &&
                     !opnd_is_instr(instr_get_src(&inst, 0)))
                bytes = opnd_size_in_bytes(opnd_get_size(instr_get_src(&inst, 0)));
            else
                bytes = 0;
        }
        if (bytes == 1)
            STATS_INC(slowpath_sz1);
        else if (bytes == 2)
            STATS_INC(slowpath_sz2);
        else if (bytes == 4)
            STATS_INC(slowpath_sz4);
        else if (bytes == 8)
            STATS_INC(slowpath_sz8);
        else if (bytes == 10)
            STATS_INC(slowpath_sz10);
        else if (bytes == 16)
            STATS_INC(slowpath_sz16);
        else
            STATS_INC(slowpath_szOther);
    }
#endif

    DOLOG(3, {
            LOG(3, "\nslow_path "PFX": ", pc);
            instr_disassemble(drcontext, &inst, LOGFILE_GET(drcontext));
            if (instr_num_dsts(&inst) > 0 &&
                opnd_is_memory_reference(instr_get_dst(&inst, 0))) {
                umbra_shadow_memory_info_t info;
                umbra_shadow_memory_info_init(&info);
                LOG(3, " | 0x%x",
                    shadow_get_byte(&info,
                                    opnd_compute_address(instr_get_dst(&inst, 0),
                                                         mc)));
            }
            LOG(3, "\n");
        });

#ifdef TOOL_DR_HEAPSTAT
    return slow_path_for_staleness(drcontext, mc, &inst, &loc);

#else
    if (!options.check_uninitialized)
        return slow_path_without_uninitialized(drcontext, mc, &inst, &loc, instr_sz);

    LOG(4, "shadow registers prior to instr:\n");
    DOLOG(4, { print_shadow_registers(); });

    /* We need to do the following:
     * - check addressability of all memory operands
     * - check definedness of all source operands if:
     *   o no GPR or memory dest (=> no way to store definedness)
     *   o if options.check_uninit_non_moves is on and this is not just a move
     * - check definedness of certain source operands:
     *   o base or index register to a memory ref
     *     (includes esp/ebp operand to a push/pop)
     *   o ecx to stringop
     *   o ebp to enter/leave
     * - combine definedness of source operands and store
     *   in dest operand shadows
     * - if a pop, make stack slot(s) unaddressable
     *
     * Usually there's one destination we need to transfer
     * definedness to.  If there are more, we can fit them side by
     * side in our 8-dword-capacity comb->dst array.
     */
    check_definedness = instr_check_definedness(&inst);
    always_defined = result_is_always_defined(&inst, false/*us*/);
    pushpop = opc_is_push(opc) || opc_is_pop(opc);
    check_srcs_after = instr_needs_all_srcs_and_vals(&inst);
    if (check_srcs_after) {
        /* We need to check definedness of addressing registers, and so we do
         * our normal src loop but we do not check undefinedness or combine
         * sources.  Below we pass pointers to later in comb->dst to
         * check_mem_opnd() and integrate_register_shadow(), causing the 2
         * sources to be laid out side-by-side in comb->dst.
         */
        ASSERT(instr_num_srcs(&inst) == 2, "and/or special handling error");
        check_definedness = false;
        IF_DEBUG(comb.opsz = 0;) /* for asserts below */
    }

    shadow_combine_init(&comb, &inst, opc, OPND_SHADOW_ARRAY_LEN);

    num_srcs = (opc == OP_lea) ? 2 : num_true_srcs(&inst, mc);
 check_srcs:
    for (i = 0; i < num_srcs; i++) {
        if (opc == OP_lea) {
            /* special case: treat address+base as propagatable sources
             * code below can handle REG_NULL
             */
            if (i == 0)
                opnd = opnd_create_reg(opnd_get_base(instr_get_src(&inst, 0)));
            else
                opnd = opnd_create_reg(opnd_get_index(instr_get_src(&inst, 0)));
        } else {
            opnd = instr_get_src(&inst, i);
        }
        if (opnd_is_memory_reference(opnd)) {
            int flags = 0;
            opnd = adjust_memop(&inst, opnd, false, &sz, &pushpop_stackop);
            /* do not combine srcs if checking after */
            if (check_srcs_after) {
                ASSERT(i == 0 || sz >= comb.opsz, "check-after needs >=-size srcs");
                comb.dst = &comb.raw[i*sz]; /* shift the dst in the array */
            }
            shadow_combine_set_opnd(&comb, opnd, sz);
            /* check_mem_opnd() checks definedness of base registers,
             * addressability of address, and if necessary checks definedness
             * and adjusts addressability of address.
             */
            if (pushpop_stackop)
                flags |= MEMREF_PUSHPOP;
            if (always_defined) {
                LOG(2, "marking and/or/xor with 0/~0/self as defined @"PFX"\n", pc);
                /* w/o MEMREF_USE_VALUES, handle_mem_ref() will use SHADOW_DEFINED */
            } else if (check_definedness || always_check_definedness(&inst, i)) {
                flags |= MEMREF_CHECK_DEFINEDNESS;
                if (options.leave_uninit)
                    flags |= MEMREF_USE_VALUES;
            } else {
                /* If we're checking, to avoid further errors we do not
                 * propagate the shadow vals (and thus we essentially
                 * propagate SHADOW_DEFINED).
                 * Conveniently all the large operand sizes always
                 * have check_definedness since they involve fp or sse.
                 */
                ASSERT(sz <= sizeof(comb.raw), "internal shadow val error");
                flags |= MEMREF_USE_VALUES;
            }
            memop = opnd;
            check_mem_opnd(opc, flags, &loc, opnd, sz, mc, i, &comb);
        } else if (opnd_is_reg(opnd)) {
            reg_id_t reg = opnd_get_reg(opnd);
            if (reg_is_shadowed(opc, reg)) {
                uint shadow = get_shadow_register(reg);
                if (opc_dst_subreg_nonlow(opc)) {
                    /* We need the whole reg as this opcode references high up */
                    sz = opnd_size_in_bytes(reg_get_size(reg));
                } else
                    sz = opnd_size_in_bytes(opnd_get_size(opnd));
                /* do not combine srcs if checking after */
                if (check_srcs_after) {
                    ASSERT(i == 0 || sz >= comb.opsz, "check-after needs >=-size srcs");
                    comb.dst = &comb.raw[i*sz]; /* shift the dst in the array */
                }
                shadow_combine_set_opnd(&comb, opnd, sz);
                if (always_defined) {
                    /* if result defined regardless, don't propagate (is
                     * equivalent to propagating SHADOW_DEFINED) or check */
                } else if (check_definedness || always_check_definedness(&inst, i)) {
                    check_register_defined(drcontext, reg, &loc, sz, mc, &inst);
                    if (options.leave_uninit) {
                        integrate_register_shadow(&comb, i, reg, shadow, pushpop);
                    }
                } else {
                    /* See above: we only propagate when not checking */
                    integrate_register_shadow(&comb, i, reg, shadow, pushpop);
                }
            } /* else always defined */
        } else /* always defined */
            ASSERT(opnd_is_immed_int(opnd) || opnd_is_pc(opnd), "unexpected opnd");
        DOLOG(4, {
            int j;
            LOG(4, "shadows after src %d ", i);
            opnd_disassemble(drcontext, opnd, LOGFILE_GET(drcontext));
            LOG(4, ": ");
            for (j = 0; j < OPND_SHADOW_ARRAY_LEN; j++)
                LOG(4, "%d", comb.raw[j]);
            LOG(4, ", eflags: %d\n", comb.eflags);
        });
    }

    /* eflags source */
    if (TESTANY(EFLAGS_READ_6, instr_get_eflags(&inst, DR_QUERY_DEFAULT))) {
        uint shadow = get_shadow_eflags();
        /* for check_srcs_after we leave comb.dst where it last was */
        if (always_defined) {
            /* if result defined regardless, don't propagate (is
             * equivalent to propagating SHADOW_DEFINED) or check */
        } else if (check_definedness) {
            check_register_defined(drcontext, REG_EFLAGS, &loc, 1, mc, &inst);
            if (options.leave_uninit)
                integrate_register_shadow(&comb, 0, REG_EFLAGS, shadow, pushpop);
        } else {
            /* See above: we only propagate when not checking */
            integrate_register_shadow(&comb, 0, REG_EFLAGS, shadow, pushpop);
        }
    } else if (num_srcs == 0) {
        /* do not propagate from comb.dst since dst size could be large (i#458)
         * (fxsave, etc.)
         */
        always_defined = true;
    }

    if (check_srcs_after)
        comb.dst = comb.raw; /* restore */

    if (check_srcs_after) {
        /* turn back on for dsts */
        check_definedness = instr_check_definedness(&inst);
        if (check_andor_sources(drcontext, mc, &inst, &comb, decode_pc + instr_sz)) {
            if (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(&inst, DR_QUERY_INCLUDE_ALL))) {
                /* We have to redo the eflags propagation.  map_src_to_dst() combined
                 * all the laid-out sources, some of which we made defined in
                 * check_andor_sources.
                 */
                comb.eflags = SHADOW_DEFINED;
                for (i = 0; i < OPND_SHADOW_ARRAY_LEN; i++)
                    accum_shadow(&comb.eflags, comb.dst[i]);
            }
        }
        if (check_definedness) {
            /* If we need to report undefs we have to go back */
            bool all_defined = true;
            for (i = 0; i < OPND_SHADOW_ARRAY_LEN; i++) {
                if (comb.dst[i] != SHADOW_DEFINED) {
                    all_defined = false;
                    break;
                }
            }
            if (!all_defined) {
                /* We do not bother to suppress reporting the particular bytes that
                 * may have been "defined" due to 0/1 in the other operand since
                 * doing so would require duplicating/extracting all the reporting
                 * logic above for regs and in handle_mem_ref(): our goto here is
                 * slightly less ugly.
                 */
                LOG(4, "and/or not all defined and need to check def: restarting\n");
                /* Avoid recursing, and don't do the side-by-side layout this time */
                check_srcs_after = false;
                for (i = 0; i < OPND_SHADOW_ARRAY_LEN; i++)
                    comb.dst[i] = SHADOW_DEFINED;
                comb.eflags = SHADOW_DEFINED;
                goto check_srcs;
            }
        }
    }

    num_dsts = num_true_dsts(&inst, mc);
    for (i = 0; i < num_dsts; i++) {
        opnd = instr_get_dst(&inst, i);
        if (opnd_is_memory_reference(opnd)) {
            int flags = MEMREF_WRITE;
            opnd = adjust_memop(&inst, opnd, true, &sz, &pushpop_stackop);
            if (pushpop_stackop)
                flags |= MEMREF_PUSHPOP;
            if (cpt->mem2fpmm_source != NULL && cpt->mem2fpmm_pc == pc) {
                /* i#471 fld;fstp heuristic: fstp's dest was marked bitlevel to
                 * get us here.  Do a special-case propagate.
                 */
                umbra_shadow_memory_info_t info;
                LOG(3, "propagating fld;fstp from "PFX"\n", cpt->mem2fpmm_source);
                /* We use a fake movs in handle_mem_ref() (can't just do
                 * shadow_copy_range() b/c we need to check base reg for
                 * definedness, check for addressability, etc.)
                 */
                umbra_shadow_memory_info_init(&info);
                shadow_set_byte(&info, cpt->mem2fpmm_dest, cpt->mem2fpmm_prev_shadow);
                comb.movs_addr = cpt->mem2fpmm_source;
                flags |= MEMREF_MOVS | MEMREF_USE_VALUES;
                cpt->mem2fpmm_source = NULL;
            } else if (always_defined) {
                /* w/o MEMREF_USE_VALUES, handle_mem_ref() will use SHADOW_DEFINED */
            } else if (check_definedness) {
                flags |= MEMREF_CHECK_DEFINEDNESS;
                if (options.leave_uninit)
                    flags |= MEMREF_USE_VALUES;
                /* since checking, we mark as SHADOW_DEFINED (see above) */
            } else {
                ASSERT(sz <= sizeof(comb.raw), "internal shadow val error");
                flags |= MEMREF_USE_VALUES;
            }
            /* check addressability, and propagate
             * we arranged xchg/xadd to not need shifting; nothing else does either.
             */
            memop = opnd;
            check_mem_opnd(opc, flags, &loc, opnd, sz, mc, i, &comb);
        } else if (opnd_is_reg(opnd)) {
            reg_id_t reg = opnd_get_reg(opnd);
            if (reg_is_shadowed(opc, reg)) {
                assign_register_shadow(&comb, i, opnd, reg, pushpop);
            }
        } else
            ASSERT(opnd_is_immed_int(opnd) || opnd_is_pc(opnd), "unexpected opnd");
    }
    if (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(&inst, DR_QUERY_INCLUDE_ALL))) {
        set_shadow_eflags(comb.eflags);
    }

    LOG(4, "shadow registers after instr:\n");
    DOLOG(4, { print_shadow_registers(); });

    instr_free(drcontext, &inst);

    /* call this last after freeing inst in case it does a synchronous flush */
    slow_path_xl8_sharing(&loc, instr_sz, memop, mc);

    DOLOG(5, { /* this pollutes the logfile, so it's a pain to have at 4 or lower */
        if (!options.single_arg_slowpath && pc == decode_pc/*else retpc not in tls3*/) {
            /* Test translation when have both args */
            /* we want the ultimate target, not whole_bb_spills_enabled()'s
             * SPILL_SLOT_5 intermediate target
             */
            byte *ret_pc = (byte *) get_own_tls_value(SPILL_SLOT_2);
            /* ensure event_restore_state() returns true */
            byte *xl8;
            cpt->self_translating = true;
            xl8 = dr_app_pc_from_cache_pc(ret_pc);
            cpt->self_translating = false;
            LOG(3, "translation test: cache="PFX", orig="PFX", xl8="PFX"\n",
                ret_pc, pc, xl8);
            ASSERT(xl8 == pc ||
                   (options.repstr_to_loop &&
                    /* Depending on -no_fastpath we'll get here for the jecxz pointing
                     * at the loop, the loop, or the stringop.
                     */
                    (opc_is_stringop(opc) || opc == OP_loop) &&
                    /* For repstr_to_loop we changed pc */
                    (xl8 == loc_to_pc(&loc) ||
                     /* For repstr_to_loop OP_loop, ret_pc is the restore
                      * code after stringop and before OP_loop*, so we'll get
                      * post-xl8 pc.
                      */
                     xl8 == decode_next_pc(drcontext, loc_to_pc(&loc)))) ||
                   /* ret_pc may be a global reg restore, and for -no_fastpath
                    * this will use the prior xl8 since there's no meta-xl8 and
                    * the real app instr is beyond ret_pc.
                    */
                   (instr_at_pc_is_restore(drcontext, ret_pc) &&
                    pc == decode_next_pc(drcontext, xl8)) ||
                   /* for native ret we changed pc */
                   (options.replace_malloc && opc == OP_ret &&
                    alloc_entering_replace_routine(xl8)),
                   "xl8 doesn't match");
        }
    });
    return true;
#endif /* !TOOL_DR_HEAPSTAT */
}

/* called from code cache */
static bool
slow_path(app_pc pc, app_pc decode_pc)
{
    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    bool res;
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL|DR_MC_INTEGER; /* don't need xmm */
    dr_get_mcontext(drcontext, &mc);
    res = slow_path_with_mc(drcontext, pc, decode_pc, &mc);
#ifdef TOOL_DR_MEMORY
    DODEBUG({
        cls_drmem_t *cpt = (cls_drmem_t *) drmgr_get_cls_field(drcontext, cls_idx_drmem);
        /* Try to ensure that mem2fpmm_source doesn't "escape" */
        ASSERT(cpt->mem2fpmm_source == NULL ||
               (pc >= cpt->mem2fpmm_load_pc && pc <= cpt->mem2fpmm_pc),
               "mem2fpmm source escaped");
    });
#endif
    return res;
}

/* Returns whether a single pc can be used for app reporting and
 * decoding of the app instr (or, whether a separate decode pc can be
 * used b/c there's fixup code for the pc to report in the slowpath).
 * The OUT param is either an immed int opnd or an instr opnd that can be
 * used as an intpr opnd for decoding.
 */
static bool
instr_shared_slowpath_decode_pc(instr_t *inst, fastpath_info_t *mi,
                                opnd_t *decode_pc_opnd)
{
    app_pc pc = instr_get_app_pc(inst);
    app_pc decode_pc = dr_app_pc_for_decoding(pc);
    if (!options.shared_slowpath) {
        *decode_pc_opnd = OPND_CREATE_INTPTR(decode_pc);
        return false;
    }
    if (mi->bb->fake_xl8_override_instr == inst) {
        *decode_pc_opnd = OPND_CREATE_INTPTR(mi->bb->fake_xl8_override_pc);
        return true;
    } else if (mi->bb->fake_xl8 != NULL) {
        *decode_pc_opnd = OPND_CREATE_INTPTR(mi->bb->fake_xl8);
        return true;
    } else if (pc != decode_pc) {
        /* We have to handle DR trampolines so we pass in a separate pc to
         * decode from
         */
        *decode_pc_opnd = OPND_CREATE_INTPTR(decode_pc);
        return false;
    } else if (pc == instr_get_raw_bits(inst)) {
        /* If it matches the raw bits we know we only need one pc */
        *decode_pc_opnd = OPND_CREATE_INTPTR(pc);
        return true;
    } else {
        if (options.replace_malloc && alloc_entering_replace_routine(pc)) {
            /* drwrap_replace_native() emulates a push for call site
             * replacement via generated instrs whose app pcs do not match
             * their code cache forms.
             */
        } else {
            DOLOG(1, {
                if (instr_get_opcode(inst) == OP_xchg &&
                    opnd_is_reg(instr_get_dst(inst, 1)) &&
                    opnd_get_reg(instr_get_dst(inst, 1)) == DR_REG_XAX &&
                    opnd_is_base_disp(instr_get_dst(inst, 0)) &&
                    opnd_get_base(instr_get_dst(inst, 0)) == DR_REG_XAX) {
                    /* this is the retaddr clobber from bb_handle_chkstk() */
                } else {
                    void *drcontext = dr_get_current_drcontext();
                    LOG(1, "unknown generated app instr: ");
                    instr_disassemble(drcontext, inst, LOGFILE_GET(drcontext));
                    LOG(1, "\n");
                }
            });
            /* To try and handle any generated app2app we point at the
             * cache instr.  We'll have to construct fake instrs to point
             * at if we end up encountering any mangled instrs.
             */
        }
        ASSERT(!instr_is_cti(inst), "assuming non-mangled");
        *decode_pc_opnd = opnd_create_instr(inst);
        return false;
    }
}

bool
instr_can_use_shared_slowpath(instr_t *inst, fastpath_info_t *mi)
{
    opnd_t ignore;
    return instr_shared_slowpath_decode_pc(inst, mi, &ignore);
}

void
instrument_slowpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi)
{
    opnd_t decode_pc_opnd;
    ASSERT(options.pattern == 0, "No slow path for pattern mode");
    if (instr_shared_slowpath_decode_pc(inst, mi, &decode_pc_opnd)) {
        /* Since the clean call instr sequence is quite long we share
         * it among all bbs.  Rather than switch to a clean stack we jmp
         * there and jmp back.  Since we don't nest we can get away
         * w/ a single TLS slot.  The other is used for the arg.  We
         * inline the call if the 2nd arg is different.
         * Note that having slow_path use dr_redirect_execution() instead
         * of coming back here is problematic since when would we execute the
         * app instr?  Can't do it before since need to emulate addresses,
         * and don't have a single-step or other way to have target not be
         * executed directly in future.
         */
        instr_t *appinst = INSTR_CREATE_label(drcontext);
        if (mi == NULL) {
            ASSERT(!whole_bb_spills_enabled(), "whole-bb needs tls preserved");
            instru_insert_mov_pc(drcontext, bb, inst,
                                 spill_slot_opnd(drcontext, SPILL_SLOT_1),
                                 decode_pc_opnd);
            /* XXX: this hardcoded address will be wrong if this
             * fragment is shifted, but DR now disables shifting in the
             * presence of clients (i#784, DRi#696).
             * The old trace API would end up copying this, but the new one
             * copies from the app code, so there's no problem there.
             * And so long as we're never at a "safe spot" in the lean procedure,
             * DR won't relocate us or remove our return point out from underneath us.
             */
            instru_insert_mov_pc(drcontext, bb, inst,
                                 spill_slot_opnd(drcontext, SPILL_SLOT_2),
                                 opnd_create_instr(appinst));
            PRE(bb, inst,
                INSTR_CREATE_jmp(drcontext, opnd_create_pc(shared_slowpath_entry)));
        } else {
            /* Don't restore, and put consts into registers if we can, to save space */
            scratch_reg_info_t *s1, *s2, *s3;
            int r1, r2, r3, ef = 0;
            bool spill_eax;
            byte *tgt;
            s1 = &mi->reg1;
            s2 = &mi->reg2;
            s3 = &mi->reg3;
            /* For whole-bb spilling we sometimes have reg3 in slot1 or slot2 b/c
             * we picked ecx as a whole-bb spill: simplest to shuffle here
             */
            if (whole_bb_spills_enabled() && mi->reg3.global) {
                if (mi->reg3.slot == SPILL_SLOT_1) {
                    s1 = &mi->reg3;
                    s3 = &mi->reg1;
                } else {
                    ASSERT(mi->reg3.slot == SPILL_SLOT_2, "spill assumption violated");
                    s2 = &mi->reg3;
                    s3 = &mi->reg2;
                }
            }
            ASSERT(s1->slot == SPILL_SLOT_1 && s2->slot == SPILL_SLOT_2, "slot error");
            r1 = (s1->dead ? (s1->reg - DR_REG_XAX + SPILL_REG_EAX_DEAD) :
                  ((!s1->used || s1->xchg != REG_NULL) ? SPILL_REG_NONE :
                   (s1->reg - DR_REG_XAX + SPILL_REG_EAX)));
            r2 = (s2->dead ? (s2->reg - DR_REG_XAX + SPILL_REG_EAX_DEAD) :
                  ((!s2->used || s2->xchg != REG_NULL) ? SPILL_REG_NONE :
                   (s2->reg - DR_REG_XAX + SPILL_REG_EAX)));
            if (whole_bb_spills_enabled()) {
                /* reg3 just like 1 and 2: can be any reg */
                r3 = (s3->dead ? (s3->reg - DR_REG_XAX + SPILL_REG_EAX_DEAD) :
                      ((!s3->used || s3->xchg != REG_NULL) ? SPILL_REG_NONE :
                       (s3->reg - DR_REG_XAX + SPILL_REG_EAX)));
            } else {
                /* if reg3 is dead we do not need to restore */
                r3 = ((!s3->used || s3->dead || s3->xchg != REG_NULL) ?
                      SPILL_REG3_NOSPILL : SPILL_REG3_SPILL);
                spill_eax = (mi->eax.used && !mi->eax.dead && mi->eax.xchg == REG_NULL);
                ef = ((whole_bb_spills_enabled() ||
                       mi->aflags == EFLAGS_WRITE_6) ? SPILL_EFLAGS_NOSPILL :
                      ((mi->aflags == EFLAGS_WRITE_OF) ?
                       (spill_eax ? SPILL_EFLAGS_5_EAX : SPILL_EFLAGS_5_NOEAX) :
                       (spill_eax ? SPILL_EFLAGS_6_EAX : SPILL_EFLAGS_6_NOEAX)));
            }
            ASSERT(r1 >= 0 && r1 < SPILL_REG_NUM, "shared slowpath index error");
            ASSERT(r2 >= 0 && r2 < SPILL_REG_NUM, "shared slowpath index error");
            tgt = (whole_bb_spills_enabled() ?
                   shared_slowpath_entry_global[r1][r2][r3]:
                   shared_slowpath_entry_local[r1][r2][r3][ef]);
            ASSERT(tgt != NULL, "targeting un-generated slowpath");
            if (options.single_arg_slowpath) {
                /* for jmp-to-slowpath optimization: we point at app instr, or a
                 * clone of it, for pc to decode from (PR 494769), as the
                 * retaddr, and thus do not need a second parameter.
                 */
                mi->appclone = instr_clone(drcontext, inst);
                mi->slow_store_dst = (r2 == SPILL_REG_NONE) ?
                    spill_slot_opnd(drcontext, SPILL_SLOT_2) : opnd_create_reg(s2->reg);
                instrlist_insert_mov_instr_addr(drcontext, mi->appclone,
                                                NULL /* in code cache */,
                                                mi->slow_store_dst,
                                                bb, inst, &mi->slow_store_retaddr,
                                                &mi->slow_store_retaddr2);
                mi->slow_jmp = INSTR_CREATE_jmp(drcontext, opnd_create_pc(tgt));
                PRE(bb, inst, mi->slow_jmp);
                instr_set_meta(mi->appclone);
                instr_set_translation(mi->appclone, NULL);
                PRE(bb, inst, mi->appclone);
            } else {
                instru_insert_mov_pc(drcontext, bb, inst,
                                     (r1 == SPILL_REG_NONE) ?
                                     spill_slot_opnd(drcontext, SPILL_SLOT_1) :
                                     opnd_create_reg(s1->reg),
                                     decode_pc_opnd);
                instru_insert_mov_pc(drcontext, bb, inst,
                                     (r2 == SPILL_REG_NONE) ?
                                     spill_slot_opnd(drcontext, SPILL_SLOT_2) :
                                     opnd_create_reg(s2->reg),
                                     opnd_create_instr(appinst));
                PRE(bb, inst, INSTR_CREATE_jmp(drcontext, opnd_create_pc(tgt)));
            }
        }
        PRE(bb, inst, appinst);
    } else {
        app_pc pc = instr_get_app_pc(inst);
        if (mi != NULL) {
            /* We assume caller did a restore */
        }
        if (!opnd_same(OPND_CREATE_INTPTR(pc), decode_pc_opnd)) {
            LOG(1, "INFO: app "PFX" has separate decode pc\n", pc);
        }
        dr_insert_clean_call(drcontext, bb, inst,
                             (void *) slow_path, false, 2,
                             OPND_CREATE_INTPTR(pc),
                             decode_pc_opnd);
    }
}

bool
is_in_gencode(byte *pc)
{
#ifdef TOOL_DR_HEAPSTAT
    ASSERT(false, "should not get here");
#endif
    return (pc >= shared_slowpath_region &&
            pc < shared_slowpath_region + SHARED_SLOWPATH_SIZE);
}

static void
shared_slowpath_spill(void *drcontext, instrlist_t *ilist, int type, int slot)
{
    if (type >= SPILL_REG_EAX && type <= SPILL_REG_EBX) {
        PRE(ilist, NULL, INSTR_CREATE_xchg
            (drcontext, spill_slot_opnd(drcontext, slot),
             opnd_create_reg(DR_REG_XAX + (type - SPILL_REG_EAX))));
    } else if (type >= SPILL_REG_EAX_DEAD && type <= SPILL_REG_EBX_DEAD) {
        PRE(ilist, NULL, INSTR_CREATE_mov_st
            (drcontext, spill_slot_opnd(drcontext, slot),
             opnd_create_reg(DR_REG_XAX + (type - SPILL_REG_EAX_DEAD))));
    } /* else param was put straight in tls slot */
}

byte *
generate_shared_slowpath(void *drcontext, instrlist_t *ilist, byte *pc)
{
    int r1, r2, r3, ef;

    /* Create our shared slowpath.  To save space at the "call" site, we
     * restore the spilled registers/eflags here; but to support site-specific
     * selection of which registers to use, we have every possible restore
     * sequence here.  An alternative is to have the C code determine
     * which registers/eflags were spilled and swap the registers with the
     * tls slots.
     * The call site places the single value for both args in reg1
     * (this slowpath call is not supported if the values differ) and
     * the return pc in reg2 and then jmps to the appropriate restore
     * entry point.  After restoring and putting the args into spill
     * slots, we do a clean call, which redirects afterward and so
     * does not return.
     */
    shared_slowpath_entry = pc;
    dr_insert_clean_call(drcontext, ilist, NULL,
                         (void *) slow_path, false, 2,
                         spill_slot_opnd(drcontext, SPILL_SLOT_1),
                         spill_slot_opnd(drcontext, SPILL_SLOT_1));
    PRE(ilist, NULL,
        INSTR_CREATE_jmp_ind(drcontext, spill_slot_opnd
                             (drcontext, whole_bb_spills_enabled() ?
                              /* for whole-bb spills we need two-step return */
                              SPILL_SLOT_5 : SPILL_SLOT_2)));
    pc = instrlist_encode(drcontext, ilist, pc, false);
    instrlist_clear(drcontext, ilist);

    for (r1 = 0; r1 < SPILL_REG_NUM; r1++) {
        for (r2 = 0; r2 < SPILL_REG_NUM; r2++) {
            /* for whole-bb, r3 is not always ecx */
            for (r3 = 0; r3 < (whole_bb_spills_enabled() ?
                               SPILL_REG_NUM : SPILL_REG3_NUM); r3++) {
                /* for whole-bb, eflags is never restored here */
                for (ef = 0; ef < (whole_bb_spills_enabled() ? 1 : SPILL_EFLAGS_NUM);
                     ef++) {
                    instr_t *return_point = NULL;
                    if (whole_bb_spills_enabled()) {
                        return_point = INSTR_CREATE_label(drcontext);
                    } else if (ef != SPILL_EFLAGS_NOSPILL) {
                        if (ef == SPILL_EFLAGS_6_EAX ||
                            ef == SPILL_EFLAGS_6_NOEAX) {
                            PRE(ilist, NULL, INSTR_CREATE_add
                                (drcontext, opnd_create_reg(REG_AL),
                                 OPND_CREATE_INT8(0x7f)));
                        }
                        PRE(ilist, NULL, INSTR_CREATE_sahf(drcontext));
                        if (ef == SPILL_EFLAGS_6_EAX ||
                            ef == SPILL_EFLAGS_5_EAX) {
                            restore_reg(drcontext, ilist, NULL, DR_REG_XAX,
                                        SPILL_SLOT_EFLAGS_EAX);
                        }
                    }
                    if (whole_bb_spills_enabled()) {
                        shared_slowpath_spill(drcontext, ilist, r3, SPILL_SLOT_4);
                    } else if (r3 != SPILL_REG3_NOSPILL) {
                        restore_reg(drcontext, ilist, NULL, SPILL_REG3_REG,
                                       spill_reg3_slot(ef == SPILL_EFLAGS_NOSPILL,
                                                       ef != SPILL_EFLAGS_5_EAX &&
                                                       ef != SPILL_EFLAGS_6_EAX,
                                                       r1 >= SPILL_REG_EAX_DEAD &&
                                                       r1 <= SPILL_REG_EBX_DEAD,
                                                       r2 >= SPILL_REG_EAX_DEAD &&
                                                       r2 <= SPILL_REG_EBX_DEAD));
                    }
                    shared_slowpath_spill(drcontext, ilist, r2, SPILL_SLOT_2);
                    if (options.single_arg_slowpath) {
                        /* for jmp-to-slowpath optimization we don't have 2nd
                         * param, so pass 0 (PR 494769)
                         */
                        if (r1 >= SPILL_REG_EAX && r1 <= SPILL_REG_EBX) {
                            PRE(ilist, NULL, INSTR_CREATE_mov_imm
                                (drcontext,
                                 opnd_create_reg(DR_REG_XAX +
                                                 (r1 - SPILL_REG_EAX)),
                                 OPND_CREATE_INT32(0)));
                        } else if (r1 >= SPILL_REG_EAX_DEAD && r1 <= SPILL_REG_EBX_DEAD) {
                            PRE(ilist, NULL, INSTR_CREATE_mov_imm
                                (drcontext,
                                 opnd_create_reg(DR_REG_XAX +
                                                 (r1 - SPILL_REG_EAX_DEAD)),
                                 OPND_CREATE_INT32(0)));
                        } else {
                            PRE(ilist, NULL, INSTR_CREATE_mov_st
                                (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_1),
                                 OPND_CREATE_INT32(0)));
                        }
                    }
                    shared_slowpath_spill(drcontext, ilist, r1, SPILL_SLOT_1);

                    if (whole_bb_spills_enabled()) {
                        /* we need to put the app's reg values back into the
                         * whole-bb spill slots.  slow_path() doesn't know which
                         * regs are being used, so we do it here via a two-step
                         * return process.  if no regs are spilled we could
                         * skip this: but would need to xfer from slot2 to slot5,
                         * which would require a spill, so we don't bother.
                         */
                        instru_insert_mov_pc(drcontext, ilist, NULL,
                                             spill_slot_opnd(drcontext, SPILL_SLOT_5),
                                             opnd_create_instr(return_point));
                    }
                    PRE(ilist, NULL,
                        INSTR_CREATE_jmp(drcontext,
                                         opnd_create_pc(shared_slowpath_entry)));
                    if (whole_bb_spills_enabled()) {
                        bool tgt_in_reg;
                        reg_id_t regtgt = REG_NULL;
                        PRE(ilist, NULL, return_point);
                        /* instrument_slowpath() re-arranges so the whole-bb
                         * spills are always r1 and r2 (have to be, since using
                         * slots 1 & 2)
                         */
                        if (r2 >= SPILL_REG_EAX && r2 <= SPILL_REG_EBX) {
                            regtgt = DR_REG_XAX + (r2 - SPILL_REG_EAX);
                            PRE(ilist, NULL,
                                INSTR_CREATE_xchg
                                (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_2),
                                 opnd_create_reg(regtgt)));
                            tgt_in_reg = true;
                        } else
                            tgt_in_reg = false;
                        if (r1 >= SPILL_REG_EAX && r1 <= SPILL_REG_EBX) {
                            /* we use xchg instead of mov_st to support
                             * PR 493257 where slowpath put shared shadow addr
                             * into slot1 and we restore it to reg1 here
                             */
                            PRE(ilist, NULL,
                                INSTR_CREATE_xchg
                                (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_1),
                                 opnd_create_reg(DR_REG_XAX +
                                                 (r1 - SPILL_REG_EAX))));
                        } else if (r1 >= SPILL_REG_EAX_DEAD && r1 <= SPILL_REG_EBX_DEAD) {
                            /* for PR 493257 we need to restore shared addr.
                             * should we split up if many bbs don't need this?
                             */
                            PRE(ilist, NULL,
                                INSTR_CREATE_mov_ld
                                (drcontext,
                                 opnd_create_reg(DR_REG_XAX +
                                                 (r1 - SPILL_REG_EAX_DEAD)),
                                 spill_slot_opnd(drcontext, SPILL_SLOT_1)));
                        }
                        if (tgt_in_reg) {
                            PRE(ilist, NULL,
                                INSTR_CREATE_jmp_ind(drcontext, opnd_create_reg(regtgt)));
                        } else {
                            PRE(ilist, NULL,
                                INSTR_CREATE_jmp_ind
                                (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_2)));
                        }
                    }

                    if (whole_bb_spills_enabled())
                        shared_slowpath_entry_global[r1][r2][r3] = pc;
                    else
                        shared_slowpath_entry_local[r1][r2][r3][ef] = pc;
                    pc = instrlist_encode(drcontext, ilist, pc, true);
                    instrlist_clear(drcontext, ilist);
                }
            }
        }
    }
    return pc;
}

void
gencode_init(void)
{
#ifdef TOOL_DR_MEMORY
    instrlist_t *ilist;
    void *drcontext = dr_get_current_drcontext();
    byte *pc;
    IF_DEBUG(bool ok;)
#endif

    gencode_lock = dr_mutex_create();

#ifdef STATISTICS
    next_stats_dump = options.stats_dump_interval;
#endif

#ifdef TOOL_DR_MEMORY
    ilist = instrlist_create(drcontext);

    shared_slowpath_region = (byte *)
        nonheap_alloc(SHARED_SLOWPATH_SIZE,
                      DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC,
                      HEAPSTAT_GENCODE);
    pc = shared_slowpath_region;

    pc = generate_shared_slowpath(drcontext, ilist, pc);
    ASSERT(pc - shared_slowpath_region <= SHARED_SLOWPATH_SIZE,
           "shared esp slowpath too large");

    pc = generate_shared_esp_slowpath(drcontext, ilist, pc);
    ASSERT(pc - shared_slowpath_region <= SHARED_SLOWPATH_SIZE,
           "shared esp slowpath too large");
    pc = generate_shared_esp_fastpath(drcontext, ilist, pc);
    ASSERT(pc - shared_slowpath_region <= SHARED_SLOWPATH_SIZE,
           "shared esp fastpath too large");

    instrlist_clear_and_destroy(drcontext, ilist);

    /* now mark as +rx (non-writable) */
    IF_DEBUG(ok = )
        dr_memory_protect(shared_slowpath_region, SHARED_SLOWPATH_SIZE,
                          DR_MEMPROT_READ|DR_MEMPROT_EXEC);
    ASSERT(ok, "-w failed on shared routines gencode");

    DOLOG(2, {
        byte *end_pc = pc;
        pc = shared_slowpath_region;
        LOG(2, "shared_slowpath region:\n");
        while (pc < end_pc) {
            pc = disassemble_with_info(drcontext, pc, f_global,
                                       true/*show pc*/, true/*show bytes*/);
        }
     });
#endif
}

void
gencode_exit(void)
{
    dr_mutex_destroy(gencode_lock);
#ifdef TOOL_DR_MEMORY
    nonheap_free(shared_slowpath_region, SHARED_SLOWPATH_SIZE,
                 HEAPSTAT_GENCODE);
#endif
}

/* PR 525807: try to handle small malloced stacks */
void
update_stack_swap_threshold(void *drcontext, int new_threshold)
{
    IF_DEBUG(bool ok;)
    if (stack_swap_threshold_fixed) {
        /* If user specifies a threshold we disable our dynamic adjustments */
        return;
    }
    LOG(1, "updating stack swap threshold from "PIFX" to "PIFX"\n",
        options.stack_swap_threshold, new_threshold);
    dr_mutex_lock(gencode_lock);
    if (dr_memory_protect(shared_slowpath_region, SHARED_SLOWPATH_SIZE,
                          DR_MEMPROT_READ|DR_MEMPROT_WRITE|DR_MEMPROT_EXEC)) {
        esp_fastpath_update_swap_threshold(drcontext, new_threshold);
        IF_DEBUG(ok = )
            dr_memory_protect(shared_slowpath_region, SHARED_SLOWPATH_SIZE,
                              DR_MEMPROT_READ|DR_MEMPROT_EXEC);
        ASSERT(ok, "-w failed on shared routines gencode");
        options.stack_swap_threshold = new_threshold;
    } else
        ASSERT(false, "+w failed on shared routines gencode");
    dr_mutex_unlock(gencode_lock);
}

static bool
stringop_equal(uint val1, uint val2, uint opsz)
{
    if (opsz == 1)
        return ((val1 & 0xff) == (val2 & 0xff));
    else if (opsz == 2)
        return ((val1 & 0xffff) == (val2 & 0xffff));
    else if (opsz == 4)
        return (val1 == val2);
    else
        ASSERT(false, "bad stringop opsz internal error");
    return false;
}

static void
get_stringop_range(reg_t base, reg_t count, reg_t eflags, uint opsz,
                   app_pc *start/*OUT*/, app_pc *end/*OUT*/)
{
    /* ecx is a pre-iter check; zf is a post-iter check */
    if (TEST(EFLAGS_DF, eflags)) {
        /* decrement each iter */
        *start = (app_pc) (base - (count-1)*opsz);
        *end = (app_pc) (base + opsz);
    } else {
        *start = (app_pc) (base);
        *end = (app_pc) (base + count*opsz);
    }
}

#ifdef TOOL_DR_MEMORY
static uint
memref_idx(uint flags, uint i)
{
    return (TEST(MEMREF_SINGLE_BYTE, flags) ? 0 :
            (TEST(MEMREF_SINGLE_WORD, flags) ? (i % 2) :
             (TEST(MEMREF_SINGLE_DWORD, flags) ? (i %4 ) : i)));
}

/* handle_mem_ref checks addressability and if necessary checks
 * definedness and adjusts addressability
 * returns true if no errors were found
 */
bool
handle_mem_ref_internal(uint flags, app_loc_t *loc, app_pc addr, size_t sz,
                        dr_mcontext_t *mc,
                        /* these 2 are required for MEMREF_USE_VALUES */
                        int opnum, shadow_combine_t *comb INOUT)
{
    uint i;
    bool allgood = true;
    /* report ranges of errors instead of individual bytes */
    app_pc bad_addr = NULL, bad_end = NULL;
    /* i#580: can't use NULL as sentinel b/c will not report as unaddr */
    bool found_bad_addr = false;
    uint bad_type = SHADOW_DEFINED; /* i.e., no error */
#ifdef STATISTICS
    bool was_special = options.shadowing ?
        shadow_get_special(addr, NULL) : false;
    bool exception = false;
#endif
    umbra_shadow_memory_info_t info;
    app_pc stack_base = NULL;
    size_t stack_size = 0;
    bool handled_push_addr = false;
    bool is_write =
        /* ADDR is assumed to be for writes only (i#517) */
        TESTANY(MEMREF_WRITE | MEMREF_CHECK_ADDRESSABLE, flags) &&
        !TEST(MEMREF_IS_READ, flags);
    if (options.pattern != 0)
        return pattern_handle_mem_ref(loc, addr, sz, mc, is_write);
    umbra_shadow_memory_info_init(&info);
    ASSERT(options.shadowing, "shadowing disabled");
    LOG(3, "memref: %s @"PFX" "PFX" "PIFX" bytes (pre-dword 0x%02x 0x%02x)%s\n",
        TEST(MEMREF_WRITE, flags) ? (TEST(MEMREF_PUSHPOP, flags) ? "push" : "write") :
        (TEST(MEMREF_PUSHPOP, flags) ? "pop" : "read"), loc_to_print(loc), addr, sz,
        shadow_get_dword(&info, addr), shadow_get_dword(&info, addr+4),
        was_special ? " (was special)" : "");
    ASSERT(addr + sz > addr, "address overflow"); /* no overflow */
    /* xref PR 466036: a very large size and a bogus address can take an
     * extremely long time here, as we query the stack bounds for every
     * single byte: now we cache them but will still be slow.
     */
    /* note that gap compiled by cl has an 18MB rep stos (PR 502506) */
    ASSERT(TEST(MEMREF_ABORT_AFTER_UNADDR, flags) ||
           sz < 32*1024*1024, "suspiciously large size");
    ASSERT(!TEST(MEMREF_USE_VALUES, flags) || comb != NULL,
           "internal invalid parameters");
    /* if no uninit, should only write to shadow mem for push/pop */
    ASSERT(options.check_uninitialized ||
           !TEST(MEMREF_WRITE, flags) ||
           TEST(MEMREF_PUSHPOP, flags), "invalid flags");
#ifdef STATISTICS
    if (TEST(MEMREF_WRITE, flags)) {
        if (TEST(MEMREF_PUSHPOP, flags))
            STATS_INC(push_slowpath);
        else
            STATS_INC(write_slowpath);
    } else {
        if (TEST(MEMREF_PUSHPOP, flags))
            STATS_INC(pop_slowpath);
        else
            STATS_INC(read_slowpath);
    }
#endif
    for (i = 0; i < sz; i++) {
        uint shadow = shadow_get_byte(&info, addr + i);
        ASSERT(shadow <= 3, "internal error");
        if (shadow == SHADOW_UNADDRESSABLE) {
            if (TEST(MEMREF_PUSHPOP, flags) && !TEST(MEMREF_WRITE, flags)) {
                ELOG(0, "ERROR: "PFX" popping unaddressable memory: possible Dr. Memory bug\n",
                     loc_to_print(loc));
                if (options.pause_at_unaddressable)
                    wait_for_user("popping unaddressable memory!");
            }
            /* XXX: stack ranges: right now we assume that a push makes memory
             * addressable, but really should check if in stack range
             */
            if (TEST(MEMREF_PUSHPOP, flags) && TEST(MEMREF_WRITE, flags)) {
                ASSERT(!TEST(MEMREF_MOVS, flags), "internal movs error");
                shadow_set_byte(&info, addr + i, TEST(MEMREF_USE_VALUES, flags) ?
                                comb->dst[memref_idx(flags, i)] : SHADOW_DEFINED);
            } else {
                /* We check stack bounds here and cache to avoid
                 * check_undefined_exceptions having to do it over and over (did
                 * show up on pc sampling at one point).  We assume that
                 * mcontext contains the app's esp for all callers (including
                 * our custom clean calls).
                 */
                bool addr_on_stack = false;
                if (stack_base == NULL)
                    stack_size = allocation_size((app_pc)mc->xsp, &stack_base);
                LOG(4, "comparing %08x %08x %08x %08x\n",
                    addr+i, stack_base, stack_base+stack_size, mc->xsp);
                /* We used to also check addr+<xsp but if we mess up our TOS tracking
                 * we end up not reporting any unaddr, as if addr_on_stack is false
                 * then we consider the stack itself an "unknown region" (i#1501).
                 * The risk of going to full stack_size is that our memquery might
                 * see a guard page or something else up there?
                 */
                if (addr+i >= stack_base && addr+i < stack_base+stack_size)
                    addr_on_stack = true;
                if (!check_unaddressable_exceptions(is_write, loc,
                                                    addr + i, sz, addr_on_stack, mc)) {
                    bool new_bad = true;
                    if (found_bad_addr) {
                        if (bad_type != SHADOW_UNADDRESSABLE) {
                            ASSERT(bad_type == SHADOW_UNDEFINED,
                                   "internal report error");
                            report_undefined_read
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 addr, addr + sz, mc);
                        } else if (bad_end < addr + i - 1 ||
                                   (TEST(MEMREF_ABORT_AFTER_UNADDR, flags) &&
                                    bad_end + 1 - bad_addr >= MEMREF_ABORT_AFTER_SIZE)) {
                            report_unaddressable_access
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 is_write, addr, addr + sz, mc);
                            if (TEST(MEMREF_ABORT_AFTER_UNADDR, flags)) {
                                found_bad_addr = false; /* avoid double-report */
                                break;
                            }
                        } else
                            new_bad = false;
                    }
                    if (new_bad) {
                        found_bad_addr = true;
                        bad_type = SHADOW_UNADDRESSABLE;
                        bad_addr = addr + i;
                    } /* else extend current bad */
                    bad_end = addr + i;
                    /* We follow Memcheck's lead and set to defined to avoid too
                     * many subsequent errors, for undefined.  However, for unaddr,
                     * we leave it that way (to avoid our own asserts if it's on
                     * the stack, and to report later but different accesses to it) --
                     * which works out b/c combine_shadows() will propagate it as
                     * though it were defined (i#1476).
                     */
                    if (addr_on_stack) {
                        LOG(2, "unaddressable beyond TOS: leaving unaddressable\n");
                    } else if (bad_type != SHADOW_UNADDRESSABLE) {
                        shadow_set_byte(&info, addr+i, SHADOW_DEFINED);
                    }
                    allgood = false;
                }
#ifdef STATISTICS
                else {
                    exception = true;
                    LOG(3, "unaddr exception for "PFX"\n", addr+i);
                }
#endif
            }
        } else if (!TESTANY(MEMREF_WRITE | MEMREF_CHECK_ADDRESSABLE, flags)) {
            if (shadow == SHADOW_UNDEFINED) {
                /* Must check for exceptions even if not reporting, since
                 * may alter value of shadow */
                if (!check_undefined_exceptions(TEST(MEMREF_PUSHPOP, flags),
                                                is_write, loc, addr + i, sz, &shadow,
                                                mc, &i) &&
                    TEST(MEMREF_CHECK_DEFINEDNESS, flags)) {
                    bool new_bad = true;
                    if (found_bad_addr) {
                        if (bad_type != SHADOW_UNDEFINED) {
                            ASSERT(bad_type == SHADOW_UNADDRESSABLE,
                                   "internal report error");
                            report_unaddressable_access
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 is_write, addr, addr + sz, mc);
                            if (TEST(MEMREF_ABORT_AFTER_UNADDR, flags)) {
                                found_bad_addr = false; /* avoid double-report */
                                break;
                            }
                        } else if (bad_end < addr + i - 1) {
                            report_undefined_read
                                (loc, bad_addr, bad_end + 1 - bad_addr,
                                 addr, addr + sz, mc);
                        } else
                            new_bad = false;
                    }
                    if (new_bad) {
                        found_bad_addr = true;
                        bad_type = SHADOW_UNDEFINED;
                        bad_addr = addr + i;
                    } /* else extend current bad */
                    bad_end = addr + i;
                    allgood = false;
                    /* Set to defined to avoid duplicate errors */
                    if (!options.leave_uninit)
                        shadow_set_byte(&info, addr+i, SHADOW_DEFINED);
                }
#ifdef STATISTICS
                else
                    exception = true;
#endif
            } else if (TEST(MEMREF_CHECK_DEFINEDNESS, flags) &&
                       shadow == SHADOW_DEFINED_BITLEVEL) {
                allgood = false;
                ASSERT(false, "bitlevel NOT YET IMPLEMENTED");
            }
            if (TEST(MEMREF_PUSHPOP, flags)) {
                shadow_set_byte(&info, addr + i, SHADOW_UNADDRESSABLE);
            }
        } else if (!TEST(MEMREF_CHECK_ADDRESSABLE, flags)) {
            uint newval;
            if (TEST(MEMREF_PUSHPOP, flags)) {
                if (!handled_push_addr) {
                    /* only call once: don't want to mark push target as unaddr,
                     * so each byte will trigger here: avoid extra warnings in logs
                     */
                    handled_push_addr =
                        handle_push_addressable(loc, addr + i, addr, sz, mc);
                }
            }
            if (TEST(MEMREF_MOVS, flags)) {
                ASSERT(TEST(MEMREF_USE_VALUES, flags), "internal movs error");
                ASSERT(memref_idx(flags, i) == i, "internal movs error");
                newval = shadow_get_byte(&info, comb->movs_addr + i);
            } else {
                newval = TEST(MEMREF_USE_VALUES, flags) ?
                    comb->dst[memref_idx(flags, i)] : SHADOW_DEFINED;
            }
            if (shadow == SHADOW_DEFINED_BITLEVEL ||
                newval == SHADOW_DEFINED_BITLEVEL) {
                ASSERT(false, "bitlevel NOT YET IMPLEMENTED");
            } else {
                if (shadow == newval) {
                    LOG(4, "store @"PFX" to "PFX" w/ already-same-val "PIFX"\n",
                        loc_to_print(loc), addr+i, newval);
                } else {
                    LOG(4, "store @"PFX" to "PFX" val="PIFX"\n",
                        loc_to_print(loc), addr + i, newval);
                    shadow_set_byte(&info, addr + i, newval);
                }
            }
        }
        if (!TEST(MEMREF_WRITE, flags) && TEST(MEMREF_USE_VALUES, flags)) {
            ASSERT(!TEST(MEMREF_MOVS, flags), "internal movs error");
            /* combine with current value */
            map_src_to_dst(comb, opnum, memref_idx(flags, i), shadow);
        }
        if (MAP_4B_TO_1B) {
            /* only need to process each 4-byte address region once */
            bool is_bad = (bad_end == addr+i);
            if (POINTER_OVERFLOW_ON_ADD(addr, 4))
                break;
            i = ((ptr_uint_t)ALIGN_FORWARD(addr + i + 1, 4) - (ptr_uint_t)addr);
            if (is_bad)
                bad_end = addr + (i > sz ? sz : i) - 1;
        }
    }
#ifdef STATISTICS
    /* check whether should have hit fast path */
    if (sz > 1 && !ALIGNED(addr, sz) && loc->type != APP_LOC_SYSCALL) {
        if (sz == 8 && ALIGNED(addr, 4)) {
            /* we allow 8-aligned-to-4, but if off block end we'll come here */
            if (((ptr_uint_t)addr & 0xffff) == 0xfffc)
                STATS_INC(slowpath_8_at_border);
        } else
            STATS_INC(slowpath_unaligned);
        DOLOG(3, {
            char buf[MAX_SYMBOL_LEN + MAX_FILENAME_LEN*2/*extra for PRINT_ABS_ADDRESS*/];
            size_t sofar = 0;
            umbra_shadow_memory_info_t info;
            umbra_shadow_memory_info_init(&info);
            print_address(buf, BUFFER_SIZE_BYTES(buf), &sofar, loc_to_pc(loc),
                          NULL, true/*for log*/);
            NULL_TERMINATE_BUFFER(buf);
            LOG(1, "unaligned slow @"PFX" %s "PFX" "PIFX
                " bytes (pre 0x%02x 0x%02x)%s %s ",
                loc_to_print(loc),
                TEST(MEMREF_WRITE, flags) ?
                (TEST(MEMREF_PUSHPOP, flags) ? "push" : "write") :
                (TEST(MEMREF_PUSHPOP, flags) ? "pop" : "read"),
                addr, sz, shadow_get_dword(&info, addr),
                shadow_get_dword(&info, addr+4),
                was_special ? " (was special)" : "", buf);
            disassemble_with_info(dr_get_current_drcontext(), loc_to_pc(loc), f_global,
                                  false/*!show pc*/, true/*show bytes*/);
        });
    }
    if (allgood && !was_special && (sz == 1 || ALIGNED(addr, 4)) && !exception &&
        loc->type != APP_LOC_SYSCALL /* not a system call */) {
        LOG(3, "\tin slow path for unknown reason @"PFX" "PFX"\n", loc_to_pc(loc), addr);
        STATS_INC(slow_instead_of_fast);
    }
#endif
    if (found_bad_addr) {
        if (bad_type == SHADOW_UNDEFINED)
            report_undefined_read(loc, bad_addr, bad_end + 1 - bad_addr,
                                  addr, addr + sz, mc);
        else {
            ASSERT(bad_type == SHADOW_UNADDRESSABLE, "internal report error");
            report_unaddressable_access
                (loc, bad_addr, bad_end + 1 - bad_addr, is_write, addr, addr + sz, mc);
        }
    }
    return allgood;
}

/* handle_mem_ref checks addressability and if necessary checks
 * definedness and adjusts addressability
 * returns true if no errors were found
 */
bool
handle_mem_ref(uint flags, app_loc_t *loc, app_pc addr, size_t sz, dr_mcontext_t *mc)
{
    ASSERT(!TEST(MEMREF_USE_VALUES, flags), "using values requires shadow_combine_t");
    return handle_mem_ref_internal(flags, loc, addr, sz, mc, 0, NULL);
}
#endif /* TOOL_DR_MEMORY */

static bool
check_mem_opnd(uint opc, uint flags, app_loc_t *loc, opnd_t opnd, uint sz,
               dr_mcontext_t *mc, int opnum, shadow_combine_t *comb INOUT)
{
    app_pc addr = NULL, end;
#ifdef TOOL_DR_MEMORY
    int i;
#endif

    ASSERT(opc != OP_lea, "lea should not get here");

#ifdef TOOL_DR_MEMORY
    if (options.check_uninitialized) {
        /* First check definedness of base+index regs */
        for (i = 0; i < opnd_num_regs_used(opnd); i++) {
            reg_id_t reg = opnd_get_reg_used(opnd, i);
            if (!reg_is_segment(reg) &&
                !is_shadow_register_defined(get_shadow_register(reg))) {
                /* FIXME: report which bytes within reg via container params? */
                report_undefined_read
                    (loc, (app_pc)(ptr_int_t)reg,
                     opnd_size_in_bytes(reg_get_size(reg)), NULL, NULL, mc);
                /* Set to defined to avoid duplicate errors */
                register_shadow_mark_defined(reg, opnd_size_in_bytes(reg_get_size(reg)));
            }
        }
    }
#endif

    if (opc_is_stringop_loop(opc) &&
        /* with -repstr_to_loop, a decoded repstr is really a non-rep str */
        !options.repstr_to_loop) {
        /* We assume flat segments for es and ds */
        /* FIXME: support addr16!  we're assuming 32-bit edi, esi! */
        ASSERT(reg_get_size(opnd_get_base(opnd)) == OPSZ_4,
               "no support yet for addr16 string operations!");
        if (opc == OP_rep_stos || opc == OP_rep_lods) {
            /* store from al/ax/eax into es:edi; load from es:esi into al/ax/eax */
            get_stringop_range(opc == OP_rep_stos ? mc->xdi : mc->xsi,
                               mc->xcx, mc->xflags, sz, &addr, &end);
            LOG(3, "rep %s "PFX"-"PFX"\n", opc == OP_rep_stos ? "stos" : "lods",
                addr, end);
            flags |= (sz == 1 ? MEMREF_SINGLE_BYTE :
                      (sz == 2 ? MEMREF_SINGLE_WORD : MEMREF_SINGLE_DWORD));
            sz = end - addr;
        } else if (opc == OP_rep_movs) {
            /* move from ds:esi to es:edi */
            LOG(3, "rep movs "PFX" "PFX" "PIFX"\n", mc->xdi, mc->xsi, mc->xcx);
            /* FIXME: if checking definedness of sources, really
             * should do read+write in lockstep, since an earlier
             * write could make a later read ok; for now we punt on
             * that.  We do an overlap check and warn below.
             * If we're propagating and not checking sources, then the
             * overlap is fine: we'll go through the source, ensure addressable
             * but do nothing if undefined, and then go through dest copying
             * from source in lockstep.
             */
            get_stringop_range(mc->xsi, mc->xcx, mc->xflags, sz, &addr, &end);
            if (!TEST(MEMREF_WRITE, flags)) {
                flags &= ~MEMREF_USE_VALUES;
            } else {
                ASSERT(comb != NULL, "assuming have shadow if marked write");
                flags |= MEMREF_MOVS | MEMREF_USE_VALUES;
                comb->movs_addr = addr;
                get_stringop_range(mc->xdi, mc->xcx, mc->xflags, sz, &addr, &end);
                if (TEST(MEMREF_CHECK_DEFINEDNESS, flags) &&
                    end > comb->movs_addr &&
                    addr < comb->movs_addr + (end - addr))
                    ELOG(0, "WARNING: rep movs overlap while checking definedness not fully supported!\n");
            }
            sz = end - addr;
        } else if (opc == OP_rep_scas || opc == OP_repne_scas) {
            /* compare es:edi to al/ax/eax */
            /* we can't just do post-instr check since we want to warn of
             * unaddressable refs prior to their occurrence, so we emulate
             * FIXME: we aren't aggregating errors in adjacent bytes */
            LOG(3, "rep scas @"PFX" "PFX" "PIFX"\n", loc_to_print(loc), mc->xdi, mc->xcx);
            while (mc->xcx != 0) { /* note the != instead of > */
                uint val;
                bool eq;
                handle_mem_ref(flags, loc, (app_pc)mc->xdi, sz, mc);
                /* remember that our notion of unaddressable is not real so we have
                 * to check with the OS to see if this will fault
                 */
                ASSERT(sz <= sizeof(uint), "internal error");
                if (safe_read((void *)mc->xdi, sz, &val)) {
                    /* Assume the real instr will fault here.
                     * FIXME: if the instr gets resumed our check won't re-execute! */
                    break;
                }
                eq = stringop_equal(val, mc->xax, sz);
                mc->xdi += (TEST(EFLAGS_DF, mc->xflags) ? -1 : 1) * sz;
                mc->xcx--;
                if ((opc == OP_rep_scas && !eq) ||
                    (opc == OP_repne_scas && eq))
                    break;
            }
            return true;
        } else if (opc == OP_rep_cmps || opc == OP_repne_cmps) {
            /* compare ds:esi to es:edi */
            /* FIXME: we aren't aggregating errors in adjacent bytes */
            if (reg_overlap(opnd_get_base(opnd), DR_REG_XDI))
                return true; /* we check both when passed esi base */
            LOG(3, "rep cmps @"PFX" "PFX" "PFX" "PIFX"\n",
                loc_to_print(loc), mc->xdi, mc->xsi, mc->xcx);
            while (mc->xcx != 0) { /* note the != instead of > */
                uint val1, val2;
                bool eq;
                handle_mem_ref(flags, loc, (app_pc)mc->xsi, sz, mc);
                handle_mem_ref(flags, loc, (app_pc)mc->xdi, sz, mc);
                /* remember that our notion of unaddressable is not real so we have
                 * to check with the OS to see if this will fault
                 */
                ASSERT(sz <= sizeof(uint), "internal error");
                if (!safe_read((void *)mc->xsi, sz, &val1) ||
                    !safe_read((void *)mc->xdi, sz, &val2)) {
                    /* Assume the real instr will fault here.
                     * FIXME: if the instr gets resumed our check won't re-execute! */
                    break;
                }
                eq = stringop_equal(val1, val2, sz);
                mc->xdi += (TEST(EFLAGS_DF, mc->xflags) ? -1 : 1) * sz;
                mc->xsi += (TEST(EFLAGS_DF, mc->xflags) ? -1 : 1) * sz;
                mc->xcx--;
                if ((opc == OP_rep_cmps && !eq) ||
                    (opc == OP_repne_cmps && eq))
                    break;
            }
            return true;
        } else
            ASSERT(false, "unknown string operation");
    } else {
        addr = opnd_compute_address(opnd, mc);
        if (opc == OP_pop && !TEST(MEMREF_PUSHPOP, flags) &&
            opnd_is_base_disp(opnd) && opnd_uses_reg(opnd, DR_REG_XSP)) {
            /* XXX i#1502: we probably want a solution coming from DR, but for
             * now we fix this inside DrMem.
             */
            if (opnd_get_base(opnd) == DR_REG_XSP)
                addr += sizeof(void*);
            else if (opnd_get_index(opnd) == DR_REG_XSP) {
                addr += opnd_get_scale(opnd)*sizeof(void*);
            } else {
                tls_util_t *pt = PT_GET(dr_get_current_drcontext());
                ELOGPT(0, pt, "ERROR: unhandled pop into base-disp using esp: ");
                opnd_disassemble(dr_get_current_drcontext(), opnd, pt->f);
                ELOGPT(0, pt, "\n");
                ASSERT(false, "unhandled pop into base-disp using esp");
            }
        }
    }
    if (sz == 0)
        return true;
#ifdef TOOL_DR_MEMORY
    return handle_mem_ref_internal(flags, loc, addr, sz, mc, opnum, comb);
#else
    return handle_mem_ref(flags, loc, addr, sz, mc);
#endif
}

bool
check_mem_opnd_nouninit(uint opc, uint flags, app_loc_t *loc, opnd_t opnd, uint sz,
                        dr_mcontext_t *mc)
{
    ASSERT(!TEST(MEMREF_USE_VALUES, flags), "using values requires shadow_combine_t");
    return check_mem_opnd(opc, flags, loc, opnd, sz, mc, 0, NULL);
}

bool
check_register_defined(void *drcontext, reg_id_t reg, app_loc_t *loc, size_t sz,
                       dr_mcontext_t *mc, instr_t *inst)
{
#ifdef TOOL_DR_MEMORY
    uint shadow = (reg == REG_EFLAGS) ? get_shadow_eflags() : get_shadow_register(reg);
    ASSERT(CHECK_UNINITS(), "shouldn't be called");
    if (reg != REG_EFLAGS && sz < opnd_size_in_bytes(reg_get_size(reg))) {
        /* only check sub-reg piece */
        shadow &= (1 << (sz*2)) - 1;
    }
    if (!is_shadow_register_defined(shadow)) {
        if (!check_undefined_reg_exceptions(drcontext, loc, reg, mc, inst)) {
            /* FIXME: report which bytes within reg via container params? */
            report_undefined_read(loc, (app_pc)(ptr_int_t)reg, sz, NULL, NULL, mc);
            if (reg == REG_EFLAGS) {
                /* now reset to avoid complaining on every branch from here on out */
                set_shadow_eflags(SHADOW_DWORD_DEFINED);
            } else {
                /* Set to defined to avoid duplicate errors */
                register_shadow_mark_defined(reg, sz);
            }
        }
    }
    /* check again, since exception may have marked as defined */
    shadow = (reg == REG_EFLAGS) ? get_shadow_eflags() : get_shadow_register(reg);
    return is_shadow_register_defined(shadow);
#else
    return true;
#endif
}

#ifdef TOOL_DR_MEMORY
/***************************************************************************
 * Module bounds
 *
 * i#412: Mark stack frames as defined in rsaenh.dll to avoid false positives
 * during random number generation.
 *
 * We assume that there are no concurrent rsaenh.dll loads, but there may be
 * other threads in the bb event.  To make sure they never observe any wide
 * intervals such as [0, old_end) during unload, we set the base to POINTER_MAX.
 * This means that no matter the order of updates, the reader will always
 * observe the old rsaenh.dll interval or an empty interval.
 *
 * XXX: Between ntdll, msvcr*, msvcp*, and rsaenh, we have a lot of dlls whose
 * bounds we cache.  Refactor this into a modbounds.c module.
 */

#ifdef WINDOWS
static app_pc rsaenh_base = (app_pc) POINTER_MAX;
static app_pc rsaenh_end = NULL;
#endif /* WINDOWS */

void
readwrite_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
#ifdef WINDOWS
    if (_stricmp("rsaenh.dll", dr_module_preferred_name(mod)) == 0) {
        rsaenh_base = mod->start;
        rsaenh_end = mod->end;
    }
#endif /* WINDOWS */
}

void
readwrite_module_unload(void *drcontext, const module_data_t *mod)
{
#ifdef WINDOWS
    if (_stricmp("rsaenh.dll", dr_module_preferred_name(mod)) == 0) {
        rsaenh_base = (app_pc) POINTER_MAX;
        rsaenh_end = NULL;
    }
#endif /* WINDOWS */
}

bool
should_mark_stack_frames_defined(app_pc pc)
{
#ifdef WINDOWS
    return (pc >= rsaenh_base && pc < rsaenh_end);
#else
    return false;
#endif
}

/***************************************************************************
 * Unit tests
 */

#ifdef BUILD_UNIT_TESTS
void
test_punpck(void)
{
    shadow_combine_t comb;
    int i;
    uint sz = opnd_size_in_bytes(reg_get_size(DR_REG_XMM0));
    comb.opsz = sz;

    shadow_combine_init(&comb, NULL, OP_punpcklbw, OPND_SHADOW_ARRAY_LEN);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 0, i, SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 1, i, i < sz/2 ? SHADOW_DEFINED : SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++) {
        EXPECT((i % 2 == 0 && comb.dst[i] == SHADOW_DEFINED) ||
               (i % 2 == 1 && comb.dst[i] == SHADOW_UNDEFINED));
    }

    shadow_combine_init(&comb, NULL, OP_punpcklwd, OPND_SHADOW_ARRAY_LEN);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 0, i, SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 1, i, i < sz/2 ? SHADOW_DEFINED : SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++) {
        EXPECT(((i / 2) % 2 == 0 && comb.dst[i] == SHADOW_DEFINED) ||
               ((i / 2) % 2 == 1 && comb.dst[i] == SHADOW_UNDEFINED));
    }

    shadow_combine_init(&comb, NULL, OP_punpckldq, OPND_SHADOW_ARRAY_LEN);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 0, i, SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 1, i, i < sz/2 ? SHADOW_DEFINED : SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++) {
        EXPECT(((i / 4) % 2 == 0 && comb.dst[i] == SHADOW_DEFINED) ||
               ((i / 4) % 2 == 1 && comb.dst[i] == SHADOW_UNDEFINED));
    }

    shadow_combine_init(&comb, NULL, OP_punpcklqdq, OPND_SHADOW_ARRAY_LEN);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 0, i, SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 1, i, i < sz/2 ? SHADOW_DEFINED : SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++) {
        EXPECT(((i / 8) % 2 == 0 && comb.dst[i] == SHADOW_DEFINED) ||
               ((i / 8) % 2 == 1 && comb.dst[i] == SHADOW_UNDEFINED));
    }

    shadow_combine_init(&comb, NULL, OP_punpckhbw, OPND_SHADOW_ARRAY_LEN);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 0, i, SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 1, i, i >= sz/2 ? SHADOW_DEFINED : SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++) {
        EXPECT((i % 2 == 0 && comb.dst[i] == SHADOW_DEFINED) ||
               (i % 2 == 1 && comb.dst[i] == SHADOW_UNDEFINED));
    }

    shadow_combine_init(&comb, NULL, OP_punpckhwd, OPND_SHADOW_ARRAY_LEN);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 0, i, SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 1, i, i >= sz/2 ? SHADOW_DEFINED : SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++) {
        EXPECT(((i / 2) % 2 == 0 && comb.dst[i] == SHADOW_DEFINED) ||
               ((i / 2) % 2 == 1 && comb.dst[i] == SHADOW_UNDEFINED));
    }

    shadow_combine_init(&comb, NULL, OP_punpckhdq, OPND_SHADOW_ARRAY_LEN);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 0, i, SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 1, i, i >= sz/2 ? SHADOW_DEFINED : SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++) {
        EXPECT(((i / 4) % 2 == 0 && comb.dst[i] == SHADOW_DEFINED) ||
               ((i / 4) % 2 == 1 && comb.dst[i] == SHADOW_UNDEFINED));
    }

    shadow_combine_init(&comb, NULL, OP_punpckhqdq, OPND_SHADOW_ARRAY_LEN);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 0, i, SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 1, i, i >= sz/2 ? SHADOW_DEFINED : SHADOW_UNDEFINED);
    for (i = 0; i < sz; i++) {
        EXPECT(((i / 8) % 2 == 0 && comb.dst[i] == SHADOW_DEFINED) ||
               ((i / 8) % 2 == 1 && comb.dst[i] == SHADOW_UNDEFINED));
    }
}

void
test_pinsr(void *dc)
{
    shadow_combine_t comb;
    int i;
    uint sz = opnd_size_in_bytes(reg_get_size(DR_REG_XMM0));
    instr_t *inst;
    comb.opsz = sz;

    /* XXX: it's hard to test pinsr* as they need real shadow vals */

    inst = INSTR_CREATE_vpinsrw(dc, opnd_create_reg(DR_REG_XMM0),
                                opnd_create_reg(DR_REG_XMM1),
                                opnd_create_reg(DR_REG_EAX),
                                OPND_CREATE_INT8(4));
    shadow_combine_init(&comb, inst, instr_get_opcode(inst), OPND_SHADOW_ARRAY_LEN);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 0, i, SHADOW_UNDEFINED);
    for (i = 0; i < 4; i++)
        map_src_to_dst(&comb, 1, i, SHADOW_DEFINED);
    for (i = 0; i < sz; i++) {
        EXPECT(((i == 8 || i == 9) && comb.dst[i] == SHADOW_DEFINED) ||
               ((i < 8 || i >= 10) && comb.dst[i] == SHADOW_UNDEFINED));
    }
    instr_destroy(dc, inst);

    inst = INSTR_CREATE_vpinsrd(dc, opnd_create_reg(DR_REG_XMM0),
                                opnd_create_reg(DR_REG_XMM1),
                                opnd_create_reg(DR_REG_EAX),
                                OPND_CREATE_INT8(2));
    shadow_combine_init(&comb, inst, instr_get_opcode(inst), OPND_SHADOW_ARRAY_LEN);
    for (i = 0; i < sz; i++)
        map_src_to_dst(&comb, 0, i, SHADOW_UNDEFINED);
    for (i = 0; i < 4; i++)
        map_src_to_dst(&comb, 1, i, SHADOW_DEFINED);
    for (i = 0; i < sz; i++) {
        EXPECT((i >= 8 && i < 12 && comb.dst[i] == SHADOW_DEFINED) ||
               ((i < 8 || i >= 12) && comb.dst[i] == SHADOW_UNDEFINED));
    }
    instr_destroy(dc, inst);
}

int
main(int argc, char *argv[])
{
    void *drcontext = dr_standalone_init();

    test_punpck();

    test_pinsr(drcontext);

    /* add more tests here */

    dr_printf("success\n");
    return 0;
}
#endif

#endif /* TOOL_DR_MEMORY */
