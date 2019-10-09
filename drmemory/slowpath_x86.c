/* **********************************************************
 * Copyright (c) 2010-2019 Google, Inc.  All rights reserved.
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
 * slowpath_x86.c: Dr. Memory memory read/write slowpath handling for x86
 */

#include "dr_api.h"
#include "drutil.h"
#include "drmemory.h"
#include "instru.h"
#include "slowpath.h"
#include "slowpath_arch.h"
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

#ifdef STATISTICS
uint movs4_src_unaligned;
uint movs4_dst_unaligned;
uint movs4_src_undef;
uint movs4_med_fast;
uint cmps1_src_undef;
uint cmps1_med_fast;
#endif

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
instr_is_jcc(instr_t *inst)
{
    uint opc = instr_get_opcode(inst);
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
            register_shadow_set_ptrsz(DR_REG_XCX, SHADOW_PTRSZ_DEFINED);
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
bool
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

bool
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

#endif /* TOOL_DR_MEMORY */

/* Opcodes that write to subreg at locations not fixed in the low part of the reg */
bool
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

#ifdef TOOL_DR_MEMORY

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
void
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
        accum_shadow(&comb->dst[(opsz - 1) - src_bytenum], shadow);
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
bool
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

/* Returns whether to skip the general integration */
bool
integrate_register_shadow_arch(shadow_combine_t *comb INOUT, int opnum,
                               reg_id_t reg, uint shadow, bool pushpop)
{
    uint opc = comb->opcode;
    /* PR 426162: ignore stack register source -- see comment in slowpath.c */
    if ((opc == OP_leave || opc == OP_enter) && reg_overlap(reg, DR_REG_XBP))
        return true;
    return false;
}

/* Returns whether to skip the general assignment code */
bool
assign_register_shadow_arch(shadow_combine_t *comb INOUT, int opnum, opnd_t opnd,
                            reg_id_t reg, bool pushpop, uint *shift INOUT)
{
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
            return true;
    } else if (/* pushpop + xsp handled in shared code */
               (opc == OP_leave || opc == OP_enter) && reg_overlap(reg, DR_REG_XBP)) {
        return true;
    } else {
        /* We need special handling for multi-dest opcodes */
        switch (opc) {
        case OP_popa:
            *shift = (reg_to_pointer_sized(reg) - DR_REG_XAX);
            break;
        case OP_xchg:
        case OP_xadd:
            *shift = opnum;
            break;
        case OP_cmpxchg8b:
            /* opnds: cmpxchg8b mem8 %eax %edx %ecx %ebx -> mem8 %eax %edx
             * operation: if (edx:eax == mem8) mem8 = ecx:ebx; else edx:eax = mem8
             * we just combine all 3 sources and write the result to both dests.
             */
            switch (opnum) {
            case 0: *shift = 0; break;
            case 1: *shift = 0; break;
            case 2: *shift = 1; break;
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
# ifdef X64
    if (opnd_get_size(opnd) == OPSZ_4 && reg_is_gpr(reg)) {
        /* Writing to the 32-bit reg clears the top 32 bits. */
        register_shadow_set_high_dword(reg, SHADOW_DWORD_DEFINED);
    }
# endif
    return false;
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
    if (opc == OP_nop_modrm) /* i#1870 */
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
    if (opc == OP_nop_modrm) /* i#1870 */
        return 0;
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

/* Returns whether it handled the instruction */
bool
medium_path_arch(app_pc decode_pc, app_loc_t *loc, dr_mcontext_t *mc)
{
    if (*decode_pc == MOVS_4_OPCODE ||
        /* we now pass original pc from -repstr_to_loop including rep.
         * ignore other prefixes here: data16 most likely and then not movs4.
         */
        (options.repstr_to_loop && *decode_pc == REP_PREFIX &&
         *(decode_pc + 1) == MOVS_4_OPCODE)) {
        /* see comments for this routine: common enough it's worth optimizing */
        medium_path_movs4(loc, mc);
        /* no sharing with string instrs so no need to call
         * slow_path_xl8_sharing
         */
        return true;
    } else if (*decode_pc == CMPS_1_OPCODE ||
               (options.repstr_to_loop &&
                (*decode_pc == REP_PREFIX || *decode_pc == REPNE_PREFIX) &&
                *(decode_pc + 1) == CMPS_1_OPCODE)) {
        medium_path_cmps1(loc, mc);
        return true;
    }
    return false;
}
#endif /* TOOL_DR_MEMORY */

void
slowpath_update_app_loc_arch(uint opc, app_pc decode_pc, app_loc_t *loc)
{
    if (options.repstr_to_loop && opc == OP_loop) {
        /* to point at an OP_loop but use app's repstr pc we use this table (i#391) */
        byte *rep_pc;
        dr_mutex_lock(stringop_lock);
        rep_pc = (byte *) hashtable_lookup(&stringop_us2app_table, decode_pc);
        dr_mutex_unlock(stringop_lock);
        if (rep_pc != NULL) {
            ASSERT(dr_memory_is_dr_internal(decode_pc), "must be drmem heap");
            /* use this as app pc if we report an error */
            pc_to_loc(loc, rep_pc);
        }
    }
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

bool
check_mem_opnd_arch(uint opc, uint flags, app_loc_t *loc, opnd_t opnd, uint sz,
                    dr_mcontext_t *mc, int opnum, shadow_combine_t *comb INOUT)
{
    app_pc addr = NULL, end;
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
    }
    return false;
}

#ifdef TOOL_DR_MEMORY
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

void
slowpath_unit_tests_arch(void *drcontext)
{
    test_punpck();

    test_pinsr(drcontext);

    /* add more tests here */
}
#endif

#endif /* TOOL_DR_MEMORY */
