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
 * fastpath.c: Dr. Memory shadow instrumentation fastpath
 */

#include "dr_api.h"
#include "drmemory.h"
#include "readwrite.h"
#include "fastpath.h"
#include "shadow.h"

#ifdef LINUX
# include <signal.h> /* for SIGSEGV */
#else
# include <stddef.h> /* for offsetof */
#endif

/* PR 493257: share shadow translation across multiple instrs.
 * Since we can't share across 64K boundaries we exit to slowpath.
 * If this happens too often, we abandon sharing.
 */
#define XL8_SHARING_THRESHOLD 5000

/* Shadow state for 4GB address space (hiding the real types) */
extern uint **shadow_table[];
#ifdef TOOL_DR_MEMORY
extern const byte shadow_dword_is_addr_not_bit[256];
extern const byte shadow_2_to_dword[256];
extern const byte shadow_4_to_dword[256];
extern const byte shadow_byte_defined[4][256];
extern const byte shadow_word_defined[4][256];
extern const byte shadow_byte_addr_not_bit[4][256];
extern const byte shadow_word_addr_not_bit[4][256];
#endif

/* Handles segment-based memory references.
 * Assumes that SPILL_SLOT_5 is available if necessary.
 */
static void
insert_lea(void *drcontext, instrlist_t *bb, instr_t *inst,
           opnd_t opnd, reg_id_t dst)
{
    if (opnd_is_far_base_disp(opnd)) {
        if (opnd_get_segment(opnd) == SEG_ES ||
            opnd_get_segment(opnd) == SEG_DS) {
            /* string operation: we assume flat segments */
            opnd_set_size(&opnd, OPSZ_lea);
            PRE(bb, inst,
                INSTR_CREATE_lea(drcontext, opnd_create_reg(dst), opnd));
        } else if (opnd_get_segment(opnd) == SEG_FS
                   IF_LINUX(||opnd_get_segment(opnd) == SEG_GS)) {
            /* convert to linear address. */
#if THREAD_PRIVATE
            /* for thread private we can statically determine the fs base */
            uint fs_addr;
            __asm {
                mov eax, fs:[0x18]
                mov fs_addr, eax
            }
            opnd = opnd_create_base_disp(opnd_get_base(opnd), opnd_get_index(opnd),
                                         opnd_get_scale(opnd),
                                         opnd_get_disp(opnd) + fs_addr, OPSZ_lea);
#else
            /* we could determine for each thread in its init and store */
            reg_id_t other_reg = REG_NULL;
            reg_id_t tmp_reg = dst;
            int scale = 0;
            /* for now we bail if we have a conflict w/ our dst reg.
             * should never happen in practice: will always be simple disp.
             */
            if (opnd_get_base(opnd) != REG_NULL) {
                other_reg = opnd_get_base(opnd);
                scale = 1;
                ASSERT(opnd_get_index(opnd) == REG_NULL,
                       "can't handle fs/gs ref w/ base and index");
            } else if (opnd_get_index(opnd) != REG_NULL) {
                other_reg = opnd_get_index(opnd);
                scale = opnd_get_scale(opnd);
            }                
            if (other_reg == dst) {
                /* This does happen on Linux:
                 *   0x0022cad0 <__printf_fp+8624>:  mov    %eax,%gs:(%edx)
                 * We assume it's rare and so rather than have callers pass us a
                 * scratch reg (which would get complicated), we do a locally
                 * transparent save+restore.  We could try to optimize
                 * if caller lets us know a faster spill slot is available.
                 */
                tmp_reg = (dst == REG_XAX ? REG_XCX : REG_XAX);
                spill_reg(drcontext, bb, inst, tmp_reg, SPILL_SLOT_5);
            }
# ifdef WINDOWS
            /* dynamically get teb->self */
            PRE(bb, inst,
                INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(tmp_reg),
                                    opnd_create_far_base_disp(SEG_FS, REG_NULL, REG_NULL,
                                                              0, offsetof(TEB, Self),
                                                              OPSZ_PTR)));
            PRE(bb, inst,
                INSTR_CREATE_lea(drcontext, opnd_create_reg(dst),
                                 opnd_create_base_disp(tmp_reg, other_reg, scale,
                                                       opnd_get_disp(opnd), OPSZ_lea)));
# else
            /* read the base we stored in a tls slot */
            PRE(bb, inst,
                INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(tmp_reg),
                                    opnd_create_seg_base_slot(opnd_get_segment(opnd),
                                                              OPSZ_PTR)));
            PRE(bb, inst,
                INSTR_CREATE_lea(drcontext, opnd_create_reg(dst),
                                 opnd_create_base_disp(tmp_reg, other_reg, scale,
                                                       opnd_get_disp(opnd), OPSZ_lea)));
# endif
            if (tmp_reg != dst) {
                restore_reg(drcontext, bb, inst, tmp_reg, SPILL_SLOT_5);
            }
#endif
        } else {
            ASSERT(false, "unsupported segment reference");
        }
    } else {
        opnd_set_size(&opnd, OPSZ_lea);
        PRE(bb, inst,
            INSTR_CREATE_lea(drcontext, opnd_create_reg(dst), opnd));
    }
}

#ifdef TOOL_DR_MEMORY
static void
insert_add_to_reg(void *drcontext, instrlist_t *bb, instr_t *inst,
                  reg_id_t reg, int diff)
{
    if (diff == 1 || diff == 2) { /* inc is 1-byte vs 3-byte lea */
        PRE(bb, inst, INSTR_CREATE_inc(drcontext, opnd_create_reg(reg)));
        if (diff == 2)
            PRE(bb, inst, INSTR_CREATE_inc(drcontext, opnd_create_reg(reg)));
    } else if (diff == -1 || diff == -2) { /* dec is 1-byte vs 3-byte lea */
        PRE(bb, inst, INSTR_CREATE_dec(drcontext, opnd_create_reg(reg)));
        if (diff == -2)
            PRE(bb, inst, INSTR_CREATE_dec(drcontext, opnd_create_reg(reg)));
    } else if (diff != 0) {
        /* could use an add since already clobbering flags, but no better (3 bytes
         * still, and lea executes faster IIRC)
         */
        PRE(bb, inst,
            INSTR_CREATE_lea(drcontext, opnd_create_reg(reg), 
                             OPND_CREATE_MEM_lea(reg, REG_NULL, 0, diff)));
    }
}
#endif /* TOOL_DR_MEMORY */

/* Returns one of these:
 *   EFLAGS_WRITE_6   = writes all 6 flags before reading any
 *   EFLAGS_WRITE_OF  = writes OF before reading it
 *   EFLAGS_READ_6    = reads some of 6 before writing
 *   0                = no information yet
 * Optionally returns the instr that does the reading/writing, if
 * the return value is EFLAGS_WRITE_6 or EFLAGS_READ_6.
 */
static uint
get_aflags_liveness(instr_t *inst)
{
    uint res = 0;
    uint merge;
    while (inst != NULL) {
        merge = instr_get_arith_flags(inst);
        if (TESTANY(EFLAGS_READ_6, merge)) {
            uint w2r = EFLAGS_WRITE_TO_READ(res);
            if (!TESTALL((merge & EFLAGS_READ_6), w2r))
                return EFLAGS_READ_6; /* reads a flag before it's written */
        }
        if (TESTANY(EFLAGS_WRITE_6, merge)) {
            res |= (merge & EFLAGS_WRITE_6);
            if (TESTALL(EFLAGS_WRITE_6, res) && !TESTANY(EFLAGS_READ_6, res))
                return EFLAGS_WRITE_6; /* all written before read */
        }
        inst = instr_get_next(inst);
    }
    if (TEST(EFLAGS_WRITE_OF, res) && !TEST(EFLAGS_READ_OF, res))
        return EFLAGS_WRITE_OF;
    return res;
}

/* Returns a LIVE_ constant for each register */
static void
get_reg_liveness(instr_t *inst, int live[NUM_LIVENESS_REGS])
{
    int r;
    for (r = 0; r < NUM_LIVENESS_REGS; r++)
        live[r] = LIVE_UNKNOWN;
    while (inst != NULL) {
        if (instr_is_cti(inst))
            return;
        for (r = 0; r < NUM_LIVENESS_REGS; r++) {
            reg_id_t reg = r + REG_START_32;
            if (live[r] == LIVE_UNKNOWN) {
                if (instr_reads_from_reg(inst, reg)) {
                    live[r] = LIVE_LIVE;
                }
                /* make sure we don't consider writes to sub-regs */
                else if (instr_writes_to_exact_reg(inst, reg)) {
                    live[r] = LIVE_DEAD;
                }
            }
        }
        inst = instr_get_next(inst);
    }
}

void
initialize_fastpath_info(fastpath_info_t *mi, bb_info_t *bi)
{
    int i;
    memset(mi, 0, sizeof(*mi));
    mi->bb = bi;
    for (i=0; i<MAX_FASTPATH_SRCS; i++) {
        mi->src[i] = opnd_create_null();
        mi->opnum[i] = -1;
    }
    for (i=0; i<MAX_FASTPATH_DSTS; i++) {
        mi->dst[i] = opnd_create_null();
    }
    /* mi->opsz and mi->offs are not set here */
}

#ifdef TOOL_DR_MEMORY
static bool
instr_needs_slowpath(instr_t *inst)
{
    int opc = instr_get_opcode(inst);
    if (opc_is_stringop(opc))
        return true;
    /* Note that for and/test/or (instr_needs_all_srcs_and_vals(inst)) and
     * for shift routines we have the fastpath check for definedness and bail
     * out to the slowpath on any undefined operands, avoiding the need for
     * fastpath work in the common case.
     */
    /* FIXME: share all of these w/ the checks for them in slow path routines */
    switch (opc) {
    case OP_sysenter:
    case OP_popa:
    case OP_xchg:
    case OP_xadd:
    case OP_cmpxchg8b:
    case OP_bswap:
        return true;
    default:
        return false;
    }
}

static bool
addr_reg_ok_for_fastpath(reg_id_t reg)
{
    return (reg == REG_NULL ||
            (reg_is_gpr(reg) && reg_is_32bit(reg)));
}

static bool
reg_ignore_for_fastpath(opnd_t reg)
{
    reg_id_t r = opnd_get_reg(reg);
    return (!reg_is_gpr(r) /* always defined if non-gpr */);
}

static bool
reg_ok_for_fastpath(opnd_t reg)
{
    reg_id_t r = opnd_get_reg(reg);
    return (reg_ignore_for_fastpath(reg) ||
            (reg_is_32bit(r) || reg_is_16bit(r) || reg_is_8bit(r)));
}

/* Up to caller to check rest of reqts for 8-byte */
static bool
memop_ok_for_fastpath(opnd_t memop, bool allow8)
{
    return ((opnd_get_size(memop) == OPSZ_4 ||
             opnd_get_size(memop) == OPSZ_2 ||
             opnd_get_size(memop) == OPSZ_1 ||
             (opnd_get_size(memop) == OPSZ_8 && allow8) ||
             opnd_get_size(memop) == OPSZ_lea) &&
            (!opnd_is_base_disp(memop) ||
             (addr_reg_ok_for_fastpath(opnd_get_base(memop)) &&
              addr_reg_ok_for_fastpath(opnd_get_index(memop)))));
}

static bool
prepend_fastpath_opnd(opnd_t op, opnd_t *array, int len)
{
    int i;
    if (!opnd_is_null(array[len-1]))
        return false;
    for (i=len-1; i>0; i--)
        array[i] = array[i-1];
    array[0] = op;
    return true;
}

static int
append_fastpath_opnd(opnd_t op, opnd_t *array, int len)
{
    int i;
    for (i=0; i<len; i++) {
        if (opnd_is_null(array[i])) {
            array[i] = op;
            return i;
        }
    }
    return -1;
}

/* Allows 8-byte opnds: up to caller to check other reqts */
static bool
opnd_ok_for_fastpath(opnd_t op, int opnum, bool dst, fastpath_info_t *mi)
{
    if (opnd_is_immed_int(op) || opnd_is_pc(op)) {
        return true;
    } else if (opnd_is_reg(op)) {
        if (!reg_ok_for_fastpath(op))
            return false;
        if (!reg_ignore_for_fastpath(op)) {
            int num = append_fastpath_opnd(op, dst ? mi->dst : mi->src,
                                           dst ? MAX_FASTPATH_DSTS : MAX_FASTPATH_SRCS);
            if (num == -1)
                return false;
            if (!dst)
                mi->opnum[num] = opnum;
        }
        return true;
    } else if (opnd_is_memory_reference(op)) {
        if (!memop_ok_for_fastpath(op, true/*8-byte ok*/))
            return false;
        /* there can only be one memory ref, except for mem2mem, which is
         * special-cased elsewhere, and alu where dst==src.
         * memory opnds are always prepended.
         */
        if ((opnd_is_memory_reference(mi->dst[0]) && (dst || !opnd_same(mi->dst[0], op))) ||
            (opnd_is_memory_reference(mi->src[0]) && (!dst || !opnd_same(mi->src[0], op))))
            return false;
        if (!prepend_fastpath_opnd(op, dst ? mi->dst : mi->src,
                                  dst ? MAX_FASTPATH_DSTS : MAX_FASTPATH_SRCS))
            return false;
        /* alu store op or mem2mem are not considered loads */
        if (dst) {
            mi->store = true;
            mi->load = false;
        } else if (!mi->store)
            mi->load = true;
        return true;
    }
    return false;
}

bool
instr_ok_for_instrument_fastpath(instr_t *inst, fastpath_info_t *mi, bb_info_t *bi)
{
    uint opc = instr_get_opcode(inst);

    /* initialize regardless */
    initialize_fastpath_info(mi, bi);

    if (!options.fastpath)
        return false;
    if (instr_needs_slowpath(inst))
        return false;

    if (opc == OP_push || opc == OP_push_imm || opc == OP_call || opc == OP_call_ind) {
        /* all have dst0=esp, dst1=(esp), src0=imm/reg/pc/mem, src1=esp */
        if (opnd_get_reg(instr_get_dst(inst, 0)) != REG_ESP ||
            opnd_get_size(instr_get_dst(inst, 1)) != OPSZ_4)
            return false;
        if (opc == OP_push_imm || opc == OP_call) {
            mi->dst[0] = instr_get_dst(inst, 1);
            if (!memop_ok_for_fastpath(mi->dst[0], false/*no 8-byte*/))
                return false;
            mi->store = true;
            mi->pushpop = true;
            return true;
        } else if (opc == OP_push || opc == OP_call_ind) {
            /* we treat call* as a push except call* must check its srcs for
             * definedness and shouldn't propagate, though when defined it's
             * ok to propagate (instead of propagating the immed==always defined)
             */
            mi->dst[0] = instr_get_dst(inst, 1);
            if (!memop_ok_for_fastpath(mi->dst[0], false/*no 8-byte*/))
                return false;
            mi->src[0] = instr_get_src(inst, 0);
            mi->store = true;
            mi->pushpop = true;
            if (opnd_is_reg(mi->src[0])) {
                if (reg_ignore_for_fastpath(mi->src[0])) {
                    mi->src[0] = opnd_create_null();
                    return true;
                } else if (reg_ok_for_fastpath(mi->src[0])) {
                    mi->opnum[0] = 0;
                    return true;
                } else
                    return false;
            } else if (opnd_is_memory_reference(mi->src[0])) {
                if (memop_ok_for_fastpath(mi->src[0], false/*no 8-byte*/)) {
                    mi->mem2mem = true;
                    return true;
                } else
                    return false;
            }
        }
    } else if (opc == OP_pushf) {
        if (opnd_get_reg(instr_get_dst(inst, 0)) != REG_ESP ||
            opnd_get_size(instr_get_dst(inst, 1)) != OPSZ_4)
            return false;
        mi->dst[0] = instr_get_dst(inst, 1);
        if (!memop_ok_for_fastpath(mi->dst[0], false/*no 8-byte*/))
            return false;
        mi->store = true;
        mi->pushpop = true;
        return true;
    } else if (opc == OP_pop) {
        if (opnd_get_reg(instr_get_dst(inst, 1)) != REG_ESP ||
            opnd_get_size(instr_get_src(inst, 1)) != OPSZ_4)
            return false;
        if (opnd_is_reg(instr_get_dst(inst, 0))) {
            if (reg_ok_for_fastpath(instr_get_dst(inst, 0))) {
                mi->src[0] = instr_get_src(inst, 1);
                if (!memop_ok_for_fastpath(mi->src[0], false/*no 8-byte*/))
                    return false;
                if (!reg_ignore_for_fastpath(instr_get_dst(inst, 0)))
                    mi->dst[0] = instr_get_dst(inst, 0);
                mi->load = true;
                mi->pushpop = true;
                return true;
            }
        }
    } else if (opc == OP_popf) {
        if (opnd_get_reg(instr_get_dst(inst, 0)) != REG_ESP ||
            opnd_get_size(instr_get_src(inst, 1)) != OPSZ_4)
            return false;
        mi->src[0] = instr_get_src(inst, 1);
        if (!memop_ok_for_fastpath(mi->src[0], false/*no 8-byte*/))
            return false;
        mi->load = true;
        mi->pushpop = true;
        return true;
    } else if (opc == OP_leave) {
        /* both a reg-reg move and a pop */
        if (opnd_get_reg(instr_get_dst(inst, 0)) != REG_ESP ||
            opnd_get_reg(instr_get_dst(inst, 1)) != REG_EBP ||
            opnd_get_size(instr_get_src(inst, 2)) != OPSZ_4)
            return false;
        /* pop into ebp */
        mi->src[0] = instr_get_src(inst, 2); /* stack memref */
        if (!memop_ok_for_fastpath(mi->src[0], false/*no 8-byte*/))
            return false;
        mi->dst[0] = instr_get_dst(inst, 1); /* ebp */
        if (!reg_ok_for_fastpath(mi->dst[0]))
            return false;
        /* for the other dst, ebp->esp, we rely on check_definedness of the src (ebp)
         * and of the dst (esp) (for dst the check is via add_addressing_register_checks()
         */
        mi->src[1] = instr_get_src(inst, 0); /* ebp */
        if (!reg_ok_for_fastpath(mi->src[1]))
            return false;
        mi->load = true;
        mi->pushpop = true;
        return true;
    } else if (opc == OP_ret) {
        /* OP_ret w/ immed is treated as single pop here: esp
         * adjustment is handled separately (it doesn't read those bytes)
         */
        if (opnd_get_reg(instr_get_dst(inst, 0)) != REG_ESP ||
            opnd_get_size(instr_get_src(inst, instr_num_srcs(inst)-1)) != OPSZ_4)
            return false;
        mi->src[0] = instr_get_src(inst, instr_num_srcs(inst)-1);
        ASSERT(opnd_is_memory_reference(mi->src[0]), "internal opnd num error");
        if (!memop_ok_for_fastpath(mi->src[0], false/*no 8-byte*/))
            return false;
        mi->load = true;
        mi->pushpop = true;
        return true;
    } else if (opc == OP_lea) {
        /* For lea we treat base+index as sources to be
         * propagated, instead of as addressing registers
         */
        opnd_t memop = instr_get_src(inst, 0);
        if (opnd_get_base(memop) != REG_NULL)
            mi->src[0] = opnd_create_reg(opnd_get_base(memop));
        if (opnd_get_index(memop) != REG_NULL) {
            if (opnd_get_base(memop) == REG_NULL)
                mi->src[0] = opnd_create_reg(opnd_get_index(memop));
            else
                mi->src[1] = opnd_create_reg(opnd_get_index(memop));
        }
        mi->dst[0] = instr_get_dst(inst, 0);
        ASSERT(reg_ok_for_fastpath(mi->dst[0]) && !reg_ignore_for_fastpath(mi->dst[0]),
               "lea handling error");
        return true;
    } else {
        /* mi->src[] and mi->dst[] are set in opnd_ok_for_fastpath() */

        if (instr_num_dsts(inst) > 2)
            return false;
        if (instr_num_srcs(inst) > 3)
            return false;

        if (instr_num_dsts(inst) > 0) {
            if (!opnd_ok_for_fastpath(instr_get_dst(inst, 0), 0, true, mi))
                return false;
            if (instr_num_dsts(inst) > 1) {
                if (instr_num_dsts(inst) == 2 && opc_2nd_dst_is_extension(opc)) {
                    if (!opnd_ok_for_fastpath(instr_get_dst(inst, 1), 1, true, mi))
                        return false;
                } else
                    return false;
            }
        }
        if (instr_num_srcs(inst) > 0) {
            if (!opnd_ok_for_fastpath(instr_get_src(inst, 0), 0, false, mi))
                return false;
            if (instr_num_srcs(inst) > 1) {
                if (!opnd_ok_for_fastpath(instr_get_src(inst, 1), 1, false, mi))
                    return false;
                if (instr_num_srcs(inst) > 2) {
                    if (!opnd_ok_for_fastpath(instr_get_src(inst, 2), 2, false, mi))
                        return false;
                }
            }
        }

        /* We only allow 8-byte memop for floats w/ no other opnds (=> no prop) */
        if (mi->load && opnd_get_size(mi->src[0]) == OPSZ_8 &&
            (!opnd_is_null(mi->src[1]) || !opnd_is_null(mi->dst[0])))
            return false;
        if (mi->store && opnd_get_size(mi->dst[0]) == OPSZ_8 &&
            (!opnd_is_null(mi->dst[1]) || !opnd_is_null(mi->src[0])))
            return false;

        return true;
    }
    return false;
}
#endif /* TOOL_DR_MEMORY */

/* Does additional adjusting and checking beyond instr_ok_for_instrument_fastpath(),
 * which must be called first.
 * Fills in these fields of fastpath_info_t:
 *  - src_reg
 *  - dst_reg
 *  - memop
 *  - src_opsz
 *  - check_definedness, but only for movzx/movsx
 * Returns whether still ok for fastpath.
 */
static bool
adjust_opnds_for_fastpath(instr_t *inst, fastpath_info_t *mi)
{
    int opc = instr_get_opcode(inst);
    ASSERT(mi != NULL, "invalid args");
    if (opnd_is_reg(mi->src[0]))
        mi->src_reg = opnd_get_reg(mi->src[0]);
    if (opnd_is_reg(mi->dst[0]))
        mi->dst_reg = opnd_get_reg(mi->dst[0]);
    ASSERT(mi->dst_reg == REG_NULL || reg_is_gpr(mi->dst_reg), "reg fastpath error");
    ASSERT(mi->src_reg == REG_NULL || reg_is_gpr(mi->src_reg), "reg fastpath error");
    ASSERT(!mi->pushpop || mi->load || mi->store, "internal error");

    /* adjust for precise memory operand */
    if (mi->load || mi->store) {
        mi->memop = adjust_memop(inst, mi->load ? mi->src[0] : mi->dst[0],
                                 mi->store, &mi->memsz, &mi->pushpop_stackop);
        /* Since we don't allow push mem or pop mem these should be equal: */
#ifdef TOOL_DR_MEMORY
        ASSERT((!mi->pushpop && !mi->pushpop_stackop) ||
               (mi->pushpop && mi->pushpop_stackop), "internal error");
#else
        mi->pushpop = mi->pushpop_stackop;
#endif
        mi->opsz = mi->memsz;
#ifdef TOOL_DR_MEMORY
        /* stack ops are the ones that vary and might reach 8+ */
        if (!((mi->opsz == 8 && !mi->pushpop) || mi->opsz == 4 ||
              mi->opsz == 2 || mi->opsz == 1)) {
            return false; /* needs slowpath */
        }
        if (mi->store)
            mi->dst[0] = mi->memop;
        else {
            if (mi->opsz < 4 && (opc == OP_movzx || opc == OP_movsx)) {
                /* see below: for smaller srcs we want opsz to be dst size */
                ASSERT(mi->dst_reg != REG_NULL, "movzx error");
                mi->opsz = opnd_size_in_bytes(reg_get_size(mi->dst_reg));
            }
            mi->src[0] = mi->memop;
        }
        if (mi->opsz >= 4)
            mi->offs = opnd_create_immed_int(0, OPSZ_1);
        else {
            /* else, mi->offs is dynamically varying; properly defined later */
            mi->offs = opnd_create_null();
        }
#else
        if (mi->store)
            mi->dst[0] = mi->memop;
        else
            mi->src[0] = mi->memop;
        mi->offs = opnd_create_immed_int(0, OPSZ_1);
#endif
    } else {
        if (mi->dst_reg != REG_NULL) {
            mi->opsz = opnd_size_in_bytes(reg_get_size(mi->dst_reg));
            mi->offs = opnd_create_immed_int(reg_offs_in_dword(mi->dst_reg), OPSZ_1);
        } else if (mi->src_reg != REG_NULL) {
            mi->opsz = opnd_size_in_bytes(reg_get_size(mi->src_reg));
            mi->offs = opnd_create_immed_int(reg_offs_in_dword(mi->src_reg), OPSZ_1);
        } else { /* jcc or other instr w/ no reg/mem/immed args */
            mi->opsz = 0;
            mi->offs = opnd_create_null();
        }
    }
    /* Having only the input byte defined and the rest of the dword
     * undefined is common enough (esp on linux) that we must fastpath
     * it and thus need the offset, but only for 1-byte src (2-byte
     * has complexities if the 2 shadows don't match).
     */
    if (opc == OP_movzx || opc == OP_movsx) {
        mi->src_opsz = opnd_size_in_bytes(opnd_get_size(mi->src[0]));
        if (mi->opsz == 4 && (mi->src_opsz == 1 || mi->src_opsz == 2))
            mi->need_offs = true;
        else {
            ASSERT(mi->opsz <= 4, "no support for >4 movzx/movsz");
            /* for movzx 1 to 2 we check_definedness and then do
             * sub-dword copy but as though src is 2 bytes.
             */
            mi->check_definedness = true;
            /* pass dst size as src size to add_dst_shadow_write */
            mi->src_opsz = mi->opsz;
        }
    } else
        mi->src_opsz = mi->opsz;
    if (!mi->need_offs) { /* if not set above */
        mi->need_offs = (mi->store || mi->dst_reg != REG_NULL) &&
            mi->opsz < 4 && !opnd_is_immed_int(mi->offs);
    }
    return true;
}

void
slow_path_xl8_sharing(app_pc pc, app_pc nxt_pc, opnd_t memop, dr_mcontext_t *mc)
{
    /* PR 493257: share shadow translation across multiple instrs */
    uint xl8_sharing_cnt = (uint) hashtable_lookup(&xl8_sharing_table, pc);
    if (xl8_sharing_cnt > 0) {
        ASSERT(!opnd_is_null(memop), "error in xl8 sharing");
        /* Since we can't share across 64K boundaries we exit to slowpath.
         * If this happens too often, abandong sharing.
         */
        if (xl8_sharing_cnt > XL8_SHARING_THRESHOLD &&
            xl8_sharing_cnt < 2*XL8_SHARING_THRESHOLD) {
            STATS_INC(xl8_not_shared_slowpaths);
            /* We don't need a synchronous flush: go w/ most performant.
             * dr_delay_flush_region() doesn't do any unlinking, so if in
             * a loop we'll repeatedly flush => performance problem!
             * So we go w/ dr_unlink_flush_region(): should be ok since
             * we'll never want -coarse_units.
             */
            LOG(3, "slow_path_xl8_sharing: flushing "PFX"\n", pc);
            dr_unlink_flush_region(pc, 1);
            /* If this instr has other reasons to go to slowpath, don't flush
             * repeatedly: only flush if it's actually due to addr sharing
             */
            hashtable_add_replace(&xl8_sharing_table, pc,
                                  (void *) (2*XL8_SHARING_THRESHOLD));
        } else {
            xl8_sharing_cnt++;
            /* We don't care about races: threshold is low enough we won't overflow */
            hashtable_add_replace(&xl8_sharing_table, pc, (void *) xl8_sharing_cnt);
        }
    }
    if (hashtable_lookup(&xl8_sharing_table, nxt_pc) > 0) {
        /* We're sharing w/ the next instr.  We had the addr in reg1 and we need
         * to put it back there.  shared_slowpath will xchg slot1 w/ reg1.  We
         * only support sharing w/ 1 memop so we ignore multiple here.
         */
        byte *addr;
        byte *memref = opnd_compute_address(memop, mc);
        if (!ALIGNED(memref, sizeof(void*))) {
            /* If we exited b/c unaligned, do not share => all subsequent instrs
             * sharing this translation will exit to slowpath
             */
            addr = shadow_bitlevel_addr();
        } else {
            /* If all subsequent shared uses of this translation are stores, we
             * can simply use shadow_translation_addr(memref) here.  But loads
             * use an offset from the original translation: and if we're now in
             * a new block (if we came to slowpath b/c we hit the redzone of
             * shared addr's original block) we can't easily recover.  We could
             * have loads update reg1 every time but that costs an extra instr
             * in the fastpath; we could instead try to decode forward and see
             * whether it's a load.  For now we take the simple route and
             * disable subsequent sharing.  This will cause slowpath exits for
             * all subsequent sharers, but we assume this first slowpath is rare
             * enough.
             */
            addr = shadow_bitlevel_addr();
        }
        LOG(3, "slow_path_xl8_sharing for pc="PFX" addr="PFX"\n", nxt_pc, addr);
        set_own_tls_value(SPILL_SLOT_1, (ptr_uint_t)addr);
    }
}

#define SHARING_XL8_ADDR_BI(bi) (!opnd_is_null(bi->shared_memop))
#define SHARING_XL8_ADDR(mi) SHARING_XL8_ADDR_BI(mi->bb)

static inline bool
should_share_addr_helper(fastpath_info_t *mi)
{
    /* FIXME OPT: PR 494727: expand sharing of shadow translation
     * across more cases:
     * - mem2mem (in particular push-mem, pop-mem, and call-ind)
     * - sub-dword
     * - app instr that reads/writes both whole-bb reg1 and reg2
     * - app instr that does not share same memref: start w/
     *     simple instrs like reg-reg moves by having them use reg2.  
     *     initial goal can be this common pattern:
     *       push ebp, mov esp->ebp, push edi, push esi, push ebx
     */
    if (!mi->load && !mi->store)
        return false;
    if (mi->mem2mem || mi->need_offs)
        return false;
    return true;
}

/* PR 493257: determines whether we should share shadow translation
 * across multiple instrs, in particular from inst to its successor
 * instruction.  Looks for identical memory reference base registers
 * and size==4 so that a register can be used to hold the
 * shared translation address.
 */
static bool
should_share_addr(instr_t *inst, fastpath_info_t *cur, opnd_t cur_memop)
{
    fastpath_info_t mi;
    instr_t *nxt = instr_get_next(inst);
    int opc;
#ifdef TOOL_DR_HEAPSTAT
    /* Not worth cost of shadow redzone and extra check + jcc slowpath
     * FIXME PR 553724: measure potential perf gains to see whether worth
     * some crazy scheme to catch over/underflow.
     */
    return false;
#endif
    if (!whole_bb_spills_enabled())
        return false;
    if (nxt == NULL)
        return false;
    if (!should_share_addr_helper(cur))
        return false;
    /* Don't share if we had too many slowpaths in the past */
    if ((uint) hashtable_lookup(&xl8_sharing_table, instr_get_app_pc(nxt)) >
        XL8_SHARING_THRESHOLD)
        return false;
    /* If the base+index are written to, do not share since no longer static.
     * The dst2 of push/pop write is ok.
     */
    opc = instr_get_opcode(inst);
    /* Do not share cmovcc since it nondet skips its mem access operand (PR 530902) */
    if (opc_is_cmovcc(opc) || opc_is_fcmovcc(opc))
        return false;
    if (opnd_is_reg(cur->dst[0]) && !opc_is_push(opc) &&
        opnd_uses_reg(cur_memop, opnd_get_reg(cur->dst[0])))
        return false;
    if (opnd_is_reg(cur->dst[1]) && !opc_is_pop(opc) &&
        opnd_uses_reg(cur_memop, opnd_get_reg(cur->dst[1])))
        return false;
    opc = instr_get_opcode(nxt);
    /* Do not share w/ cmovcc since it nondet skips its mem access operand (PR 530902) */
    if (opc_is_cmovcc(opc) || opc_is_fcmovcc(opc))
        return false;
    if (instr_ok_for_instrument_fastpath(nxt, &mi, cur->bb) &&
        adjust_opnds_for_fastpath(nxt, &mi)) {
        opnd_t memop;
        int cur_disp, nxt_disp, shadow_diff;
        if (!should_share_addr_helper(&mi)) {
#ifdef STATISTICS
            if (mi.load || mi.store) {
                memop = adjust_memop(nxt, mi.load ? mi.src[0] : mi.dst[0],
                                     mi.store, &mi.memsz, &mi.pushpop_stackop);
                if (opnd_get_base(cur_memop) == opnd_get_base(memop) &&
                    opnd_get_index(cur_memop) == opnd_get_index(memop) &&
                    opnd_get_scale(cur_memop) == opnd_get_scale(memop) &&
                    opnd_get_segment(cur_memop) == opnd_get_segment(memop)) {
                    if (mi.mem2mem)
                        STATS_INC(xl8_not_shared_mem2mem);
                    else
                        STATS_INC(xl8_not_shared_offs);
                }
            }
#endif
            return false;
        }
        memop = adjust_memop(nxt, mi.load ? mi.src[0] : mi.dst[0],
                             mi.store, &mi.memsz, &mi.pushpop_stackop);
        if (cur->memsz != mi.memsz)
            return false;
        if (!opnd_is_base_disp(cur_memop) || !opnd_is_base_disp(memop)) {
            ASSERT(false, "NYI: handle others: x64 only");
            return false;
        }
        if (opnd_get_base(cur_memop) != opnd_get_base(memop) ||
            opnd_get_index(cur_memop) != opnd_get_index(memop) ||
            opnd_get_scale(cur_memop) != opnd_get_scale(memop) ||
            opnd_get_segment(cur_memop) != opnd_get_segment(memop))
            return false;
        if (opnd_is_null(cur->bb->shared_memop))
            cur_disp = opnd_get_disp(cur_memop);
        else
            cur_disp = opnd_get_disp(cur->bb->shared_memop);
        if (cur->pushpop_stackop)
            cur_disp += (cur->load ? -(int)cur->memsz : cur->memsz);
        cur_disp += cur->bb->shared_disp_implicit;
        nxt_disp = opnd_get_disp(memop);
        /* ok for disp to not be aligned to 4 so long as combined w/ base+index
         * it is I suppose
         */
        shadow_diff = (nxt_disp - cur_disp) / 4; /* 2 shadow bits per byte */
        if (shadow_diff > SHADOW_REDZONE_SIZE || shadow_diff < -SHADOW_REDZONE_SIZE) {
            STATS_INC(xl8_not_shared_disp_too_big);
            return false;
        }
        return true;
    }
    return false;
}

#ifdef DEBUG
static void
print_scratch_reg(void *drcontext, scratch_reg_info_t *si, int num, file_t file)
{
    dr_fprintf(file, "r%d=", num);
    opnd_disassemble(drcontext, opnd_create_reg(si->reg), file);
    if (si->xchg != REG_NULL) {
        /* opnd_disassemble adds a space */
        dr_fprintf(file, "xchg ");
        opnd_disassemble(drcontext, opnd_create_reg(si->xchg), file);
    } else if (si->dead) {
        dr_fprintf(file, "dead");
    } else {
        dr_fprintf(file, "spill#%d", si->slot);
    }
}

static void
check_scratch_reg_no_overlap(scratch_reg_info_t *s1, scratch_reg_info_t *s2)
{
    ASSERT(s1->reg != s2->reg, "scratch reg error");
    ASSERT(s1->xchg != s2->reg, "scratch reg error");
    ASSERT(s2->xchg != s1->reg, "scratch reg error");
    /* if both are using slots (no xchg, not dead) then make sure they differ */
    ASSERT(s1->xchg != REG_NULL || s2->xchg != REG_NULL ||
           s1->dead || s2->dead || 
           s1->slot != s2->slot, "scratch reg error");
}
#endif

/* It's up to the caller to ensure that fixed was not already chosen
 * for an earlier scratch reg
 */
static void
pick_scratch_reg_helper(fastpath_info_t *mi, scratch_reg_info_t *si,
                        int live[NUM_LIVENESS_REGS],
                        bool only_abcd, reg_id_t fixed, int slot,
                        opnd_t no_overlap1, opnd_t no_overlap2)
{
    int nxt_dead;
    for (nxt_dead = 0; nxt_dead < NUM_LIVENESS_REGS; nxt_dead++) {
        if (live[nxt_dead] == LIVE_DEAD)
            break;
    }
    si->global = false;
    /* FIXME PR 463053: we're technically being a little unsafe here:
     * even if a register is dead on the normal path, if a fault
     * can occur before the register is written to, we should
     * restore its value in the fault handler.  Pretty pathological
     * so for now we ignore it, given that we have larger problems
     * and we need the speed.
     */
    if (nxt_dead < NUM_LIVENESS_REGS &&
        (!only_abcd || nxt_dead <= REG_EBX - REG_START_32) &&
        !opnd_uses_reg(no_overlap1, REG_START_32 + nxt_dead) &&
        !opnd_uses_reg(no_overlap2, REG_START_32 + nxt_dead) &&
        /* do not pick local reg that overlaps w/ whole-bb reg */
        REG_START_32 + nxt_dead != mi->bb->reg1.reg &&
        REG_START_32 + nxt_dead != mi->bb->reg2.reg) {
        /* we can use it directly */
        si->reg = REG_START_32 + nxt_dead;
        si->xchg = REG_NULL;
        si->dead = true;
        STATS_INC(reg_dead);
        live[nxt_dead] = LIVE_LIVE;
    } else if (nxt_dead < NUM_LIVENESS_REGS &&
               /* FIXME OPT: if we split the spills up we could use xchg for
                * reg2 or reg3 even if not for reg1
                */
               !opnd_uses_reg(no_overlap1, REG_START_32 + nxt_dead) &&
               !opnd_uses_reg(no_overlap2, REG_START_32 + nxt_dead) &&
               !opnd_uses_reg(no_overlap1, fixed) &&
               !opnd_uses_reg(no_overlap2, fixed) &&
               /* do not pick local reg that overlaps w/ whole-bb reg */
               REG_START_32 + nxt_dead != mi->bb->reg1.reg &&
               REG_START_32 + nxt_dead != mi->bb->reg2.reg) {
        /* pick fixed reg and xchg for it */
        si->reg = fixed;
        si->xchg = REG_START_32 + nxt_dead;
        si->dead = false;
        STATS_INC(reg_xchg);
        live[nxt_dead] = LIVE_LIVE;
    } else {
        /* pick fixed reg and spill it */
        si->reg = fixed;
        si->xchg = REG_NULL;
        si->dead = false;
        si->slot = slot;
        STATS_INC(reg_spill);
   }
}

/* Chooses scratch registers and sets liveness and eflags info 
 * If mi->eax.used is set, does NOT determine how to spill eax based
 * on eflags and does NOT use the SPILL_SLOT_EFLAGS_EAX unless eflags
 * is dead.
 */
void
pick_scratch_regs(instr_t *inst, fastpath_info_t *mi, bool only_abcd, bool need3,
                  bool reg3_must_be_ecx, opnd_t no_overlap1, opnd_t no_overlap2)
{
    int nxt_dead;
    int live[NUM_LIVENESS_REGS];
    /* Slots for additional local regs, when using whole-bb slots 1 and 2
     * for regs and slot 3 (SPILL_SLOT_EFLAGS_EAX) for eflags
     */
    int local_slot[] = {SPILL_SLOT_4, SPILL_SLOT_5};
    int local_idx = 0;
    IF_DEBUG(const int local_idx_max = sizeof(local_slot)/sizeof(local_slot[0]);)
    get_reg_liveness(inst, live);
    mi->aflags = get_aflags_liveness(inst);

    ASSERT((whole_bb_spills_enabled() && mi->bb->reg1.reg != REG_NULL) ||
           (!whole_bb_spills_enabled() && mi->bb->reg1.reg == REG_NULL),
           "whole_bb_spills_enabled() should correspond to reg1,reg2 being set");

    /* don't pick esp since it can't be an index register */
    live[REG_ESP - REG_START_32] = LIVE_LIVE;

    if (mi->eax.used) {
        /* caller wants us to ignore eax and eflags */
    } else if (!whole_bb_spills_enabled() && mi->aflags != EFLAGS_WRITE_6) {
        mi->eax.reg = REG_EAX;
        mi->eax.used = true;
        mi->eax.dead = (live[REG_EAX - REG_START_32] == LIVE_DEAD);
        /* Ensure we don't use eax for another scratch reg */
        if (mi->eax.dead) {
            live[REG_EAX - REG_START_32] = LIVE_LIVE;
            STATS_INC(reg_dead);
        } else
            STATS_INC(reg_spill);
        /* we do not try to xchg instead of spilling as that would complicate
         * shared_slowpath, spill_reg3_slot, etc.
         */
        mi->eax.xchg = REG_NULL;
        mi->eax.slot = SPILL_SLOT_EFLAGS_EAX;
        mi->eax.global = false;
    } else
        mi->eax.used = false;

    /* Up to 3 scratch regs (beyond eax for eflags) need to be from
     * ecx, edx, ebx so we can reference low and high 8-bit sub-regs
     */
    mi->reg1.used = false; /* set later */
    mi->reg2.used = false; /* set later */
    mi->reg3.used = false; /* set later */

    if (need3) {
        if (reg3_must_be_ecx && mi->bb->reg1.reg == REG_ECX) {
            mi->reg3 = mi->bb->reg1;
            mi->reg3.dead = (live[mi->reg3.reg - REG_START_32] == LIVE_DEAD);
        } else if (reg3_must_be_ecx && mi->bb->reg2.reg == REG_ECX) {
            mi->reg3 = mi->bb->reg2;
            mi->reg3.dead = (live[mi->reg3.reg - REG_START_32] == LIVE_DEAD);
        } else if (reg3_must_be_ecx && only_abcd) {
            /* instrument_fastpath requires reg3 to be ecx since we have
             * to use cl for OP_shl var op.
             */
            mi->reg3.reg = REG_ECX;
            mi->reg3.dead = (live[mi->reg3.reg - REG_START_32] == LIVE_DEAD);
            mi->reg3.global = false;
            /* Ensure we don't use for another scratch reg */
            live[mi->reg3.reg - REG_START_32] = LIVE_LIVE;
            if (!mi->reg3.dead) {
                for (nxt_dead = 0; nxt_dead < NUM_LIVENESS_REGS; nxt_dead++) {
                    if (live[nxt_dead] == LIVE_DEAD)
                        break;
                }
                if (nxt_dead < NUM_LIVENESS_REGS &&
                    !opnd_uses_reg(no_overlap1, REG_START_32 + nxt_dead) &&
                    !opnd_uses_reg(no_overlap2, REG_START_32 + nxt_dead) &&
                    !opnd_uses_reg(no_overlap1, mi->reg3.reg) &&
                    !opnd_uses_reg(no_overlap2, mi->reg3.reg) &&
                    /* we can't xchg with what we'll use for reg1 or reg2 */
                    REG_START_32 + nxt_dead != REG_EDX &&
                    REG_START_32 + nxt_dead != REG_EBX &&
                    /* do not pick local reg that overlaps w/ whole-bb reg */
                    REG_START_32 + nxt_dead != mi->bb->reg1.reg &&
                    REG_START_32 + nxt_dead != mi->bb->reg2.reg) {
                    mi->reg3.xchg = REG_START_32 + nxt_dead;
                    live[nxt_dead] = LIVE_LIVE;
                    STATS_INC(reg_xchg);
                } else {
                    mi->reg3.slot = spill_reg3_slot(mi->aflags == EFLAGS_WRITE_6,
                                                    !mi->eax.used || mi->eax.dead,
                                                    /* later we'll update these */
                                                    false, false);
                    STATS_INC(reg_spill);
                }
            } else
                STATS_INC(reg_dead);
        } else {
            pick_scratch_reg_helper(mi, &mi->reg3, live, only_abcd,
                                    (mi->bb->reg1.reg == REG_ECX ?
                                     ((mi->bb->reg2.reg == REG_EDX) ? REG_EBX : REG_EDX) :
                                     ((mi->bb->reg2.reg == REG_ECX) ?
                                      ((mi->bb->reg1.reg == REG_EDX) ? REG_EBX : REG_EDX)
                                      : REG_ECX)),
                                    spill_reg3_slot(mi->aflags == EFLAGS_WRITE_6,
                                                    !mi->eax.used || mi->eax.dead,
                                                    /* later we'll update these */
                                                    false, false),
                                    no_overlap1, no_overlap2);
        }
        if (mi->bb->reg1.reg != REG_NULL && !mi->reg3.dead && mi->reg3.xchg == REG_NULL) {
            if (!mi->reg3.global) {
                /* spill_reg3_slot() should return SPILL_SLOT_4 for us */
                ASSERT(mi->reg3.slot == local_slot[local_idx], "reg3: wrong slot!");
                local_idx++;
            } else
                ASSERT(mi->reg3.slot < SPILL_SLOT_EFLAGS_EAX, "reg3 global: 0 or 1!");
        }
   } else
        mi->reg3.reg = REG_NULL;

    if (mi->bb->reg1.reg != REG_NULL &&
        (!need3 || !reg3_must_be_ecx || mi->bb->reg1.reg != REG_ECX) &&
        /* we only need to check for overlap for xchg (since messes up
         * app values) so we ignore no_overlap*
         */
        (!mi->eax.used || mi->bb->reg1.reg != REG_EAX)) {
        /* Use whole-bb spilled reg (PR 489221) */
        mi->reg1 = mi->bb->reg1;
        mi->reg1.dead = (live[mi->reg1.reg - REG_START_32] == LIVE_DEAD);
    } else {
        /* Pick primary scratch reg */
        ASSERT(local_idx < local_idx_max, "local slot overflow");
        pick_scratch_reg_helper(mi, &mi->reg1, live, only_abcd,
                                (need3 && mi->reg3.reg == REG_EDX) ? REG_ECX :
                                ((mi->bb->reg2.reg == REG_EDX) ? REG_EBX : REG_EDX),
                                /* if whole-bb ecx is in slot 1 or 2, use 3rd slot */
                                (mi->bb->reg1.reg == REG_NULL) ? SPILL_SLOT_1 :
                                local_slot[local_idx++], no_overlap1, no_overlap2);
    }
    

    if (mi->bb->reg2.reg != REG_NULL &&
        (!need3 || !reg3_must_be_ecx || mi->bb->reg2.reg != REG_ECX) &&
        (!mi->eax.used || mi->bb->reg2.reg != REG_EAX)) {
        /* Use whole-bb spilled reg (PR 489221) */
        mi->reg2 = mi->bb->reg2;
        mi->reg2.dead = (live[mi->reg2.reg - REG_START_32] == LIVE_DEAD);
    } else {
        /* Pick secondary scratch reg */
        ASSERT(local_idx < local_idx_max, "local slot overflow");
        pick_scratch_reg_helper(mi, &mi->reg2, live, only_abcd,
                                mi->reg1.reg == REG_EBX ?
                                ((need3 && mi->reg3.reg == REG_EDX) ? REG_ECX : REG_EDX) :
                                ((need3 && mi->reg3.reg == REG_EBX) ? REG_ECX : REG_EBX),
                                /* if whole-bb ecx is in slot 1 or 2, use 3rd slot */
                                (mi->bb->reg2.reg == REG_NULL) ? SPILL_SLOT_2 :
                                local_slot[local_idx++], no_overlap1, no_overlap2);
    }

    if (mi->bb->reg1.reg == REG_NULL &&
        need3 && !mi->reg3.dead && mi->reg3.xchg == REG_NULL) {
        /* See if we can use slots 1 or 2 instead: matters when using DR slots */
        mi->reg3.slot = spill_reg3_slot(mi->aflags == EFLAGS_WRITE_6,
                                        !mi->eax.used || mi->eax.dead,
                                        mi->reg1.dead, mi->reg2.dead);
    }

    DOLOG(3, {
        void *drcontext = dr_get_current_drcontext();
        per_thread_t *pt;
        ASSERT(drcontext != NULL, "should always have dcontext in cur DR");
        pt = (per_thread_t *) dr_get_tls_field(drcontext);
        LOG(3, "scratch: ");
        instr_disassemble(drcontext, inst, LOGFILE(pt));
        LOG(3, "| ");
        print_scratch_reg(drcontext, &mi->reg1, 1, LOGFILE(pt));
        LOG(3, ", ");
        print_scratch_reg(drcontext, &mi->reg2, 2, LOGFILE(pt));
        if (need3) {
            LOG(3, ", ");
            print_scratch_reg(drcontext, &mi->reg3, 3, LOGFILE(pt));
        }
        LOG(3, "\n");
    });

#ifdef DEBUG
    check_scratch_reg_no_overlap(&mi->reg1, &mi->reg2);
    if (need3) {
        check_scratch_reg_no_overlap(&mi->reg1, &mi->reg3);
        check_scratch_reg_no_overlap(&mi->reg2, &mi->reg3);
    }
#endif
}

static bool
insert_spill_common(void *drcontext, instrlist_t *bb, instr_t *inst,
                    scratch_reg_info_t *si, bool spill,
                    bool just_xchg, bool do_global)
{
    /* No need to do a local spill/restore if globally spilled (PR 489221) */
    if (si->used && !si->dead && (!si->global || do_global)) {
        if (si->xchg != REG_NULL) {
            /* spill/restore are identical */
            PRE(bb, inst, INSTR_CREATE_xchg
                (drcontext, opnd_create_reg(si->reg), opnd_create_reg(si->xchg)));
        } else if (!just_xchg) {
            if (spill)
                spill_reg(drcontext, bb, inst, si->reg, si->slot);
            else
                restore_reg(drcontext, bb, inst, si->reg, si->slot);
        }
        if (!spill && do_global) {
            /* FIXME PR 553724: avoid later redundant restore at
             * bottom of bb by setting used to false here.
             * However that's not working for reasons I haven't yet determined.
             */
        }
        return true;
    }
    return false;
}

bool
insert_spill_global(void *drcontext, instrlist_t *bb, instr_t *inst,
                    scratch_reg_info_t *si, bool spill)
{
    return insert_spill_common(drcontext, bb, inst, si, spill, false, true);
}

void
insert_spill_or_restore(void *drcontext, instrlist_t *bb, instr_t *inst,
                        scratch_reg_info_t *si, bool spill, bool just_xchg)
{
    insert_spill_common(drcontext, bb, inst, si, spill, just_xchg, false);
}

void
insert_save_aflags(void *drcontext, instrlist_t *bb, instr_t *inst,
                   scratch_reg_info_t *si, int aflags)
{
    if (si->reg != REG_NULL) {
        ASSERT(si->reg == REG_EAX, "must use eax for aflags");
        insert_spill_or_restore(drcontext, bb, inst, si, true/*save*/, false);
    }
    PRE(bb, inst, INSTR_CREATE_lahf(drcontext));
    if (aflags != EFLAGS_WRITE_OF) {
        PRE(bb, inst,
            INSTR_CREATE_setcc(drcontext, OP_seto, opnd_create_reg(REG_AL)));
    }
}

void
insert_restore_aflags(void *drcontext, instrlist_t *bb, instr_t *inst,
                      scratch_reg_info_t *si, int aflags)
{
    if (aflags != EFLAGS_WRITE_OF) {
        PRE(bb, inst, INSTR_CREATE_add
            (drcontext, opnd_create_reg(REG_AL), OPND_CREATE_INT8(0x7f)));
    }
    PRE(bb, inst, INSTR_CREATE_sahf(drcontext));
    if (si->reg != REG_NULL) {
        ASSERT(si->reg == REG_EAX, "must use eax for aflags");
        insert_spill_or_restore(drcontext, bb, inst, si, false/*restore*/, false);
    }
}

static inline bool
scratch_reg1_is_avail(instr_t *inst, fastpath_info_t *mi, bb_info_t *bi)
{
    int opc = instr_get_opcode(inst);
    return (bi->reg1.used && 
             /* ensure neither sharing w/ next nor sharing w/ prev */
            !SHARING_XL8_ADDR_BI(bi) && mi != NULL && !mi->use_shared &&
            /* cmovcc does an aflags restore after the lea, so reg1 needs
             * to stay untouched
             */
            !opc_is_cmovcc(opc) && !opc_is_fcmovcc(opc));
}

static inline bool
scratch_reg2_is_avail(instr_t *inst, fastpath_info_t *mi, bb_info_t *bi)
{
    int opc = instr_get_opcode(inst);
    return (bi->reg2.used &&
            /* we use reg2 for cmovcc */
            !opc_is_cmovcc(opc) && !opc_is_fcmovcc(opc));
}

/* single eflags save per bb */
static void
save_aflags_if_live(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi, bb_info_t *bi)
{
    scratch_reg_info_t si;
    /* We save aflags unless there's no read prior to the 1st write.
     * We clobber eax while doing so if eax is dead.
     * Technically both are unsafe: should restore on a fault (PR
     * 463053) but we consider that too pathological to bother.
     */
    bool eax_dead = bi->eax_dead ||
        (bi->reg1.reg == REG_EAX && scratch_reg1_is_avail(inst, mi, bi)) ||
        (bi->reg2.reg == REG_EAX && scratch_reg2_is_avail(inst, mi, bi));
    if (!bi->eflags_used)
        return;
    if (bi->aflags != EFLAGS_WRITE_6) {
        /* slot 5 won't be used for 3rd reg (that's 4) and is ok for temp use */
        si.slot = SPILL_SLOT_5;
        if (eax_dead) {
            si.reg = REG_NULL;
        } else {
            si.reg = REG_EAX;
            /* reg1 is used for xl8 sharing so check whether shared_memop is set
             * == share w/ next.  it's cleared prior to post-app-write aflags save
             * so we use mi->use_shared to detect share w/ prev.
             * for aflags restore code added later it's ok to be too conservative:
             * these fields should all be cleared anyway, and won't matter for
             * top-of-bb save.
             * we can assume that reg2 is dead.
             */
            if (scratch_reg1_is_avail(inst, mi, bi))
                si.xchg = bi->reg1.reg;
            else if (scratch_reg2_is_avail(inst, mi, bi))
                si.xchg = bi->reg2.reg;
            else
                si.xchg = REG_NULL;
            ASSERT(si.xchg != REG_EAX, "xchg w/ self is not a save");
            si.used = true;
            si.dead = false;
            si.global = false; /* to enable the save */
        }
        insert_save_aflags(drcontext, bb, inst, &si, bi->aflags);
        if (!eax_dead) {
            /* now restore eax and save eflags to the spill slot */
            /* FIXME optimization: if eax isn't used by any app instrs
             * between here and the next eflags restore, we can just keep
             * the flags in eax and not put in tls.
             * Since a lahf followed by a read of eax causes a partial-reg
             * stall that could improve perf noticeably.
             */
            /* I used to use xchg to avoid needing two instrs, but xchg w/ mem's
             * lock of the bus shows up as a measurable perf hit (PR 553724)
             */
            PRE(bb, inst, INSTR_CREATE_mov_st
                (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_EFLAGS_EAX),
                 opnd_create_reg(REG_EAX)));
            insert_spill_or_restore(drcontext, bb, inst, &si, false/*restore*/, false);
        } else {
            PRE(bb, inst, INSTR_CREATE_mov_st
                (drcontext, spill_slot_opnd(drcontext, SPILL_SLOT_EFLAGS_EAX),
                 opnd_create_reg(REG_EAX)));
        }
    }
}

/* single eflags save per bb */
static void
restore_aflags_if_live(void *drcontext, instrlist_t *bb, instr_t *inst,
                       fastpath_info_t *mi, bb_info_t *bi)
{
    scratch_reg_info_t si;
    if (!bi->eflags_used)
        return;
    /* eflags is not sitting in eax: it's always in tls */
    si.reg = REG_EAX;
    si.xchg = REG_NULL;
    si.slot = SPILL_SLOT_EFLAGS_EAX;
    si.used = true;
    si.dead = false;
    si.global = false; /* to enable the restore */
    if (bi->eax_dead ||
        (bi->reg1.reg == REG_EAX && scratch_reg1_is_avail(inst, mi, bi)) ||
        (bi->reg2.reg == REG_EAX && scratch_reg2_is_avail(inst, mi, bi))) {
        insert_spill_or_restore(drcontext, bb, inst, &si, false/*restore*/, false);
        /* we do NOT want the eax-restore at the end of insert_restore_aflags() */
        si.reg = REG_NULL;
    } else {
        si.slot = SPILL_SLOT_5;
        /* See notes in save_aflags_if_live on sharing impacting reg1 being scratch */
        if (scratch_reg1_is_avail(inst, mi, bi))
            si.xchg = bi->reg1.reg;
        else if (scratch_reg2_is_avail(inst, mi, bi))
            si.xchg = bi->reg2.reg;
        ASSERT(si.xchg != REG_EAX, "xchg w/ self is not a save");
        /* I used to use xchg to avoid needing two instrs, but xchg w/ mem's
         * lock of the bus shows up as a measurable perf hit (PR 553724)
         */
        insert_spill_or_restore(drcontext, bb, inst, &si, true/*save*/, false);
        PRE(bb, inst, INSTR_CREATE_mov_ld
            (drcontext, opnd_create_reg(REG_EAX),
             spill_slot_opnd(drcontext, SPILL_SLOT_EFLAGS_EAX)));
        /* we DO want the eax-restore at the end of insert_restore_aflags() */
    }
    insert_restore_aflags(drcontext, bb, inst, &si, bi->aflags);
    /* avoid re-restoring.  FIXME: do this for insert_spill_global too? */
    bi->eflags_used = false;
}

#ifdef TOOL_DR_MEMORY
static void
insert_cmp_for_equality(void *drcontext, instrlist_t *bb, instr_t *inst,
                        opnd_t op, int val)
{
    /* test with self is smaller instr than cmp to 0, for self=reg */
    if (val == 0 && opnd_is_reg(op)) {
        PRE(bb, inst, INSTR_CREATE_test(drcontext, op, op));
    } else if (val >= SCHAR_MIN && val <= SCHAR_MAX) {
        PRE(bb, inst, INSTR_CREATE_cmp(drcontext, op, OPND_CREATE_INT8((char)val)));
    } else {
        PRE(bb, inst, INSTR_CREATE_cmp(drcontext, op, OPND_CREATE_INT32(val)));
    }
}

/* Adds a check that app_op's shadow in shadow_op has its shadow bits
 * defined.
 */
static void
insert_check_defined(void *drcontext, instrlist_t *bb, instr_t *inst,
                     fastpath_info_t *mi, opnd_t app_op, opnd_t shadow_op)
{
    ASSERT(!opnd_is_null(shadow_op), "shadow op can't be empty");
    ASSERT(!opnd_is_null(app_op), "app op can't be empty");
    /* We require whole-bb so that we know the regs when we set mi->need_offs */
    if (whole_bb_spills_enabled() && mi->opsz < 4) {
        /* PR 425240: check just the bits involved.  We use a table lookup
         * and risk extra data cache pressure to avoid the series of shifts
         * and masks and extra spilled regs needed to pull out the bits we
         * want.
         */
        int disp = 0;
        int sz;
        reg_id_t base = REG_NULL;
        reg_id_t index = REG_NULL;
        if (opnd_is_reg(shadow_op)) {
            /* came from a memref, where we should have zeroed the rest of offs */
            sz = mi->memsz;
            ASSERT(opnd_is_memory_reference(app_op), "reg shadow == mem app");
            ASSERT(mi->zero_rest_of_offs, "need zeroed offs to check mem src");
            /* mi->need_offs may not be set, if avoiding 3rd reg */
            if (opnd_is_null(mi->offs)) {
                /* movzx 2-to-4 or 1-to-2 don't store the offs: so we bail */
                insert_cmp_for_equality(drcontext, bb, inst, shadow_op,
                                        SHADOW_DWORD_DEFINED);
                return;
            }
            base = reg_to_pointer_sized(opnd_get_reg(shadow_op));
            /* offs is kept in high reg8 => offs is already multiplied by 256 for us */
            index = reg_to_pointer_sized(opnd_get_reg(mi->offs));
            LOG(3, "check_defined: using table for mem op base=%d index=%d\n",
                base, index);
        } else {
            /* for movzx we want src opsz not mi->opsz == dst sz */
            sz = mi->src_opsz;
            if (mi->store) {
                /* More complex to find or create a free register: bailing for now */
                insert_cmp_for_equality(drcontext, bb, inst, shadow_op,
                                        SHADOW_DWORD_DEFINED);
                return;
            }
            LOG(3, "check_defined: using table for reg op\n");
            ASSERT(opnd_is_reg(app_op), "if not memop, must be reg");
            disp += reg_offs_in_dword(opnd_get_reg(app_op)) * 256;
            /* load from reg shadow tls slot into reg2, which should
             * be scratch
             * FIXME PR 494720: add annotations so it's easier to know which
             * regs are dead at which points, and to check assumptions
             */
            if (!mi->store && !SHARING_XL8_ADDR(mi)) {
                base = mi->reg1.reg;
                mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg1);
            } else {
                base = mi->reg2.reg;
                mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);
            }
            PRE(bb, inst,
                INSTR_CREATE_movzx(drcontext, opnd_create_reg(base), shadow_op));
        }
        mark_eflags_used(drcontext, bb, mi->bb);
        disp += (int)
            ((sz == 1) ? shadow_byte_defined : shadow_word_defined);
        /* look up in series of 4 tables, one for each offset */
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext,
                             opnd_create_base_disp(base, index, 1, disp, OPSZ_1),
                             OPND_CREATE_INT8(1)));
    } else {
        insert_cmp_for_equality(drcontext, bb, inst, shadow_op, SHADOW_DWORD_DEFINED);
    }
}

/* Manipulates the one-byte shadow value in register reg that represents an
 * app dword, appropriately for the app instruction inst.
 */
static void
insert_shadow_op(void *drcontext, instrlist_t *bb, instr_t *inst,
                 reg_id_t reg8, reg_id_t scratch8)
{
#if 0
    /* FIXME: not fully operational yet: not called everywhere in instrument_fastpath(),
     * and doesn't have all the shift or other cases yet.
     * For now we rely on a shift w/ any undefined operand to bail out to
     * the slowpath.
     */
    int opc = instr_get_opcode(inst);
    switch (opc) {
    case OP_shl: {
        if (opnd_is_immed_int(instr_get_src(inst, 0))) {
            int shift = opnd_get_immed_int(instr_get_src(inst, 0));
            uint opsz = opnd_size_in_bytes(opnd_get_size(instr_get_dst(inst, 0)));
            if (shift > opsz*8)
                shift = opsz*8;
            if (shift % 8 == 0) {
                PRE(bb, inst,
                    INSTR_CREATE_shl(drcontext, opnd_create_reg(reg8),
                                     OPND_CREATE_INT8((shift / 8)*2)));
            } else {
                /* need to merge partial bytes */
                PRE(bb, inst,
                    INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(reg8),
                                        opnd_create_reg(scratch8)));
                PRE(bb, inst,
                    INSTR_CREATE_shl(drcontext, opnd_create_reg(reg8),
                                     OPND_CREATE_INT8((((shift-1) / 8)+1)*2)));
                PRE(bb, inst,
                    INSTR_CREATE_shl(drcontext, opnd_create_reg(scratch8),
                                     OPND_CREATE_INT8((shift / 8)*2)));
                PRE(bb, inst,
                    INSTR_CREATE_or(drcontext, opnd_create_reg(reg8),
                                    opnd_create_reg(scratch8)));
            }
        } else {
            /* FIXME: how get app value of %cl? */
            ASSERT(false, "fastpath of OP_shl %cl not implemented");
            break;
        }
    }
    }
#endif
}

static bool
write_shadow_eflags(void *drcontext, instrlist_t *bb, instr_t *inst,
                    reg_id_t load_through, opnd_t val)
{
    if (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst))) {
        /* rather than test if undefined, or just write 2 bits, we
         * write the whole byte (and read the whole byte as well) */
        if (load_through == REG_NULL || opnd_is_immed_int(val) || opnd_is_reg(val)) {
            ASSERT(opnd_is_immed_int(val) || opnd_is_reg(val),
                   "internal shadow eflags error");
            PRE(bb, inst,
                INSTR_CREATE_mov_st(drcontext, opnd_create_shadow_eflags_slot(), val));
        } else {
            PRE(bb, inst,
                INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(load_through), val));
            PRE(bb, inst,
                INSTR_CREATE_mov_st(drcontext, opnd_create_shadow_eflags_slot(),
                                    opnd_create_reg(load_through)));
        }
        return true;
    }
    return false;
}
#endif /* TOOL_DR_MEMORY */

void
add_jcc_slowpath(void *drcontext, instrlist_t *bb, instr_t *inst, uint jcc_opcode,
                 fastpath_info_t *mi)
{
    /* FIXME: for longer sequences like opsz<4 or esp-adjust we need 32-bit reach;
     * but for others 8-bit suffices.  Should auto-discover: jmp_smart!
     */
    PRE(bb, inst,
        INSTR_CREATE_jcc(drcontext, jcc_opcode, opnd_create_instr(mi->slowpath)));
    mi->need_slowpath = true;
}

#ifdef TOOL_DR_MEMORY
static void
add_addressing_register_checks(void *drcontext, instrlist_t *bb, instr_t *inst,
                               opnd_t memop, fastpath_info_t *mi)
{
    reg_id_t base = opnd_get_base(memop);
    reg_id_t index = opnd_get_index(memop);
    if (base != REG_NULL) {
        /* if we've previously checked, and hasn't been written to, skip check */
        if (!mi->bb->addressable[reg_to_pointer_sized(base) - REG_EAX]) {
            ASSERT(reg_get_size(base) == OPSZ_4, "internal base size error");
            PRE(bb, inst,
                INSTR_CREATE_cmp(drcontext,
                                 opnd_create_shadow_reg_slot(base),
                                 OPND_CREATE_INT8((char)SHADOW_DWORD_DEFINED)));
            mark_eflags_used(drcontext, bb, mi->bb);
            add_jcc_slowpath(drcontext, bb, inst, 
                             /* short doesn't quite reach for mem2mem's 1st check
                              * FIXME: use short for 2nd though! */
                             mi->mem2mem ? OP_jne : OP_jne_short, mi);
            mi->bb->addressable[reg_to_pointer_sized(base) - REG_EAX] = true;
        } else
            STATS_INC(addressable_checks_elided);
    }
    if (index != REG_NULL) {
        /* if we've previously checked, and hasn't been written to, skip check */
        if (!mi->bb->addressable[reg_to_pointer_sized(index) - REG_EAX]) {
            ASSERT(reg_get_size(index) == OPSZ_4, "internal index size error");
            PRE(bb, inst,
                INSTR_CREATE_cmp(drcontext,
                                 opnd_create_shadow_reg_slot(index),
                                 OPND_CREATE_INT8((char)SHADOW_DWORD_DEFINED)));
            mark_eflags_used(drcontext, bb, mi->bb);
            add_jcc_slowpath(drcontext, bb, inst, OP_jne_short, mi);
            mi->bb->addressable[reg_to_pointer_sized(index) - REG_EAX] = true;
        } else
            STATS_INC(addressable_checks_elided);
    }
}
#endif /* TOOL_DR_MEMORY */

/* Today we pass in reg enum values instead of pointers to
 * scratch_reg_info_t, so we resort to searching for the data
 * for each one passed to add_shadow_table_lookup
 */
static void
mark_matching_scratch_reg(void *drcontext, instrlist_t *bb,
                          fastpath_info_t *mi, reg_id_t reg)
{
    scratch_reg_info_t *si = NULL;
    scratch_reg_info_t *si_local = NULL;
    if (reg == mi->reg1.reg)
        si = &mi->reg1;
    else if (reg == mi->reg2.reg)
        si = &mi->reg2;
    else if (reg == mi->reg3.reg)
        si = &mi->reg3;
    else
        ASSERT(false, "cannot find scratch reg");
    si_local = si;
    if (si->global) {
        ASSERT(mi->bb != NULL, "global requires bb data");
        if (si->reg == mi->bb->reg1.reg)
            si = &mi->bb->reg1;
        else if (si->reg == mi->bb->reg2.reg)
            si = &mi->bb->reg2;
        else
            ASSERT(false, "cannot find global reg");
    }
    mark_scratch_reg_used(drcontext, bb, mi->bb, si);
    /* enable asserts on local used field */
    if (si->global)
        si_local->used = si->used;
}

/* Assumes that the address is in reg1.
 * Uses the passed-in need_offs rather than mi->need_offs.
 * If mi->memsz > 1, bails to mi->slowpath if unaligned.
 * At completion the following hold:
 *   reg1 holds address or value (depending on get_value) of shadow byte
 *     for the containing dword of the address stored in reg1.
 *     if value, top bytes are zeroed out (top 3 for sz=4, top 2 for sz=8).
 *     if value_in_reg2 and get_value, then reg2 holds value.
 *   If need_offs:
 *     - mi->offs is reg2_8h (reg1_8h if value_in_reg2, reg3_8h if
 *       zero_rest_of_offs and !mi->need_offs)
 *     - reg3 has been written to
 *   Else if zero_rest_of_offs (which asks for offs even if !need_offs):
 *     - mi->offs is reg1_8h
 *   Else:
 *     - reg3 has not been touched
 *     - reg2 holds the offset within the shadow block
 * If !get_value and !need_offs:
 *   reg1, reg3, and reg3 can be any 32-bit regs
 * Else, they should be a,b,c,d for 8-bit sub-reg
 */
void
add_shadow_table_lookup(void *drcontext, instrlist_t *bb, instr_t *inst,
                        fastpath_info_t *mi,
                        bool get_value, bool value_in_reg2, bool need_offs,
                        bool zero_rest_of_offs,
                        reg_id_t reg1, reg_id_t reg2, reg_id_t reg3)
{
    /* Shadow memory table lookup:
     * 1) Shift to get 64K base
     * 2) Simple hash mask index into table
     *    Table is allocated max size (64K entries) so we have constant
     *    global value for table itself and for hash mask, as well as
     *    no need to cmp to a tag.
     * 3) Result points to 8K shadow chunk
     */
    reg_id_t reg1_8h = reg_32_to_8h(reg1);
    reg_id_t reg2_8h = reg_32_to_8h(reg2);
    reg_id_t reg3_8 = (reg3 == REG_NULL) ? REG_NULL : reg_32_to_8(reg3);
    reg_id_t reg3_8h = (reg3 == REG_NULL) ? REG_NULL : reg_32_to_8h(reg3);
    ASSERT(reg3 != REG_NULL || !need_offs, "spill error");
    mark_matching_scratch_reg(drcontext, bb, mi, reg1);
    mark_matching_scratch_reg(drcontext, bb, mi, reg2);
    mark_eflags_used(drcontext, bb, mi->bb);
    /* Bottom 16 bits */
#ifdef TOOL_DR_HEAPSTAT
    /* Staleness stores displacement so wants copy of whole addr */
    PRE(bb, inst,
        INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(reg2), opnd_create_reg(reg1)));
    /* Staleness has 1 shadow byte per 8 app bytes and doesn't care about alignment */
    PRE(bb, inst,
        INSTR_CREATE_shr(drcontext, opnd_create_reg(reg2), OPND_CREATE_INT8(3)));
#else
    PRE(bb, inst,
        INSTR_CREATE_movzx(drcontext, opnd_create_reg(reg2),
                           opnd_create_reg(reg_32_to_16(reg1))));
#endif
    ASSERT(mi->memsz <= 4 || !need_offs, "unsupported fastpath memsz");
#ifdef TOOL_DR_MEMORY
    if (mi->memsz > 1) {
        /* if not aligned so all bytes are in same shadow byte, go to slowpath */
        /* saving space trumps sub-reg slowdown (for crafty at least: 33:20 vs 32:20)
         * so we just compare the bottom 8 bits
         */
        /* PR 504162: keep 4-byte-aligned 8-byte fp ops on fastpath, so we only
         * require 4-byte alignment for 8-byte memops and check bounds below
         */
        PRE(bb, inst,
            INSTR_CREATE_test(drcontext, opnd_create_reg(reg_32_to_8(reg2)),
                              OPND_CREATE_INT8(mi->memsz == 4 ? 0x3 :
                                               (mi->memsz == 8 ? 0x3 : 0x1))));
        /* With PR 448701 a short jcc reaches */
        add_jcc_slowpath(drcontext, bb, inst, OP_jnz_short, mi);
        if (mi->memsz == 8) {
            /* PR 504162: keep 4-byte-aligned 8-byte fp ops on fastpath.
             * We checked for 4-byte alignment, so ensure doesn't straddle 64K.
             * Since 4-aligned, only bad if bottom 16 == 0xffffc.
             */
            PRE(bb, inst,
                INSTR_CREATE_cmp(drcontext, opnd_create_reg(reg2),
                                 OPND_CREATE_INT32(0xfffc)));
            add_jcc_slowpath(drcontext, bb, inst, OP_je_short, mi);
        }
    }
#else
    /* staleness doesn't care about alignment: the assumption is that any
     * (non-string) memory reference will only access one heap allocation
     * so we don't care whether it straddles two 8-byte shadow regions:
     * doesn't matter which side we mark as accessed.  FIXME: if we extend
     * to data section our assumptions will no longer be valid.
     */
#endif
    /* Get top 16 bits into lower half.  We'll do x4 in a scale later, which
     * saves us from having to clear the lower bits here via OP_and or sthg (PR
     * 553724).
     */
    PRE(bb, inst,
        INSTR_CREATE_shr(drcontext, opnd_create_reg(reg1), OPND_CREATE_INT8(16)));

    /* Index into table: no collisions and no tag storage since full size */
#ifdef TOOL_DR_HEAPSTAT
    /* Storing displacement, so add table result to app addr */
    PRE(bb, inst,
        INSTR_CREATE_add(drcontext, opnd_create_reg(reg2), opnd_create_base_disp
                         (REG_NULL, reg1, 4, (uint)shadow_table, OPSZ_PTR)));
#else
    PRE(bb, inst,
        INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(reg1), opnd_create_base_disp
                            (REG_NULL, reg1, 4, (uint)shadow_table, OPSZ_PTR)));
#endif

    if (need_offs) {
        /* Need 3rd scratch reg: can't ror and add since can't add 16-bit reg
         * to 32-bit reg.
         */
        /* FIXME opt: could re-lea, if addr doesn't use reg1 or reg2, and
         * avoid the need for reg3 for some uses that do not need it
         * later (e.g., insert_check_defined())
         */
        mark_matching_scratch_reg(drcontext, bb, mi, reg3);
        PRE(bb, inst,
            INSTR_CREATE_mov_st(drcontext, opnd_create_reg(reg3),
                                opnd_create_reg(reg2)));
    }
    /* Instead of finding the uint array index we go straight to the single
     * byte (or 2 bytes) that shadows this <4-byte (or 8-byte) read, since aligned.
     * If sub-dword but not aligned we go ahead and get shadow byte for
     * containing dword.
     */
#ifdef TOOL_DR_MEMORY
    PRE(bb, inst,
        INSTR_CREATE_shr(drcontext, opnd_create_reg(reg2), OPND_CREATE_INT8(2)));
#endif
    if (get_value) {
        /* load value from shadow table to reg1 */
        PRE(bb, inst,
            INSTR_CREATE_movzx(drcontext,
                               opnd_create_reg(value_in_reg2 ? reg2 : reg1),
                               opnd_create_base_disp
                               (reg1, reg2, 1, 0, mi->memsz == 8 ? OPSZ_2 : OPSZ_1)));
    } else {
#ifdef TOOL_DR_MEMORY
        PRE(bb, inst,
            INSTR_CREATE_lea(drcontext, opnd_create_reg(reg1),
                             opnd_create_base_disp(reg1, reg2, 1, 0, OPSZ_lea)));
#else
        /* more efficient for staleness to directly access via reg1+reg2 */
#endif
    }
    if (need_offs) {
        IF_DRHEAP(ASSERT(false, "shouldn't get here"));
        mi->offs = (!mi->need_offs && zero_rest_of_offs) ?
            opnd_create_reg(reg3_8h) :
            ((get_value && value_in_reg2) ?
             opnd_create_reg(reg1_8h) : opnd_create_reg(reg2_8h));
        /* store offset within containing dword in high 8 bits */
        ASSERT(mi->reg3.used, "spill error");
        PRE(bb, inst,
            INSTR_CREATE_mov_st(drcontext, mi->offs, opnd_create_reg(reg3_8)));
        if (zero_rest_of_offs) {
            /* for stores the top 16 bits are zero but not for loads: but data16 and
             * may not be any faster even if 1 byte smaller.
             *
             * FIXME opt: for some uses that don't need reg3 later (no
             * dest, but need offs for checking definedness) could avoid
             * the store above and keep offs in reg3_8h
             */
            reg_id_t reg = reg_to_pointer_sized(opnd_get_reg(mi->offs));
            PRE(bb, inst,
                INSTR_CREATE_and(drcontext, opnd_create_reg(reg),
                                 OPND_CREATE_INT32(0x00000300)));
        } else {
            PRE(bb, inst,
                INSTR_CREATE_and(drcontext, mi->offs, OPND_CREATE_INT8(0x3)));
        }
    } else if (zero_rest_of_offs) {
        IF_DRHEAP(ASSERT(false, "shouldn't get here"));
        /* caller wants the offset for checking definedness (PR 425240) but
         * doesn't need it for propagating, so need_offs is false and thus
         * no 3rd scratch reg was asked for.
         * we avoid a 3rd reg when not needed below by re-doing the lea */
        ASSERT(!mi->reg3.used, "spill error");
        ASSERT(!opnd_uses_reg(mi->memop, reg1) &&
               !opnd_uses_reg(mi->memop, reg2), "cannot re-lea");
        /* only used by non-mem2mem loads, so val is in reg2 and reg1 is now scratch */
        ASSERT(value_in_reg2, "clobbering reg1");
        ASSERT(!SHARING_XL8_ADDR(mi), "when sharing reg1 is in use");
        insert_lea(drcontext, bb, inst, mi->memop, reg1);
        mi->offs = opnd_create_reg(reg1_8h);
        PRE(bb, inst,
            INSTR_CREATE_and(drcontext, opnd_create_reg(reg1),
                             OPND_CREATE_INT32(0x3)));
        PRE(bb, inst,
            INSTR_CREATE_shl(drcontext, opnd_create_reg(reg1), OPND_CREATE_INT8(8)));
    }
}

#ifdef TOOL_DR_MEMORY
static opnd_t
shadow_immed(uint memsz, uint shadow_val)
{
    if (memsz <= 4)
        return OPND_CREATE_INT8((char)val_to_dword[shadow_val]);
    else
        return OPND_CREATE_INT16((short)val_to_qword[shadow_val]);
}

/* Assumes that scratch8 is the lower 8 bits of a GPR.
 * If opsz != 4 and offs is not constant neither src nor dst nor offs can use ecx.
 * May write to the upper 8 bits of scratch8's containing 16-bit register.
 * For opsz==4 this routine simply does a store from src to dst; else it
 * stores just those bits for opsz and offs from src into dst.
 * Assumes that src_opsz != dst_opsz only for movzx/movsx and only for
 * src_opsz==1 and dst_opsz==4.
 * If it uses scratch8, it calls mark_scratch_reg_used on si8.
 */
static inline void
add_dst_shadow_write(void *drcontext, instrlist_t *bb, instr_t *inst,
                     opnd_t dst, opnd_t src, int src_opsz, int dst_opsz,
                     opnd_t offs, reg_id_t scratch8, scratch_reg_info_t *si8,
                     bb_info_t *bi)
{
    /* PR 448701: we need to support writes to shadow blocks faulting.
     * Meta-instrs can't fault so we have to mark as non-meta and give
     * a translation.
     */
    app_pc xl8 = instr_get_app_pc(inst);
    ASSERT(src_opsz <= dst_opsz, "invalid opsz");
    ASSERT(dst_opsz <= 4 || dst_opsz == 8, "invalid opsz");
    ASSERT(src_opsz == dst_opsz ||
           ((src_opsz == 1 || src_opsz == 2) && dst_opsz == 4),
           "mismatched sizes only supported for src==1 or 2 dst==4");
    if (src_opsz == 4) {
        /* copy entire byte shadowing the dword */
        PREXL8M(bb, inst, INSTR_XL8(INSTR_CREATE_mov_st(drcontext, dst, src), xl8));
    } else if (src_opsz == 8) {
        /* copy entire 2 bytes shadowing the qword */
        PREXL8M(bb, inst, INSTR_XL8(INSTR_CREATE_mov_st(drcontext, dst, src), xl8));
    } else if (opnd_is_immed_int(src) && opnd_get_immed_int(src) == 0 &&
               opnd_is_immed_int(offs)) {
        int ofnum = opnd_get_immed_int(offs);
        ASSERT(src_opsz == dst_opsz, "expect same size for immed opnd");
        PREXL8M(bb, inst,
               INSTR_XL8(INSTR_CREATE_and
                         (drcontext, dst,
                          opnd_create_immed_int(~(((1 << dst_opsz*2)-1) << ofnum*2),
                                                OPSZ_1)), xl8));
        mark_eflags_used(drcontext, bb, bi);
    } else {
        reg_id_t temp = scratch8;
        opnd_t bits_op;
        /* dynamically-varying offset */
        mark_scratch_reg_used(drcontext, bb, bi, si8);
        mark_eflags_used(drcontext, bb, bi);
        if (opnd_is_immed_int(offs)) {
            int ofnum = opnd_get_immed_int(offs);
            if (src_opsz == dst_opsz) {
                bits_op = opnd_create_immed_int(~(((1 << src_opsz*2)-1) << ofnum*2),
                                                OPSZ_1);
            } else {
                bits_op = opnd_create_immed_int(((1 << src_opsz*2)-1) << ofnum*2, OPSZ_1);
            }
        } else {
            /* for shl we must use %cl */
            ASSERT(opnd_is_reg(offs), "offs invalid opnd");
            ASSERT(!opnd_uses_reg(dst, REG_ECX) &&
                   !opnd_uses_reg(src, REG_ECX) &&
                   !opnd_uses_reg(offs, REG_ECX),
                   "internal scratch reg error");
            bits_op = opnd_create_reg(REG_CH);
            temp = REG_CL;
            if (scratch8 != REG_CL) {
                PRE(bb, inst,
                    INSTR_CREATE_xchg(drcontext, opnd_create_reg(REG_ECX),
                                      opnd_create_reg(reg_to_pointer_sized(scratch8))));
                if (opnd_is_reg(offs) &&
                    reg_to_pointer_sized(opnd_get_reg(offs)) ==
                    reg_to_pointer_sized(scratch8)) {
                    reg_id_t r = opnd_get_reg(offs);
                    ASSERT(reg_is_8bit(r), "non-dword error");
                    offs = opnd_create_reg(reg_is_8bit_high(r) ? REG_CH : REG_CL);
                }
            }
            PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(REG_CL), offs));
            PRE(bb, inst,
                INSTR_CREATE_mov_imm(drcontext, bits_op,
                                     opnd_create_immed_int((1 << src_opsz*2)-1, OPSZ_1)));
            PRE(bb, inst, INSTR_CREATE_shl(drcontext, bits_op, opnd_create_reg(REG_CL)));
            PRE(bb, inst, INSTR_CREATE_shl(drcontext, bits_op, opnd_create_reg(REG_CL)));
            if (src_opsz == dst_opsz)
                PRE(bb, inst, INSTR_CREATE_not(drcontext, bits_op));
        }

        if (opnd_is_immed_int(src) && opnd_get_immed_int(src) == 0) {
            ASSERT(src_opsz == dst_opsz, "expect same size for immed opnd");
            PREXL8M(bb, inst, INSTR_XL8(INSTR_CREATE_and(drcontext, dst, bits_op), xl8));
        } else if (src_opsz != dst_opsz) {
            /* Propagate 2/4-bit pattern to entire 8, for movzx/movsx 
             * FIXME: movzx should set upper bits to 0 regardless; only movsx
             * should have upper bits depend on lower!
             */
            ASSERT((src_opsz == 1 || src_opsz == 2) && dst_opsz == 4, "movzx error");
            PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(temp), src));
            PRE(bb, inst, INSTR_CREATE_and(drcontext, opnd_create_reg(temp), bits_op));
            PRE(bb, inst, INSTR_CREATE_movzx(drcontext, opnd_create_reg(REG_ECX),
                                             opnd_create_reg(temp)));
            PRE(bb, inst,
                INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(REG_CL),
                                    OPND_CREATE_MEM8(REG_ECX,
                                                     (int)((src_opsz == 1) ?
                                                           shadow_2_to_dword :
                                                           shadow_4_to_dword))));
            PREXL8M(bb, inst, INSTR_XL8(INSTR_CREATE_mov_st
                                       (drcontext, dst, opnd_create_reg(REG_CL)), xl8));
        } else {
            /* set_2bits():
             *   orig &= (((0xfffffffc | val) << shift) | (~(0xffffffff << shift)));
             *   orig |= (val << shift);
             */
            /* Add ones around the source bits and set zeroes in target bits */
            PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(temp), src));
            PRE(bb, inst, INSTR_CREATE_or(drcontext, opnd_create_reg(temp), bits_op));
            PREXL8M(bb, inst, INSTR_XL8(INSTR_CREATE_and
                                       (drcontext, dst, opnd_create_reg(temp)), xl8));
            /* FIXME: this two-part non-atomic shadow table update is prone to
             * races.  Also note that we now use faults for PR 448701, but there
             * we always re-execute the cache instr.  If we ever redirect to
             * the app instr again we'll need to change this code to an atomic
             * single write at the end!
             */
            /* Place zeroes around the source bits and set ones in target bits */
            PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(temp), src));
            PRE(bb, inst, INSTR_CREATE_and(drcontext, opnd_create_reg(temp), bits_op));
            PREXL8M(bb, inst, INSTR_XL8(INSTR_CREATE_or
                                       (drcontext, dst, opnd_create_reg(temp)), xl8));
        }

        if (!opnd_is_immed_int(offs) && scratch8 != REG_CL) {
            PRE(bb, inst,
                INSTR_CREATE_xchg(drcontext, opnd_create_reg(REG_ECX),
                                  opnd_create_reg(reg_to_pointer_sized(scratch8))));
        }
    }
}

/* Calls add_dst_shadow_write() on both dst1 and dst2, with the same src */
static inline void
add_dstX2_shadow_write(void *drcontext, instrlist_t *bb, instr_t *inst,
                       opnd_t dst1, opnd_t dst2, opnd_t src, int src_opsz, int dst_opsz,
                       opnd_t offs, reg_id_t scratch8, scratch_reg_info_t *si8,
                       bb_info_t *bi)
{
    if (!opnd_is_null(dst1)) {
        add_dst_shadow_write(drcontext, bb, inst, dst1, src, src_opsz, dst_opsz, offs,
                             scratch8, si8, bi);
    }
    if (!opnd_is_null(dst2)) {
        add_dst_shadow_write(drcontext, bb, inst, dst2, src, src_opsz, dst_opsz, offs,
                             scratch8, si8, bi);
    }
}
#endif /* TOOL_DR_MEMORY */

/* PR 448701: we fault if we write to a special block, and we want to keep
 * specials in place when not actually changing them.  Instead of checking all
 * the specials, we compare the to-be-written shadow value to the existing
 * shadow value and avoid a write on the most common case of fully-defined being
 * written to SHADOW_SPECIAL_DEFINED, but also redundant writes to defined
 * non-special blocks.  On a mismatch if the target is a special shadow block
 * we'll fault, but that's rare enough that more inlined checks in the common
 * case are not worthwhile.
 *
 * Assumes that mi->reg1.reg holds the address of the shadow value.
 */
static inline void
add_check_datastore(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi, opnd_t shadow_val, instr_t *match_target)
{
    /* For a push/pop we should almost never hit a special-defined (even for a
     * new thread's stack since starts partway in) so we avoid the extra cmp.
     */
    if (mi->store && !mi->ignore_heap && !mi->pushpop_stackop) {
        /* If sub-dword we'll have a chance of a fault even if we wouldn't
         * be writing the mis-matching bits but not worth splitting out
         * in fastpath.
         */
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext,
                             mi->memsz <= 4 ? OPND_CREATE_MEM8(mi->reg1.reg, 0) :
                             OPND_CREATE_MEM16(mi->reg1.reg, 0), shadow_val));
        mark_eflags_used(drcontext, bb, mi->bb);
        PRE(bb, inst,
            INSTR_CREATE_jcc_short(drcontext, OP_je_short,
                                   opnd_create_instr(match_target)));
    }
}

#ifdef TOOL_DR_MEMORY
/* PR 448701: handle fault on write to a special shadow block */
static byte *
compute_app_address_on_shadow_fault(void *drcontext, byte *target,
                                    dr_mcontext_t *raw_mc, dr_mcontext_t *mc,
                                    byte *pc_post_fault, bb_saved_info_t *save)
{
    app_pc pc;
    app_pc addr;
    instr_t inst, app_inst;
    uint memopidx;
    bool write;
#ifdef DEBUG
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
#endif

    /* We need to restore the app registers in order to emulate the app instr
     * and obtain the original address referenced.  We assume all shadow table
     * writes involve a single base register and are followed by no ctis prior
     * to restoring the registers.
     */
    /* We're re-executing from raw_mc, so we change mc, which we did NOT fix up
     * in our restore_state event.  Note that our restore_state event has
     * restored eflags, but that doesn't hurt anything.
     */
    DOLOG(3, {
        LOG(3, "faulting cache instr:\n");
        disassemble_with_info(drcontext, raw_mc->pc, pt->f, true/*pc*/, true/*bytes*/);
        LOG(3, "original app instr:\n");
        disassemble_with_info(drcontext, mc->pc, pt->f, true/*pc*/, true/*bytes*/);
    });
    instr_init(drcontext, &app_inst);
    /* i#268: mc->pc might be in the middle of a hooked region so call
     * dr_app_pc_for_decoding()
     */
    decode(drcontext, dr_app_pc_for_decoding(mc->pc), &app_inst);
    pc = pc_post_fault;
    instr_init(drcontext, &inst);
    while (true) {
        pc = decode(drcontext, pc, &inst);
        DOLOG(3, {
            LOG(3, "considering potential restore instr: ");
            instr_disassemble(drcontext, &inst, pt->f);
            LOG(3, "\n");
        });
        ASSERT(instr_valid(&inst), "unknown suspect instr");
        if (instr_get_opcode(&inst) == OP_xchg) {
            reg_t val1, val2;
            reg_id_t reg1, reg2;
            bool swap = true;
            ASSERT(opnd_is_reg(instr_get_src(&inst, 0)) &&
                   opnd_is_reg(instr_get_src(&inst, 1)), "unknown xchg!");
            reg1 = opnd_get_reg(instr_get_src(&inst, 0));
            reg2 = opnd_get_reg(instr_get_src(&inst, 1));
            /* If one of the regs is a whole-bb spill, its real value is
             * in the TLS slot, so don't swap (PR 501740)
             */
            if (mc->pc != save->last_instr) {
                if (reg1 == save->scratch1 || reg1 == save->scratch2) {
                    swap = false;
                    if (reg2 == save->scratch1 || reg2 == save->scratch2) {
                        /* Both are global: do nothing since the fault
                         * restore put the proper values into mcxt
                         */
                    } else {
                        /* The app's value was in the global's mcxt slot */
                        val2 = reg_get_value(reg1, raw_mc);
                        reg_set_value(reg2, mc, val2);
                    }
                } else if (reg2 == save->scratch1 || reg2 == save->scratch2) {
                    swap = false;
                    /* The app's value was in the global's mcxt slot */
                    val1 = reg_get_value(reg2, raw_mc);
                    reg_set_value(reg1, mc, val1);
                }
            }
            if (swap) {
                val1 = reg_get_value(reg1, mc);
                val2 = reg_get_value(reg2, mc);
                reg_set_value(reg2, mc, val1);
                reg_set_value(reg1, mc, val2);
            }
        } else if (instr_get_opcode(&inst) == OP_mov_ld &&
                   opnd_is_far_base_disp(instr_get_src(&inst, 0))) {
            int offs = opnd_get_disp(instr_get_src(&inst, 0));
            ASSERT(opnd_get_index(instr_get_src(&inst, 0)) == REG_NULL, "unknown tls");
            ASSERT(opnd_get_segment(instr_get_src(&inst, 0)) == SEG_FS, "unknown tls");
            ASSERT(opnd_is_reg(instr_get_dst(&inst, 0)), "unknown tls");
            /* We read directly from the tls slot regardless of whether ours or
             * DR's: no easy way to translate to DR spill slot # and use C
             * interface.
             */
            reg_set_value(opnd_get_reg(instr_get_dst(&inst, 0)), mc,
                          get_raw_tls_value(offs));
        } else if (instr_get_opcode(&inst) == OP_mov_st &&
                   opnd_is_far_base_disp(instr_get_dst(&inst, 0)) &&
                   /* distinguish our pop store of 0x55 from slow slot eax spill */
                   opnd_get_size(instr_get_src(&inst, 0)) == OPSZ_PTR) {
            /* Start of non-fast DR spill slot sequence */
            /* FIXME: NOT TESTED: not easy since we now require our own spill slots */
            reg_t val;
            int offs;
            instr_reset(drcontext, &inst);
            pc = decode(drcontext, pc, &inst);
            ASSERT(instr_get_opcode(&inst) == OP_mov_ld &&
                   opnd_is_far_base_disp(instr_get_src(&inst, 0)), "unknown slow spill");

            /* Load from mcontext */
            instr_reset(drcontext, &inst);
            pc = decode(drcontext, pc, &inst);
            ASSERT(instr_get_opcode(&inst) == OP_mov_ld &&
                   opnd_is_near_base_disp(instr_get_src(&inst, 0)), "unknown slow spill");
            ASSERT(opnd_get_index(instr_get_src(&inst, 0)) == REG_NULL,
                   "unknown slow spill");
            ASSERT(opnd_is_reg(instr_get_dst(&inst, 0)), "unknown slow spill");
            offs = opnd_get_disp(instr_get_src(&inst, 0));
            ASSERT(offs < sizeof(*raw_mc), "unknown slow spill");
            val = *(reg_t *)(((byte *)raw_mc) + offs);
            reg_set_value(opnd_get_reg(instr_get_dst(&inst, 0)), mc, val);

            instr_reset(drcontext, &inst);
            pc = decode(drcontext, pc, &inst);
            ASSERT(instr_get_opcode(&inst) == OP_mov_ld &&
                   opnd_is_far_base_disp(instr_get_src(&inst, 0)), "unknown slow spill");
        } else if (instr_is_cti(&inst)) {
            break;
        }
        instr_reset(drcontext, &inst);
    }
    instr_free(drcontext, &inst);

    /* Adjust (esp) => (esp-X).  Xref i#164/PR 214976 where DR should adjust for us. */
    if (opc_is_push(instr_get_opcode(&app_inst))) {
        mc->xsp -= adjust_memop_push_offs(&app_inst);
    }

    for (memopidx = 0;
         instr_compute_address_ex(&app_inst, mc, memopidx, &addr, &write);
         memopidx++) {
        LOG(3, "considering emulated target %s "PFX" => shadow "PFX" vs fault "PFX"\n",
            write ? "write" : "read", addr, shadow_translation_addr(addr), target);
        if (shadow_translation_addr(addr) == target)
            break;
    }
    ASSERT(shadow_translation_addr(addr) == target,
           "unable to compute original address on shadow fault");
    instr_free(drcontext, &app_inst);

    return addr;
}

static void
handle_special_shadow_fault(void *drcontext, byte *target,
                            dr_mcontext_t *raw_mc, dr_mcontext_t *mc, void *tag)
{
    /* Re-execute the faulting instruction.  We have to shift the instruction's
     * base register from the special block to the new block.  An alternative is
     * to restore the app context and then re-direct execution to a new bb: but
     * that's more complex (have to decode forward and emulate all xchg +
     * restore-from-tls until next cti) and less efficient (new bb, and we'd
     * have to change two-part sub-dword dst write to get final value in reg
     * before committing).  Actually we do have to restore app state to get app
     * address -- but the other arguments still apply so sticking w/ re-execute.
     */
    app_pc pc;
    app_pc addr;
    instr_t fault_inst;
    byte *new_shadow;
    opnd_t shadowop;
    bb_saved_info_t *save;
#ifdef DEBUG
    per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
#endif

    LOG(2, "write fault to special shadow @"PFX"\n", target);
    STATS_INC(num_faults);
#ifdef TOOL_DR_HEAPSTAT
    ASSERT(false, "should not get here");
#endif

    if (is_in_gencode(raw_mc->pc)) {
        /* PR 503778: the esp_adjust fastpath now touches more than just the 64K
         * region containing the app esp.  We could calculate its exact address
         * by locating the precise routine and then use the count from tls and
         * remaining count, and then below adjust the stored boundary, but
         * simpler to bail to slowpath.
         */
        byte *nxt_pc;
        instr_t inst;
        pc = raw_mc->pc;
        instr_init(drcontext, &inst);
        nxt_pc = decode(drcontext, pc, &inst);
        do {
            if (instr_get_opcode(&inst) == OP_mov_ld &&
                opnd_is_far_base_disp(instr_get_src(&inst, 0))) {
                ASSERT(opnd_get_index(instr_get_src(&inst, 0)) == REG_NULL, "bad tls");
                ASSERT(opnd_get_segment(instr_get_src(&inst, 0)) == SEG_FS, "bad tls");
                ASSERT(opnd_is_reg(instr_get_dst(&inst, 0)), "bad tls");
                LOG(3, "write fault in gencode "PFX" => xl8 to slowpath "PFX"\n",
                    raw_mc->pc, pc);
                raw_mc->pc = pc;
                instr_free(drcontext, &inst);
                return;
            }
            instr_reset(drcontext, &inst);
            pc = nxt_pc;
            nxt_pc = decode(drcontext, pc, &inst);
        } while (pc - raw_mc->pc < PAGE_SIZE);
        ASSERT(false, "cannot find slowpath sequence in esp fastpath!");
    }

    instr_init(drcontext, &fault_inst);
    pc = decode(drcontext, raw_mc->pc, &fault_inst);

    hashtable_lock(&bb_table);
    save = (bb_saved_info_t *) hashtable_lookup(&bb_table, tag);
    addr = compute_app_address_on_shadow_fault(drcontext, target, raw_mc, mc, pc,
                                               save);
    hashtable_unlock(&bb_table);

    /* Create a non-special shadow block */
    new_shadow = shadow_replace_special(addr);
    /* Change base register to point at it */
    shadowop = instr_get_dst(&fault_inst, 0);
    ASSERT(opnd_is_base_disp(shadowop) && opnd_get_index(shadowop) == REG_NULL,
           "emulation error");
    ASSERT(opnd_compute_address(shadowop, raw_mc) == target, "emulation error");
    reg_set_value(opnd_get_base(shadowop), raw_mc, (reg_t)new_shadow);
    DOLOG(3, {
        LOG(3, "changed base reg in ");
        opnd_disassemble(drcontext, shadowop, pt->f);
        LOG(3, " to new non-special translation "PFX"\n", new_shadow);
    });

    instr_free(drcontext, &fault_inst);
}
#endif /* TOOL_DR_MEMORY */

/* PR 448701: we fault if we write to a special block */
#ifdef LINUX
dr_signal_action_t
event_signal_instrument(void *drcontext, dr_siginfo_t *info)
{
# ifdef TOOL_DR_MEMORY
    /* Handle faults from writes to special shadow blocks */
    if (info->sig == SIGSEGV) {
        byte *target = info->access_address;
        /* We don't know whether a write since DR isn't providing that info but
         * shouldn't matter enough to be worth our determining
         */
        LOG(3, "SIGSEGV @"PFX" (xl8=>"PFX") accessing "PFX"\n",
            info->raw_mcontext.xip, info->mcontext.xip, target);
        if (is_in_special_shadow_block(target)) {
            ASSERT(info->raw_mcontext_valid, "raw mc should always be valid for SEGV");
            handle_special_shadow_fault(drcontext, target, &info->raw_mcontext,
                                        &info->mcontext, info->fault_fragment_info.tag);
            /* Re-execute the faulting cache instr.  If we ever change to redirect
             * to a new bb at the app instr we must change our two-part shadow
             * write for sub-dword.
             */
            return DR_SIGNAL_SUPPRESS;
        }
    }
# endif
    return DR_SIGNAL_DELIVER;
}
#else
bool
event_exception_instrument(void *drcontext, dr_exception_t *excpt)
{
# ifdef TOOL_DR_MEMORY
    if (excpt->record->ExceptionCode == STATUS_ACCESS_VIOLATION) {
        app_pc target = (app_pc) excpt->record->ExceptionInformation[1];
        if (excpt->record->ExceptionInformation[0] == 1 /* write */ &&
            is_in_special_shadow_block(target)) {
            handle_special_shadow_fault(drcontext, target, &excpt->raw_mcontext,
                                        &excpt->mcontext, excpt->fault_fragment_info.tag);
            /* Re-execute the faulting cache instr.  If we ever change to redirect
             * to a new bb at the app instr we must change our two-part shadow
             * write for sub-dword.
             */
            return false;
        }
    }
# endif
    return true;
}
#endif

/* Fast path for "normal" instructions with a single memory 
 * reference using 4-byte addressing registers.
 * Handles mem-to-reg (including pop), reg-to-mem (including push),
 * ALU ops, and destination-less loads (like cmp and test).
 * Does NOT handle pop into mem.
 * Handles push from mem and call*.
 * Bails to slowpath on corner cases, but does not modify
 * any state beforehand, so slowpath can start over.
 * Those corner cases include:
 * - unaligned accesses
 * - not fully defined operands
 * - shadow table alloc needed
 */
/* TODO Optimizations:
 * - shared restore of eflags + spill1 + spill2 among slow and fastpath?
 *   then need to store 1,0 into ecx and use jecxz.  can save some code
 *   but it's not huge.  better to optimize for push,pop (either for
 *   multiple in a row, or via shadow stack at const offset from real stack)
 *   or optimize across instrs for dead regs.
 *
 * - jcc => saves eflags, cmps eflags shadow to 0, restores eflags on
 *     both sides of cmp with one side jmping to shared slowpath.
 *   changing to jecxz only saves lahf,seto and 2x add,sahf
 */
void
instrument_fastpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi, bool ignore_heap)
{
    uint opc = instr_get_opcode(inst);
    reg_id_t reg1_8, reg2_16, reg2_8, reg2_8h, reg3_8;
#ifdef TOOL_DR_MEMORY
    reg_id_t scratch8;
    scratch_reg_info_t *si8;
    opnd_t shadow_dst, shadow_dst2;
    opnd_t shadow_src, shadow_src2, shadow_src3;
#endif
    instr_t *nextinstr = INSTR_CREATE_label(drcontext);
    instr_t *fastpath_restore = INSTR_CREATE_label(drcontext);
    instr_t *spill_location = INSTR_CREATE_label(drcontext);
#ifdef TOOL_DR_MEMORY
    instr_t *marker1, *marker2;
    bool mark_defined;
#endif
    bool save_aflags;
    int num_to_propagate = 0;
#ifdef TOOL_DR_MEMORY
    bool checked_src2 = false, checked_memsrc = false;
#endif
    bool share_addr = false;
    bool need_nonoffs_reg3 = false;
#ifdef DEBUG
    instr_t *instru_start = instr_get_prev(inst);
#endif

    /* mi is memset to 0 so bools and pointers are false/NULL */
    mi->ignore_heap = ignore_heap;
    mi->slowpath = INSTR_CREATE_label(drcontext);

#ifdef TOOL_DR_MEMORY
    ASSERT(!opc_is_stringop_loop(opc), "internal error"); /* handled elsewhere */
#endif
    mi->check_definedness = instr_check_definedness(inst);

    /* we assume caller has called instr_ok_for_instrument_fastpath() */
    if (!adjust_opnds_for_fastpath(inst, mi)) {
        instrument_slowpath(drcontext, bb, inst, NULL);
        return;
    }

    /* check sharing prior to picking scratch regs b/c in combination w/
     * sub-dword check_definedness (PR 425240) we need a 3rd reg
     */
    if ((mi->load || mi->store) && (!mi->ignore_heap || mi->pushpop_stackop)) {
        mi->use_shared = SHARING_XL8_ADDR(mi);
        /* See if we can share our translation w/ next instr.  Decide up
         * front, b/c preserving the addr takes an extra step for loads.
         */
        if (should_share_addr(inst, mi, mi->use_shared ? mi->bb->shared_memop :
                              mi->memop)) {
            share_addr = true;
            if (!mi->use_shared) { /* store the 1st, to calculate max disp */
                mi->bb->shared_memop = mi->memop;
                mi->bb->shared_disp_implicit = 0;
                mi->bb->shared_disp_reg1 = 0;
            }
        }
        if (!mi->need_offs && mi->opsz < 4 && !opnd_is_immed_int(mi->offs) && mi->load) {
            /* PR 425240: check just the bits involved for srcs => need a reg
             * to put offs in.  If we're not sharing we use reg1: else we need
             * a 3rd reg.
             */
            if (mi->use_shared || share_addr ||
                /* We can only use reg1 if we can re-lea: we can't if mem op uses regs.
                 * We require whole-bb so that we know the regs here.
                 */
                (whole_bb_spills_enabled() && mi->load &&
                 (opnd_uses_reg(mi->memop, mi->bb->reg1.reg) ||
                  opnd_uses_reg(mi->memop, mi->bb->reg2.reg))))                
                need_nonoffs_reg3 = true;
        }
    }

    /* set up regs and spill info */
    pick_scratch_regs(inst, mi, true/*only pick a,b,c,d*/,
                      /* we need 3rd reg for temp to get offs while getting
                       * shadow byte address, and also temp to set dest bits in
                       * add_dst_shadow_write(); we also need to handle 2nd
                       * memop for mem2mem.
                       */
                      mi->need_offs || mi->mem2mem || need_nonoffs_reg3,
                      !need_nonoffs_reg3, mi->memop,
                      (mi->mem2mem && !mi->ignore_heap) ? mi->src[0] : opnd_create_null());
    reg1_8 = reg_32_to_8(mi->reg1.reg);
    reg2_16 = reg_32_to_16(mi->reg2.reg);
    reg2_8 = reg_32_to_8(mi->reg2.reg);
    reg2_8h = reg_32_to_8h(mi->reg2.reg);
    reg3_8 = (mi->reg3.reg == REG_NULL) ? REG_NULL : reg_32_to_8(mi->reg3.reg);

#ifdef TOOL_DR_MEMORY
    /* point at the locations of shadow values for operands */
    if (opnd_is_memory_reference(mi->dst[0])) {
        if (mi->ignore_heap && !mi->pushpop_stackop)
            shadow_dst = opnd_create_null();
        else {
            if (mi->memsz <= 4)
                shadow_dst = OPND_CREATE_MEM8(mi->reg1.reg, 0);
            else
                shadow_dst = OPND_CREATE_MEM16(mi->reg1.reg, 0);
        }
    } else if (mi->dst_reg != REG_NULL)
        shadow_dst = opnd_create_shadow_reg_slot(mi->dst_reg);
    else
        shadow_dst = opnd_create_null();
    if (opnd_is_null(mi->dst[1]))
        shadow_dst2 = opnd_create_null();
    else {
        ASSERT(opnd_is_reg(mi->dst[1]) && reg_is_gpr(opnd_get_reg(mi->dst[1])),
               "reg fastpath error");
        shadow_dst2 = opnd_create_shadow_reg_slot(opnd_get_reg(mi->dst[1]));
    }
    if (opnd_is_memory_reference(mi->src[0])) {
        if (mi->store && !mi->mem2mem) {
            /* must be alu */
            ASSERT(opnd_same(mi->dst[0], mi->src[0]), "dual mem ref error");
            /* need to reference by address not value so copy dst shadow */
            shadow_src = shadow_dst;
        } else {
            ASSERT(mi->load || mi->store, "mem must be load or store");
            if (mi->memsz <= 4)
                shadow_src = opnd_create_reg(reg2_8);
            else
                shadow_src = opnd_create_reg(reg2_16);
        }
        num_to_propagate++;
    } else if (!opnd_is_null(mi->src[0])) {
        shadow_src = opnd_create_shadow_reg_slot(mi->src_reg);
        num_to_propagate++;
    } else 
        shadow_src = opnd_create_null();
    if (opnd_is_null(mi->src[1]))
        shadow_src2 = opnd_create_null();
    else {
        ASSERT(opnd_is_reg(mi->src[1]) && reg_is_gpr(opnd_get_reg(mi->src[1])),
               "reg fastpath error");
        shadow_src2 = opnd_create_shadow_reg_slot(opnd_get_reg(mi->src[1]));
        num_to_propagate++;
    }
    if (opnd_is_null(mi->src[2]))
        shadow_src3 = opnd_create_null();
    else {
        ASSERT(opnd_is_reg(mi->src[2]) && reg_is_gpr(opnd_get_reg(mi->src[2])),
               "reg fastpath error");
        shadow_src3 = opnd_create_shadow_reg_slot(opnd_get_reg(mi->src[2]));
        num_to_propagate++;
    }

    mark_defined = result_is_always_defined(inst) ||
        /* no sources (e.g., rdtsc) */
        opnd_is_null(mi->src[0]) ||
        (mi->ignore_heap && mi->store && !mi->pushpop_stackop) ||
        /* move immed into reg or memory */
        (!mi->load && num_to_propagate == 0 && (mi->store || mi->dst_reg != REG_NULL));
    if (mark_defined) {
        LOG(3, "\tmark_defined\n");
        num_to_propagate = 0;
    }

    if (instr_needs_all_srcs_and_vals(inst)) {
        /* Strategy for and/test/or: don't need 2 passes like slowpath since
         * if check_definedness we can bail out to slowpath and start over there.
         * Thus we mark as checking for OP_and and OP_or; OP_test by default is
         * if options.check_cmps.
         */
        mi->check_definedness = true;
        /* To do the full check in the fastpath would take some work:
         * would need to get vals and if defined and 0/1 => dst defined
         */
    }
    /* Similarly for shifts, since we don't have insert_shadow_op() fully
     * operational yet
     */
    if (opc_is_gpr_shift(opc))
        mi->check_definedness = true;
    /* For 1-byte and 2-byte operand sizes, we bail to slowpath if any part of
     * containing aligned dword for sources or mem opnd is undefined.  Then we
     * can use entire dword's shadow byte just like a 4-byte operand, both for
     * registers and for memory, for comparing sources and writing to eflags.
     *
     * Update: with PR 425240 for check_defined sources we use a table lookup to
     * check only the appropriate shadow bits, keeping OP_cmp and other common
     * sub-dword-defined ops off the slowpath.  Since we only do this for
     * check_defined, which are not propagated, we can still write to eflags w/o
     * extracting bits.
     *
     * This also lets us handle movzx and movsx in the fastpath.  When
     * they have 1-byte source and 4-byte dst we have special support
     * to extract just the 2 bits needed and expand, as it's common
     * to have the rest of the dword undefined.
     * (movzx/movsx are marked undefined up above)
     *
     * We still need to extract and write only the appropriate bits when
     * propagating to shadow dest, though, but for reg-reg we can simply
     * do a bitwise and.
     */
    if (mi->opsz != 4 ||
        (!opnd_is_null(mi->src[0]) &&
         opnd_size_in_bytes(opnd_get_size(mi->src[0])) < mi->opsz &&
         /* cwde, etc. */
         opc != OP_movzx && opc != OP_movsx))
        mi->check_definedness = true;
    /* We support push-mem and call_ind but we bail to slowpath if push-mem src is
     * not fully defined, since we don't support fastpath propagation for mem2mem
     */
    if (mi->mem2mem) {
        ASSERT(mi->store && opnd_same(mi->memop, mi->dst[0]), "mem2mem error");
        ASSERT(opnd_is_memory_reference(mi->src[0]), "mem2mem error");
        mi->check_definedness = true;
    }
    /* For the 2nd dst of OP_leave, ebp->esp, we rely on check_definedness to
     * ensure ebp is defined and add_addressing_register_checks for esp being defined,
     * and bail to slowpath o/w, as we don't support 2 separate propagation chains
     */
    if (opc == OP_leave)
        mi->check_definedness = true;
    DOLOG(4, {
        if (mi->check_definedness) {
            per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
            LOG(3, "checking definedness for: ");
            instr_disassemble(drcontext, inst, pt->f);
            LOG(3, "\n");
        }
    });
#endif /* TOOL_DR_MEMORY */

    LOG(5, "aflags: %s\n", mi->aflags == EFLAGS_WRITE_6 ? "W6" :
          (mi->aflags == EFLAGS_WRITE_OF ? "WO" :
           (mi->aflags == EFLAGS_READ_6 ? "R6" : "0")));
    ASSERT(mi->opsz != 4 || opnd_same(mi->offs, opnd_create_immed_int(0, OPSZ_1)),
           "4-byte should have 0 offset");
    ASSERT(mi->dst_reg == REG_NULL || opnd_size_in_bytes(opnd_get_size(mi->dst[0])) == mi->opsz,
           "dst/src size mismatch");
    ASSERT(mi->src_reg == REG_NULL || opnd_is_immed_int(mi->src[0]) ||
           opc_is_gpr_shift(opc) /* %cl */ ||
           ((mi->check_definedness /* see above: ok to have smaller srcs here */
             || opc == OP_movzx || opc == OP_movsx) &&
           opnd_size_in_bytes(opnd_get_size(mi->src[0])) <= mi->opsz) ||
           opnd_size_in_bytes(opnd_get_size(mi->src[0])) == mi->opsz,
           "dst/src size mismatch");
#ifdef TOOL_DR_MEMORY
    ASSERT(!mi->mem2mem || mi->check_definedness, "mem2mem only supported if not propagating");
#endif

    /* leave a marker so we can insert spills once we know whether we need them */
    PRE(bb, inst, spill_location);

    /* Before any of the leas, restore global spilled registers */
    /* not doing lea if sharing trans, and this restore will clobber shared addr */
    if (!mi->use_shared) {
        if (opnd_uses_reg(mi->memop, mi->bb->reg1.reg)) {
            insert_spill_global(drcontext, bb, inst, &mi->bb->reg1, false/*restore*/);
        }
        if (opnd_uses_reg(mi->memop, mi->bb->reg2.reg)) {
            insert_spill_global(drcontext, bb, inst, &mi->bb->reg2, false/*restore*/);
        }
    } else
        ASSERT(!mi->mem2mem, "once share for mem2mem must spill for lea");

    /* lea before any reg write (incl eflags eax) in case address calc uses that reg */
    if ((mi->load || mi->store) && (!mi->ignore_heap || mi->pushpop_stackop ||
                                    (mi->opsz != 4 && !opnd_is_immed_int(mi->offs)))) {
        if (!mi->use_shared) { /* don't need lea if sharing trans */
            mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg1);
            insert_lea(drcontext, bb, inst, mi->memop, mi->reg1.reg);
        }
    }
    if (mi->mem2mem && !mi->ignore_heap) {
        mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg3);
        if (opnd_uses_reg(mi->src[0], mi->bb->reg2.reg))
            insert_spill_global(drcontext, bb, inst, &mi->bb->reg2, false/*restore*/);
        if (opnd_uses_reg(mi->src[0], mi->reg1.reg)) {
            spill_reg(drcontext, bb, inst, mi->reg1.reg, SPILL_SLOT_5);
            if (mi->reg1.global)
                insert_spill_global(drcontext, bb, inst, &mi->bb->reg1, false/*restore*/);
            else
                restore_reg(drcontext, bb, inst, mi->reg1.reg, mi->reg1.slot);
            insert_lea(drcontext, bb, inst, mi->src[0], mi->reg3.reg);
            restore_reg(drcontext, bb, inst, mi->reg1.reg, SPILL_SLOT_5);
        } else
            insert_lea(drcontext, bb, inst, mi->src[0], mi->reg3.reg);
    }

    /* don't need to save flags for things like rdtsc */
    save_aflags = (!whole_bb_spills_enabled() &&
                   (mi->load || mi->store ||
                    num_to_propagate > 0 ||
                    mi->src_opsz != 4 ||
#ifdef STATISTICS
                    options.statistics ||
#endif
                    TESTANY(EFLAGS_READ_6, instr_get_eflags(inst))));
    /* we don't use dr_save_arith_flags so we can use seto only when necessary */
    if (save_aflags && mi->aflags != EFLAGS_WRITE_6) {
        insert_save_aflags(drcontext, bb, inst, &mi->eax, mi->aflags);
    }

    /* PR 530902: cmovcc should ignore src+dst unless eflags matches.  See full
     * notes below.  We record here whether the condition matches prior to
     * messing up the app aflags (condition depends on app aflags).  Checking
     * aflags definedness won't disturb reg2 and the leas above do not use reg2.
     * We update scratch_reg*_is_avail() so aflags save won't touch reg1
     * (holds lea result) or reg2 (holds setcc result) (PR 558319).
     */
    if (opc_is_cmovcc(opc) || opc_is_fcmovcc(opc)) {
        int setcc_opc = instr_cmovcc_to_jcc(opc) - OP_jo + OP_seto;
        /* for whole-bb we have to restore and then re-save aflags.
         * optimization: we should avoid the restore+spill of eax
         */
        if (whole_bb_spills_enabled()) {
            restore_aflags_if_live(drcontext, bb, inst, mi, mi->bb);
            /* avoid double-save at top */
            mi->bb->eflags_used = true;
        }
        mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);
        PRE(bb, inst, INSTR_CREATE_setcc(drcontext, setcc_opc, opnd_create_reg(reg2_8)));
        if (whole_bb_spills_enabled()) {
            save_aflags_if_live(drcontext, bb, inst, mi, mi->bb);
        }
    }

#ifdef TOOL_DR_MEMORY
    /* Check definedness of eflags.  Xref PR 425622. */
    if (TESTANY(EFLAGS_READ_6, instr_get_eflags(inst))) {
        /* we always write the full byte to make this cmp easy */
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, opnd_create_shadow_eflags_slot(),
                             OPND_CREATE_INT8((char)SHADOW_DWORD_DEFINED)));
        mark_eflags_used(drcontext, bb, mi->bb);
        add_jcc_slowpath(drcontext, bb, inst, OP_jne, mi);
        ASSERT(save_aflags || whole_bb_spills_enabled(),
               "must save aflags if instr reads eflags");
    }
#endif /* TOOL_DR_MEMORY */

    /* PR 530902: cmovcc should ignore src+dst unless eflags matches.  For both
     * cmovcc and fcmovcc we treat an unmatched case as though the source and
     * dest do not exist: certainly source should not propagate to dest, whether
     * we should check for addressability of source is debatable: not doing it
     * for now.  We do have to check whether eflags is defined though, so prior
     * to that we setcc into reg2_8.
     */
    if (opc_is_cmovcc(opc) || opc_is_fcmovcc(opc)) {
        /* Unfortunately we have to save aflags for eflags-defined check and
         * then restore here. Since reg restores must come before aflags
         * restore, we can't re-use any post-instr restores (even harder w/
         * whole-bb) so we must re-save aflags before jumping to end of instr
         */
        PRE(bb, inst, INSTR_CREATE_cmp(drcontext, opnd_create_reg(reg2_8),
                                       OPND_CREATE_INT8(0)));
        PRE(bb, inst, INSTR_CREATE_jcc_short(drcontext, OP_je,
                                            opnd_create_instr(fastpath_restore)));
    }

#ifdef TOOL_DR_MEMORY
    /* check definedness of addressing registers.
     * for pushpop this also suffices to cover the read+write of esp
     * (and thus we don't need to propagate definedness for esp, reducing
     *  # opnds for pushpop instrs).
     * we do this for mi->ignore_heap as well.
     * for lea probably better to consider addressing registers are
     * non-memory-related operands: but then I'd need to support 2 reg
     * sources in fastpath, so for now we treat as addressing.
     */
    if ((mi->load || mi->store) && opnd_is_base_disp(mi->memop)) {
        add_addressing_register_checks(drcontext, bb, inst, mi->memop, mi);
    }
    if (mi->mem2mem) {
        add_addressing_register_checks(drcontext, bb, inst, mi->src[0], mi);
    }
#endif /* TOOL_DR_MEMORY */

    if (mi->mem2mem && !mi->ignore_heap) {
        bool need_value = IF_DRMEM_ELSE(true, false);
        add_shadow_table_lookup(drcontext, bb, inst, mi, need_value,
                                false/*val in reg1*/, false/*no offs*/, false/*no offs*/,
                                mi->reg3.reg, mi->reg2.reg,
                                mi->reg1.reg/*won't be touched!*/);
        ASSERT(reg3_8 != REG_NULL && mi->reg3.used, "reg spill error");
#ifdef TOOL_DR_MEMORY
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, opnd_create_reg(reg3_8),
                             OPND_CREATE_INT8((char)SHADOW_DWORD_DEFINED)));
        mark_eflags_used(drcontext, bb, mi->bb);
        add_jcc_slowpath(drcontext, bb, inst, OP_jne, mi);
        /* now we're done with the src mem op so we proceed to the dst.
         * if we want to use shadow_dword_is_addr_not_bit table we'll have
         * to add propagation of this mem src.
         */
        shadow_src = opnd_create_null();
        num_to_propagate--;
        /* shouldn't be other srcs */
        ASSERT(opnd_is_null(shadow_src2), "mem2mem error");
#else
        /* shadow lookup left reg3+reg2 holding address */
        if (!options.stale_blind_store) {
            /* FIXME: measure perf to see which is better */
            /* cmp and avoid store can be faster than blindly storing */
            PRE(bb, inst,
                INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg2.reg, 0),
                                 OPND_CREATE_INT8(0)));
            mark_eflags_used(drcontext, bb, mi->bb);
            PRE(bb, inst,
                INSTR_CREATE_jcc(drcontext, OP_jnz_short,
                                 opnd_create_instr(fastpath_restore)));
        }
        PRE(bb, inst,
            INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM8(mi->reg2.reg, 0),
                                OPND_CREATE_INT8(1)));
#endif
    }

#ifdef TOOL_DR_MEMORY
    /* PR 425240: check just the bits for sub-dword sources 
     * This setting is independent of mi->need_offs, b/c for some
     * operands we don't need the offset later.
     */
    mi->zero_rest_of_offs =
        (mi->load &&
         ((mi->opsz < 4 && !mark_defined && mi->check_definedness) ||
          /* PR 503782: we use the offs for table lookup for loads */
          (mi->memsz < 4 && options.loads_use_table && mi->need_offs)));

    if ((mi->load || mi->store) && (!mi->ignore_heap || mi->pushpop_stackop)) {
        /* want value only for some loads */
        bool need_value;
        /* we set mi->use_shared, share_addr, and mi->bb->shared_* above */
        IF_DEBUG(if (share_addr))
            ASSERT(mi->reg1.reg == mi->bb->reg1.reg, "sharing requires reg1==bb reg1");
        need_value = mi->load && !mi->pushpop && !share_addr;

        /* PR 493257: share shadow translation across multiple instrs */
        if (!mi->use_shared) {
            add_shadow_table_lookup(drcontext, bb, inst, mi, need_value,
                                    true/*val in reg2*/,
                                    mi->need_offs || need_nonoffs_reg3,
                                    mi->zero_rest_of_offs,
                                    mi->reg1.reg, mi->reg2.reg, mi->reg3.reg);
            /* For mi->need_offs, we assume that all uses of reg2 below are
             * low 8 bits only! 
             */
        } else {
            /* The prev instr already checked for whether should share */
            int diff;
            STATS_INC(xl8_shared);
            hashtable_add(&xl8_sharing_table, instr_get_app_pc(inst), (void *)1);
            /* FIXME: best to remove these entires when containing fragment
             * gets flushed: but would have to walk whole table.  Never
             * deleting for now.  If address is re-used we simply won't share
             * so nothing that bad will happen.
             */
            ASSERT(mi->reg1.reg == mi->bb->reg1.reg, "sharing requires reg1==bb reg1");
            diff = opnd_get_disp(mi->memop) -
                (opnd_get_disp(mi->bb->shared_memop) + mi->bb->shared_disp_implicit);
            LOG(3, "  sharing shadow addr: disp = %d - (%d + %d) => %d /4 - %d\n",
                opnd_get_disp(mi->memop), opnd_get_disp(mi->bb->shared_memop),
                mi->bb->shared_disp_implicit, diff, mi->bb->shared_disp_reg1);
            diff /= 4; /* 2 shadow bits per byte */
            /* Subtract what's already been incorporated into the reg */
            diff -= mi->bb->shared_disp_reg1;
            if (mi->load && !mi->pushpop) { /* want value */
                PRE(bb, inst,
                    INSTR_CREATE_movzx(drcontext, opnd_create_reg(mi->reg2.reg),
                                       OPND_CREATE_MEM8(mi->reg1.reg, diff)));
            } else {
                mi->bb->shared_disp_reg1 += diff;
                /* No reason to avoid eflags since will use cmp below anyway */
                mark_eflags_used(drcontext, bb, mi->bb);
                insert_add_to_reg(drcontext, bb, inst, mi->reg1.reg, diff);
            }
        }
        if (!share_addr)
            mi->bb->shared_memop = opnd_create_null();
        else if (mi->pushpop_stackop)
            mi->bb->shared_disp_implicit += (mi->load ? -(int)mi->memsz : mi->memsz);
    } else if ((mi->load || mi->store) && mi->need_offs) {
        ASSERT(false, "not supported"); /* not updated for PR 425240, etc. */
        mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);
        mark_eflags_used(drcontext, bb, mi->bb);
        PRE(bb, inst,
            INSTR_CREATE_mov_st(drcontext, opnd_create_reg(reg2_8h),
                                opnd_create_reg(reg1_8)));
        PRE(bb, inst,
            INSTR_CREATE_and(drcontext, opnd_create_reg(reg2_8h),
                             OPND_CREATE_INT8(0x3)));
        mi->offs = opnd_create_reg(reg2_8h);
    }
    if (mi->load && (mi->pushpop || (share_addr && !mi->use_shared))) {
        /* A pop into a register or memory, or any load sharing its shadow addr.
         * We need both shadow table slot address and value.  Address is
         * currently in reg1; we get value into reg2.
         */
        ASSERT(mi->reg1.used && mi->reg2.used, "internal reg spill error");
        ASSERT(!mi->need_offs, "assuming don't need reg2_8h");
        PRE(bb, inst,
            INSTR_CREATE_movzx(drcontext, opnd_create_reg(mi->reg2.reg),
                               OPND_CREATE_MEM8(mi->reg1.reg, 0)));
    }

    /* check definedness of sources, if necessary.
     * we process in reverse order so we can shift shadow_src* but we 
     * insert in normal order so we can use reg2 in insert_check_defined.
     */
    marker2 = instr_get_prev(inst);
    marker1 = inst;
    if (!opnd_is_null(mi->src[2]) && !mark_defined &&
        (mi->check_definedness ||
         (mi->opnum[2] != -1 &&
          always_check_definedness(inst, mi->opnum[2])))) {
        LOG(4, "\tchecking definedness of src3 => %d to propagate\n", num_to_propagate-1);
        insert_check_defined(drcontext, bb, marker1, mi, mi->src[2], shadow_src3);
        mark_eflags_used(drcontext, bb, mi->bb);
        add_jcc_slowpath(drcontext, bb, marker1, OP_jne_short, mi);
        num_to_propagate--;
        shadow_src3 = opnd_create_null();
    }
    marker1 = instr_get_next(marker2);
    if (!opnd_is_null(mi->src[1]) && !mark_defined &&
        (mi->check_definedness ||
         (mi->opnum[1] != -1 &&
          always_check_definedness(inst, mi->opnum[1])))) {
        LOG(4, "\tchecking definedness of src2 => %d to propagate\n", num_to_propagate-1);
        insert_check_defined(drcontext, bb, marker1, mi, mi->src[1], shadow_src2);
        mark_eflags_used(drcontext, bb, mi->bb);
        add_jcc_slowpath(drcontext, bb, marker1, OP_jne_short, mi);
        num_to_propagate--;
        shadow_src2 = shadow_src3;
        shadow_src3 = opnd_create_null();
        checked_src2 = true;
    }
    marker1 = instr_get_next(marker2);
    if (mi->ignore_heap && mi->load && !mi->pushpop) {
        /* we didn't need to load the shadow value but that's ok, rare case */
        num_to_propagate--;
        shadow_src = shadow_src2;
        shadow_src2 = shadow_src3;
        shadow_src3 = opnd_create_null();
    } else if (!opnd_is_null(mi->src[0]) && !opnd_is_null(shadow_src) &&
               !mark_defined &&
               (mi->check_definedness ||
                (mi->opnum[0] != -1 &&
                 always_check_definedness(inst, mi->opnum[0])))) {
        LOG(4, "\tchecking definedness of src1 => %d to propagate\n", num_to_propagate-1);
        /* optimization: avoid duplicate check if both sources identical */
        if (!checked_src2 || !opnd_same(mi->src[1], mi->src[0])) {
            insert_check_defined(drcontext, bb, marker1, mi, mi->src[0], shadow_src);
            mark_eflags_used(drcontext, bb, mi->bb);
            add_jcc_slowpath(drcontext, bb, marker1, OP_jne_short, mi);
            if (mi->load)
                checked_memsrc = true;
        }
        num_to_propagate--;
        shadow_src = shadow_src2;
        shadow_src2 = shadow_src3;
        shadow_src3 = opnd_create_null();
    }
    ASSERT(mi->memsz <= 4 || num_to_propagate == 0,
           "propagation not suported for 8-byte memops");
    /* optimization to avoid checks on jcc after cmp/test */
    if (mi->check_definedness && TESTALL(EFLAGS_WRITE_6, instr_get_eflags(inst)))
        mi->bb->eflags_defined = true;
    else if (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst)))
        mi->bb->eflags_defined = false;

    /* Check memory operand(s) for addressability.
     * For mem2mem we checked the source mem op already.
     */
    if (mi->load && (!mi->ignore_heap || mi->pushpop_stackop) &&
        /* if we checked memsrc for definedness we also checked for addressability */
        !checked_memsrc) {
        mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);
        if (options.loads_use_table && mi->memsz <= 4) {
            /* Check for unaddressability via table lookup */
            if (mi->memsz < 4 && mi->need_offs) {
                /* PR 503782: check just the bytes referenced.  We've zeroed the
                 * rest of mi->offs and in 8h position it's doing x256 already.
                 * FIXME: do for stores too?
                 */
                int disp = (int) ((mi->memsz == 1) ? shadow_byte_addr_not_bit :
                                  shadow_word_addr_not_bit);
                reg_id_t idx = reg_to_pointer_sized(opnd_get_reg(mi->offs));
                ASSERT(mi->zero_rest_of_offs, "table lookup requires zeroing");
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext,
                                     opnd_create_base_disp(mi->reg2.reg, idx,
                                                           1, disp, OPSZ_1),
                                     OPND_CREATE_INT8(1)));
            } else {
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext,
                                     OPND_CREATE_MEM8(mi->reg2.reg,
                                                      (int)shadow_dword_is_addr_not_bit),
                                     OPND_CREATE_INT8(1)));
            }
        } else {
            /* Conservative check for addressability: check for definedness.
             * We go ahead and leave the (duplicate) checks for source definedess
             * on check_definedness, for simplicity.  Note that if we have heap
             * header undefinedess exceptions in slow path, we won't duplicate
             * those checks here and they'll probably show up as false positives
             * later after propagation: best to not have such exceptions (we
             * don't have them on Linux: see check_undefined_exceptions()).
             */
            if (mi->memsz <= 4) {
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext, opnd_create_reg(reg2_8),
                                     OPND_CREATE_INT8((char)SHADOW_DWORD_DEFINED)));
            } else {
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext, opnd_create_reg(reg2_16),
                                     OPND_CREATE_INT16((short)SHADOW_QWORD_DEFINED)));
            }
        }
        mark_eflags_used(drcontext, bb, mi->bb);
        add_jcc_slowpath(drcontext, bb, inst, OP_jne_short, mi);
    } else if (mi->store) {
        /* shadow table slot address is in reg1 */
        mark_eflags_used(drcontext, bb, mi->bb);
        if (mi->pushpop) { /* push of a reg or immed */
            /* it should be unaddressable, but might not be if app has malloced
             * a stack.  we use this as more than a debug check: it triggers
             * handling of malloc-based stacks (PR 525807).  we provide an
             * option to disable if our handling isn't working and we just
             * want to get some performance and don't care about false negatives
             * and have already tuned the stack swap threshold.
             */
            if (options.check_push) {
                ASSERT(mi->reg1.used, "internal reg spill error");
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg1.reg, 0),
                                     OPND_CREATE_INT8((char)SHADOW_DWORD_UNADDRESSABLE)));
                add_jcc_slowpath(drcontext, bb, inst, OP_jne_short, mi);
            }
        } else if (!mi->ignore_heap || mi->pushpop_stackop) {
            if (options.stores_use_table && mi->memsz <= 4) {
                /* check for unaddressability.  we used to combine it with
                 * a definedness check but there are too many instances of
                 * not-fully-defined dwords, so we have separate checks.
                 */
                reg_id_t scratch;
                ASSERT(mi->reg1.used, "internal reg spill error");
                /* Our table lookup requires an explicit load but it should still
                 * be more performant than the series of compares we used to use,
                 * as it keeps partial-defined dwords on the fastpath.
                 */
                if (mi->need_offs) {
                    ASSERT(mi->reg3.used, "reg spill incorrect assumption");
                    scratch = mi->reg3.reg;
                } else {
                    mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);
                    scratch = mi->reg2.reg;
                }
                PRE(bb, inst,
                    INSTR_CREATE_movzx(drcontext, opnd_create_reg(scratch),
                                       OPND_CREATE_MEM8(mi->reg1.reg, 0)));
                /* optimization: avoid redundant load below for num_to_propagate==1 */
                if (opnd_same(shadow_src, OPND_CREATE_MEM8(mi->reg1.reg, 0)))
                    shadow_src = opnd_create_reg(reg_32_to_8(scratch));
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext, 
                                     OPND_CREATE_MEM8(scratch,
                                                      (int)shadow_dword_is_addr_not_bit),
                                     OPND_CREATE_INT8(1)));
                add_jcc_slowpath(drcontext, bb, inst, OP_jne_short, mi);
            } else {
                /* check for unaddressability by checking for definedness.
                 * see !options.loads_use_table comments above on dup src def checks.
                 */
                instr_t *ok_to_write = INSTR_CREATE_label(drcontext);
                ASSERT(mi->reg1.used, "internal reg spill error");
                PRE(bb, inst, INSTR_CREATE_cmp
                    (drcontext, mi->memsz <= 4 ? OPND_CREATE_MEM8(mi->reg1.reg, 0) :
                     OPND_CREATE_MEM16(mi->reg1.reg, 0),
                     shadow_immed(mi->memsz, SHADOW_DEFINED)));
                /* for slow_path we do not propagate src shadow vals to dst when
                 * check_definedness, but here we always bail to slow path if
                 * srcs are undefined, and we use check_definedness to also mean
                 * "bail to slow path if complex, but propagate shadow vals", so
                 * we always propagate
                 */
                PRE(bb, inst,
                    INSTR_CREATE_jcc(drcontext, OP_je_short,
                                     opnd_create_instr(ok_to_write)));
                /* If we're checking definedness and dst is a src bail to slowpath */
                if (!mi->check_definedness || !opnd_same(mi->src[0], mi->dst[0])) {
                    /* would be nice to check for subsets of undefined but we have to rule
                     * out any byte being unaddressable so we require all-undefined
                     */
                    PRE(bb, inst, INSTR_CREATE_cmp
                        (drcontext, mi->memsz <= 4 ? OPND_CREATE_MEM8(mi->reg1.reg, 0) :
                         OPND_CREATE_MEM16(mi->reg1.reg, 0),
                         shadow_immed(mi->memsz, SHADOW_UNDEFINED)));
                    if (mi->opsz < 4) {
                        /* rather than a full table lookup we put in just the common cases
                         * where upper bytes are undefined and lower are defined */
                        PRE(bb, inst,
                            INSTR_CREATE_jcc(drcontext, OP_je_short,
                                             opnd_create_instr(ok_to_write)));
                        PRE(bb, inst,
                            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg1.reg, 0),
                                             OPND_CREATE_INT8((char)0xf0)));
                        PRE(bb, inst,
                            INSTR_CREATE_jcc(drcontext, OP_je_short,
                                             opnd_create_instr(ok_to_write)));
                        PRE(bb, inst,
                            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg1.reg, 0),
                                             OPND_CREATE_INT8((char)0xfc)));
                        PRE(bb, inst,
                            INSTR_CREATE_jcc(drcontext, OP_je_short,
                                             opnd_create_instr(ok_to_write)));
                        PRE(bb, inst,
                            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg1.reg, 0),
                                             OPND_CREATE_INT8((char)0xc0)));
                    } else if (mi->opsz == 8) {
                        /* check for half-undef to avoid slowpath (PR 504162) */
                        PRE(bb, inst,
                            INSTR_CREATE_jcc(drcontext, OP_je_short,
                                             opnd_create_instr(ok_to_write)));
                        PRE(bb, inst,
                            INSTR_CREATE_cmp(drcontext,
                                             OPND_CREATE_MEM16(mi->reg1.reg, 0),
                                             OPND_CREATE_INT16((short)0xff00)));
                        PRE(bb, inst,
                            INSTR_CREATE_jcc(drcontext, OP_je_short,
                                             opnd_create_instr(ok_to_write)));
                        PRE(bb, inst,
                            INSTR_CREATE_cmp(drcontext,
                                             OPND_CREATE_MEM16(mi->reg1.reg, 0),
                                             OPND_CREATE_INT16((short)0x00ff)));
                    }
                }
                add_jcc_slowpath(drcontext, bb, inst, OP_jne_short, mi);
                PRE(bb, inst, ok_to_write);
            }
        }
    }

    if (mi->pushpop && mi->load) { /* pop into a reg */
        /* reg1 still has our address and we have the src memop value in reg2,
         * so go ahead and write to the shadow table so we can trash reg2
         */
        ASSERT(mi->reg2.used, "internal reg spill error");
        add_dst_shadow_write(drcontext, bb, inst,
                             OPND_CREATE_MEM8(mi->reg1.reg, 0),
                             OPND_CREATE_INT8((char)SHADOW_DWORD_UNADDRESSABLE),
                             mi->opsz, mi->opsz, mi->offs, reg2_8, &mi->reg2, mi->bb);
    }

    /* Combine sources and write result to dest.
     * Be sure to write to eflags before calling add_check_datastore(),
     * as the latter will jump out to fastpath_restore.
     */

    if (opnd_uses_reg(shadow_dst, mi->reg1.reg) ||
        opnd_uses_reg(shadow_src, mi->reg2.reg)) {
        ASSERT(!opnd_uses_reg(shadow_dst, mi->reg2.reg), "scratch reg error");
        scratch8 = reg2_8;
        si8 = &mi->reg2;
    } else {
        ASSERT(!opnd_uses_reg(shadow_dst, mi->reg1.reg), "scratch reg error");
        scratch8 = reg1_8;
        si8 = &mi->reg1;
    }

    ASSERT(num_to_propagate >= 0, "propagation count error");
    if (num_to_propagate == 0) {
        write_shadow_eflags(drcontext, bb, inst, REG_NULL,
                            OPND_CREATE_INT8((char)SHADOW_DWORD_DEFINED));
        add_check_datastore(drcontext, bb, inst, mi,
                            shadow_immed(mi->memsz, SHADOW_DEFINED),
                            fastpath_restore);
        add_dstX2_shadow_write(drcontext, bb, inst, shadow_dst, shadow_dst2,
                               shadow_immed(mi->memsz, SHADOW_DEFINED),
                               mi->src_opsz, mi->opsz, mi->offs, scratch8, si8, mi->bb);
    } else if (num_to_propagate == 1) {
        /* copy src shadow to eflags shadow and dst shadow */
        mark_scratch_reg_used(drcontext, bb, mi->bb, si8);
        if (!opnd_is_reg(shadow_src) || opnd_get_reg(shadow_src) != scratch8) {
            ASSERT(!opnd_is_null(shadow_src), "src can't be null");
            PRE(bb, inst,
                INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(scratch8), shadow_src));
        }
        insert_shadow_op(drcontext, bb, inst, scratch8,
                         (mi->store && mi->need_offs) ? reg3_8 :
                         reg_32_to_8h(reg_to_pointer_sized(scratch8)));
        write_shadow_eflags(drcontext, bb, inst, REG_NULL, opnd_create_reg(scratch8));
        add_check_datastore(drcontext, bb, inst, mi,
                            opnd_create_reg(scratch8), fastpath_restore);
        add_dstX2_shadow_write(drcontext, bb, inst, shadow_dst, shadow_dst2,
                               opnd_create_reg(scratch8),
                               mi->src_opsz, mi->opsz, mi->offs, reg3_8, &mi->reg3, mi->bb);
        ASSERT(!mi->reg3.used || mi->reg3.reg != REG_NULL, "spill error");
    } else {
        /* combine the N sources and then write to the dest + eflags.
         * in general we want U+D=>U, U+U=>U, and D+D=>D: so we want bitwise or.
         * FIXME: for ops that promote bits we need to promote undefinedness
         */
        mark_scratch_reg_used(drcontext, bb, mi->bb, si8);
        mark_eflags_used(drcontext, bb, mi->bb);
        if (!opnd_is_reg(shadow_src) || opnd_get_reg(shadow_src) != scratch8) {
            PRE(bb, inst,
                INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(scratch8), shadow_src));
        }
        if (num_to_propagate == 2 && mi->opsz == 4 && opnd_same(shadow_src2, shadow_dst)) {
            /* optimization for alu ops */
            /* FIXME: if we get rid of this opt we'd have each scenario put
             * value for dst into scratch8 => can move write_shadow_eflags(),
             * add_check_datastore(), and insert_shadow_op() into
             * add_dstX2_shadow_write()
             */
            /* we can skip the or if add_check_datastore() finds that the src
             * equals the src2/dst, but we still need to write eflags
             */
            instr_t *no_dst_write = INSTR_CREATE_label(drcontext);
            add_check_datastore(drcontext, bb, inst, mi,
                                opnd_create_reg(scratch8), no_dst_write);
            PREXL8M(bb, inst,
                   INSTR_XL8(INSTR_CREATE_or
                             (drcontext, shadow_dst, opnd_create_reg(scratch8)),
                             instr_get_app_pc(inst)));
            PRE(bb, inst, no_dst_write);
            write_shadow_eflags(drcontext, bb, inst, scratch8, shadow_dst);
        } else {
            PRE(bb, inst,
                INSTR_CREATE_or(drcontext, opnd_create_reg(scratch8), shadow_src2));
            if (!opnd_is_null(shadow_src3)) {
                PRE(bb, inst,
                    INSTR_CREATE_or(drcontext, opnd_create_reg(scratch8), shadow_src3));
            }
            write_shadow_eflags(drcontext, bb, inst, REG_NULL, opnd_create_reg(scratch8));
            add_check_datastore(drcontext, bb, inst, mi,
                                opnd_create_reg(scratch8), fastpath_restore);
            /* FIXME: call insert_shadow_op() */
            add_dstX2_shadow_write(drcontext, bb, inst, shadow_dst, shadow_dst2,
                                   opnd_create_reg(scratch8), mi->src_opsz,
                                   mi->opsz, mi->offs, reg3_8, &mi->reg2, mi->bb);
            ASSERT(!mi->reg3.used || mi->reg3.reg != REG_NULL, "spill error");
        }
        /* FIXME: for insert_shadow_op() for shifts, need to
         * either do the bitwise or into reg1_8, then call:
         *   insert_shadow_op(drcontext, bb, inst, reg1_8, reg_32_to_8h(mi->reg1.reg));
         * and then store into dst_reg?  lots of work if not a shift, so have
         * insert_shadow_op() handle both mem8 or reg8?
         */
    }
#else /* TOOL_DR_MEMORY */
    add_shadow_table_lookup(drcontext, bb, inst, mi, false/*addr not value*/,
                            false, false/*!need_offs*/, false/*!zero_rest*/,
                            mi->reg1.reg, mi->reg2.reg, mi->reg3.reg);
    ASSERT(reg1_8 != REG_NULL && mi->reg1.used, "reg spill error");
    /* shadow lookup left reg1+reg2 holding address */
    if (!options.stale_blind_store) {
        /* FIXME: measure perf to see which is better */
        /* cmp and avoid store can be faster than blindly storing */
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg2.reg, 0),
                             OPND_CREATE_INT8(0)));
        mark_eflags_used(drcontext, bb, mi->bb);
        /* too bad there's no cmovcc to memory! */
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_jnz_short,
                             opnd_create_instr(fastpath_restore)));
    }
    PRE(bb, inst,
        INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM8(mi->reg2.reg, 0),
                            OPND_CREATE_INT8(1)));
#endif /* TOOL_DR_MEMORY */

    PRE(bb, inst, fastpath_restore);
#ifdef STATISTICS
    if (options.statistics) {
        PRE(bb, inst,
            INSTR_CREATE_inc(drcontext, OPND_CREATE_MEM32
                             (REG_NULL, (int)(mi->pushpop ? (mi->store ? &push4_fastpath :
                                                             &pop4_fastpath) :
                                              (mi->store ? &write4_fastpath :
                                               &read4_fastpath)))));
        mark_eflags_used(drcontext, bb, mi->bb);
    }
#endif
    insert_spill_or_restore(drcontext, bb, spill_location, &mi->reg1, true/*save*/, false);
    insert_spill_or_restore(drcontext, bb, spill_location, &mi->reg2, true/*save*/, false);
    insert_spill_or_restore(drcontext, bb, spill_location, &mi->reg3, true/*save*/, false);
    /* restoring may involve xchg so must be prior to aflags restore */
    insert_spill_or_restore(drcontext, bb, inst, &mi->reg3, false/*restore*/,false);
    insert_spill_or_restore(drcontext, bb, inst, &mi->reg2, false/*restore*/,false);
    insert_spill_or_restore(drcontext, bb, inst, &mi->reg1, false/*restore*/,false);
    if (save_aflags && mi->aflags != EFLAGS_WRITE_6) {
        insert_restore_aflags(drcontext, bb, inst, &mi->eax, mi->aflags);
    }
#ifdef DEBUG
    else if (!save_aflags && mi->aflags != EFLAGS_WRITE_6) {
        instr_t *in;
        per_thread_t *pt = (per_thread_t *) dr_get_tls_field(drcontext);
        if (instru_start == NULL)
            in = instrlist_first(bb);
        else
            in = instr_get_next(instru_start);
        for (; in != inst; in = instr_get_next(in)) {
            if (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(in)) &&
                (!whole_bb_spills_enabled() || !mi->bb->eflags_used)) {
                ELOGPT(0, pt, "ERROR: not saving flags when should for: ");
                instr_disassemble(drcontext, inst, pt->f);
                ELOGPT(0, pt, "\n\nentire instrlist:");
                instrlist_disassemble(drcontext, NULL, bb, pt->f);
                ASSERT(false, "not saving flags but clobbering them!");
            }
        }
    }
#endif
    if (mi->need_slowpath) {
        bool shared = instr_can_use_shared_slowpath(inst);
        if (shared) {
            PRE(bb, inst,
                INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(nextinstr)));
        } else {
            /* need to reach over clean call */
            PRE(bb, inst,
                INSTR_CREATE_jmp(drcontext, opnd_create_instr(nextinstr)));
        }
        PRE(bb, inst, mi->slowpath);
        if (!shared) {
            /* must restore now */
            if (mi->aflags != EFLAGS_WRITE_6) {
                if (mi->aflags != EFLAGS_WRITE_OF) {
                    PRE(bb, inst, INSTR_CREATE_add
                        (drcontext, opnd_create_reg(REG_AL), OPND_CREATE_INT8(0x7f)));
                }
                PRE(bb, inst, INSTR_CREATE_sahf(drcontext));
                insert_spill_or_restore(drcontext, bb, inst, &mi->eax, false/*restore*/,
                                        false);
            }
            insert_spill_or_restore(drcontext, bb, inst, &mi->reg3, false/*restore*/,false);
            insert_spill_or_restore(drcontext, bb, inst, &mi->reg2, false/*restore*/,false);
            insert_spill_or_restore(drcontext, bb, inst, &mi->reg1, false/*restore*/,false);
        } else {
            /* We restore in the shared slowpath for slot spills, but here for
             * xchg to avoid having too many variations in slow path entrances.
             */
            insert_spill_or_restore(drcontext, bb, inst, &mi->reg3, false/*restore*/,true);
            insert_spill_or_restore(drcontext, bb, inst, &mi->reg2, false/*restore*/,true);
            insert_spill_or_restore(drcontext, bb, inst, &mi->reg1, false/*restore*/,true);
        }
        instrument_slowpath(drcontext, bb, inst, mi);
    } else {
        /* avoid leaks, be defensive in case we buggily did target it */
        PRE(bb, inst, mi->slowpath);
    }
    PRE(bb, inst, nextinstr);
}

/***************************************************************************
 * Whole-bb spilling (PR 489221)
 */

static void
pick_bb_scratch_regs_helper(opnd_t opnd, int uses[NUM_LIVENESS_REGS])
{
    int j;
    for (j = 0; j < opnd_num_regs_used(opnd); j++) {
        reg_id_t reg = opnd_get_reg_used(opnd, j);
        if (reg_is_gpr(reg)) {
            int idx = reg_to_pointer_sized(reg) - REG_START_32;
            ASSERT(idx >= 0 && idx < NUM_LIVENESS_REGS, "reg enum error");
            uses[idx]++;
            if (opnd_is_memory_reference(opnd))
                uses[idx]++;
        }
    }
}

static void
pick_bb_scratch_regs(instr_t *inst, bb_info_t *bi)
{
    /* Pick the best regs to use as scratch.  We want the fewest uses,
     * since we have to restore on each use (twice for a memref: once
     * for lea, once for app instr).
     * Having varying scratch regs per bb forces us to store which
     * ones so we can restore on slowpath/shadow fault/app fault but
     * it is worth it to shrink fastpath instru.
     *
     * Plan: pick just 2 scratches, and then those that need 3
     * (mem2mem or sub-dword) have to grab a local 3rd but adjust so
     * that ecx is considered #3.
     * Going to always put whole-bb eflags into tls slot, so not
     * considering leaving it in eax and getting 2 more scratch regs, for
     * simplicity: though that could be more efficient for some bbs.
     * 
     * Future work PR 492073: if bb has high scores for all regs, try to
     * split into 2: maybe 1st half diff from 2nd half.  Or, fall back to
     * per-instr, can be less expensive than restoring regs before each lea
     * and app instr.
     */
    int uses[NUM_LIVENESS_REGS] = {0,};
    int i, uses_least = INT_MAX, uses_second = INT_MAX;

    while (inst != NULL) {
        if (instr_is_cti(inst))
            break;
        for (i = 0; i < instr_num_dsts(inst); i++)
            pick_bb_scratch_regs_helper(instr_get_dst(inst, i), uses);
        for (i = 0; i < instr_num_srcs(inst); i++)
            pick_bb_scratch_regs_helper(instr_get_src(inst, i), uses);
        inst = instr_get_next(inst);
    }
    /* Too risky to use esp: if no alt sig stk (ESXi) or on Windows can't
     * handle fault
     */
    uses[REG_ESP - REG_START_32] = INT_MAX;
    /* Future work PR 492073: If esi/edi/ebp are among the least-used, xchg
     * w/ cx/dx/bx and swap in each app instr.  Have to ensure results in
     * legal instrs (if app uses sub-dword, or certain addressing modes).
     */
    uses[REG_EBP - REG_START_32] = INT_MAX;
    uses[REG_ESI - REG_START_32] = INT_MAX;
    uses[REG_EDI - REG_START_32] = INT_MAX;
    for (i = 0; i < NUM_LIVENESS_REGS; i++) {
        if (uses[i] < uses_least) {
            uses_second = uses_least;
            bi->reg2.reg = bi->reg1.reg;
            uses_least = uses[i];
            bi->reg1.reg = REG_START_32 + i;
        } else if (uses[i] < uses_second) {
            uses_second = uses[i];
            bi->reg2.reg = REG_START_32 + i;
        }
    }
    /* For PR 493257 (share shadow translations) we do NOT want reg1 to be
     * eax, so we can save eflags w/o clobbering shared shadow addr in reg1
     */
    if (bi->reg1.reg == REG_EAX) {
        scratch_reg_info_t tmp = bi->reg1;
        ASSERT(bi->reg2.reg != REG_EAX, "reg2 shouldn't be eax");
        bi->reg1 = bi->reg2;
        bi->reg2 = tmp;
    }
    ASSERT(bi->reg1.reg <= REG_EBX, "NYI non-a/b/c/d reg");
    bi->reg1.slot = SPILL_SLOT_1;
    /* Dead-across-whole-bb is rare so we don't bother to support xchg */
    bi->reg1.xchg = REG_NULL;
    /* The dead fields will be computed in fastpath_pre_app_instr */
    bi->reg1.dead = false;
    bi->reg1.used = false; /* will be set once used */
    bi->reg1.global = true;
    ASSERT(bi->reg2.reg <= REG_EBX, "NYI non-a/b/c/d reg");
    ASSERT(bi->reg1.reg != bi->reg2.reg, "reg conflict");
    bi->reg2.slot = SPILL_SLOT_2;
    bi->reg2.xchg = REG_NULL;
    bi->reg2.dead = false;
    bi->reg2.used = false; /* will be set once used */
    bi->reg2.global = true;

#ifdef STATISTICS
    if (uses_least > 0)
        STATS_INC(reg_spill_used_in_bb);
    else
        STATS_INC(reg_spill_unused_in_bb);
    if (uses_second > 0)
        STATS_INC(reg_spill_used_in_bb);
    else
        STATS_INC(reg_spill_unused_in_bb);
#endif
    DOLOG(3, {
        void *drcontext = dr_get_current_drcontext();
        per_thread_t *pt;
        ASSERT(drcontext != NULL, "should always have dcontext in cur DR");
        pt = (per_thread_t *) dr_get_tls_field(drcontext);
        LOG(3, "whole-bb scratch: ");
        print_scratch_reg(drcontext, &bi->reg1, 1, LOGFILE(pt));
        LOG(3, " x%d, ", uses_least);
        print_scratch_reg(drcontext, &bi->reg2, 2, LOGFILE(pt));
        LOG(3, " x%d\n", uses_second);
    });
}

bool
whole_bb_spills_enabled(void)
{
    /* Whole-bb eflags and register saving requires spill slots that
     * can be live across instructions == our own spill slots.
     * We use SPILL_SLOT_1, SPILL_SLOT_2, and SPILL_SLOT_EFLAGS_EAX
     * for 2 registers and eflags.
     */
    return (options.num_spill_slots >= SPILL_SLOT_EFLAGS_EAX &&
#ifdef TOOL_DR_HEAPSTAT
            options.staleness &&
#endif
            /* should we enable whole-bb for -leaks_only?
             * we'd need to enable bb table and state restore on fault.
             * since it's rare to have more than one stack adjust in a
             * single bb, I don't think we'd gain enough perf to be worth
             * the complexity.
             */
            !options.leaks_only);
}

void
fastpath_top_of_bb(void *drcontext, void *tag, instrlist_t *bb, bb_info_t *bi)
{
    instr_t *inst = instrlist_first(bb);
    if (inst == NULL || !whole_bb_spills_enabled()) {
        bi->eflags_used = false;
        bi->reg1.reg = REG_NULL;
        bi->reg1.used = false;
        bi->reg2.reg = REG_NULL;
        bi->reg2.used = false;
        return;
    }
    /* analyze bb and pick which scratch regs to use.  don't actually do
     * the spills until we know there's actual instrumentation in this bb.
     * we don't also delay the analysis b/c it's simpler to analyze the
     * unmodified instrlist: we do add clean calls that don't count as
     * instru we need to spill for, etc.  we could put in checks for meta
     * but will wait until analysis shows up as perf bottleneck.
     */
    pick_bb_scratch_regs(inst, bi);
}

/* Invoked before the regular pre-app instrumentation */
void
fastpath_pre_instrument(void *drcontext, instrlist_t *bb, instr_t *inst, bb_info_t *bi)
{
    int live[NUM_LIVENESS_REGS];
    if (!whole_bb_spills_enabled())
        return;
    /* Haven't instrumented below here yet, so forward analysis should
     * see only app instrs
     */
    get_reg_liveness(inst, live);
    /* Update the dead fields */
    bi->reg1.dead = (live[bi->reg1.reg - REG_START_32] == LIVE_DEAD);
    bi->reg2.dead = (live[bi->reg2.reg - REG_START_32] == LIVE_DEAD);

    bi->aflags = get_aflags_liveness(inst);
    bi->eax_dead = (live[REG_EAX - REG_START_32] == LIVE_DEAD);
}

static bool
instr_is_spill(instr_t *inst)
{
    return (instr_get_opcode(inst) == OP_mov_st &&
            opnd_is_far_base_disp(instr_get_dst(inst, 0)) &&
            opnd_get_index(instr_get_dst(inst, 0)) == REG_NULL &&
            opnd_get_segment(instr_get_dst(inst, 0)) == SEG_FS &&
            opnd_is_reg(instr_get_src(inst, 0)));
    /* should we also check that disp is in our or DR's TLS range?
     * but we don't know DR's
     */
}

void
mark_eflags_used(void *drcontext, instrlist_t *bb, bb_info_t *bi)
{
    instr_t *where_spill = (bi == NULL || bi->spill_after == NULL) ?
        instrlist_first(bb) : instr_get_next(bi->spill_after);
    if (!whole_bb_spills_enabled() || bi == NULL/*gencode*/ || bi->eflags_used)
        return;
    /* optimization: if flags are dead then ignore our use.
     * technically unsafe (PR 463053).
     * FIXME: for use in fastpath_pre_instrument() for post-instr
     * save are we using the pre-instr analysis?
     */
    if (bi->aflags == EFLAGS_WRITE_6) {
        LOG(3, "eflags are dead so not saving\n");
        return;
    }
    /* To use global-eax for eflags we must spill regs before flags */
    while (!instr_ok_to_mangle(where_spill) &&
           instr_is_spill(where_spill) &&
           instr_get_next(where_spill) != NULL)
        where_spill = instr_get_next(where_spill);
    LOG(4, "marking eflags used => spilling if live\n");
    bi->eflags_used = true;
    save_aflags_if_live(drcontext, bb, where_spill, NULL, bi);
#ifdef STATISTICS
    if (bi->aflags != EFLAGS_WRITE_6)
        STATS_INC(aflags_saved_at_top);
#endif
}

void
mark_scratch_reg_used(void *drcontext, instrlist_t *bb,
                      bb_info_t *bi, scratch_reg_info_t *si)
{
    instr_t *where_spill = (bi == NULL || bi->spill_after == NULL) ?
        instrlist_first(bb) : instr_get_next(bi->spill_after);
    /* Update global used values, and if global save on first use in bb */
    if (si->used)
        return;
    if (si->global) {
        ASSERT(bi != NULL, "should only use global in bb, not gencode");
        /* To use global-eax for eflags we must spill regs before flags */
        while (instr_get_prev(where_spill) != NULL &&
               !instr_ok_to_mangle(instr_get_prev(where_spill)) &&
               /* We want to NOT walk back into clean call: clean call
                * ends in restore, not spill 
                */
               instr_is_spill(instr_get_prev(where_spill)))
            where_spill = instr_get_prev(where_spill);
        if (si->reg == bi->reg1.reg) {
            bi->reg1.used = true;
            insert_spill_global(drcontext, bb, where_spill, &bi->reg1, true/*save*/);
        } else {
            ASSERT(si->reg == bi->reg2.reg, "global vs local mismatch");
            bi->reg2.used = true;
            insert_spill_global(drcontext, bb, where_spill, &bi->reg2, true/*save*/);
        }
    }
    /* Even if global we have to mark the si copy as used too */
    si->used = true;
}

/* Invoked after the regular pre-app instrumentation */
void
fastpath_pre_app_instr(void *drcontext, instrlist_t *bb, instr_t *inst,
                       bb_info_t *bi, fastpath_info_t *mi)
{
    /* Preserve app semantics wrt global spilled registers */
    instr_t *next = instr_get_next(inst);
    int live[NUM_LIVENESS_REGS];
    bool restored_for_read = false;

    if (!whole_bb_spills_enabled())
        return;
    /* If this is the last instr, the end-of-bb restore will restore for any read,
     * and everything is dead so we can ignore writes
     */
    if (next == NULL)
        return;

    /* Before each read, restore global spilled registers */
    if (TESTANY(EFLAGS_READ_6, instr_get_eflags(inst)) ||
        /* If the app instr writes some subset of eflags we need to restore
         * rest so they're combined properly
         */
        (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst)) && 
         bi->aflags != EFLAGS_WRITE_6))
        restore_aflags_if_live(drcontext, bb, inst, mi, bi);
    /* Optimization: don't bother to restore if this is not a meaningful read
     * (e.g., xor with self)
     */
    if (!result_is_always_defined(inst) ||
        /* if sub-dword then we have to restore for rest of bits */
        opnd_get_size(instr_get_src(inst, 0)) != OPSZ_4) {
        /* we don't mark as used: if unused so far, no reason to restore */
        if (instr_reads_from_reg(inst, bi->reg1.reg) ||
            /* if sub-reg is written we need to restore rest */
            (instr_writes_to_reg(inst, bi->reg1.reg) &&
             !instr_writes_to_exact_reg(inst, bi->reg1.reg))) {
            restored_for_read = true;
            /* If reg1 holds a shared shadow addr, better to preserve it than
             * to have to re-translate
             */
            if (!opnd_is_null(bi->shared_memop)) {
                if (instr_writes_to_reg(inst, bi->reg1.reg) ||
                    instr_writes_to_reg(inst, bi->reg2.reg) ||
                    /* must consider reading the other reg (PR 494169) */
                    instr_reads_from_reg(inst, bi->reg2.reg)) {
                    /* give up: not worth complexity (PR 494727 covers handling) */
                    STATS_INC(xl8_not_shared_reg_conflict);
                    bi->shared_memop = opnd_create_null();
                } else {
                    PRE(bb, inst,
                        INSTR_CREATE_mov_st(drcontext, opnd_create_reg(bi->reg2.reg),
                                            opnd_create_reg(bi->reg1.reg)));
                    PRE(bb, next,
                        INSTR_CREATE_mov_st(drcontext, opnd_create_reg(bi->reg1.reg),
                                            opnd_create_reg(bi->reg2.reg)));
                }
            }
            insert_spill_global(drcontext, bb, inst, &bi->reg1, false/*restore*/);
        }
        if (instr_reads_from_reg(inst, bi->reg2.reg) ||
            /* if sub-reg is written we need to restore rest */
            (instr_writes_to_reg(inst, bi->reg2.reg) &&
             !instr_writes_to_exact_reg(inst, bi->reg2.reg))) {
            restored_for_read = true;
            insert_spill_global(drcontext, bb, inst, &bi->reg2, false/*restore*/);
        }
    }

    /* After each write, update global spilled values, unless that reg is
     * dead (xref PR 463053 for safety)
     */
    /* Haven't instrumented below here yet, so forward analysis should
     * see only app instrs
     */
    bi->aflags = get_aflags_liveness(next);
    /* We updated reg*.dead in fastpath_pre_instrument() but here we want
     * liveness post-app-instr
     */
    get_reg_liveness(next, live);
    /* Update the dead fields */
    bi->reg1.dead = (live[bi->reg1.reg - REG_START_32] == LIVE_DEAD);
    bi->reg2.dead = (live[bi->reg2.reg - REG_START_32] == LIVE_DEAD);
    bi->eax_dead = (live[REG_EAX - REG_START_32] == LIVE_DEAD);

    if (instr_writes_to_reg(inst, bi->reg1.reg)) {
        if (!bi->reg1.dead) {
            bi->reg1.used = true;
            insert_spill_global(drcontext, bb, next, &bi->reg1, true/*save*/);
        }
        /* If reg1 holds a shared shadow addr, better to preserve it than
         * to have to re-translate.  We must do this even if reg1 is dead.
         */
        if (!opnd_is_null(bi->shared_memop)) {
            if (restored_for_read ||
                (instr_writes_to_reg(inst, bi->reg2.reg) && !bi->reg2.dead)) {
                /* give up: not worth complexity for now (PR 494727 covers handling) */
                STATS_INC(xl8_not_shared_reg_conflict);
                bi->shared_memop = opnd_create_null();
            } else {
                bi->reg1.used = true;
                PRE(bb, inst,
                    INSTR_CREATE_mov_st(drcontext, opnd_create_reg(bi->reg2.reg),
                                        opnd_create_reg(bi->reg1.reg)));
                PRE(bb, next,
                    INSTR_CREATE_mov_st(drcontext, opnd_create_reg(bi->reg1.reg),
                                        opnd_create_reg(bi->reg2.reg)));
            }
        }
    }
    if (instr_writes_to_reg(inst, bi->reg2.reg) && !bi->reg2.dead) {
        bi->reg2.used = true;
        insert_spill_global(drcontext, bb, next, &bi->reg2, true/*save*/);
    }
    if (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst)) && bi->aflags != EFLAGS_WRITE_6) {
        /* Optimization: no need if next is jcc and we just checked definedness */
        if (IF_DRMEM(bi->eflags_defined && ) opc_is_jcc(instr_get_opcode(next))) {
            /* We just wrote to real eflags register, so don't restore at end */
            LOG(4, "next instr is jcc so not saving eflags\n");
            bi->eflags_used = false;
        } else {
            save_aflags_if_live(drcontext, bb, next, mi, bi);
        }
    }
}

void
fastpath_bottom_of_bb(void *drcontext, void *tag, instrlist_t *bb,
                      bb_info_t *bi, bool added_instru, bool translating)
{
    instr_t *last = instrlist_last(bb);
    bb_saved_info_t *save;
    if (!whole_bb_spills_enabled())
        return;
    if (!added_instru)
        return;
    ASSERT(instrlist_first(bb) != NULL, "can't add instru w/o instrs");

    /* the .used field controls whether we actually saved, and thus restore */
    LOG(3, "whole-bb scratch: r1=%s, r2=%s, efl=%s\n",
        bi->reg1.used ? "used" : "unused",
        bi->reg2.used ? "used" : "unused",
        bi->eflags_used ? "used" : "unused");
    restore_aflags_if_live(drcontext, bb, last, NULL, bi);
    insert_spill_global(drcontext, bb, last, &bi->reg1, false/*restore*/);
    insert_spill_global(drcontext, bb, last, &bi->reg2, false/*restore*/);

    if (!translating) {
        bb_saved_info_t *old;
        /* Add to table so we can restore on slowpath or a fault */
        save = (bb_saved_info_t *) global_alloc(sizeof(*save), HEAPSTAT_PERBB);
        memset(save, 0, sizeof(*save));
        /* If dead initially and only used later, fine to have fault path
         * restore from TLS early since dead.  But if never used and thus never
         * spilled then we have to tell the fault path to not restore from TLS.
         */
        if (bi->reg1.used)
            save->scratch1 = bi->reg1.reg;
        else
            save->scratch1 = REG_NULL;
        if (bi->reg2.used)
            save->scratch2 = bi->reg2.reg;
        else
            save->scratch2 = REG_NULL;
        save->eflags_saved = bi->eflags_used;
        /* We store the pc of the last instr, since everything is restored
         * already (and NOT present in our tls slots) if have a fault in that
         * instr.
         */
        save->last_instr = instr_get_app_pc(last);
        /* PR 495787: Due to non-precise flushing we can have a flushed bb
         * removed from the htables and then a new bb created before we received
         * the deletion event.  We can't tell this apart from duplication due to
         * thread-private copies: but this mechanism should handle that as well,
         * since our saved info should be deterministic and identical for each
         * copy.  Note that we do not want a new "unreachable event" b/c we need
         * to keep our bb info around in case the semi-flushed bb hits a fault.
         */
        hashtable_lock(&bb_table);
        old = (bb_saved_info_t *) hashtable_add_replace(&bb_table, tag, (void*)save);
        if (old != NULL) {
            ASSERT(old->ignore_next_delete < UCHAR_MAX, "ignore_next_delete overflow");
            save->ignore_next_delete = old->ignore_next_delete + 1;
            global_free(old, sizeof(*old), HEAPSTAT_PERBB);
            LOG(2, "bb "PFX" duplicated: assuming non-precise flushing\n", tag);
        }
        hashtable_unlock(&bb_table);
    }
}

