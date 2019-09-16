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
 * fastpath_x86.c: Dr. Memory shadow instrumentation fastpath for x86
 */

#include "dr_api.h"
#include "drutil.h"
#include "drmemory.h"
#include "slowpath.h"
#include "spill.h"
#include "fastpath.h"
#include "fastpath_arch.h"
#include "shadow.h"
#include "stack.h"
#ifdef TOOL_DR_MEMORY
# include "alloc_drmem.h"
# include "report.h"
#endif
#include "instru.h"
#include "pattern.h"

#ifdef UNIX
# include <signal.h> /* for SIGSEGV */
#else
# include <stddef.h> /* for offsetof */
#endif

/* Shadow value lookup tables */
#ifdef TOOL_DR_MEMORY
extern const byte shadow_dword_is_addr_not_bit[256];
extern const byte shadow_2_to_dword[256];
extern const byte shadow_4_to_dword[256];
extern const byte shadow_byte_defined[4][256];
extern const byte shadow_word_defined[4][256];
extern const byte shadow_byte_addr_not_bit[4][256];
extern const byte shadow_word_addr_not_bit[4][256];
#endif

#ifdef TOOL_DR_MEMORY
static bool needs_shadow_op(instr_t *inst);

static bool
load_reg_shadow_val(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi, reg_id_t target, opnd_info_t *cur);

# ifdef DEBUG
static void
print_opnd(void *drcontext, opnd_t op, file_t file, const char *prefix)
{
    dr_fprintf(file, "%s", prefix);
    opnd_disassemble(drcontext, op, file);
    dr_fprintf(file, " sz=%d\n", opnd_is_null(op) ? 0 :
               opnd_size_in_bytes(opnd_get_size(op)));
}
# endif
#endif /* TOOL_DR_MEMORY */

/* Handles segment-based memory references.
 * Assumes that SPILL_SLOT_5 is available if necessary.
 */
static void
insert_lea(void *drcontext, instrlist_t *bb, instr_t *inst,
           opnd_t opnd, reg_id_t dst, reg_id_t scratch/*can be REG_NULL*/)
{
    bool using_temp = false;
    /* We assume that drutil_insert_get_mem_addr() will not use scratch unless
     * either the opnd uses dst or the opnd has a base and an index.
     * It's not easy for us to get an extra scratch reg so we limit the cases.
     */
    if (scratch == REG_NULL &&
        (opnd_uses_reg(opnd, dst) ||
         (opnd_is_base_disp(opnd) && opnd_get_base(opnd) != REG_NULL &&
          opnd_get_index(opnd) != REG_NULL) ||
         opnd_get_index(opnd) == DR_REG_AL)) {
        /* This does happen on Linux:
         *   0x0022cad0 <__printf_fp+8624>:  mov    %eax,%gs:(%edx)
         * We assume it's rare and so rather than have callers pass us a
         * scratch reg (which would get complicated), we do a locally
         * transparent save+restore.
         */
        scratch = (dst == REG_XAX ? REG_XCX : REG_XAX);
        spill_reg(drcontext, bb, inst, scratch, SPILL_SLOT_5);
        using_temp = true;
    }
    IF_DEBUG(bool ok =)
        drutil_insert_get_mem_addr(drcontext, bb, inst, opnd, dst, scratch);
    ASSERT(ok, "drutil_insert_get_mem_addr failed");
    if (using_temp) {
        restore_reg(drcontext, bb, inst, scratch, SPILL_SLOT_5);
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
 *
 * Returns a LIVE_ constant for each register in live[]
 */
uint
get_aflags_and_reg_liveness(instr_t *inst, int live[NUM_LIVENESS_REGS],
                            bool aflags_only)
{
    uint res = 0;
    uint merge;
    int r, r_start, r_end;
    bool aflags_known = false;
    if (aflags_only) {
        /* for aflags_only, we only care about XAX. */
        r_start = DR_REG_XAX - REG_START;
        r_end   = r_start + 1;
    } else {
        r_start = 0;
        r_end   = NUM_LIVENESS_REGS;
    }
    for (r = r_start; r < r_end; r++)
        live[r] = LIVE_UNKNOWN;
    while (inst != NULL) {
        /* aflags */
        if (!aflags_known) {
            merge = instr_get_arith_flags(inst, DR_QUERY_DEFAULT);
            if (TESTANY(EFLAGS_READ_6, merge)) {
                uint w2r = EFLAGS_WRITE_TO_READ(res);
                if (!TESTALL((merge & EFLAGS_READ_6), w2r)) {
                    res = EFLAGS_READ_6; /* reads a flag before it's written */
                    aflags_known = true;
                }
            }
            if (TESTANY(EFLAGS_WRITE_6, merge)) {
                res |= (merge & EFLAGS_WRITE_6);
                if (TESTALL(EFLAGS_WRITE_6, res) && !TESTANY(EFLAGS_READ_6, res)) {
                    res = EFLAGS_WRITE_6; /* all written before read */
                    aflags_known = true;
                }
            }
        }
        if (instr_is_cti(inst))
            break;
        /* liveness */
        for (r = r_start; r < r_end; r++) {
            reg_id_t reg = r + REG_START;
            if (live[r] == LIVE_UNKNOWN) {
                if (instr_reads_from_reg(inst, reg, DR_QUERY_DEFAULT)) {
                    live[r] = LIVE_LIVE;
                }
                /* make sure we don't consider writes to sub-regs */
                else if (instr_writes_to_exact_reg(inst, reg, DR_QUERY_DEFAULT)) {
                    live[r] = LIVE_DEAD;
                }
            }
        }
        inst = instr_get_next(inst);
    }
    if (!aflags_known && TEST(EFLAGS_WRITE_OF, res) && !TEST(EFLAGS_READ_OF, res))
        return EFLAGS_WRITE_OF;
    return res;
}

static void
initialize_opnd_info(opnd_info_t *info)
{
    info->app = opnd_create_null();
    info->shadow = opnd_create_null();
    info->offs = opnd_create_null();
    info->indir_size = OPSZ_NA;
}

void
initialize_fastpath_info(fastpath_info_t *mi, bb_info_t *bi, instr_t *app_inst)
{
    int i;
    memset(mi, 0, sizeof(*mi));
    mi->bb = bi;
    for (i=0; i<MAX_FASTPATH_SRCS; i++) {
        initialize_opnd_info(&mi->src[i]);
        mi->opnum[i] = -1;
    }
    for (i=0; i<MAX_FASTPATH_DSTS; i++) {
        initialize_opnd_info(&mi->dst[i]);
    }
    mi->xl8 = instr_get_app_pc(app_inst);
    /* mi->opsz and mi->memoffs are not set here */
}

#ifdef TOOL_DR_MEMORY
static bool
instr_needs_slowpath(instr_t *inst)
{
    int opc = instr_get_opcode(inst);
    if (instr_is_predicated(inst) &&
        !opc_is_cmovcc(opc) && !opc_is_fcmovcc(opc)) {
        /* XXX i#1649: fastpath handles only cmovcc predication */
        return true;
    }
    /* Note that for and/test/or (instr_needs_all_srcs_and_vals(inst)) and
     * for shift routines we have the fastpath check for definedness and bail
     * out to the slowpath on any undefined operands, avoiding the need for
     * fastpath work in the common case.
     */
    /* FIXME: share all of these w/ the checks for them in slow path routines */
    /* OP_xchg and OP_xadd need slowpath to propagate, but if srcs are
     * defined they can stay on fastpath (PR 495277)
     */
    switch (opc) {
    case OP_popa:
        return true;
    case OP_bswap:
        return options.check_uninitialized;
    default:
        return false;
    }
}

static bool
addr_reg_ok_for_fastpath(reg_id_t reg)
{
    return (reg == REG_NULL ||
            (reg_is_gpr(reg) &&
             IF_X64_ELSE(reg_is_64bit(reg), reg_is_32bit(reg))));
}

static bool
reg_ignore_for_fastpath(int opc, opnd_t reg, bool dst)
{
    reg_id_t r = opnd_get_reg(reg);
    return (!reg_is_shadowed(opc, r));
}

static bool
reg_ok_for_fastpath(int opc, opnd_t reg, bool dst)
{
    reg_id_t r = opnd_get_reg(reg);
    return (reg_ignore_for_fastpath(opc, reg, dst) ||
            (reg_is_32bit(r) || reg_is_16bit(r) || reg_is_8bit(r) ||
             IF_X64(reg_is_64bit(r) ||)
             /* i#1453: we shadow xmm regs now
              * XXX i#243: but not ymm regs
              */
             (reg_is_xmm(r) && !reg_is_ymm(r)) ||
             /* i#1473: propagate mmx regs */
             reg_is_mmx(r)));
}

/* Up to caller to check rest of reqts for 8+-byte */
static bool
memop_ok_for_fastpath(opnd_t memop, bool allow8plus)
{
    return ((opnd_get_size(memop) == OPSZ_4 ||
             opnd_get_size(memop) == OPSZ_2 ||
             opnd_get_size(memop) == OPSZ_1 ||
             ((opnd_get_size(memop) == OPSZ_8 ||
               opnd_get_size(memop) == OPSZ_10 ||
               opnd_get_size(memop) == OPSZ_16) && allow8plus) ||
             opnd_get_size(memop) == OPSZ_lea) &&
            (!opnd_is_base_disp(memop) ||
             (addr_reg_ok_for_fastpath(opnd_get_base(memop)) &&
              addr_reg_ok_for_fastpath(opnd_get_index(memop)))));
}

static bool
prepend_fastpath_opnd(opnd_t op, opnd_info_t *array, int len)
{
    int i;
    if (!opnd_is_null(array[len-1].app))
        return false;
    for (i=len-1; i>0; i--)
        array[i] = array[i-1];
    array[0].app = op;
    return true;
}

static int
append_fastpath_opnd(opnd_t op, opnd_info_t *array, int len)
{
    int i;
    for (i=0; i<len; i++) {
        if (opnd_is_null(array[i].app)) {
            array[i].app = op;
            return i;
        }
    }
    return -1;
}

static inline bool
is_alu(fastpath_info_t *mi)
{
    /* yeah identifying ALU is a pain w/ mem-must-be-first */
    return ((mi->store && opnd_same(mi->src[0].app, mi->dst[0].app)) ||
            (!mi->store && opnd_same(mi->src[1].app, mi->dst[0].app)));
}

/* Allows 8-byte opnds: up to caller to check other reqts */
static bool
opnd_ok_for_fastpath(int opc, opnd_t op, int opnum, bool dst, fastpath_info_t *mi)
{
    if (opnd_is_immed_int(op) || opnd_is_pc(op) || opnd_is_instr(op)) {
        return true;
    } else if (opnd_is_reg(op)) {
        if (!reg_ok_for_fastpath(opc, op, dst))
            return false;
        if (!reg_ignore_for_fastpath(opc, op, dst)) {
            int num = append_fastpath_opnd(op, dst ? mi->dst : mi->src,
                                           dst ? MAX_FASTPATH_DSTS : MAX_FASTPATH_SRCS);
            if (num == -1)
                return false;
            if (!dst)
                mi->opnum[num] = opnum;
        }
        if (reg_is_xmm(opnd_get_reg(op)) || reg_is_mmx(opnd_get_reg(op)))
            mi->shadow_indir = true;
        return true;
    } else if (opnd_is_memory_reference(op)) {
        if (!memop_ok_for_fastpath(op, true/*8-byte ok*/))
            return false;
        /* there can only be one memory ref, except for mem2mem, which is
         * special-cased elsewhere, and alu where dst==src.
         * memory opnds are always prepended.
         */
        if ((opnd_is_memory_reference(mi->dst[0].app) &&
             (dst || !opnd_same(mi->dst[0].app, op))) ||
            (opnd_is_memory_reference(mi->src[0].app) &&
             (!dst || !opnd_same(mi->src[0].app, op))))
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
    initialize_fastpath_info(mi, bi, inst);

    /* now bail if no real fastpath */
    if (!options.fastpath)
        return false;
    if (instr_needs_slowpath(inst))
        return false;
#ifdef DEBUG
    if (bi->force_slowpath)
        return false;
#endif

    switch (opc) {
    case OP_push:
    case OP_push_imm:
    case OP_call:
    case OP_call_ind:
        /* all have dst0=esp, dst1=(esp), src0=imm/reg/pc/mem, src1=esp */
        if (opnd_get_reg(instr_get_dst(inst, 0)) != DR_REG_XSP ||
            opnd_get_size(instr_get_dst(inst, 1)) != OPSZ_4)
            return false;
        if (opc == OP_push_imm || opc == OP_call) {
            mi->dst[0].app = instr_get_dst(inst, 1);
            if (!memop_ok_for_fastpath(mi->dst[0].app, false/*no 8-byte*//*XXX i#111*/))
                return false;
            mi->store = true;
            mi->pushpop = true;
            return true;
        } else if (opc == OP_push || opc == OP_call_ind) {
            /* we treat call* as a push except call* must check its srcs for
             * definedness and shouldn't propagate, though when defined it's
             * ok to propagate (instead of propagating the immed==always defined)
             */
            mi->dst[0].app = instr_get_dst(inst, 1);
            if (!memop_ok_for_fastpath(mi->dst[0].app, false/*no 8-byte*//*XXX i#111*/))
                return false;
            mi->src[0].app = instr_get_src(inst, 0);
            mi->store = true;
            mi->pushpop = true;
            if (opnd_is_reg(mi->src[0].app)) {
                if (reg_ignore_for_fastpath(opc, mi->src[0].app, false/*!dst*/)) {
                    mi->src[0].app = opnd_create_null();
                    return true;
                } else if (reg_ok_for_fastpath(opc, mi->src[0].app, false/*!dst*/)) {
                    mi->opnum[0] = 0;
                    return true;
                } else
                    return false;
            } else if (opnd_is_memory_reference(mi->src[0].app)) {
                if (memop_ok_for_fastpath(mi->src[0].app, false/*no 8-byte*//*XXX i#111*/)) {
                    mi->mem2mem = true;
                    return true;
                } else
                    return false;
            }
        }
        return false;
    case OP_pushf:
        if (opnd_get_reg(instr_get_dst(inst, 0)) != DR_REG_XSP ||
            opnd_get_size(instr_get_dst(inst, 1)) != OPSZ_4)
            return false;
        mi->dst[0].app = instr_get_dst(inst, 1);
        if (!memop_ok_for_fastpath(mi->dst[0].app, false/*no 8-byte*//*XXX i#111*/))
            return false;
        mi->store = true;
        mi->pushpop = true;
        return true;
    case OP_pop:
        if (opnd_get_reg(instr_get_dst(inst, 1)) != DR_REG_XSP ||
            opnd_get_size(instr_get_src(inst, 1)) != OPSZ_4)
            return false;
        mi->dst[0].app = instr_get_dst(inst, 0);
        if (opnd_is_reg(mi->dst[0].app)) {
            if (reg_ok_for_fastpath(opc, mi->dst[0].app, true/*dst*/)) {
                mi->src[0].app = instr_get_src(inst, 1);
                if (!memop_ok_for_fastpath(mi->src[0].app, false/*no 8-byte*//*XXX i#111*/))
                    return false;
                if (!reg_ignore_for_fastpath(opc, mi->dst[0].app, true/*dst*/))
                    mi->dst[0].app = mi->dst[0].app;
                mi->load = true;
                mi->pushpop = !instr_pop_into_esp(inst); /* i#1500: pop into esp */
                return true;
            }
        } else if (opnd_is_memory_reference(mi->dst[0].app)) {
            /* XXX: to support mem2mem here we need to update instrument_fastpath
             * to treat the load as the primary for pushpop-ness (normally mem2mem
             * treats the load as secondary and the store as primary)
             */
            return false;
        }
        return false;
    case OP_popf:
        if (opnd_get_reg(instr_get_dst(inst, 0)) != DR_REG_XSP ||
            opnd_get_size(instr_get_src(inst, 1)) != OPSZ_4)
            return false;
        mi->src[0].app = instr_get_src(inst, 1);
        if (!memop_ok_for_fastpath(mi->src[0].app, false/*no 8-byte*//*XXX i#111*/))
            return false;
        mi->load = true;
        mi->pushpop = true;
        return true;
    case OP_leave:
        /* both a reg-reg move and a pop */
        if (opnd_get_reg(instr_get_dst(inst, 0)) != DR_REG_XSP ||
            opnd_get_reg(instr_get_dst(inst, 1)) != DR_REG_XBP ||
            opnd_get_size(instr_get_src(inst, 2)) != OPSZ_4)
            return false;
        /* pop into ebp */
        mi->src[0].app = instr_get_src(inst, 2); /* stack memref */
        if (!memop_ok_for_fastpath(mi->src[0].app, false/*no 8-byte*//*XXX i#111*/))
            return false;
        mi->dst[0].app = instr_get_dst(inst, 1); /* ebp */
        if (!reg_ok_for_fastpath(opc, mi->dst[0].app, true/*dst*/))
            return false;
        /* for the other dst, ebp->esp, we rely on check_definedness of the src (ebp)
         * and of the dst (esp) (for dst the check is via add_addressing_register_checks()
         */
        mi->src[1].app = instr_get_src(inst, 0); /* ebp */
        if (!reg_ok_for_fastpath(opc, mi->src[1].app, true/*dst*/))
            return false;
        mi->load = true;
        mi->pushpop = true;
        return true;
    case OP_ret:
        /* OP_ret w/ immed is treated as single pop here: esp
         * adjustment is handled separately (it doesn't read those bytes)
         */
        mi->src[0].app = instr_get_src(inst, instr_num_srcs(inst)-1);
        /* L4 ret may have this size.  will encode as OPSZ_PTR b/c there's
         * no other data prefix constraint.
         */
        if (opnd_get_size(mi->src[0].app) == OPSZ_ret)
            opnd_set_size(&mi->src[0].app, OPSZ_PTR);
        if (opnd_get_reg(instr_get_dst(inst, 0)) != DR_REG_XSP ||
            opnd_get_size(mi->src[0].app) != OPSZ_PTR)
            return false;
        ASSERT(opnd_is_memory_reference(mi->src[0].app), "internal opnd num error");
        if (!memop_ok_for_fastpath(mi->src[0].app, false/*no 8-byte*//*XXX i#111*/))
            return false;
        mi->load = true;
        mi->pushpop = true;
        return true;
    case OP_lea:
        /* For lea we treat base+index as sources to be
         * propagated, instead of as addressing registers
         */
        if (options.check_uninitialized) {
            opnd_t memop = instr_get_src(inst, 0);
            if (opnd_is_base_disp(memop)) {
                if (opnd_get_base(memop) != REG_NULL)
                    mi->src[0].app = opnd_create_reg(opnd_get_base(memop));
                if (opnd_get_index(memop) != REG_NULL) {
                    if (opnd_get_base(memop) == REG_NULL)
                        mi->src[0].app = opnd_create_reg(opnd_get_index(memop));
                    else {
                        /* if 16-bit we're ok in fastpath b/c will have same offs */
                        mi->src[1].app = opnd_create_reg(opnd_get_index(memop));
                    }
                }
            }
#ifdef X64
            else if (opnd_is_rel_addr(memop)) {
                /* By leaving mi->src[0] null this will be mark_defined. */
            }
#endif
            else
                ASSERT(false, "unsupported memop type");
            mi->dst[0].app = instr_get_dst(inst, 0);
            ASSERT(reg_ok_for_fastpath(opc, mi->dst[0].app, true/*dst*/) &&
                   !reg_ignore_for_fastpath(opc, mi->dst[0].app, true/*dst*/),
                   "lea handling error");
        }
        return true;
    case OP_cmpxchg:
        /* We keep in fastpath by treating as a 3-source 0-dest instr
         * and using check_definedness, bailing to slowpath if any operand
         * is other than fully defined.
         */
        if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 0), 0, false, mi))
            return false;
        if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 1), 1, false, mi))
            return false;
        if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 2), 2, false, mi))
            return false;
        mi->check_definedness = true;
        return true;
    case OP_cmpxchg8b:
        /* We keep in fastpath by treating as a 5-source 0-dest instr
         * and using check_definedness, bailing to slowpath if any operand
         * is other than fully defined.
         */
        if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 0), 0, false, mi) ||
            !opnd_ok_for_fastpath(opc, instr_get_src(inst, 1), 1, false, mi) ||
            !opnd_ok_for_fastpath(opc, instr_get_src(inst, 2), 2, false, mi))
            return false;
        /* Rather than extending the general fastpath arrays we hardcode the final 2 */
        ASSERT(opnd_is_reg(instr_get_src(inst, 3)), "cmpxchg8b srcs changed in DR?");
        ASSERT(opnd_is_reg(instr_get_src(inst, 4)), "cmpxchg8b srcs changed in DR?");
        mi->check_definedness = true;
        return true;
    case OP_xadd:
    case OP_xchg:
        /* PR 495277: since dsts==srcs, if srcs are defined can stay on fastpath */
        if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 0), 0, false, mi))
            return false;
        if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 1), 1, false, mi))
            return false;
        mi->check_definedness = true;
        return true;
    case OP_movs:
    case OP_stos:
    case OP_lods:
        /* the edi/esi reg opnds are also base regs so we're already checking
         * for definedness: thus we can ignore and get on the fastpath,
         * though w/ check_definedness unless word-sized, like all mem2mem
         */
        if (!opnd_ok_for_fastpath(opc, instr_get_dst(inst, 0), 0, true, mi))
            return false;
        if (opc == OP_movs) {
            mi->src[0].app = instr_get_src(inst, 0);
            if (!memop_ok_for_fastpath(mi->src[0].app, true))
                return false;
            mi->mem2mem = true;
        } else {
            if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 0), 0, false, mi))
                return false;
        }
        return true;
    case OP_cmps:
    case OP_scas:
        /* the other reg opnds are also base regs so we're already checking
         * for definedness: thus we can ignore and get on the fastpath
         */
        if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 0), 0, false, mi))
            return false;
        if (opc == OP_scas) {
            if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 1), 1, false, mi))
                return false;
            /* No support for combining two sub-dword w/ diff offs in fastpath */
            mi->check_definedness = true;
        } else {
            mi->src[1].app = instr_get_src(inst, 1);
            if (!memop_ok_for_fastpath(mi->src[1].app, true))
                return false;
            mi->load2x = true;
        }
        return true;
    case OP_pinsrb:
    case OP_pinsrw:
    case OP_pinsrd:
    case OP_pextrb:
    case OP_pextrw:
    case OP_pextrd:
    case OP_vpextrb:
    case OP_vpextrw:
    case OP_vpextrd:
    case OP_extractps:
    case OP_insertps:
    case OP_movhps: /* would need to add check_definedness of dst too */
    case OP_movhpd: /* would need to add check_definedness of dst too */
    case OP_movlps: /* would need to add check_definedness of dst too */
        /* XXX i#243: these are tricky as they access sub-dword parts of xmm.
         * Bail for now to slowpath.
         */
        return false;
    case OP_idiv:
    case OP_div:
        if (opnd_get_size(instr_get_dst(inst, 0)) == OPSZ_1) {
            /* treat %ah + %al dsts as single %ax dst so can treat as ALU */
            if (!opnd_ok_for_fastpath(opc, opnd_create_reg(REG_AX), 0, true, mi))
                return false;
            if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 0), 0, false, mi))
                return false;
            if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 1), 1, false, mi))
                return false;
            return true;
        }
        /* else fall-through: 2-byte is check-defined (i#401 covers doing better)
         * and 4-byte is handled normally
         */
    case OP_movzx:
    case OP_movsx:
        if (opnd_get_size(instr_get_dst(inst, 0)) == OPSZ_8) {
            /* XXX i#111: fastpath code for these doesn't yet handle 8-byte dests. */
            return false;
        }
        /* else fall-through */
    }
    /* default */
    {
        /* mi->src[] and mi->dst[] are set in opnd_ok_for_fastpath() */

        int num_dsts = num_true_dsts(inst, NULL);
        int num_srcs = num_true_srcs(inst, NULL);

        if (num_dsts > 2)
            return false;
        if (num_srcs > 3)
            return false;

        if (opc == OP_sbb) {
            /* sbb with self should consider srcs defined, except eflags so can't
             * be in result_is_always_defined (PR 425498, PR 425622)
             */
            if (opnd_same(instr_get_src(inst, 0), instr_get_src(inst, 1))) {
                /* just add dst, no srcs */
                if (!opnd_ok_for_fastpath(opc, instr_get_dst(inst, 0), 0, true, mi))
                    return false;
                return true;
            }
        }

        if (num_dsts > 0) {
            if (!opnd_ok_for_fastpath(opc, instr_get_dst(inst, 0), 0, true, mi))
                return false;
            if (num_dsts > 1) {
                if (num_dsts == 2 && opc_2nd_dst_is_extension(opc)) {
                    if (!opnd_ok_for_fastpath(opc, instr_get_dst(inst, 1), 1, true, mi))
                        return false;
                } else
                    return false;
            }
        }
        if (num_srcs > 0) {
            if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 0), 0, false, mi))
                return false;
            if (num_srcs > 1) {
                if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 1), 1, false, mi))
                    return false;
                if (num_srcs > 2) {
                    if (!opnd_ok_for_fastpath(opc, instr_get_src(inst, 2), 2, false, mi))
                        return false;
                }
            }
        }

        /* a sub-dword ALU store that needs shadow op cannot go in fastpath b/c
         * fastpath doesn't handle both src and dst w/ dynamic sub-dword
         * alignment (i#877)
         */
        if (needs_shadow_op(inst) && mi->store &&
            opnd_same(mi->dst[0].app, mi->src[0].app) &&
            opnd_size_in_bytes(opnd_get_size(mi->dst[0].app)) < 4)
            return false;

        /* We only allow 8-byte or 10-byte memop for floats if we do
         * no real propagation.  We do propagate 16-byte xmm.
         */
        if (mi->load && (opnd_get_size(mi->src[0].app) == OPSZ_8 ||
                         opnd_get_size(mi->src[0].app) == OPSZ_10) &&
            (!opnd_is_null(mi->src[1].app) || !opnd_is_null(mi->dst[0].app) ||
             TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)))) {
            mi->check_definedness = true;
        }
        if (mi->store && (opnd_get_size(mi->dst[0].app) == OPSZ_8 ||
                          opnd_get_size(mi->dst[0].app) == OPSZ_10) &&
            (!opnd_is_null(mi->dst[1].app) || !opnd_is_null(mi->src[0].app) ||
             TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)))) {
            mi->check_definedness = true;
        }

        return true;
    }
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

    if (!mi->check_definedness) /* sometimes set in instr_ok_for_instrument_fastpath */
        mi->check_definedness = instr_check_definedness(inst);

    if (opnd_is_reg(mi->src[0].app))
        mi->src_reg = opnd_get_reg(mi->src[0].app);
    if (opnd_is_reg(mi->dst[0].app))
        mi->dst_reg = opnd_get_reg(mi->dst[0].app);
    ASSERT(mi->dst_reg == REG_NULL ||
           reg_is_shadowed(opc, mi->dst_reg), "reg fastpath error");
    ASSERT(mi->src_reg == REG_NULL ||
           reg_is_shadowed(opc, mi->src_reg), "reg fastpath error");
    ASSERT(!mi->pushpop || mi->load || mi->store, "internal error");

    if (opnd_is_null(mi->dst[0].app)) {
        mi->opsz = 0;
    } else
        mi->opsz = opnd_size_in_bytes(opnd_get_size(mi->dst[0].app));
    if (opnd_is_null(mi->src[0].app)) {
#ifdef TOOL_DR_MEMORY
        if (TESTANY(EFLAGS_READ_6, instr_get_eflags(inst, DR_QUERY_DEFAULT))) {
            /* match dst size, shadow slot holds whole dword's worth */
            if (mi->opsz > 0) {
                ASSERT(mi->opsz <= sizeof(void*) || mi->check_definedness ||
                       result_is_always_defined(inst, false/*us*/),
                       "no prop eflags to > gpr size");
                mi->src_opsz = mi->opsz; /* eflags */
            } else
                mi->src_opsz = SHADOW_GPR_OPSZ; /* eflags */
        } else
#endif
            mi->src_opsz = 0;
    } else
        mi->src_opsz = opnd_size_in_bytes(opnd_get_size(mi->src[0].app));
#ifdef TOOL_DR_MEMORY
    if (mi->opsz == 0 &&
        TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL))) {
        /* match src size, shadow slot holds whole dword's worth */
        if (mi->src_opsz > 0) {
            ASSERT(mi->src_opsz <= sizeof(void*) || mi->check_definedness ||
                   result_is_always_defined(inst, false/*us*/),
                   "no prop eflags to > gpr size");
            mi->opsz = mi->src_opsz; /* eflags */
        } else
            mi->opsz = 1; /* eflags */
    }
#endif

    /* adjust for precise memory operand */
    if (mi->load || mi->store) {
        mi->memop = adjust_memop(inst, mi->load ? mi->src[0].app : mi->dst[0].app,
                                 mi->store, &mi->memsz, &mi->pushpop_stackop);
        /* Since we don't allow pop mem, and push mem has stack op as primary mem
         * ref, these should be equal:
         */
#ifdef TOOL_DR_MEMORY
        ASSERT((!mi->pushpop && !mi->pushpop_stackop) ||
               (mi->pushpop && mi->pushpop_stackop), "internal error");
#else
        mi->pushpop = mi->pushpop_stackop;
#endif
#ifdef TOOL_DR_MEMORY
        if (mi->load2x) {
            uint mem2sz;
            bool pushpop2;
            IF_DEBUG(opnd_t mem2op = )
                adjust_memop(inst, mi->src[1].app, false, &mem2sz, &pushpop2);
            ASSERT(opnd_same(mem2op, mi->src[1].app), "load2x 2nd mem can't be stack op");
            ASSERT(mem2sz == mi->memsz, "load2x 2nd mem must be same size as 1st");
        }
        /* stack ops are the ones that vary and might reach 8+ */
        if (!(((mi->memsz == 8 || mi->memsz == 16 || mi->memsz == 10) && !mi->pushpop) ||
              mi->memsz == 4 || mi->memsz == 2 || mi->memsz == 1)) {
            return false; /* needs slowpath */
        }
        if (mi->store) {
            mi->dst[0].app = mi->memop;
            mi->opsz = mi->memsz;
        } else {
            mi->src[0].app = mi->memop;
            mi->src_opsz = mi->memsz;
        }
        if (mi->opsz >= 4)
            mi->memoffs = opnd_create_immed_int(0, OPSZ_1);
        else {
            /* else, mi->memoffs is dynamically varying; properly defined later */
            mi->memoffs = opnd_create_null();
        }
#else
        if (mi->store)
            mi->dst[0].app = mi->memop;
        else
            mi->src[0].app = mi->memop;
        mi->memoffs = opnd_create_immed_int(0, OPSZ_1);
#endif
    } else
        mi->memoffs = opnd_create_immed_int(0, OPSZ_1);

    /* Having only the input byte defined and the rest of the dword
     * undefined is common enough (esp on linux) that we must fastpath
     * it and thus need the offset.
     */
    if (opc == OP_movzx || opc == OP_movsx) {
        if ((mi->opsz == 4 IF_X64(|| mi->opsz == 8)) &&
            (mi->src_opsz == 1 || mi->src_opsz == 2))
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
    }
    if (!mi->need_offs) { /* if not set above */
        mi->need_offs =
            ( (mi->store || mi->dst_reg != REG_NULL) ||
              /* need offs if propagating eflags (esp for -no_check_uninit_cmps) */
              (mi->load &&
               TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)) &&
               !instr_check_definedness(inst)) ) &&
            (mi->memsz < 4 && !opnd_is_immed_int(mi->memoffs));
    }
    if (!options.check_uninitialized)
        mi->need_offs = false;
    return true;
}

#ifdef TOOL_DR_MEMORY
static inline opnd_size_t
shadow_reg_indir_size(opnd_info_t *info)
{
    uint bytes = opnd_size_in_bytes(info->indir_size);
    /* For sub-reg (e.g., 12 bytes out of 16 in an xmm reg) we assume
     * we're just checking definedness and can safely round up.  We'll
     * need i#1562 to handle shadow destinations.
     */
    if (bytes > 8 && bytes < 16)
        bytes = 16;
    return opnd_size_from_bytes(bytes/SHADOW_GRANULARITY);
}

static void
set_reg_shadow_opnds(fastpath_info_t *mi, opnd_info_t *oi, reg_id_t reg)
{
    if (reg_is_gpr(reg)) {
        oi->shadow = opnd_create_shadow_reg_slot(reg);
        oi->offs = opnd_create_immed_int(reg_offs_in_dword(reg), OPSZ_1);
    } else {
        ASSERT(reg_is_xmm(reg) || reg_is_mmx(reg), "only expect gpr or xmm");
        ASSERT(mi->shadow_indir, "shadow_indir should be set");
        /* This points at what we need to de-reference via a scratch reg */
        oi->shadow = opnd_create_shadow_reg_slot(reg);
        oi->offs = opnd_create_immed_int(get_shadow_xmm_offs(reg), OPSZ_1);
        /* For partial xmm regs we need the opnd size, not reg size */
        ASSERT(opnd_get_reg(oi->app) == reg, "reg mismatch");
        oi->indir_size = opnd_get_size(oi->app);
        ASSERT(mi->need_nonoffs_reg3, "spill mismatch");
        /* XXX i#1562: we can't yet handle sub-xmm-reg in fastpath */
        if (oi->indir_size != reg_get_size(reg))
            mi->check_definedness = true;
    }
}

/* Translates from sources and dests into shadow operands and offsets
 * and initializes mi->num_to_propagate.  Does not set the offsets
 * of memory operands as those are dynamic and will be set later
 * from mi->memoffs which will be set by add_shadow_table_lookup().
 */
static void
set_shadow_opnds(fastpath_info_t *mi)
{
    ASSERT(mi != NULL, "invalid args");
    if (opnd_is_memory_reference(mi->dst[0].app)) {
        if (mi->memsz <= 4)
            mi->dst[0].shadow = OPND_CREATE_MEM8(mi->reg1.reg, 0);
        else if (mi->memsz == 8)
            mi->dst[0].shadow = OPND_CREATE_MEM16(mi->reg1.reg, 0);
        else {
            ASSERT(mi->memsz == 16 || mi->memsz == 10, "invalid memsz");
            mi->dst[0].shadow = OPND_CREATE_MEM32(mi->reg1.reg, 0);
        }
    } else if (mi->dst_reg != REG_NULL) {
        set_reg_shadow_opnds(mi, &mi->dst[0], mi->dst_reg);
    } else
        mi->dst[0].shadow = opnd_create_null();
    if (opnd_is_null(mi->dst[1].app))
        mi->dst[1].shadow = opnd_create_null();
    else {
        /* We assume no xmm regs are 2nd dests */
        ASSERT(opnd_is_reg(mi->dst[1].app) && reg_is_gpr(opnd_get_reg(mi->dst[1].app)),
               "reg fastpath error");
        set_reg_shadow_opnds(mi, &mi->dst[1], opnd_get_reg(mi->dst[1].app));
    }
    if (opnd_is_memory_reference(mi->src[0].app)) {
        if (!options.check_uninitialized) {
            if (mi->memsz <= 4)
                mi->src[0].shadow = OPND_CREATE_MEM8(mi->reg1.reg, 0);
            else if (mi->memsz == 8)
                mi->src[0].shadow = OPND_CREATE_MEM16(mi->reg1.reg, 0);
            else {
                ASSERT(mi->memsz == 16 || mi->memsz == 10, "invalid memsz");
                mi->src[0].shadow = OPND_CREATE_MEM32(mi->reg1.reg, 0);
            }
        } else if (mi->store && !mi->mem2mem) {
            /* must be alu */
            ASSERT(opnd_same(mi->dst[0].app, mi->src[0].app), "dual mem ref error");
            /* need to reference by address not value so copy dst shadow */
            mi->src[0].shadow = mi->dst[0].shadow;
            /* we copy offs later */
        } else {
            /* for mem2mem we'll adjust below */
            ASSERT(mi->load || mi->store, "mem must be load or store");
            if (mi->memsz <= 4)
                mi->src[0].shadow = opnd_create_reg(mi->reg2_8);
            else if (mi->memsz == 8)
                mi->src[0].shadow = opnd_create_reg(mi->reg2_16);
            else {
                ASSERT(mi->memsz == 16 || mi->memsz == 10, "invalid memsz");
                mi->src[0].shadow = opnd_create_reg(reg_ptrsz_to_32(mi->reg2.reg));
            }
        }
        mi->num_to_propagate++;
    } else if (!opnd_is_null(mi->src[0].app)) {
        set_reg_shadow_opnds(mi, &mi->src[0], mi->src_reg);
        mi->num_to_propagate++;
    } else
        mi->src[0].shadow = opnd_create_null();
    if (opnd_is_memory_reference(mi->src[1].app)) {
        ASSERT(mi->load2x, "2nd mem src must be load2x");
        ASSERT(mi->memsz <= 4, "load2x of 8-byte memop not supported");
        mi->src[1].shadow = opnd_create_reg(mi->reg1_8);
        mi->num_to_propagate++;
    } else if (opnd_is_null(mi->src[1].app))
        mi->src[1].shadow = opnd_create_null();
    else {
        set_reg_shadow_opnds(mi, &mi->src[1], opnd_get_reg(mi->src[1].app));
        mi->num_to_propagate++;
    }
    if (opnd_is_null(mi->src[2].app))
        mi->src[2].shadow = opnd_create_null();
    else {
        set_reg_shadow_opnds(mi, &mi->src[2], opnd_get_reg(mi->src[2].app));
        mi->num_to_propagate++;
    }
}

/* Identifies other cases where we check definedness rather than propagating.
 * Called prior to obtaining scratch regs, and thus prior to setting
 * mi->src and mi->dst.
 */
static void
set_check_definedness_pre_regs(void *drcontext, instr_t *inst, fastpath_info_t *mi)
{
    int opc = instr_get_opcode(inst);
    ASSERT(mi != NULL, "invalid args");
    if (instr_needs_all_srcs_and_vals(inst)) {
        /* Strategy for and/test/or: don't need 2 passes like slowpath since
         * if check_definedness we can bail out to slowpath and start over there.
         * Thus we mark as checking for OP_and and OP_or; OP_test by default is
         * if options.check_uninit_cmps.
         */
        mi->check_definedness = true;
        /* To do the full check in the fastpath would take some work:
         * would need to get vals and if defined and 0/1 => dst defined
         */
    }
    /* Similarly for shifts, since we don't have insert_shadow_op() fully
     * operational yet for non-immed-int-%8 shifts (xref PR 574918)
     */
    if (opc_is_gpr_shift(opc) &&
        (!opnd_is_immed_int(instr_get_src(inst, 0)) ||
         opnd_get_immed_int(instr_get_src(inst, 0)) % 8 != 0))
         mi->check_definedness = true;

    /* i#1525: these are tricky to implement in fastpath for partially-defined */
    switch (opc) {
    case OP_punpcklbw:    case OP_punpckhbw:
    case OP_punpcklwd:    case OP_punpckhwd:
    case OP_punpckldq:    case OP_punpckhdq:
    case OP_punpcklqdq:   case OP_punpckhqdq:
    case OP_vpunpcklbw:   case OP_vpunpckhbw:
    case OP_vpunpcklwd:   case OP_vpunpckhwd:
    case OP_vpunpckldq:   case OP_vpunpckhdq:
    case OP_vpunpcklqdq:  case OP_vpunpckhqdq:
    case OP_unpcklps:     case OP_vunpcklps:
    case OP_unpcklpd:     case OP_vunpcklpd:
    case OP_unpckhps:     case OP_vunpckhps:
    case OP_unpckhpd:     case OP_vunpckhpd:
    case OP_shufps:       case OP_shufpd:
    case OP_vshufps:      case OP_vshufpd:
    case OP_pshufw:       case OP_pshufd:
    case OP_pshufhw:      case OP_pshuflw:
    case OP_pshufb:
    case OP_vpshufhw:     case OP_vpshuflw:
    case OP_vpshufd:      case OP_vpshufb:
    case OP_vpinsrb:      case OP_vpinsrw:    case OP_vpinsrd:
    case OP_psrlw:        case OP_psrld:      case OP_psrlq:
    case OP_psraw:        case OP_psrad:
    case OP_psrldq:
    case OP_vpsrlw:       case OP_vpsrld:     case OP_vpsrlq:
    case OP_vpsraw:       case OP_vpsrad:
    case OP_vpsrldq:
    case OP_vpsravd:
    case OP_vpsrlvd:      case OP_vpsrlvq:
    case OP_psllw:        case OP_pslld:      case OP_psllq:
    case OP_pslldq:
    case OP_vpsllw:       case OP_vpslld:     case OP_vpsllq:
    case OP_vpslldq:
    case OP_vpsllvd:      case OP_vpsllvq:
    /* conversions that shrink */
    case OP_cvttpd2pi:    case OP_cvttsd2si:
    case OP_cvtpd2pi:     case OP_cvtsd2si:
    case OP_cvtpd2ps:     case OP_cvtsd2ss:
    case OP_cvtdq2pd:
    case OP_cvttpd2dq:    case OP_cvtpd2dq:
    /* blend and other complex operations */
    case OP_pblendvb:     case OP_blendvps:
    case OP_blendvpd:     case OP_blendps:
    case OP_blendpd:      case OP_pblendw:
    case OP_vpblendvb:    case OP_vblendvps:
    case OP_vblendvpd:    case OP_vblendps:
    case OP_vblendpd:     case OP_vpblendw:
    case OP_vpblendd:
    case OP_palignr:
    case OP_phminposuw:
    case OP_pcmpestrm:    case OP_pcmpestri:
    /* XXX i#1484: add OP_por, OP_pand, and OP_pand here for handling and/or w/ const */
        mi->check_definedness = true;
        break;
    }
}

/* Identifies other cases where we check definedness rather than propagating.
 * Called after obtaining scratch regs, and thus after setting
 * mi->src and mi->dst.
 */
static void
set_check_definedness_post_regs(void *drcontext, instr_t *inst, fastpath_info_t *mi)
{
    int opc = instr_get_opcode(inst);
    ASSERT(mi != NULL, "invalid args");
    /* cwde, etc. aren't handled in fastpath */
    if (!opnd_is_null(mi->src[0].app) && mi->src_opsz < mi->opsz &&
        opc != OP_movzx && opc != OP_movsx)
        mi->check_definedness = true;
    /* We support push-mem and call_ind and other mem2mem, but we can
     * only propagate if we don't need the 3rd scratch reg: i.e., if
     * they're word-sized
     */
    if (mi->mem2mem) {
        ASSERT(mi->store && opnd_same(mi->memop, mi->dst[0].app), "mem2mem error");
        ASSERT(opnd_is_memory_reference(mi->src[0].app), "mem2mem error");
        if (mi->memsz == 4 &&
            !mi->need_offs && !mi->need_offs_early && !mi->zero_rest_of_offs &&
            /* not much point in propagating w/o good addr check */
            options.loads_use_table) {
            /* propagate */
        } else {
            mi->check_definedness = true;
        }
    }
    /* Propagation not supported: no support for multi-src
     * propagation, and not enough reg for sub-dword
     */
    if (mi->load2x) {
        ASSERT(mi->load && opnd_is_memory_reference(mi->src[1].app), "load2x error");
        mi->check_definedness = true;
    }
    /* For the 2nd dst of OP_leave, ebp->esp, we rely on check_definedness to
     * ensure ebp is defined and add_addressing_register_checks for esp being defined,
     * and bail to slowpath o/w, as we don't support 2 separate propagation chains
     */
    if (opc == OP_leave)
        mi->check_definedness = true;


    if (mi->opsz < 4 && mi->num_to_propagate >= 2) {
        /* XXX i#401: some cases that we could propagate if we took multiple steps
         * and pretended src0 was a dst when calling add_dstX2_shadow_write() the
         * first time (and setting preserve=true) but that's NYI (i#401).
         */
        if (is_alu(mi)) {
            if (!opnd_is_null(mi->src[2].shadow) &&
                !opnd_same(mi->src[0].offs, mi->src[2].offs)) {
                /* {div,idiv}w */
                mi->check_definedness = true;
            }
        } else if (!opnd_is_null(mi->src[1].shadow) &&
                   !opnd_same(mi->src[1].offs, mi->src[0].offs)) {
            /* 1-byte {mul,imul} */
            mi->check_definedness = true;
        }
    }

    DOLOG(4, {
        if (mi->check_definedness) {
            LOG(3, "checking definedness for: ");
            instr_disassemble(drcontext, inst, LOGFILE_GET(drcontext));
            LOG(3, "\n");
        }
    });

    /* Propagate eflags if we have room: else check definedness (PR 425622) */
    mi->check_eflags_defined = true;
    if (!mi->check_definedness &&
        TESTANY(EFLAGS_READ_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)) &&
        /* XXX i#402: since eflags shadow can have undef bits at any part of it,
         * to propagate to sub-dword we'd need to map it down
         */
        mi->opsz >= 4) {
        if (opnd_is_null(mi->src[0].shadow)) {
            mi->src[0].shadow = opnd_create_shadow_eflags_slot();
            mi->src[0].offs = opnd_create_immed_int(0, OPSZ_1);
            mi->check_eflags_defined = false;
        } else if (opnd_is_null(mi->src[1].shadow)) {
            mi->src[1].shadow = opnd_create_shadow_eflags_slot();
            mi->src[1].offs = opnd_create_immed_int(0, OPSZ_1);
            mi->check_eflags_defined = false;
        } else if (opnd_is_null(mi->src[2].shadow)) {
            mi->src[2].shadow = opnd_create_shadow_eflags_slot();
            mi->src[2].offs = opnd_create_immed_int(0, OPSZ_1);
            mi->check_eflags_defined = false;
        }
        if (!mi->check_eflags_defined) {
            LOG(3, "propagating eflags shadow to dst\n");
            mi->num_to_propagate++;
        }
    }
}
#endif /* TOOL_DR_MEMORY */

static inline bool
should_share_addr_helper(fastpath_info_t *mi)
{
    /* FIXME OPT: i#165/PR 494727: expand sharing of shadow translation
     * across more cases:
     * - mem2mem (in particular push-mem, pop-mem, and call-ind)
     *   or load2x
     * - sub-dword
     * - app instr that reads/writes both whole-bb reg1 and reg2
     * - app instr that does not share same memref: start w/
     *     simple instrs like reg-reg moves by having them use reg2.
     *     initial goal can be this common pattern:
     *       push ebp, mov esp->ebp, push edi, push esi, push ebx
     */
    if (!mi->load && !mi->store)
        return false;
    if (mi->mem2mem || mi->load2x || mi->need_offs)
        return false;
    /* i#2032: sub-dword w/ check-defined was supported before but it was buggy
     * so we are disabling it until it can be re-examined.
     */
    if (mi->memsz < 4)
        return false;
    /* XXX i#243: we rule out sharing here b/c it's too hard to figure out whether
     * we can use reg3 down below -- probably we can?  it's hard to ensure.
     * once we get drreg we should be able to share these and avoid reg
     * conflicts.
     */
    if (mi->shadow_indir)
        return false;
    return true;
}

/* PR 493257: determines whether we should share shadow translation
 * across multiple instrs, in particular from inst to its successor
 * instruction.  Looks for identical memory reference base registers
 * and size==4 so that a register can be used to hold the
 * shared translation address.
 *
 * We do this locally b/c it only needs a small window of the next
 * instruction.  We could do this in the analysis phase instead,
 * though likely at higher overhead.  If we do expand xl8 sharing any
 * further, with larger windows, we should probably move to the
 * analysis phase.
 */
static bool
should_share_addr(instr_t *inst, fastpath_info_t *cur, opnd_t cur_memop)
{
    fastpath_info_t mi;
    instr_t *nxt = instr_get_next_app_instr(inst);
    int opc;
#ifdef TOOL_DR_HEAPSTAT
    /* Not worth cost of shadow redzone and extra check + jcc slowpath
     * FIXME PR 553724: measure potential perf gains to see whether worth
     * some crazy scheme to catch over/underflow.
     */
    return false;
#endif
    if (!options.share_xl8)
        return false;
    if (!whole_bb_spills_enabled())
        return false;
    if (nxt == NULL)
        return false;
    if (!should_share_addr_helper(cur))
        return false;
    /* Don't share if we had too many slowpaths in the past */
    if ((uint)(ptr_uint_t)
        hashtable_lookup(&xl8_sharing_table, instr_get_app_pc(nxt)) >
        options.share_xl8_max_slow)
        return false;
    /* If the base+index are written to, do not share since no longer static.
     * The dst2 of push/pop write is ok.
     */
    opc = instr_get_opcode(inst);
    /* Do not share cmovcc since it nondet skips its mem access operand (PR 530902) */
    if (instr_is_predicated(inst))
        return false;
    if (opnd_is_reg(cur->dst[0].app) && !opc_is_push(opc) &&
        opnd_uses_reg(cur_memop, opnd_get_reg(cur->dst[0].app)))
        return false;
    if (opnd_is_reg(cur->dst[1].app) && !opc_is_pop(opc) &&
        opnd_uses_reg(cur_memop, opnd_get_reg(cur->dst[1].app)))
        return false;
    /* Do not share from a stringop since they modify their base reg and
     * we don't model that in our sharing displacement calculations
     */
    if (opc_is_stringop(opc))
        return false;
    /* Do not share w/ cmovcc since it nondet skips its mem access operand (PR 530902) */
    if (instr_is_predicated(nxt))
        return false;
    if (instr_ok_for_instrument_fastpath(nxt, &mi, cur->bb) &&
        adjust_opnds_for_fastpath(nxt, &mi)) {
        opnd_t memop;
        ptr_int_t cur_disp, nxt_disp, shadow_diff;
        if (!should_share_addr_helper(&mi)) {
#ifdef STATISTICS
            if (mi.load || mi.store) {
                memop = adjust_memop(nxt, mi.load ? mi.src[0].app : mi.dst[0].app,
                                     mi.store, &mi.memsz, &mi.pushpop_stackop);
                /* FIXME i#111: all the opnd_get_base() callers need to handle rip-rel */
                if (opnd_get_base(cur_memop) == opnd_get_base(memop) &&
                    opnd_get_index(cur_memop) == opnd_get_index(memop) &&
                    opnd_get_scale(cur_memop) == opnd_get_scale(memop) &&
                    opnd_get_segment(cur_memop) == opnd_get_segment(memop)) {
                    if (mi.mem2mem || mi.load2x)
                        STATS_INC(xl8_not_shared_mem2mem);
                    else
                        STATS_INC(xl8_not_shared_offs);
                }
            }
#endif
            return false;
        }
        memop = adjust_memop(nxt, mi.load ? mi.src[0].app : mi.dst[0].app,
                             mi.store, &mi.memsz, &mi.pushpop_stackop);
        if (cur->memsz != mi.memsz)
            return false;
#ifdef X64
        if (opnd_is_rel_addr(cur_memop) && opnd_is_rel_addr(memop)) {
            cur_disp = (ptr_int_t) opnd_get_addr(cur_memop);
            nxt_disp = (ptr_int_t) opnd_get_addr(memop);
        } else
#endif
        if (opnd_is_base_disp(cur_memop) && opnd_is_base_disp(memop)) {
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
            nxt_disp = opnd_get_disp(memop);
        } else {
            return false;
        }
        cur_disp += cur->bb->shared_disp_implicit;
        /* We do a static check for aligned disp, and so will only share
         * when base+index is aligned as well, but should be rare to have
         * unaligned base+index and unaligned disp that add to become aligned
         */
        if (!ALIGNED(cur_disp, mi.memsz) || !ALIGNED(nxt_disp, mi.memsz)) {
            LOG(3, "  NOT sharing: %d or %d not aligned\n", cur_disp, nxt_disp);
            STATS_INC(xl8_not_shared_unaligned);
            return false;
        }
        shadow_diff = (nxt_disp - cur_disp) / 4; /* 2 shadow bits per byte */
        /* The option is more intuitive to have it *4 so we /4 here */
        if (shadow_diff > (ptr_int_t)cur->bb->share_xl8_max_diff/4 ||
            shadow_diff < -(ptr_int_t)(cur->bb->share_xl8_max_diff/4)) {
            LOG(3, "  NOT sharing: disp diff %d too big\n", shadow_diff);
            STATS_INC(xl8_not_shared_disp_too_big);
            return false;
        }
        return true;
    }
    return false;
}

#ifdef TOOL_DR_MEMORY
static void
insert_cmp_for_equality(void *drcontext, instrlist_t *bb, instr_t *inst,
                        fastpath_info_t *mi, opnd_t op, int val)
{
    /* test with self is smaller instr than cmp to 0, for self=reg */
    if (val == 0 && opnd_is_reg(op)) {
        PRE(bb, inst, INSTR_CREATE_test(drcontext, op, op));
    } else if (val >= SCHAR_MIN && val <= SCHAR_MAX) {
        /* all shadow de-refs need xl8 as Umbra uses page faults */
        PREXL8M(bb, inst, INSTR_XL8
                (INSTR_CREATE_cmp(drcontext, op, OPND_CREATE_INT8((char)val)),
                 mi->xl8));
    } else {
        /* all shadow de-refs need xl8 as Umbra uses page faults */
        PREXL8M(bb, inst, INSTR_XL8
                (INSTR_CREATE_cmp(drcontext, op, OPND_CREATE_INT32(val)),
                 mi->xl8));
    }
}

/* Assumes base_reg is pointer-sized but only contains data in the bottom 16 bits. */
static int
insert_table_access_pre(void *drcontext, instrlist_t *bb, instr_t *inst,
                        ptr_int_t table_addr, reg_id_t base_reg)
{
    int disp = (int) table_addr;
#ifdef X64
    if (disp == table_addr)
        return disp;
    /* To avoid having to spill yet another register to access a table not in the low
     * 2GB, we add the high 32 bits of the address to the base register.
     * An alternative would be to mmap space in the low 2GB and copy our tables there:
     * but __PAGEZERO makes that impossible on Mac, and we do not have enough TLS
     * slots to copy our tables there.  Xref i#2083.
     */
    LOG(4, "%s: table addr " PFX " >2GB so using ror,or,ror to add upper bits.\n",
        __FUNCTION__, table_addr);
    PRE(bb, inst,
        INSTR_CREATE_ror(drcontext, opnd_create_reg(base_reg), OPND_CREATE_INT8(32)));
    int top_bits = (int)((table_addr - disp) >> 32);
    PRE(bb, inst,
        INSTR_CREATE_or(drcontext, opnd_create_reg(base_reg),
                        OPND_CREATE_INT32(top_bits)));
    PRE(bb, inst,
        INSTR_CREATE_ror(drcontext, opnd_create_reg(base_reg), OPND_CREATE_INT8(32)));
#endif
    return disp;
}

static void
insert_table_access_post(void *drcontext, instrlist_t *bb, instr_t *inst,
                         ptr_int_t table_addr, reg_id_t base_reg)
{
#ifdef X64
    int disp = (int) table_addr;
    if (disp == table_addr)
        return;
    /* Clear the top bits again. */
    reg_id_t reg32 = reg_ptrsz_to_32(base_reg);
    PRE(bb, inst,
        INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(reg32), opnd_create_reg(reg32)));
#endif
}

/* Adds a check that app_op's shadow in shadow_op has its shadow bits
 * defined.  mi->src_opsz is assumed to be the size.
 */
static void
insert_check_defined(void *drcontext, instrlist_t *bb, instr_t *inst,
                     fastpath_info_t *mi, opnd_info_t *oi,
                     opnd_t app_op, opnd_t shadow_op)
{
    ASSERT(!opnd_is_null(shadow_op), "shadow op can't be empty");
    ASSERT(!opnd_is_null(app_op), "app op can't be empty");
    /* We require whole-bb so that we know the regs when we set mi->need_offs */
    if (whole_bb_spills_enabled() && mi->src_opsz < 4 &&
        /* allow callers to not zero it out and use full check:
         * primarily for load2x where we don't have another reg for offs */
        mi->zero_rest_of_offs) {
        /* PR 425240: check just the bits involved.  We use a table lookup
         * and risk extra data cache pressure to avoid the series of shifts
         * and masks and extra spilled regs needed to pull out the bits we
         * want.
         */
        int disp = 0;
        int sz = mi->src_opsz;
        reg_id_t base = REG_NULL;
        reg_id_t index = REG_NULL;
        if (opnd_is_reg(shadow_op)) {
            /* came from a memref, where we should have zeroed the rest of offs */
            sz = mi->memsz;
            ASSERT(opnd_is_memory_reference(app_op), "reg shadow == mem app");
            ASSERT(mi->zero_rest_of_offs, "need zeroed offs to check mem src");
            /* mi->need_offs may not be set, if avoiding 3rd reg */
            if (opnd_is_null(mi->memoffs)) {
                /* movzx 2-to-4 or 1-to-2 don't store the offs: so we bail */
                insert_cmp_for_equality(drcontext, bb, inst, mi, shadow_op,
                                        SHADOW_DWORD_DEFINED);
                return;
            }
            base = reg_to_pointer_sized(opnd_get_reg(shadow_op));
            /* offs is kept in high reg8 => offs is already multiplied by 256 for us */
            index = reg_to_pointer_sized(opnd_get_reg(mi->memoffs));
            LOG(3, "check_defined: using table for mem op base=%d index=%d\n",
                base, index);
        } else {
            if (mi->mem2mem || mi->load2x) {
                /* More complex to find or create a free register: bailing for now */
                insert_cmp_for_equality(drcontext, bb, inst, mi, shadow_op,
                                        SHADOW_DWORD_DEFINED);
                return;
            }
            LOG(3, "check_defined: using table for reg op\n");
            if (opnd_is_reg(app_op)) {
                disp += reg_offs_in_dword(opnd_get_reg(app_op)) * 256;
            } else {
                ASSERT(opnd_is_reg(mi->memoffs), "must have offs");
                index = reg_to_pointer_sized(opnd_get_reg(mi->memoffs));
            }
            /* load from reg shadow tls slot into reg2, which should
             * be scratch
             * FIXME PR 494720: add annotations so it's easier to know which
             * regs are dead at which points, and to check assumptions
             */
            if (mi->store) {
                base = mi->need_offs ? mi->reg3.reg : mi->reg2.reg;
                mark_scratch_reg_used(drcontext, bb, mi->bb,
                                      mi->need_offs ? &mi->reg3 : &mi->reg2);
            } else if (!SHARING_XL8_ADDR(mi)) {
                base = mi->reg1.reg;
                mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg1);
            } else {
                base = mi->reg2.reg;
                mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);
            }
            /* all shadow de-refs need xl8 as Umbra uses page faults */
            PREXL8M(bb, inst, INSTR_XL8
                    (INSTR_CREATE_movzx(drcontext, opnd_create_reg(base), shadow_op),
                     mi->xl8));
        }
        mark_eflags_used(drcontext, bb, mi->bb);

        ptr_int_t table_addr = (ptr_int_t)
            ((sz == 1) ? shadow_byte_defined : shadow_word_defined);
        disp += insert_table_access_pre(drcontext, bb, inst, table_addr, base);
        /* look up in series of 4 tables, one for each offset */
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext,
                             opnd_create_base_disp(base, index, 1, disp, OPSZ_1),
                             OPND_CREATE_INT8(1)));
        insert_table_access_post(drcontext, bb, inst, table_addr, base);
    } else {
        if (oi != NULL && oi->indir_size != OPSZ_NA) {
            reg_id_t indir_tgt = reg_to_size(mi->reg3.reg, shadow_reg_indir_size(oi));
            ASSERT(mi->reg3.reg != DR_REG_NULL, "spill error");
            mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg3);
            load_reg_shadow_val(drcontext, bb, inst, mi, indir_tgt, oi);
            shadow_op = opnd_create_reg(indir_tgt);
        }
        insert_cmp_for_equality(drcontext, bb, inst, mi, shadow_op, SHADOW_DWORD_DEFINED);
    }
}

static bool
needs_shadow_op(instr_t *inst)
{
    int opc = instr_get_opcode(inst);
    switch (opc) {
    case OP_shl:
    case OP_shr:
    case OP_sar:
        return true;
    default: return false;
    }
}

/* Manipulates the shadow value in register reg that is the product of
 * combining the sources of instruction inst, prior to storing into the
 * destination(s) of inst, to mirror the instruction's operation.
 * Keep in sync w/ needs_shadow_op().
 */
static void
insert_shadow_op(void *drcontext, instrlist_t *bb, fastpath_info_t *mi, instr_t *inst,
                 reg_id_t reg, reg_id_t scratch,
                 scratch_reg_info_t *si/*for scratch*/)
{
    ASSERT(scratch == DR_REG_NULL ||
           reg_get_size(reg) == reg_get_size(scratch), "caller must size scratch reg");
    /* FIXME: doesn't support non-immed-int operands yet: for those we
     * go to slowpath (xref PR 574918).  Also requires a scratch reg for %8!=0
     * which currently we aren't acquiring up front.
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
                    INSTR_CREATE_shl(drcontext, opnd_create_reg(reg),
                                     OPND_CREATE_INT8((shift / 8)*2)));
            } else {
                /* need to merge partial bytes */
                ASSERT(scratch != REG_NULL, "invalid scratch reg");
                mark_scratch_reg_used(drcontext, bb, mi->bb, si);
                PRE(bb, inst,
                    INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(scratch),
                                        opnd_create_reg(reg)));
                PRE(bb, inst,
                    INSTR_CREATE_shl(drcontext, opnd_create_reg(reg),
                                     OPND_CREATE_INT8((((shift-1) / 8)+1)*2)));
                PRE(bb, inst,
                    INSTR_CREATE_shl(drcontext, opnd_create_reg(scratch),
                                     OPND_CREATE_INT8((shift / 8)*2)));
                PRE(bb, inst,
                    INSTR_CREATE_or(drcontext, opnd_create_reg(reg),
                                    opnd_create_reg(scratch)));
            }
        } else {
            /* FIXME: how get app value of %cl? */
            ASSERT(false, "fastpath of OP_shl %cl not implemented");
            break;
        }
        break;
    }
    case OP_shr:
    case OP_sar: {
        if (opnd_is_immed_int(instr_get_src(inst, 0))) {
            int shift = opnd_get_immed_int(instr_get_src(inst, 0));
            uint opsz = opnd_size_in_bytes(opnd_get_size(instr_get_dst(inst, 0)));
            if (shift > opsz*8)
                shift = opsz*8;
            if (shift % 8 == 0) {
                if (opc == OP_shr) {
                    PRE(bb, inst,
                        INSTR_CREATE_shr(drcontext, opnd_create_reg(reg),
                                         OPND_CREATE_INT8((shift / 8)*2)));
                } else {
                    /* shift-in bits come from top bit */
                    ASSERT(scratch != REG_NULL, "invalid scratch reg");
                    mark_scratch_reg_used(drcontext, bb, mi->bb, si);
                    while (shift > 0) {
                        PRE(bb, inst,
                            INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(scratch),
                                                opnd_create_reg(reg)));
                        PRE(bb, inst,
                            INSTR_CREATE_sar(drcontext, opnd_create_reg(reg),
                                             OPND_CREATE_INT8(2)));
                        PRE(bb, inst,
                            INSTR_CREATE_or(drcontext, opnd_create_reg(reg),
                                            opnd_create_reg(scratch)));
                        shift -= 8;
                    }
                }
            } else {
                /* need to merge partial bytes */
                ASSERT(scratch != REG_NULL, "invalid scratch reg");
                mark_scratch_reg_used(drcontext, bb, mi->bb, si);
                ASSERT(opc != OP_sar, "NYI");
                PRE(bb, inst,
                    INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(scratch),
                                        opnd_create_reg(reg)));
                PRE(bb, inst,
                    INSTR_CREATE_shr(drcontext, opnd_create_reg(reg),
                                     OPND_CREATE_INT8((((shift-1) / 8)+1)*2)));
                PRE(bb, inst,
                    INSTR_CREATE_shr(drcontext, opnd_create_reg(scratch),
                                     OPND_CREATE_INT8((shift / 8)*2)));
                PRE(bb, inst,
                    INSTR_CREATE_or(drcontext, opnd_create_reg(reg),
                                    opnd_create_reg(scratch)));
            }
        } else {
            /* FIXME: how get app value of %cl? */
            ASSERT(false, "fastpath of OP_shl %cl not implemented");
            break;
        }
        break;
    }
    }
}

/* insert_shadow_op() operates on the destination, after the sources are merged
 * together using this routine.  This routine merges memsrc and regsrc together,
 * possibly using the scratch register si, and puts the result in regsrc.
 */
static void
merge_src_shadows(void *dc, instrlist_t *bb, fastpath_info_t *mi, instr_t *inst,
                  opnd_t memsrc, reg_id_t regsrc, scratch_reg_info_t *si)
{
    int opc = instr_get_opcode(inst);
    switch (opc) {
    /* XXX i#243: add more complex data movements to the fastpath */
    default:
        if (opnd_get_size(memsrc) > reg_get_size(regsrc)) {
            /* This happens with our 2-byte eflags shadow and 32-bit operations on x64.
             * Our solution for now is to do two separate OR operations.
             * XXX: better to shrink the eflags shadow to 1 byte and combine the
             * 2 shadow bytes from a 64-bit arith operation??
             */
            ASSERT(opnd_get_size(memsrc) == SHADOW_GPR_OPSZ, "unhandled size mismatch");
            opnd_set_size(&memsrc, OPSZ_1);
            PRE(bb, inst, INSTR_CREATE_or(dc, opnd_create_reg(regsrc), memsrc));
            opnd_set_disp(&memsrc, opnd_get_disp(memsrc) + 1);
        }
        PRE(bb, inst, INSTR_CREATE_or(dc, opnd_create_reg(regsrc), memsrc));
    }
}

/* val should be SHADOW_GPR_OPSZ.  this routine supports a larger val if it's
 * an immed int, in which case it's truncated.
 */
static bool
write_shadow_eflags(void *drcontext, instrlist_t *bb, instr_t *inst,
                    reg_id_t load_through, opnd_t val)
{
    /* XXX: conditional eflags writes don't exist on x86.
     * On ARM we expect to mark the instru w/ the same predicate
     * where possible; IT blocks may need extra work (xref DR i#1555).
     */
    ASSERT(instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL) ==
           instr_get_eflags(inst, DR_QUERY_DEFAULT),
           "conditionally written eflags not supported");
    if (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL))) {
        if (opnd_get_size(val) != SHADOW_GPR_OPSZ) {
            /* truncate/expand */
            if (opnd_is_immed_int(val))
                opnd_set_size(&val, SHADOW_GPR_OPSZ);
#ifdef X64
            else if (opnd_is_reg(val) && reg_is_8bit(opnd_get_reg(val))) {
                reg_id_t reg16 = reg_ptrsz_to_16(reg_to_pointer_sized(opnd_get_reg(val)));
                PRE(bb, inst,
                    INSTR_CREATE_movzx(drcontext, opnd_create_reg(reg16), val));
                val = opnd_create_reg(reg16);
            }
#endif
            else
                ASSERT_NOT_REACHED();
        }
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

/* Called right after inserting fastpath_restore and any reg
 * restores needed.  If no reg restores needed, we can eliminate
 * the extra jmp over the slowpath.
 * May modify mi->need_slowpath and/or fastpath_restore.
 */
void
add_jmp_done_with_fastpath(void *drcontext, instrlist_t *bb, instr_t *inst,
                           fastpath_info_t *mi, instr_t *nextinstr,
                           /* is there going to be ignore_unaddr code before
                            * the slowpath?
                            */
                           bool ignore_unaddr_pre_slow,
                           instr_t **fastpath_restore /*IN/OUT*/)
{
    instr_t *prev;
    ASSERT(fastpath_restore != NULL, "invalid param");

    if (!instr_can_use_shared_slowpath(inst, mi)) {
        /* need to reach over clean call.  we don't bother w/ optimizations
         * in this case since rare.
         */
        PRE(bb, inst,
            INSTR_CREATE_jmp(drcontext, opnd_create_instr(nextinstr)));
        return;
    }

    prev = instr_get_prev(inst);
    if (prev != NULL && prev == *fastpath_restore)
        prev = instr_get_prev(prev);
    if (prev != NULL && instr_get_opcode(prev) == OP_jz_short &&
        opnd_is_instr(instr_get_target(prev)) &&
        opnd_get_instr(instr_get_target(prev)) == mi->slowpath) {
        /* instead of jz slow; jmp done; slow: <slow>; done:"
         * change to "jnz done".
         */
        /* even better: if only using slowpath for real unaddr, change
         * the whole slowpath transition sequence to an instr that
         * faults.  originally I tried using cmovcc, but a jne over
         * the fault ends up being shorter and faster.
         *     80 39 00             cmp    (%ecx) $0
         *     75 02                jnz    skip_fault
         *  # (%edx) is shorter than 0x0 abs addr.
         *  # %edx had shr 16 so in lower 64KB => will crash
         *  # UPDATE: actually if we're sharing and either we
         *  # adjust edx on prior fault or app needs it restored
         *  # there is no guaranteed fault so we just use ud2a
         *     8b 1b                mov    (%ebx) -> %ebx
         *  skip_fault:
         */
        instr_t *in;
        bool slowpath_for_err_only = true;
        if (!options.fault_to_slowpath ||
            options.check_uninitialized ||
            ignore_unaddr_pre_slow)
            slowpath_for_err_only = false;
        else {
            for (in = instrlist_first(bb); in != NULL; in = instr_get_next(in)) {
                if (in != prev &&
                    instr_is_cti(in) && opnd_is_instr(instr_get_target(in)) &&
                    opnd_get_instr(instr_get_target(in)) == mi->slowpath) {
                    slowpath_for_err_only = false;
                    break;
                }
            }
        }
        if (slowpath_for_err_only && whole_bb_spills_enabled()) {
            /* we're ok not executing the reg restores first:
             * for whole_bb_spills_enabled we can restore in
             * fault handler
             */
            instr_t *skip_fault = INSTR_CREATE_label(drcontext);
            instrlist_remove(bb, prev);
            instr_destroy(drcontext, prev);
            prev = NULL;
            ASSERT((mi->store && opnd_is_base_disp(mi->dst[0].shadow) &&
                    opnd_get_base(mi->dst[0].shadow) == mi->reg1.reg) ||
                   (mi->load && opnd_is_base_disp(mi->src[0].shadow) &&
                    opnd_get_base(mi->src[0].shadow) == mi->reg1.reg),
                   "assuming shadow addr is in reg1");
            /* N.B.: handle_slowpath_fault() checks for this exact sequence */
            PRE(bb, inst, INSTR_CREATE_jcc
                (drcontext, OP_jne_short, opnd_create_instr(skip_fault)));
            PREXL8M(bb, inst, INSTR_XL8
                    (INSTR_CREATE_ud2a(drcontext), mi->xl8));
            if (SHARING_XL8_ADDR(mi)) {
                /* Clear address reg */
                instru_insert_mov_pc(drcontext, bb, inst, opnd_create_reg(mi->reg1.reg),
                                     OPND_CREATE_INTPTR(shadow_bitlevel_addr()));
            }
            PRE(bb, inst, skip_fault);
            mi->need_slowpath = false;
        } else {
            instr_invert_cbr(prev);
            instr_set_target(prev, opnd_create_instr(nextinstr));
        }
        for (in = instrlist_first(bb); in != NULL; in = instr_get_next(in)) {
            if (instr_is_cti(in) && opnd_is_instr(instr_get_target(in)) &&
                opnd_get_instr(instr_get_target(in)) == *fastpath_restore) {
                instr_set_target(in, opnd_create_instr(nextinstr));
            }
        }
        *fastpath_restore = nextinstr;
    } else {
        PRE(bb, inst,
            INSTR_CREATE_jmp_short(drcontext, opnd_create_instr(nextinstr)));
    }
}

#ifdef TOOL_DR_MEMORY
static opnd_t
shadow_immed(uint memsz, uint shadow_val)
{
    if (memsz <= 4)
        return OPND_CREATE_INT8((char)val_to_dword[shadow_val]);
    else if (memsz == 8)
        return OPND_CREATE_INT16((short)val_to_qword[shadow_val]);
    else {
        ASSERT(memsz == 16 || memsz == 10, "invalid memsz");
        return OPND_CREATE_INT32((int)val_to_dqword[shadow_val]);
    }
}

static void
add_addressing_register_checks(void *drcontext, instrlist_t *bb, instr_t *inst,
                               opnd_t memop, fastpath_info_t *mi)
{
    reg_id_t base = opnd_get_base(memop);
    reg_id_t index = opnd_get_index(memop);
    if (base != REG_NULL) {
        /* if we've previously checked, and hasn't been written to, skip check */
        if (!mi->bb->addressable[reg_to_pointer_sized(base) - DR_REG_XAX]) {
            ASSERT(reg_get_size(base) == OPSZ_PTR, "internal base size error");
            PRE(bb, inst,
                INSTR_CREATE_cmp(drcontext, opnd_create_shadow_reg_slot(base),
                                 shadow_immed(sizeof(void*), SHADOW_DEFINED)));
            mark_eflags_used(drcontext, bb, mi->bb);
            add_jcc_slowpath(drcontext, bb, inst,
                             /* short doesn't quite reach for mem2mem's 1st check
                              * FIXME: use short for 2nd though! */
                             /* XXX DRi#56: have a pass to auto-convert short jumps
                              * to long that don't reach; some new drx_ utility maybe. */
                             (mi->mem2mem || mi->load2x ||
                              /* i#2118: 16-byte add_check_partial_undefined() */
                              mi->memsz > 8 ||
                              /* new zero-src check => require long */
                              instr_needs_all_srcs_and_vals(inst) ||
                              /* x64 instru is generally longer */
                              IF_X64(true ||)
                              (mi->memsz < 4 && !opnd_is_null(mi->src[1].app))) ?
                             OP_jne : OP_jne_short, mi);
            mi->bb->addressable[reg_to_pointer_sized(base) - DR_REG_XAX] = true;
        } else
            STATS_INC(addressable_checks_elided);
    }
    if (index != REG_NULL) {
        /* if we've previously checked, and hasn't been written to, skip check */
        if (!mi->bb->addressable[reg_to_pointer_sized(index) - DR_REG_XAX]) {
            ASSERT(reg_get_size(index) == OPSZ_PTR, "internal index size error");
            PRE(bb, inst,
                INSTR_CREATE_cmp(drcontext, opnd_create_shadow_reg_slot(index),
                                 shadow_immed(sizeof(void*), SHADOW_DEFINED)));
            mark_eflags_used(drcontext, bb, mi->bb);
            add_jcc_slowpath(drcontext, bb, inst,
                             (mi->mem2mem || mi->load2x ||
                              /* i#2118: 16-byte add_check_partial_undefined() */
                              mi->memsz > 8 ||
                              /* new zero-src check => require long */
                              instr_needs_all_srcs_and_vals(inst) ||
                              /* x64 instru is generally longer */
                              IF_X64(true ||)
                              (mi->memsz < 4 && !opnd_is_null(mi->src[1].app))) ?
                             OP_jne : OP_jne_short, mi);
            mi->bb->addressable[reg_to_pointer_sized(index) - DR_REG_XAX] = true;
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

/* When we can't or won't use table lookup to find unaddressable, we check
 * some common partial-undefined patterns and if they match we jmp to
 * ok_to_write
 */
void
add_check_partial_undefined(void *drcontext, instrlist_t *bb, instr_t *inst,
                            fastpath_info_t *mi, bool is_src, instr_t *ok_to_write)
{
    int sz = is_src ? mi->src_opsz : mi->opsz;
    if (sz <= 4) {
        /* rather than a full table lookup we put in just the common cases
         * where upper bytes are undefined and lower are defined */
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg1.reg, 0),
                             OPND_CREATE_INT8((char)0xf0)));
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg1.reg, 0),
                             OPND_CREATE_INT8((char)0xfc)));
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg1.reg, 0),
                             OPND_CREATE_INT8((char)0xc0)));
    } else if (sz == 8) {
        /* check for half-undef to avoid slowpath (PR 504162) */
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM16(mi->reg1.reg, 0),
                             OPND_CREATE_INT16((short)0xff00)));
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM16(mi->reg1.reg, 0),
                             OPND_CREATE_INT16((short)0x00ff)));
    } else {
        ASSERT(sz == 16 || sz == 10, "unknown memsz");
        /* check for partial-undef to avoid slowpath */
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM32(mi->reg1.reg, 0),
                             OPND_CREATE_INT32((int)0xffffffff)));
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM32(mi->reg1.reg, 0),
                             OPND_CREATE_INT32((int)0xffff0000)));
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM32(mi->reg1.reg, 0),
                             OPND_CREATE_INT32((int)0x0000ffff)));
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM32(mi->reg1.reg, 0),
                             OPND_CREATE_INT32((int)0xff000000)));
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM32(mi->reg1.reg, 0),
                             OPND_CREATE_INT32((int)0x00ffffff)));
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM32(mi->reg1.reg, 0),
                             OPND_CREATE_INT32((int)0x000000ff)));
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_je_short, opnd_create_instr(ok_to_write)));
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM32(mi->reg1.reg, 0),
                             OPND_CREATE_INT32((int)0xffffff00)));
    }
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
 *     - mi->memoffs is reg2_8h (reg1_8h if value_in_reg2, reg3_8h if
 *       zero_rest_of_offs and !mi->need_offs)
 *     - reg3 has been written to
 *   Else if zero_rest_of_offs (which asks for offs even if !need_offs):
 *     - mi->memoffs is reg1_8h
 *   Else:
 *     - reg3 has not been touched
 *     - reg2 has been clobbered (this routine no longer computes the offset
 *       within the shadow block: caller can do so via
 *         "movzx reg2, reg_ptrsz_to_16(orig_addr); shr reg2, 2"
 * If !get_value and !need_offs and !zero_rest_of_offs:
 *   reg1, reg3, and reg3 can be any pointer-sized regs
 * Else, they should be a,b,c,d for 8-bit sub-reg
 */
void
add_shadow_table_lookup(void *drcontext, instrlist_t *bb, instr_t *inst,
                        fastpath_info_t *mi,
                        bool get_value, bool value_in_reg2, bool need_offs,
                        bool zero_rest_of_offs,
                        reg_id_t reg1, reg_id_t reg2, reg_id_t reg3,
                        bool check_alignment)
{
    /* Shadow memory table lookup:
     * 1) Shift to get 64K base
     * 2) Simple hash mask index into table
     *    Table is allocated max size (64K entries) so we have constant
     *    global value for table itself and for hash mask, as well as
     *    no need to cmp to a tag.
     * 3) Result points to 8K shadow chunk
     */
    reg_id_t reg1_8h = REG_NULL;
    reg_id_t reg2_8h = reg_ptrsz_to_8h(reg2);
    reg_id_t reg3_8 = (reg3 == REG_NULL) ? REG_NULL : reg_ptrsz_to_8(reg3);
    ASSERT(reg3 != REG_NULL || !need_offs, "spill error");
    if (need_offs || zero_rest_of_offs)
        reg1_8h = reg_ptrsz_to_8h(reg1);
    mark_matching_scratch_reg(drcontext, bb, mi, reg1);
    mark_matching_scratch_reg(drcontext, bb, mi, reg2);
    mark_eflags_used(drcontext, bb, mi->bb);
    ASSERT(mi->memsz <= 4 || !need_offs, "unsupported fastpath memsz");
#ifdef TOOL_DR_MEMORY
    if (check_alignment && mi->memsz > 1) {
        /* if not aligned so all bytes are in same shadow byte, go to slowpath */
        /* saving space trumps sub-reg slowdown (for crafty at least: 33:20 vs 32:20)
         * so we just compare the bottom 8 bits
         */
        /* PR 504162: keep 4-byte-aligned 8-byte fp ops on fastpath, so we only
         * require 4-byte alignment for 8-byte memops and check bounds below
         */
        /* PR 614275: for xmm regs we require 16-byte align: has to be for movdqa
         * anyway else will fault.
         * PR 624474: we handle OPSZ_10 fld on fastpath if 16-byte aligned
         */
        PRE(bb, inst,
            INSTR_CREATE_test(drcontext, opnd_create_reg(reg_ptrsz_to_8(reg1)),
                              OPND_CREATE_INT8(mi->memsz == 4 ? 0x3 :
                                               (mi->memsz == 8 ? 0x3 :
                                                ((mi->memsz == 16 || mi->memsz == 10) ?
                                                 0xf : 0x1)))));
        /* i#1694: a short jcc doesn't always reach so we always use a long to
         * be on the safe side.
         */
        add_jcc_slowpath(drcontext, bb, inst, OP_jnz, mi);
        if (mi->memsz == 8) {
            /* PR 504162: keep 4-byte-aligned 8-byte fp ops on fastpath.
             * We checked for 4-byte alignment, so ensure doesn't straddle 64K.
             * Since 4-aligned, only bad if bottom 16 == 0xfffc.
             *
             * Update i#264: With displacements stored in shadow table, we no
             * longer do a movzx, so we'd have to add that here to do a cmp to
             * 0xfffc.  But, with the bitlevel-marked redzones around all shadow
             * blocks, we will naturally go to slowpath on overflow: so we don't
             * need to do anything!
             */
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

    if (need_offs) {
        /* Need 3rd scratch reg: can't ror and add since can't add 16-bit reg
         * to 32-bit reg.
         */
        /* FIXME opt: could re-lea, if addr doesn't use reg1 or reg2, and
         * avoid the need for reg3 for some uses that do not need it
         * later (e.g., insert_check_defined())
         */
        mark_matching_scratch_reg(drcontext, bb, mi, reg3);
        /* FIXME: does this really need top 16 bits zeroed?  can save 1 byte
         * using mov_st instead of movzx
         */
        PRE(bb, inst,
            INSTR_CREATE_movzx(drcontext, opnd_create_reg(reg3),
                               opnd_create_reg(reg_ptrsz_to_16(reg1))));
    }

    /* translate app address in r1 to shadow address in r1 */
    shadow_gen_translation_addr(drcontext, bb, inst, reg1, reg2);

    if (get_value) {
        /* load value from shadow table to reg1 */
        if (IF_X64_ELSE(false, mi->memsz == 16 || mi->memsz == 10)) {
            /* all shadow de-refs need xl8 as Umbra uses page faults */
            PREXL8M(bb, inst, INSTR_XL8
                    (INSTR_CREATE_mov_ld(drcontext,
                                         opnd_create_reg(value_in_reg2 ? reg2 : reg1),
                                         opnd_create_base_disp(reg1, REG_NULL, 0, 0,
                                                               OPSZ_4)),
                     mi->xl8));
        } else {
            /* all shadow de-refs need xl8 as Umbra uses page faults */
            PREXL8M(bb, inst, INSTR_XL8
                    (INSTR_CREATE_movzx(drcontext,
                                        opnd_create_reg(value_in_reg2 ? reg2 : reg1),
                                        opnd_create_base_disp
                                        (reg1, REG_NULL, 0, 0,
                                         mi->memsz == 8 ? OPSZ_2 : OPSZ_1)),
                     mi->xl8));
        }
    } else {
        /* addr is already in reg1 */
    }
    if (need_offs) {
        reg_id_t reg3_8h = (reg3 == REG_NULL) ? REG_NULL : reg_ptrsz_to_8h(reg3);
        IF_DRHEAP(ASSERT(false, "shouldn't get here"));
        mi->memoffs = (!mi->need_offs && zero_rest_of_offs) ?
            opnd_create_reg(reg3_8h) :
            ((get_value && value_in_reg2) ?
             opnd_create_reg(reg1_8h) : opnd_create_reg(reg2_8h));
        /* store offset within containing dword in high 8 bits */
        ASSERT(mi->reg3.used, "spill error");
        PRE(bb, inst,
            INSTR_CREATE_mov_st(drcontext, mi->memoffs, opnd_create_reg(reg3_8)));
        if (zero_rest_of_offs) {
            /* for stores the top 16 bits are zero but not for loads: but data16 and
             * may not be any faster even if 1 byte smaller.
             *
             * FIXME opt: for some uses that don't need reg3 later (no
             * dest, but need offs for checking definedness) could avoid
             * the store above and keep offs in reg3_8h
             */
            reg_id_t reg = reg_to_pointer_sized(opnd_get_reg(mi->memoffs));
            PRE(bb, inst,
                INSTR_CREATE_and(drcontext, opnd_create_reg(reg),
                                 OPND_CREATE_INT32(0x00000300)));
        } else {
            PRE(bb, inst,
                INSTR_CREATE_and(drcontext, mi->memoffs, OPND_CREATE_INT8(0x3)));
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
        ASSERT(!mi->mem2mem, "mem2mem zero-offs NYI");
        ASSERT(value_in_reg2, "clobbering reg1");
        ASSERT(!SHARING_XL8_ADDR(mi), "when sharing reg1 is in use");
        insert_lea(drcontext, bb, inst, mi->memop, reg1, REG_NULL);
        mi->memoffs = opnd_create_reg(reg1_8h);
        PRE(bb, inst,
            INSTR_CREATE_and(drcontext, opnd_create_reg(reg1),
                             OPND_CREATE_INT32(0x3)));
        PRE(bb, inst,
            INSTR_CREATE_shl(drcontext, opnd_create_reg(reg1), OPND_CREATE_INT8(8)));
    }
}

#ifdef TOOL_DR_MEMORY
/* PR 448701: we fault if we write to a special block, and we want to keep
 * specials in place when not actually changing them.  Instead of checking all
 * the specials, we compare the to-be-written shadow value to the existing
 * shadow value and avoid a write on the most common case of fully-defined being
 * written to SHADOW_SPECIAL_DEFINED, but also redundant writes to defined
 * non-special blocks.  On a mismatch if the target is a special shadow block
 * we'll fault, but that's rare enough that more inlined checks in the common
 * case are not worthwhile.
 */
static inline void
add_check_datastore(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi, opnd_t src,
                    opnd_t dst, instr_t *match_target)
{
    /* For a push/pop we should almost never hit a special-defined (even for a
     * new thread's stack since starts partway in) so we avoid the extra cmp.
     */
    if (mi->store && !mi->pushpop_stackop) {
        /* If sub-dword we'll have a chance of a fault even if we wouldn't
         * be writing the mis-matching bits but not worth splitting out
         * in fastpath.
         */
        /* all shadow de-refs need xl8 as Umbra uses page faults */
        PREXL8M(bb, inst, INSTR_XL8
                (INSTR_CREATE_cmp(drcontext, dst, src), mi->xl8));
        mark_eflags_used(drcontext, bb, mi->bb);
        PRE(bb, inst,
            INSTR_CREATE_jcc_short(drcontext, OP_je_short,
                                   opnd_create_instr(match_target)));
    }
}

/* See comments in add_dst_shadow_write */
static inline void
subdword_get_shift_value(void *drcontext, instrlist_t *bb, instr_t *inst,
                         opnd_t memoffs, uint ofnum)
{
    /* Get dynamic offset into %cl and double it for shift/rotate */
    PRE(bb, inst, INSTR_CREATE_mov_ld
        (drcontext, opnd_create_reg(REG_CL), memoffs));
    if (ofnum == 1) {
        PRE(bb, inst, INSTR_CREATE_dec
            (drcontext, opnd_create_reg(REG_CL)));
        PRE(bb, inst, INSTR_CREATE_and
            (drcontext, opnd_create_reg(REG_CL), OPND_CREATE_INT8(0x3)));
    }
    PRE(bb, inst, INSTR_CREATE_shl
        (drcontext, opnd_create_reg(REG_CL), OPND_CREATE_INT8(1)));
}

/* See comments in add_dst_shadow_write */
static inline void
subdword_zero_rest_of_dword(void *drcontext, instrlist_t *bb, instr_t *inst,
                            opnd_t op, uint ofnum, size_t opsz)
{
    ASSERT((opsz == 1 && (ofnum == 0 || ofnum ==1)) ||
           (opsz == 2 && ofnum == 0), "invalid offset");
    /* Clear rest of src shadow byte */
    PRE(bb, inst, INSTR_CREATE_and
        (drcontext, op, OPND_CREATE_INT8
         ((char)(opsz == 1 ? (ofnum == 1 ? 0x0c : 0x03) : 0x0f))));
}

static inline opnd_t
shadow_reg_indir_opnd(opnd_info_t *info, reg_id_t base)
{
    /* For sub-reg (e.g., 12 bytes out of 16 in an xmm reg) we assume we're
     * just checking definedness.  For writing destination shadow values
     * we'll need extra steps (i#1562).
     */
    return opnd_create_base_disp
        (base, REG_NULL, 0, opnd_get_immed_int(info->offs), shadow_reg_indir_size(info));
}

/* May write to the entire pointer-sized expansion of target */
static bool
load_reg_shadow_val(void *drcontext, instrlist_t *bb, instr_t *inst,
                    fastpath_info_t *mi, reg_id_t target, opnd_info_t *cur)
{
    ASSERT(!opnd_is_null(cur->shadow), "cur opnd can't be null");
    if (!opnd_is_reg(cur->shadow) || opnd_get_reg(cur->shadow) != target) {
        if (cur->indir_size != OPSZ_NA) {
            /* Indirection */
            reg_id_t indir = reg_to_pointer_sized(target);
            ASSERT(opnd_get_size(cur->shadow) == OPSZ_PTR, "invalid opnd size");
            PRE(bb, inst,
                INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(indir),
                                    cur->shadow));
            PRE(bb, inst,
                INSTR_CREATE_mov_ld
                (drcontext, opnd_create_reg(target), shadow_reg_indir_opnd(cur, indir)));
        } else {
            opnd_t shadow = cur->shadow;
            if (opnd_get_size(shadow) > reg_get_size(target)) {
                /* This happens w/ our 2-byte eflags shadow and 32-bit operations on x64.
                 * Our solution for now is to do two separate operations.
                 * XXX: better to shrink the eflags shadow to 1 byte and combine the
                 * 2 shadow bytes from a 64-bit arith operation??
                 */
                ASSERT(opnd_is_base_disp(shadow) &&
                       opnd_get_size(shadow) == SHADOW_GPR_OPSZ,
                       "unhandled size mismatch");
                opnd_set_size(&shadow, OPSZ_1);
                PRE(bb, inst,
                    INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(target), shadow));
                opnd_set_disp(&shadow, opnd_get_disp(shadow) + 1);
                mark_eflags_used(drcontext, bb, mi->bb);
                PRE(bb, inst,
                    INSTR_CREATE_or(drcontext, opnd_create_reg(target), shadow));
            } else {
                ASSERT(opnd_get_size(shadow) == reg_get_size(target),
                       "shadow size mismatch");
                PRE(bb, inst,
                    INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(target), shadow));
            }
        }
        return true;
    }
    return false;
}

/* Writes the shadow value in src to the eflags (if necessary) and to
 * up to two destinations.
 * src must be a register, not a memory reference.
 * If src_opsz < 4, then assumes that scratch is the lower 8 bits of a GPR, and
 * may write to the upper 8 bits of scratch's containing 16-bit register.
 * If opsz != 4 and offs is not constant neither src nor dst nor offs can use ecx.
 * For opsz>=4 this routine simply does a store from src to dst; else it
 * stores just those bits for opsz and offs from src into dst.
 * Assumes that src_opsz != dst_opsz only for movzx/movsx and only for
 * src_opsz=={1,2} and dst_opsz==4.
 * If it uses scratch, it calls mark_scratch_reg_used on si.
 * If preserve is true, does not clobber src.offs or src.shadow.
 */
static inline void
add_dst_shadow_write(void *drcontext, instrlist_t *bb, instr_t *inst,
                     fastpath_info_t *mi, opnd_info_t dst,
                     opnd_info_t src, int src_opsz, int dst_opsz,
                     reg_id_t scratch, scratch_reg_info_t *si,
                     bool process_eflags, bool alu_uncombined, bool preserve)
{
    /* PR 448701: we need to support writes to shadow blocks faulting.
     * Meta-instrs can't fault so we have to mark as non-meta and give
     * a translation.
     */
    /* Be sure to write to eflags before calling add_check_datastore(),
     * as the latter will skip to the end of this instrumentation.
     */
    instr_t *skip_write_tgt = INSTR_CREATE_label(drcontext);
    if (src_opsz > dst_opsz) {
        /* We now have DRi#1382 but we still hit this for cases like
         * OP_cvtsd2si.
         */
        reg_id_t reg_ptr = reg_to_pointer_sized(opnd_get_reg(src.shadow));
        ASSERT(opnd_is_reg(src.shadow) && (src_opsz == 16 || src_opsz == 8) &&
               (dst_opsz == 8 || dst_opsz == 4), "invalid srcsz <= dstsz case");
        if (dst_opsz > 8)
            src.shadow = opnd_create_reg(reg_ptrsz_to_32(reg_ptr));
        if (dst_opsz == 8)
            src.shadow = opnd_create_reg(reg_ptrsz_to_16(reg_ptr));
        else if (dst_opsz == 4)
            src.shadow = opnd_create_reg(reg_ptrsz_to_8(reg_ptr));
        src_opsz = dst_opsz;
    }
    ASSERT(src_opsz <= dst_opsz, "invalid opsz");
    ASSERT(dst_opsz <= 4 || dst_opsz == 8 || dst_opsz == 10 || dst_opsz == 16,
           "invalid opsz");
    ASSERT(src_opsz == dst_opsz ||
           ((src_opsz == 1 || src_opsz == 2) && dst_opsz == 4),
           "mismatched sizes only supported for src==1 or 2 dst==4");
    ASSERT(!opnd_is_null(dst.shadow) ||
           (process_eflags && !opnd_is_null(src.shadow)), "shouldn't be called");
    ASSERT(src_opsz > 0 && !opnd_is_null(src.shadow), "shouldn't be called");

    DOLOG(4, {
        file_t f = LOGFILE_GET(drcontext);
        print_opnd(drcontext, src.shadow, f, "\tsrc shadow = ");
        print_opnd(drcontext, dst.shadow, f, "\tdst shadow = ");
        print_opnd(drcontext, src.offs, f, "\tsrc offs = ");
        print_opnd(drcontext, dst.offs, f, "\tdst offs = ");
    });

    /* The shadow value to propagate, resulting from combining all sources,
     * is in src.  We now perform any shifting, and then write to dest.
     */
    if (opnd_is_reg(src.shadow)) {
        insert_shadow_op(drcontext, bb, mi, inst, opnd_get_reg(src.shadow), scratch, si);
    } else
        ASSERT(opnd_is_immed_int(src.shadow), "invalid shadow src");
    ASSERT(dst.indir_size == OPSZ_NA || src_opsz == 4 || src_opsz == 8 || src_opsz == 16,
           "unexpected shadow reg indir");
    if (src_opsz == 4 || src_opsz == 8 || src_opsz == 10 || src_opsz == 16) {
        /* copy entire byte(s) (1, 2, or 4) shadowing the dword */
        /* write_shadow_eflags will convert src.shadow to single-byte size */
        if (process_eflags)
            write_shadow_eflags(drcontext, bb, inst, REG_NULL, src.shadow);
        if (!opnd_is_null(dst.shadow)) {
            if (dst.indir_size != OPSZ_NA) {
                /* we're going to use the whole register */
                ASSERT(!mi->need_offs, "assuming don't need mi->reg2_8h");
                mark_scratch_reg_used(drcontext, bb, mi->bb, si);
                PRE(bb, inst,
                    INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(si->reg),
                                        dst.shadow));
                dst.shadow = shadow_reg_indir_opnd(&dst, si->reg);
            }
#ifdef X86_64
            /* Writing to a 32-bit GPR zeroes the top 32 bits. */
            if (opnd_is_reg(dst.app) && reg_is_32bit(opnd_get_reg(dst.app))) {
                if (opnd_is_immed_int(src.shadow) &&
                    opnd_get_immed_int(src.shadow) == SHADOW_DWORD_DEFINED) {
                    src.shadow = shadow_immed(sizeof(void*), SHADOW_DEFINED);
                    opnd_set_size(&dst.shadow, SHADOW_GPR_OPSZ);
                } else {
                    opnd_t top32_src = shadow_immed(4, SHADOW_DEFINED);
                    opnd_t top32_dst = opnd_create_shadow_reg_slot_high_dword
                        (opnd_get_reg(dst.app));
                    instr_t *skip_topwrite_tgt = INSTR_CREATE_label(drcontext);
                    add_check_datastore(drcontext, bb, inst, mi, top32_src, top32_dst,
                                        skip_topwrite_tgt);
                    PREXL8M(bb, inst, INSTR_XL8(INSTR_CREATE_mov_st(drcontext, top32_dst,
                                                                    top32_src), mi->xl8));
                    PRE(bb, inst, skip_topwrite_tgt);
                }
            }
#endif
            ASSERT(opnd_get_size(dst.shadow) == opnd_get_size(src.shadow),
                   "shadow size mismatch");
            add_check_datastore(drcontext, bb, inst, mi, src.shadow, dst.shadow,
                                skip_write_tgt);
            PREXL8M(bb, inst, INSTR_XL8(INSTR_CREATE_mov_st(drcontext, dst.shadow,
                                                            src.shadow), mi->xl8));
        }
        PRE(bb, inst, skip_write_tgt);
    } else if (src_opsz == 10) {
        /* We only get here if aligned to 16 bytes and mark_defined.
         * First write 8 bytes; then write 2 bytes.
         */
        ASSERT(opnd_is_immed_int(src.shadow) && opnd_get_size(src.shadow) == OPSZ_16,
               "10-byte should be treated as 16");
        if (process_eflags) {
            write_shadow_eflags(drcontext, bb, inst, REG_NULL,
                                shadow_immed(1, SHADOW_DEFINED));
        }
        if (!opnd_is_null(dst.shadow)) {
            opnd_t imm8 = shadow_immed(8, SHADOW_DEFINED);
            /* check whole 16 bytes */
            add_check_datastore(drcontext, bb, inst, mi, src.shadow, dst.shadow,
                                skip_write_tgt);
            opnd_set_size(&dst.shadow, OPSZ_8);
            PREXL8M(bb, inst, INSTR_XL8(INSTR_CREATE_mov_st(drcontext, dst.shadow, imm8),
                                        mi->xl8));
            PREXL8M(bb, inst,
                    INSTR_XL8(INSTR_CREATE_and
                              (drcontext, dst.shadow,
                               /* 2 = dst_opsz, 0 = ofnum */
                               opnd_create_immed_int(~(((1 << 2*2)-1) << 0*2),
                                                     OPSZ_1)), mi->xl8));
            mark_eflags_used(drcontext, bb, mi->bb);
        }
        PRE(bb, inst, skip_write_tgt);
    } else if (opnd_is_immed_int(src.shadow) && opnd_get_immed_int(src.shadow) == 0 &&
               opnd_is_immed_int(dst.offs)) {
        int ofnum = opnd_get_immed_int(dst.offs);
        ASSERT(src_opsz == dst_opsz, "expect same size for immed opnd");
        if (process_eflags)
            write_shadow_eflags(drcontext, bb, inst, REG_NULL, src.shadow);
        if (!opnd_is_null(dst.shadow)) {
            add_check_datastore(drcontext, bb, inst, mi, src.shadow, dst.shadow,
                                skip_write_tgt);
            PREXL8M(bb, inst,
                    INSTR_XL8(INSTR_CREATE_and
                              (drcontext, dst.shadow,
                               opnd_create_immed_int(~(((1 << dst_opsz*2)-1) << ofnum*2),
                                                     OPSZ_1)), mi->xl8));
            mark_eflags_used(drcontext, bb, mi->bb);
        }
        PRE(bb, inst, skip_write_tgt);
    } else {
        /* dynamically-varying src.shadow or offset */
        opnd_t opreg1, opreg2, memoffs;
        opnd_t shiftby;
        bool wrote_shadow_eflags = false;
        instr_t *preserve_memoffs_tgt = INSTR_CREATE_label(drcontext);
        ASSERT(scratch != REG_NULL, "invalid scratch reg");
        ASSERT(reg_is_8bit(scratch) && !reg_is_8bit_high(scratch),
               "scratch must be low8 reg");
        ASSERT(!opnd_is_null(src.offs) &&
               (opnd_is_null(dst.shadow) || !opnd_is_null(dst.offs)),
               "must have offs set for src and dst");

        mark_scratch_reg_used(drcontext, bb, mi->bb, si);
        mark_eflags_used(drcontext, bb, mi->bb);

        /* We split into cases based on which of src and dst has a constant
         * offset.  Only one should dynamically vary.
         */
        if ((opnd_is_null(dst.offs) || opnd_is_immed_int(dst.offs)) &&
            opnd_is_immed_int(src.offs)) {
            /* Reg-to-reg move, or movzx reg to aligned 4-byte memory */
            int ofnum_src = opnd_get_immed_int(src.offs);
            int ofnum_dst = opnd_is_null(dst.offs) ? 0 : opnd_get_immed_int(dst.offs);
            if (src_opsz == 2) {
                ASSERT(ofnum_src == 0 && ofnum_dst == 0, "must have 0 offs");
                shiftby = opnd_create_null();
            } else {
                ASSERT(src_opsz == 1, "impossible register");
                /* we're going to ror the src by this amount */
                if (ofnum_src == ofnum_dst)
                    shiftby = opnd_create_null();
                else if (ofnum_src == 1) {
                    ASSERT(ofnum_dst == 0, "impossible register/4-byte-mem");
                    shiftby = opnd_create_immed_int(2, OPSZ_1);
                } else {
                    ASSERT(ofnum_src == 0 && ofnum_dst == 1, "impossible register");
                    shiftby = opnd_create_immed_int(6, OPSZ_1); /* wraparound */
                }
            }
            memoffs = opnd_create_null();
            opreg1 = opnd_create_reg(scratch);
            opreg2 = opnd_create_reg(reg_ptrsz_to_8h(reg_to_pointer_sized(scratch)));
            ASSERT(!opnd_uses_reg(dst.shadow, reg_to_pointer_sized(scratch)) &&
                   !opnd_uses_reg(src.shadow, reg_to_pointer_sized(scratch)),
                   "internal scratch reg error");
        } else {
            /* For dynamic shift amount we must use %cl (implicit opnd) */
            memoffs = mi->memoffs;
            ASSERT(opnd_is_reg(mi->memoffs), "offs invalid opnd");
            ASSERT(!opnd_uses_reg(dst.shadow, DR_REG_XCX) &&
                   !opnd_uses_reg(src.shadow, DR_REG_XCX) &&
                   !opnd_uses_reg(mi->memoffs, DR_REG_XCX),
                   "internal scratch reg error");
            if (scratch != REG_CL) {
                PRE(bb, inst,
                    INSTR_CREATE_xchg(drcontext, opnd_create_reg(DR_REG_XCX),
                                      opnd_create_reg(reg_to_pointer_sized(scratch))));
                if (opnd_is_reg(mi->memoffs) &&
                    reg_to_pointer_sized(opnd_get_reg(mi->memoffs)) ==
                    reg_to_pointer_sized(scratch)) {
                    ASSERT(reg_is_8bit_high(opnd_get_reg(mi->memoffs)), "subdword error");
                    memoffs = opnd_create_reg(REG_CH);
                    opreg2 = opnd_create_reg
                        (reg_ptrsz_to_8h(reg_to_pointer_sized(scratch)));
                }
            } else {
                opreg2 = opnd_create_reg(REG_CH);
            }
            shiftby = opnd_create_reg(REG_CL);
            /* We're ok clobbering memoffs since we can recover from %cl */
            opreg1 = memoffs;
        }

        if (opnd_is_immed_int(src.shadow) && opnd_get_immed_int(src.shadow) == 0 &&
            !alu_uncombined) {
            /* since all-0 can write as is.  do this now to avoid work if datastore
             * matches.  we also avoid the or-undef steps below since no undef bits.
             */
            if (process_eflags)
                write_shadow_eflags(drcontext, bb, inst, REG_NULL, src.shadow);
            if (!opnd_is_null(dst.shadow)) {
                /* Yes, we want to skip the restore of memoffs if preserve is set */
                add_check_datastore(drcontext, bb, inst, mi, src.shadow, dst.shadow,
                                    skip_write_tgt);
            }
            wrote_shadow_eflags = true;

            ASSERT(src_opsz == dst_opsz, "expect same size for immed");
            if (opnd_is_immed_int(dst.offs)) {
                /* Move immed into register */
                int ofnum = opnd_get_immed_int(dst.offs);
                opnd_t immed = OPND_CREATE_INT8
                    ((char)(dst_opsz == 1 ? (ofnum == 1 ? 0xf3 : 0xfc) : 0xf0));
                /* zero out defined bits */
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_and(drcontext, dst.shadow, immed), mi->xl8));
            } else {
                /* Store immed into memory */
                int ofnum = opnd_get_immed_int(src.offs);
                ASSERT(ofnum == 0, "invalid immed");
                subdword_get_shift_value(drcontext, bb, inst, memoffs, ofnum);
                PRE(bb, inst, INSTR_CREATE_mov_imm
                    (drcontext, opreg1, OPND_CREATE_INT8
                     ((char)(dst_opsz == 1 ? 0xfc : 0xf0))));
                PRE(bb, inst, INSTR_CREATE_rol
                    (drcontext, opreg1, opnd_create_reg(REG_CL)));
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_and(drcontext, dst.shadow, opreg1), mi->xl8));
            }
        }
        else if (src_opsz != dst_opsz) {
            int ofnum;
            ASSERT(dst_opsz == 4, "movzx to 2 prop not supported");
            ASSERT(opnd_is_immed_int(dst.offs), "movzx to 2 prop not supported");
            ofnum = opnd_get_immed_int(dst.offs);
            /* For movzx, shift src to 0, then set its top bits to 0, and
             * copy directy to dst.
             */
            /* For movsz, shift src to 0, then use table lookup to get full
             * shadow byte's worth.
             */
            ASSERT((src_opsz == 1 || src_opsz == 2) && dst_opsz == 4, "movzx error");

            if (opnd_is_reg(shiftby)) /* else, const or no shift */
                subdword_get_shift_value(drcontext, bb, inst, memoffs, ofnum);

            if (preserve) {
                /* Make a copy into memoffs reg (we can recover it later) */
                PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opreg1, src.shadow));
            } else
                opreg1 = src.shadow;

            /* Register dst is at offs 0 so shift src memory shadow to match */
            if (!opnd_is_null(shiftby))
                PRE(bb, inst, INSTR_CREATE_shr (drcontext, opreg1, shiftby));

            /* Zero based on src size but dst offs */
            subdword_zero_rest_of_dword(drcontext, bb, inst, opreg1, ofnum, src_opsz);

            if (instr_get_opcode(inst) == OP_movsx) {
                reg_id_t reg32 = reg_to_pointer_sized(opnd_get_reg(opreg1));
                PRE(bb, inst, INSTR_CREATE_movzx
                    (drcontext, opnd_create_reg(reg32), opreg1));
                ptr_int_t table_addr = (ptr_int_t)
                    ((src_opsz == 1) ? shadow_2_to_dword : shadow_4_to_dword);
                int disp = insert_table_access_pre(drcontext, bb, inst, table_addr, reg32);
                PRE(bb, inst, INSTR_CREATE_mov_ld
                    (drcontext, opreg1, OPND_CREATE_MEM8(reg32, disp)));
                insert_table_access_post(drcontext, bb, inst, table_addr, reg32);
            }

            /* Write result */
            if (!wrote_shadow_eflags) {
                if (process_eflags &&
                    TESTANY(EFLAGS_WRITE_6,
                            instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL))) {
                    write_shadow_eflags(drcontext, bb, inst, REG_NULL, opreg1);
                }
                if (!opnd_is_null(dst.shadow)) {
                    /* Go to preserve_memoffs_tgt, not skip_write_tgt, as we
                     * clobbered memoffs already
                     */
                    add_check_datastore(drcontext, bb, inst, mi, opreg1,
                                        dst.shadow, preserve_memoffs_tgt);
                }
                wrote_shadow_eflags = true;
            }
            PREXL8M(bb, inst, INSTR_XL8
                    (INSTR_CREATE_mov_st(drcontext, dst.shadow, opreg1), mi->xl8));
        }
        else if (opnd_is_immed_int(dst.offs) || opnd_is_null(dst.offs)) {
            /* Load from memory into register, or register-to-register move,
             * or cmp mem,reg/immed with -no_check_uninit_cmps
             */
            int ofnum = opnd_is_null(dst.offs) ? 0/*eflags*/ :
                opnd_get_immed_int(dst.offs);
            ASSERT(opnd_is_null(dst.shadow) ||
                   (opnd_is_reg(mi->dst[0].app) &&
                    (mi->load || opnd_is_immed_int(src.offs))), "invalid assumptions");
            ASSERT(src_opsz == dst_opsz, "movzx not supported here");

            /* For 2-byte to 2-byte: fastpath requires memory to be 2-byte aligned,
             * and register must have offs 0, so we just need to shift memory right
             * by memoffs*2 and it will be lined up for dst reg.
             */
            /* For 1-byte to 1-byte: identical to 2-byte to 2-byte if the dst reg has
             * offs 0.  The only other case is dst reg having offs 1, and there we
             * want to do the following to the memory shadow value to line it up with
             * the dst reg:
             *
             *   ror src.shadow, ((memoffs-1)&3)*2
             *
             * So if mem has offs 0 it wraps around 6 spots, offs 1 does nothing,
             * offs 2 or 3 rotate to the right to line up.
             *
             * Here's the code for 2-byte load mem to reg where
             * %dh has load offs, %dl has load val, %ebx has reg addr:
             *    mov %dh %cl
             *    shl %cl 1
             *    shr %dl %cl
             *    mov %dl %dh
             *    and %dh 0x0f
             *    <if prop to eflags, can write %dh at this point>
             *    or %dh (%ebx) -> (%ebx)
             *    or %dl 0xf0
             *    and %dl (%ebx) -> (%ebx)
             *
             * For ALU we need to combine first to write to eflags.
             * We can write to dest before eflags b/c as a load
             * there is no datastore check:
             *    mov %dh %cl
             *    shl %cl 1
             *    shr %dl %cl
             *    and %dl 0x0f
             *    mov (%ebx) %dh
             *    or %dl %dh
             *    or %dh (%ebx)
             *    and %dh 0x0f
             *    mov %dh <eflags-shadow>
             *
             * For 1-byte the constants differ and if ofnum==1 we use ror with the
             * memoffs calculation as presented above.
             * For preserve we copy for the final or+and.
             */
            ASSERT((dst_opsz == 1 && (ofnum == 0 || ofnum ==1)) ||
                   (dst_opsz == 2 && ofnum == 0), "invalid offset");

            if (opnd_is_reg(shiftby)) /* else, const or no shift */
                subdword_get_shift_value(drcontext, bb, inst, memoffs, ofnum);

            if (preserve) {
                /* Make a copy into memoffs reg (we can recover it later) */
                PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opreg1, src.shadow));
            }

            /* Register dst is at offs 0 so shift src memory shadow to match.
             * ofnum==1 needs ror and should be same perf as shr so we use
             * ror for all.  We're zeroing out the other bits regardless.
             */
            if (!opnd_is_null(shiftby)) {
                PRE(bb, inst, INSTR_CREATE_ror
                    (drcontext, preserve ? opreg1 : src.shadow, shiftby));
            }

            if (alu_uncombined && !preserve) {
                /* We can clobber src.shadow */
                opreg1 = src.shadow;
            } else if (!preserve) {
                /* Make a copy into memoffs reg (we can recover it later) */
                PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opreg1, src.shadow));
            }
            subdword_zero_rest_of_dword(drcontext, bb, inst, opreg1, ofnum, dst_opsz);

            if (alu_uncombined) {
                /* Load from dst shadow */
                PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opreg2, dst.shadow));
                /* Combine the two sources */
                PRE(bb, inst, INSTR_CREATE_or(drcontext, opreg1, opreg2));
                /* Write result to dst subdword via or */
                ASSERT(!mi->store, "assuming no datastore check");
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_or(drcontext, dst.shadow, opreg1), mi->xl8));
                /* Clear rest of bits in result for write to eflags */
                subdword_zero_rest_of_dword(drcontext, bb, inst, opreg1,
                                            ofnum, dst_opsz);
            }

            /* Shadow src is now in ok state to write to eflags */
            if (!wrote_shadow_eflags) {
                if (process_eflags &&
                    TESTANY(EFLAGS_WRITE_6,
                            instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL))) {
                    write_shadow_eflags(drcontext, bb, inst, REG_NULL, opreg1);
                }
                if (!opnd_is_null(dst.shadow)) {
                    /* Go to preserve_memoffs_tgt, not skip_write_tgt, as we
                     * clobbered memoffs already
                     */
                    add_check_datastore(drcontext, bb, inst, mi, opreg1,
                                        dst.shadow, preserve_memoffs_tgt);
                }
                wrote_shadow_eflags = true;
            }

            if (alu_uncombined || opnd_is_null(dst.shadow)) {
                /* no more to do */
            } else {
                opnd_t andbits = src.shadow;
                /* or in undefined bits */
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_or(drcontext, dst.shadow, opreg1), mi->xl8));
                if (preserve) {
                    /* Copy source again */
                    PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opreg1, src.shadow));
                    /* Need to rotate it again */
                    if (!opnd_is_null(shiftby))
                        PRE(bb, inst, INSTR_CREATE_ror(drcontext, opreg1, shiftby));
                    andbits = opreg1;
                }
                PRE(bb, inst, INSTR_CREATE_or
                    (drcontext, andbits, OPND_CREATE_INT8
                     ((char)(dst_opsz == 1 ? (ofnum == 1 ? 0xf3 : 0xfc) : 0xf0))));
                /* zero out defined bits */
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_and(drcontext, dst.shadow, andbits), mi->xl8));
            }
        }
        else if (opnd_is_immed_int(src.offs)) {
            /* Store from register into memory */
            int ofnum = opnd_get_immed_int(src.offs);
            ASSERT(mi->store && opnd_is_reg(mi->src[0].app), "invalid assumptions");
            ASSERT(src_opsz == dst_opsz, "movzx not supported here");

            /* Similar to load except we shift in the other direction.
             *
             * Here's the code for 2-byte store reg to mem where
             * %dh has load offs, %dl has load val, %ebx has reg addr:
             *    mov %dh %cl
             *    shl %cl 1
             *    mov %dl -> %dh
             *    and %dh 0x0f
             *    <if prop to eflags, can write %dh at this point>
             *    shl %cl %dh
             *    cmp    (%ebx) %dh  # for check_datastore, cmp to rest being defined
             *    jz     $0x244ace7d
             *    or %dh (%ebx) -> (%ebx)
             *    or %dl 0xf0
             *    rol %dl %cl
             *    and %dl (%ebx) -> (%ebx)
             *
             * For ALU that writes eflags:
             *    mov %dh %cl
             *    shl %cl 1
             *    mov (%ebx) %dh
             *    shr %dh %cl
             *    or  %dl %dh
             *    and %dh 0x0f
             *    mov %dh <eflags-shadow>
             *    shl %dh %cl
             *    cmp    (%ebx) %dh  # for check_datastore, cmp to rest being defined
             *    jz     $0x244ace7d
             *    or %dh (%ebx) -> (%ebx)
             */
            ASSERT((src_opsz == 1 && (ofnum == 0 || ofnum ==1)) ||
                   (src_opsz == 2 && ofnum == 0), "invalid offset");

            subdword_get_shift_value(drcontext, bb, inst, memoffs, ofnum);

            if (alu_uncombined) {
                PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opreg1, dst.shadow));
                /* Shift to 0 offset */
                PRE(bb, inst, INSTR_CREATE_shr
                    (drcontext, opreg1, opnd_create_reg(REG_CL)));
                /* Combine w/ src */
                PRE(bb, inst, INSTR_CREATE_or(drcontext, opreg1, src.shadow));
            } else {
                /* Make a copy into memoffs reg (we can recover it later) */
                PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opreg1, src.shadow));
            }
            subdword_zero_rest_of_dword(drcontext, bb, inst, opreg1, ofnum, src_opsz);

            /* Register src (or combined val for alu_uncombined) is at offs 0,
             * shift to match memory.  OK to do this before eflags write since
             * we can write to any bits of eflags.
             */
            PRE(bb, inst, INSTR_CREATE_shl(drcontext, opreg1, opnd_create_reg(REG_CL)));

            /* Shadow src is now in ok state to write to eflags */
            if (!wrote_shadow_eflags) {
                if (process_eflags &&
                    TESTANY(EFLAGS_WRITE_6,
                            instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL))) {
                    write_shadow_eflags(drcontext, bb, inst, REG_NULL, opreg1);
                }
                if (!opnd_is_null(dst.shadow)) {
                    /* Go to preserve_memoffs_tgt, not skip_write_tgt, as we
                     * clobbered memoffs already
                     */
                    add_check_datastore(drcontext, bb, inst, mi, opreg1,
                                        dst.shadow, preserve_memoffs_tgt);
                }
                wrote_shadow_eflags = true;
            }

            if (opnd_is_null(dst.shadow)) {
                /* no more to do */
            } else if (alu_uncombined) {
                /* store to dest: rest of bits are zero so we can or */
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_or(drcontext, dst.shadow, opreg1), mi->xl8));
            } else {
                opnd_t andbits = src.shadow;
                /* or in undefined bits */
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_or(drcontext, dst.shadow, opreg1), mi->xl8));
                if (preserve) {
                    /* Copy source again */
                    PRE(bb, inst, INSTR_CREATE_mov_ld(drcontext, opreg1, src.shadow));
                    andbits = opreg1;
                }
                PRE(bb, inst, INSTR_CREATE_or
                    (drcontext, andbits, OPND_CREATE_INT8
                     ((char)(src_opsz == 1 ? (ofnum == 1 ? 0xf3 : 0xfc) : 0xf0))));
                PRE(bb, inst, INSTR_CREATE_rol
                    (drcontext, andbits, opnd_create_reg(REG_CL)));
                /* zero out defined bits */
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_and(drcontext, dst.shadow, andbits), mi->xl8));
            }
        }
        else {
            ASSERT(false, "only one of src and dst can have non-const offs");
        }

        PRE(bb, inst, preserve_memoffs_tgt);
        if (preserve && !opnd_is_null(memoffs)/*nothing clobbered*/) {
            /* XXX: more efficient to combine the 2 dst writes but simpler
             * code-wise for now to fully restore and then put back into cl
             */
            PRE(bb, inst, INSTR_CREATE_mov_ld
                (drcontext, memoffs, opnd_create_reg(REG_CL)));
            PRE(bb, inst, INSTR_CREATE_shr
                (drcontext, memoffs, OPND_CREATE_INT8(1)));
        }
        PRE(bb, inst, skip_write_tgt);
        if (!opnd_is_immed_int(mi->memoffs) && scratch != REG_CL) {
            PRE(bb, inst,
                INSTR_CREATE_xchg(drcontext, opnd_create_reg(DR_REG_XCX),
                                  opnd_create_reg(reg_to_pointer_sized(scratch))));
        }
    }
}

/* Calls add_dst_shadow_write() on both mi->dst[0] and mi->dst[1], with the same src */
static inline void
add_dstX2_shadow_write(void *drcontext, instrlist_t *bb, instr_t *inst,
                       fastpath_info_t *mi, opnd_info_t src, int src_opsz, int dst_opsz,
                       reg_id_t scratch, scratch_reg_info_t *si,
                       bool process_eflags, bool alu_uncombined)
{
    /* even if dst1 is empty we need to write to eflags */
    if (!opnd_is_null(mi->dst[0].shadow) ||
        (process_eflags &&
         TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)))) {
        add_dst_shadow_write(drcontext, bb, inst, mi, mi->dst[0],
                             src, src_opsz, dst_opsz, scratch, si,
                             process_eflags, alu_uncombined,
                             /* preserve src if we need to write to 2nd dst */
                             !opnd_is_null(mi->dst[1].shadow));
    }
    if (!opnd_is_null(mi->dst[1].shadow)) {
        add_dst_shadow_write(drcontext, bb, inst, mi, mi->dst[1],
                             src, src_opsz, dst_opsz, scratch, si,
                             process_eflags, alu_uncombined,
                             false/*we assume ok to clobber src*/);
    }
}
#endif /* TOOL_DR_MEMORY */

/* restores global regs but preserves mi->reg1.
 * clobbers reg2 and reg3 (so requires reg3 to be set up).
 */
static void
insert_lea_preserve_reg(void *drcontext, instrlist_t *bb, instr_t *inst,
                        fastpath_info_t *mi, opnd_t memop)
{
    mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg3);
    if (mi->bb->reg1.reg != mi->reg1.reg &&
        opnd_uses_reg(memop, mi->bb->reg1.reg))
        insert_spill_global(drcontext, bb, inst, &mi->bb->reg1, false/*restore*/);
    if (mi->bb->reg2.reg != mi->reg1.reg &&
        opnd_uses_reg(memop, mi->bb->reg2.reg))
        insert_spill_global(drcontext, bb, inst, &mi->bb->reg2, false/*restore*/);
    /* mi->reg1 holds the first lea so we have to preserve it */
    if (opnd_uses_reg(memop, mi->reg1.reg)) {
        spill_reg(drcontext, bb, inst, mi->reg1.reg, SPILL_SLOT_5);
        if (mi->reg1.global)
            insert_spill_global(drcontext, bb, inst, &mi->reg1, false/*restore*/);
        else
            restore_reg(drcontext, bb, inst, mi->reg1.reg, mi->reg1.slot);
        insert_lea(drcontext, bb, inst, memop, mi->reg3.reg, mi->reg2.reg);
        restore_reg(drcontext, bb, inst, mi->reg1.reg, SPILL_SLOT_5);
    } else
        insert_lea(drcontext, bb, inst, memop, mi->reg3.reg, mi->reg2.reg);
}

/* Fast path for "normal" instructions with a single memory
 * reference using 4-byte addressing registers.
 * Also handles mem2mem in certain cases.
 * Handles mem-to-reg (including pop), reg-to-mem (including push),
 * ALU ops, and destination-less loads (like cmp and test).
 * Does NOT handle pop into mem.
 * Handles push from mem and call*.
 * Bails to slowpath on corner cases, but does not modify
 * any state beforehand, so slowpath can start over.
 * Those corner cases include:
 * - unaligned accesses
 * - not fully defined operands for instrs too complex to easily propagate
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
                    fastpath_info_t *mi, bool check_ignore_unaddr)
{
    uint opc = instr_get_opcode(inst);
#ifdef TOOL_DR_MEMORY
    reg_id_t scratch, scratch3, src_val_reg;
    scratch_reg_info_t *si;
#endif
    instr_t *nextinstr = INSTR_CREATE_label(drcontext);
    instr_t *fastpath_restore = INSTR_CREATE_label(drcontext);
    instr_t *spill_location = INSTR_CREATE_label(drcontext);
#ifdef TOOL_DR_MEMORY
    instr_t *heap_unaddr = INSTR_CREATE_label(drcontext);
    opnd_t heap_unaddr_shadow = opnd_create_null();
    instr_t *marker1, *marker2;
    bool mark_defined;
#endif
    bool save_aflags;
#ifdef TOOL_DR_MEMORY
    bool checked_src2 = false, checked_memsrc = false;
#endif
    bool share_addr = false;
#ifdef DEBUG
    instr_t *instru_start = instr_get_prev(inst);
#endif
#ifdef TOOL_DR_MEMORY
    instr_t *check_ignore_resume = NULL;
    bool check_ignore_tls = true;
#endif
    bool check_appval, need_reg3_for_appval;

    /* mi is memset to 0 so bools and pointers are false/NULL */
    mi->slowpath = INSTR_CREATE_label(drcontext);

#ifdef TOOL_DR_MEMORY
    ASSERT(!opc_is_stringop_loop(opc), "internal error"); /* handled elsewhere */
#endif
    /* we assume caller has called instr_ok_for_instrument_fastpath() */
    if (!adjust_opnds_for_fastpath(inst, mi)) {
        instrument_slowpath(drcontext, bb, inst, NULL);
        return;
    }

    /* check sharing prior to picking scratch regs b/c in combination w/
     * sub-dword check_definedness (PR 425240) we need a 3rd reg
     */
    if (mi->load || mi->store) {
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
        if (!mi->need_offs && mi->memsz < 4 && options.check_uninitialized &&
            !opnd_is_immed_int(mi->memoffs) && mi->load) {
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
                mi->need_offs_early = true;
        }
    }
    if (!mi->need_offs && mi->opsz < 4 && options.check_uninitialized &&
        (mi->store || reg_is_gpr(mi->dst_reg) ||
         /* if writes eflags we'll need a 3rd reg for write_shadow_eflags */
         (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)) &&
          !mi->check_definedness)))
        mi->need_nonoffs_reg3 = true;

#ifdef TOOL_DR_MEMORY
    /* other cases where we check definedness rather than propagating */
    set_check_definedness_pre_regs(drcontext, inst, mi);

    if (!mi->need_offs && options.check_uninitialized && !mi->check_definedness &&
        /* We need a scratch reg in insert_shadow_op().
         * XXX: would be better to request down there -- feasible with drreg?
         */
        (needs_shadow_op(inst) &&
         opnd_is_immed_int(instr_get_src(inst, 0)) &&
         (opc == OP_sar || opnd_get_immed_int(instr_get_src(inst, 0)) % 8 != 0)))
        mi->need_nonoffs_reg3 = true;
    if (mi->shadow_indir) {
        /* We need a temp reg for indirected shadow memory */
        ASSERT(!mi->need_nonoffs_reg3, "spill overlap");
        mi->need_nonoffs_reg3 = true;
    }
#endif

    check_appval = (opc == OP_and || opc == OP_test || opc == OP_or) &&
        /* only for word size so no conflict w/ reg3 */
        mi->src_opsz == 4;
    need_reg3_for_appval =
        /* to read the app value for and/test/or memop we need 3rd reg */
        check_appval && (mi->load || mi->store);

    /* set up regs and spill info */
    pick_scratch_regs(inst, mi,
                      /*only pick a,b,c,d: need 8-bit for uninit or mem2mem */
                      options.check_uninitialized || mi->mem2mem || mi->load2x,
                      /* we need 3rd reg for temp to get offs while getting
                       * shadow byte address, and also temp to set dest bits in
                       * add_dst_shadow_write(); we also need to handle 2nd
                       * memop for mem2mem or load2x.
                       */
                      mi->need_offs || mi->mem2mem || mi->load2x ||
                      mi->need_offs_early || mi->need_nonoffs_reg3 ||
                      /* to read the app value for and/test/or memop we need 3rd reg */
                      need_reg3_for_appval,
                      mi->need_offs || mi->need_offs_early,
                      mi->memop,
                      mi->mem2mem ? mi->src[0].app :
                      (mi->load2x ? mi->src[1].app : opnd_create_null()));
    mi->reg1_16 = reg_ptrsz_to_16(mi->reg1.reg);
    mi->reg1_8 = reg_ptrsz_to_8(mi->reg1.reg);
    mi->reg2_16 = reg_ptrsz_to_16(mi->reg2.reg);
    mi->reg2_8 = reg_ptrsz_to_8(mi->reg2.reg);
    mi->reg2_8h = reg_ptrsz_to_8h(mi->reg2.reg);
    mi->reg3_8 = (mi->reg3.reg == REG_NULL) ? REG_NULL : reg_ptrsz_to_8(mi->reg3.reg);

    /* i#1590: if our scratch regs are ecx and eax and we have sub-dword memrefs, we
     * can't share them, either w/ prior (mi->use_shared) or next (share_addr) inst.
     * XXX i#165: add whole-bb xl8-sharing analysis and measure the usage of the
     * 3rd-best scratch reg and if the extra spills+restores will be outweighed
     * by the elimination of xl8 we should use edx or ebx as our 1st scratch.
     */
    if ((mi->use_shared || share_addr) && mi->reg1.reg != mi->bb->reg1.reg) {
        DOLOG(3, {
            LOG(3, "disabling sharing b/c reg1 is ");
            opnd_disassemble(drcontext, opnd_create_reg(mi->reg1.reg),
                             LOGFILE(PT_GET(drcontext)));
            LOG(3, "\n");
        });
        STATS_INC(xl8_not_shared_scratch_conflict);
        share_addr = false;
        mi->use_shared = false;
        mi->bb->shared_memop = opnd_create_null();
        mi->bb->shared_disp_implicit = 0;
    }

#ifdef TOOL_DR_MEMORY
    /* point at the locations of shadow values for operands */
    set_shadow_opnds(mi);

    /* other cases where we check definedness rather than propagating */
    set_check_definedness_post_regs(drcontext, inst, mi);

    mark_defined =
        !options.check_uninitialized ||
        /* i#1529: mark all instrs in blacklisted modules defined.  We check this
         * before result_is_always_defined to avoid a lookup there.
         */
        mi->bb->mark_defined ||
        result_is_always_defined(inst, false/*us*/) ||
        /* no sources (e.g., rdtsc) */
        (opnd_is_null(mi->src[0].app) &&
         !TESTANY(EFLAGS_READ_6, instr_get_eflags(inst, DR_QUERY_DEFAULT))) ||
        /* move immed into reg or memory */
        (!mi->load && mi->num_to_propagate == 0 &&
         (mi->store || mi->dst_reg != REG_NULL));
    if (mark_defined) {
        mi->num_to_propagate = 0;
    }

    DOLOG(3, {
        LOG(3, "fastpath: ");
        instr_disassemble(drcontext, inst, LOGFILE_GET(drcontext));
        LOG(3, "| prop=%d srcsz=%d dstsz=%d checkdef=%d markdef=%d checkunaddr=%d\n",
            mi->num_to_propagate, mi->src_opsz, mi->opsz, mi->check_definedness,
            mark_defined, check_ignore_unaddr);
    });
#endif /* TOOL_DR_MEMORY */

    LOG(5, "aflags: %s\n", mi->aflags == EFLAGS_WRITE_6 ? "W6" :
        (mi->aflags == EFLAGS_WRITE_OF ? "WO" :
         (mi->aflags == EFLAGS_READ_6 ? "R6" : "0")));
    ASSERT(mi->opsz != 4 || (!mi->load && !mi->store) ||
           opnd_same(mi->memoffs, opnd_create_immed_int(0, OPSZ_1)),
           "4-byte should have 0 offset");
    ASSERT(mi->dst_reg == REG_NULL || opnd_size_in_bytes(opnd_get_size(mi->dst[0].app)) ==
           mi->opsz,
           "mi->opsz should be dst size");
    ASSERT(mi->src_reg == REG_NULL || opnd_is_immed_int(mi->src[0].app) ||
           opc_is_gpr_shift(opc) /* %cl */ ||
           /* we use src as dst for these */
           ((opc == OP_movzx || opc == OP_movsx) && mi->opsz < 4) ||
           opnd_size_in_bytes(opnd_get_size(mi->src[0].app)) == mi->src_opsz,
           "mi->src_opsz should be src size");
#ifdef TOOL_DR_MEMORY
    ASSERT(!mi->load2x || mi->check_definedness,
           "load2x only supported if not propagating");
#endif

#ifdef TOOL_DR_MEMORY
    if (hashtable_lookup(&ignore_unaddr_table, mi->xl8) != NULL) {
        /* i#768: Double-check that it's still OK to ignore unaddrs from this
         * instruction in case the code changed.
         */
        app_pc pc = mi->xl8;
        app_pc next_pc = pc + instr_length(drcontext, inst);
        bool now_addressable;  /* unused */
        ASSERT(mi->xl8 == instr_get_app_pc(inst), "init error");
        if (is_alloca_pattern(drcontext, pc, next_pc, inst, &now_addressable)) {
            check_ignore_unaddr = true;
            check_ignore_tls = false; /* do not check in-heap tls slot */
        } else {
            /* The code changed, so remove the stale PC. */
            hashtable_remove(&ignore_unaddr_table, pc);
            LOG(2, "removing stale alloca probe exception at "PFX NL, pc);
        }
    }
#endif

    /* PR 578892: fastpath heap routine unaddr accesses */
    if (check_ignore_unaddr && (mi->load || mi->store)) {
        LOG(4, "in heap routine: adding nop-if-mem-unaddr checks\n");
    }

    /* leave a marker so we can insert spills once we know whether we need them */
    PRE(bb, inst, spill_location);

    /* Before any of the leas, restore global spilled registers */
    /* not doing lea if sharing trans, and this restore will clobber shared addr */
    if (!mi->use_shared) {
        if (mi->load || mi->store) {
            /* XXX xref PR 494720: need a better system here.  The out-of-order
             * top-of-bb aflags save uses xchg w/ a scratch reg if that reg
             * has been used: but that varies based on when mark_eflags_used()
             * is called vs mark_scratch_reg_used().  The restore here relies
             * on mark_scratch_reg_used() having been called as well.  We won't
             * have app correctness issues but we can get the wrong app value
             * for our lea and exit to slowpath when we shouldn't, so we
             * just mark reg1 and reg2 up front here since we know we'll need them.
             */
            mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg1);
            mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);
        }
        if (opnd_uses_reg(mi->memop, mi->bb->reg1.reg)) {
            insert_spill_global(drcontext, bb, inst, &mi->bb->reg1, false/*restore*/);
        }
        if (opnd_uses_reg(mi->memop, mi->bb->reg2.reg)) {
            insert_spill_global(drcontext, bb, inst, &mi->bb->reg2, false/*restore*/);
        }
    } else {
        ASSERT(!mi->mem2mem && !mi->load2x,
               "once share for mem2mem or load2x must spill for lea");
    }

#ifdef TOOL_DR_MEMORY
    if (!options.check_uninitialized && check_ignore_unaddr && check_ignore_tls) {
        mark_eflags_used(drcontext, bb, mi->bb);
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, opnd_create_shadow_inheap_slot(),
                             OPND_CREATE_INT8(0)));
        PRE(bb, inst, INSTR_CREATE_jcc
            /* i#1969: OP_jne_short does not always reach. */
            (drcontext, OP_jne, opnd_create_instr(fastpath_restore)));
        check_ignore_unaddr = false; /* can ignore from now on */
    }
#endif

    /* lea before any reg write (incl eflags eax) in case address calc uses that reg */
    if (mi->load || mi->store) {
        if (mi->use_shared && mi->memsz < 4) {
            /* i#1597: reg1 holds xl8 share, but we need addr to check dword bounds */
            mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);
            insert_lea(drcontext, bb, inst, mi->memop, mi->reg2.reg, mi->reg3.reg);
        } else if (!mi->use_shared) { /* don't need lea if sharing trans */
            mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg1);
            insert_lea(drcontext, bb, inst, mi->memop, mi->reg1.reg, mi->reg3.reg);
        }
    }
    if (mi->mem2mem || mi->load2x) {
        opnd_t mem2 = mi->mem2mem ? mi->src[0].app : mi->src[1].app;
        insert_lea_preserve_reg(drcontext, bb, inst, mi, mem2);
    }

    /* don't need to save flags for things like rdtsc */
    save_aflags = (!whole_bb_spills_enabled() &&
                   (mi->load || mi->store ||
                    mi->num_to_propagate > 0 ||
                    mi->src_opsz != 4 ||
#ifdef STATISTICS
                    options.statistics ||
#endif
                    TESTANY(EFLAGS_READ_6, instr_get_eflags(inst, DR_QUERY_DEFAULT))));
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
     *
     * XXX i#1649: generalize this to handle other types of predication on fastpath.
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
        PRE(bb, inst,
            INSTR_CREATE_setcc(drcontext, setcc_opc, opnd_create_reg(mi->reg2_8)));
        if (whole_bb_spills_enabled()) {
            save_aflags_if_live(drcontext, bb, inst, mi, mi->bb);
        }
    }

#ifdef TOOL_DR_MEMORY
    /* Check definedness of eflags if we don't have room to propagate (PR 425622) */
    if (mi->check_eflags_defined &&
        TESTANY(EFLAGS_READ_6, instr_get_eflags(inst, DR_QUERY_DEFAULT))) {
        /* we always write the full byte to make this cmp easy */
        PRE(bb, inst,
            INSTR_CREATE_cmp(drcontext, opnd_create_shadow_eflags_slot(),
                             shadow_immed(sizeof(void*), SHADOW_DEFINED)));
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
     * to that we setcc into mi->reg2_8.
     */
    if (opc_is_cmovcc(opc) || opc_is_fcmovcc(opc)) {
        /* Unfortunately we have to save aflags for eflags-defined check and
         * then restore here. Since reg restores must come before aflags
         * restore, we can't re-use any post-instr restores (even harder w/
         * whole-bb) so we must re-save aflags before jumping to end of instr
         */
        PRE(bb, inst, INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi->reg2_8),
                                       OPND_CREATE_INT8(0)));
        PRE(bb, inst, INSTR_CREATE_jcc_short(drcontext, OP_je,
                                            opnd_create_instr(fastpath_restore)));
    }

#ifdef TOOL_DR_MEMORY
    if (options.check_uninitialized) {
        /* check definedness of addressing registers.
         * for pushpop this also suffices to cover the read+write of esp
         * (and thus we don't need to propagate definedness for esp, reducing
         *  # opnds for pushpop instrs).
         * for lea probably better to consider addressing registers are
         * non-memory-related operands: but then I'd need to support 2 reg
         * sources in fastpath, so for now we treat as addressing.
         */
        if ((mi->load || mi->store) && opnd_is_base_disp(mi->memop)) {
            add_addressing_register_checks(drcontext, bb, inst, mi->memop, mi);
        }
        if (mi->mem2mem || mi->load2x) {
            opnd_t mem2 = mi->mem2mem ? mi->src[0].app : mi->src[1].app;
            add_addressing_register_checks(drcontext, bb, inst, mem2, mi);
        }
    }
#endif /* TOOL_DR_MEMORY */

    if (mi->mem2mem || mi->load2x) {
        bool need_value = IF_DRMEM_ELSE(true, false);
#ifdef TOOL_DR_MEMORY
        uint jcc_not_unaddr = OP_je;
#endif
        bool check_alignment = options.check_uninitialized;
        add_shadow_table_lookup(drcontext, bb, inst, mi, need_value,
                                false/*val in reg1*/, false/*no offs*/, false/*no offs*/,
                                mi->reg3.reg, mi->reg2.reg,
                                mi->reg1.reg/*won't be touched!*/, check_alignment);
        ASSERT(mi->reg3_8 != REG_NULL && mi->reg3.used, "reg spill error");
#ifdef TOOL_DR_MEMORY
        if (!options.check_uninitialized) {
            /* all shadow de-refs need xl8 as Umbra uses page faults */
            PREXL8M(bb, inst, INSTR_XL8
                    (INSTR_CREATE_cmp(drcontext,  opnd_create_reg(mi->reg3_8),
                                      OPND_CREATE_INT8((char)SHADOW_DWORD_UNADDRESSABLE)),
                     mi->xl8));
            jcc_not_unaddr = OP_jne;
            mi->src[0].shadow = opnd_create_reg(mi->reg3_8);
        } else if (mi->mem2mem && !mi->check_definedness) {
            int disp;
            /* if we don't need the 3rd reg for the main mem lookup (i.e., word-sized
             * (and word-aligned) mem2mem), go ahead and propagate.
             * XXX i#164: add a reg "claimed" field to enforce us owning reg3
             */
            ASSERT(mi->memsz == 4, "only word-sized mem2mem prop supported");
            /* Check for unaddressability via table lookup */
            ptr_int_t table_addr = (ptr_int_t)shadow_dword_is_addr_not_bit;
            disp = insert_table_access_pre(drcontext, bb, inst, table_addr, mi->reg3.reg);
            PRE(bb, inst,
                INSTR_CREATE_cmp(drcontext,
                                 OPND_CREATE_MEM8(mi->reg3.reg, disp),
                                 OPND_CREATE_INT8(1)));
            insert_table_access_post(drcontext, bb, inst, table_addr, mi->reg3.reg);
            mi->src[0].shadow = opnd_create_reg(mi->reg3_8);
            /* shouldn't be other srcs */
            ASSERT(opnd_is_null(mi->src[1].shadow), "mem2mem error");
        } else {
            PRE(bb, inst,
                INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi->reg3_8),
                                 OPND_CREATE_INT8((char)SHADOW_DWORD_DEFINED)));
            /* now we're done with the src mem op so we proceed to the dst */
            if (mi->mem2mem) {
                mi->src[0].shadow = opnd_create_null();
                /* shouldn't be other srcs */
                ASSERT(opnd_is_null(mi->src[1].shadow), "mem2mem error");
            } else {
                mi->src[1].shadow = opnd_create_null();
                /* shouldn't be other srcs */
                ASSERT(opnd_is_null(mi->src[2].shadow), "mem2mem error");
                checked_src2 = true;
            }
            if (mi->num_to_propagate > 0)
                mi->num_to_propagate--;
        }
        mark_eflags_used(drcontext, bb, mi->bb);
        if (mi->mem2mem && check_ignore_unaddr && !opnd_is_null(mi->src[0].shadow)) {
            /* PR 578892: fastpath heap routine unaddr accesses.  Yes, there
             * are mem2mem w/ load being heap unaddr: push of heap lock to
             * pass to RtlTryEnterCriticalSection
             */
            instr_t *not_unaddr = INSTR_CREATE_label(drcontext);
            PRE(bb, inst,
                INSTR_CREATE_jcc(drcontext, jcc_not_unaddr,
                                 opnd_create_instr(not_unaddr)));
            mi->need_slowpath = true;
            ASSERT(opnd_is_null(heap_unaddr_shadow), "only 1 unaddr check");
            heap_unaddr_shadow = mi->src[0].shadow;
            /* mem2mem needs to handle the other memref, and push-mem
             * needs to mark the stack slot as addressable so come
             * back here after the check_ignore_unaddr
             */
            PRE(bb, inst, INSTR_CREATE_jmp(drcontext, opnd_create_instr(heap_unaddr)));
            check_ignore_resume = INSTR_CREATE_label(drcontext);
            PRE(bb, inst, check_ignore_resume);
            /* heap_unaddr checked that we're in a heap routine and the src is unaddr.
             * follow slowpath's lead and propagate defined, though we avoid
             * marking orig as defined: not ideal but is there a better solution?
             * else have to have in-heap allow touching ANY unaddr mem, not just
             * in-heap, b/c unaddr will flow to stack, etc., and need
             * to support propagating unaddr in combine_shadows().
             */
            if (options.check_uninitialized) {
                PRE(bb, inst,
                    INSTR_CREATE_mov_imm(drcontext, mi->src[0].shadow,
                                         shadow_immed(mi->memsz, SHADOW_DEFINED)));
            }
            PRE(bb, inst, not_unaddr);
        } else {
            add_jcc_slowpath(drcontext, bb, inst,
                             jcc_not_unaddr == OP_je ? OP_jne : OP_je, mi);
        }
#else
        /* shadow lookup left reg3 holding address */
        if (!options.stale_blind_store) {
            /* FIXME: measure perf to see which is better */
            /* cmp and avoid store can be faster than blindly storing */
            /* all shadow de-refs need xl8 as Umbra uses page faults */
            PREXL8M(bb, inst, INSTR_XL8
                    (INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg3.reg, 0),
                                      OPND_CREATE_INT8(0)),
                     mi->xl8));
            mark_eflags_used(drcontext, bb, mi->bb);
            PRE(bb, inst,
                INSTR_CREATE_jcc(drcontext, OP_jnz_short,
                                 opnd_create_instr(fastpath_restore)));
        }
        PRE(bb, inst,
            INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM8(mi->reg3.reg, 0),
                                OPND_CREATE_INT8(1)));
#endif
    }

#ifdef TOOL_DR_MEMORY
    /* PR 425240: check just the bits for sub-dword sources
     * This setting is independent of mi->need_offs, b/c for some
     * operands we don't need the offset later.
     */
    mi->zero_rest_of_offs =
        ((mi->load || mi->store) && !mi->load2x/*don't have free reg for offs*/ &&
         ((mi->memsz < 4 && !mark_defined && mi->check_definedness) ||
          /* PR 503782: we use the offs for table lookup for loads
           * PR 574918: also for stores
           */
          (mi->memsz < 4 &&
           ((mi->load && options.loads_use_table) ||
            (mi->store && options.stores_use_table)) &&
           mi->need_offs)));

    if (mi->load || mi->store) {
        /* want value only for some loads */
        bool need_value;
        /* we set mi->use_shared, share_addr, and mi->bb->shared_* above */
        IF_DEBUG(if (share_addr))
            ASSERT(mi->reg1.reg == mi->bb->reg1.reg, "sharing requires reg1==bb reg1");
        need_value = options.check_uninitialized &&
            mi->load && !mi->pushpop && !share_addr;

        /* PR 493257: share shadow translation across multiple instrs */
        if (!mi->use_shared) {
            bool check_alignment =
                /* for !uninit we still need alignment for push/pop stack writes */
                options.check_uninitialized || mi->pushpop_stackop;
            add_shadow_table_lookup(drcontext, bb, inst, mi, need_value,
                                    true/*val in reg2*/,
                                    mi->need_offs || mi->need_offs_early,
                                    mi->zero_rest_of_offs,
                                    mi->reg1.reg, mi->reg2.reg, mi->reg3.reg,
                                    check_alignment);
            /* For mi->need_offs, we assume that all uses of reg2 below are
             * low 8 bits only!
             */
        } else {
            /* The prev instr already checked for whether should share */
            int diff;
            STATS_INC(xl8_shared);
            hashtable_add(&xl8_sharing_table, mi->xl8, (void *)1);
            /* FIXME: best to remove these entries when containing fragment
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
            if (mi->use_shared && mi->memsz < 4 && diff != 0) {
                /* i#1597: check for and handle dword boundaries.  We did a
                 * lea into reg2 above, and here we check whether we just crossed
                 * a dword boundary (b/c our shadow is 1B-2b) and we need the
                 * next or prior shadow byte instead of the one the prior
                 * memref wanted.
                 * XXX: is all this complexity worth it?  We avoid the table
                 * lookup memref but we complicate the code.  This is all
                 * unnecessary for byte-to-byte shadowing.
                 */
                /* FIXME i#2032: this is broken: it needs to also incorporate
                 * the delta!  It is now disabled until we have time to either
                 * fix it or abandon completely.
                 */
                ASSERT_NOT_REACHED();
                instr_t *adjust_sharing = INSTR_CREATE_label(drcontext);
                instr_t *no_adjust_sharing = INSTR_CREATE_label(drcontext);
                PRE(bb, inst,
                    INSTR_CREATE_and(drcontext, opnd_create_reg(mi->reg2.reg),
                                     /* 1-byte: check for mod 4 == 0 or 3;
                                      * 2-byte: check for mod 4 == 0,1 vs 2,3.
                                      */
                                     OPND_CREATE_INT8(mi->memsz == 2 ? 2 : 3)));
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi->reg2.reg),
                                     OPND_CREATE_INT32(diff > 0 ?
                                                       (mi->memsz == 2 ? 0 : 0) :
                                                       (mi->memsz == 2 ? 2 : 3))));
                PRE(bb, inst,
                    INSTR_CREATE_jcc(drcontext, OP_je,
                                     opnd_create_instr(adjust_sharing)));
                PRE(bb, inst,
                    INSTR_CREATE_jmp(drcontext, opnd_create_instr(no_adjust_sharing)));
                PRE(bb, inst, adjust_sharing);
                PRE(bb, inst,
                    INSTR_CREATE_add(drcontext, opnd_create_reg(mi->reg1.reg),
                                     OPND_CREATE_INT8(diff > 0 ? 1 : -1)));
                PRE(bb, inst, no_adjust_sharing);
            }
            /* See alignment comments in should_share_addr() */
            ASSERT(ALIGNED(diff, mi->memsz), "can only share aligned references");
            diff /= 4; /* 2 shadow bits per byte */
            /* Subtract what's already been incorporated into the reg */
            diff -= mi->bb->shared_disp_reg1;
            if (mi->load && !mi->pushpop && options.check_uninitialized) { /*want value*/
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_movzx(drcontext, opnd_create_reg(mi->reg2.reg),
                                            OPND_CREATE_MEM8(mi->reg1.reg, diff)),
                         mi->xl8));
                mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);
            } else {
                mi->bb->shared_disp_reg1 += diff;
                /* No reason to avoid eflags since will use cmp below anyway */
                mark_eflags_used(drcontext, bb, mi->bb);
                insert_add_to_reg(drcontext, bb, inst, mi->reg1.reg, diff);
            }
        }
        if (!share_addr) {
            mi->bb->shared_memop = opnd_create_null();
            mi->bb->shared_disp_implicit = 0;
        } else if (mi->pushpop_stackop)
            mi->bb->shared_disp_implicit += (mi->load ? -(int)mi->memsz : mi->memsz);
    } else if ((mi->load || mi->store) && mi->need_offs) {
        ASSERT(false, "not supported"); /* not updated for PR 425240, etc. */
        mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);
        mark_eflags_used(drcontext, bb, mi->bb);
        PRE(bb, inst,
            INSTR_CREATE_mov_st(drcontext, opnd_create_reg(mi->reg2_8h),
                                opnd_create_reg(mi->reg1_8)));
        PRE(bb, inst,
            INSTR_CREATE_and(drcontext, opnd_create_reg(mi->reg2_8h),
                             OPND_CREATE_INT8(0x3)));
        mi->memoffs = opnd_create_reg(mi->reg2_8h);
    }

    /* we now have mi->memoffs so set appropriate src/dst offs */
    if (mi->load)
        mi->src[0].offs = mi->memoffs;
    else if (mi->store) {
        mi->dst[0].offs = mi->memoffs;
        if (opnd_same(mi->dst[0].app, mi->src[0].app)) /* ALU store */
            mi->src[0].offs = mi->memoffs;
    }

    if (options.check_uninitialized &&
        mi->load && (mi->pushpop || (share_addr && !mi->use_shared))) {
        /* A pop into a register or memory, or any load sharing its shadow addr.
         * We need both shadow table slot address and value.  Address is
         * currently in reg1; we get value into reg2.
         */
        ASSERT(mi->reg1.used && mi->reg2.used, "internal reg spill error");
        ASSERT(!mi->need_offs, "assuming don't need mi->reg2_8h");
        PREXL8M(bb, inst, INSTR_XL8
                (INSTR_CREATE_movzx(drcontext, opnd_create_reg(mi->reg2.reg),
                                    OPND_CREATE_MEM8(mi->reg1.reg, 0)), mi->xl8));
    }

    /* check definedness of sources, if necessary.
     * we process in reverse order so we can shift mi->src[0].shadow* but we
     * insert in normal order so we can use reg2 in insert_check_defined.
     */
    marker2 = instr_get_prev(inst);
    marker1 = inst;
    if (!opnd_is_null(mi->src[2].app) && !mark_defined &&
        (mi->check_definedness ||
         (mi->opnum[2] != -1 &&
          always_check_definedness(inst, mi->opnum[2])))) {
        LOG(4, "\tchecking definedness of src3 => %d to propagate\n",
            mi->num_to_propagate-1);
        insert_check_defined(drcontext, bb, marker1, mi, &mi->src[2],
                             mi->src[2].app, mi->src[2].shadow);
        mark_eflags_used(drcontext, bb, mi->bb);
        add_jcc_slowpath(drcontext, bb, marker1,
                         (IF_X64(true ||) check_ignore_unaddr) ?
                         OP_jne : OP_jne_short, mi);
        mi->num_to_propagate--;
        mi->src[2].shadow = opnd_create_null();
    }
    marker1 = instr_get_next(marker2);
    if (!checked_src2 && !opnd_is_null(mi->src[1].app) && !mark_defined &&
        (mi->check_definedness ||
         (mi->opnum[1] != -1 &&
          always_check_definedness(inst, mi->opnum[1])))) {
        opnd_info_t tmp;
        LOG(4, "\tchecking definedness of src2 => %d to propagate\n",
            mi->num_to_propagate-1);
        insert_check_defined(drcontext, bb, marker1, mi, &mi->src[1],
                             mi->src[1].app, mi->src[1].shadow);
        mark_eflags_used(drcontext, bb, mi->bb);
        /* relies on src1 undef going to slowpath so only for !opnd_same */
        if (check_appval && !opnd_same(mi->src[1].app, mi->src[0].app)) {
            /* handle common cases of undef and/test/or in fastpath: only handling
             * 2nd src being undef when 1st src is defined and entirely 0 or 1.
             * i#254 covers doing more.
             */
            instr_t *src2_defined = INSTR_CREATE_label(drcontext);
            opnd_t app_val;
            PRE(bb, marker1, INSTR_CREATE_jcc(drcontext, OP_je,
                                              opnd_create_instr(src2_defined)));
            if (mi->load || mi->store) {
                /* re-lea */
                ASSERT(mi->reg3.reg != REG_NULL, "need reg3");
                ASSERT(!(mi->need_offs || mi->mem2mem || mi->load2x ||
                         mi->need_offs_early || mi->need_nonoffs_reg3),
                       "shouldn't need reg3 for any other reason");
                insert_lea_preserve_reg(drcontext, bb, inst, mi, mi->memop);
                app_val = opnd_create_base_disp(mi->reg3.reg, REG_NULL, 0, 0,
                                                opnd_get_size(mi->memop));
            } else {
                app_val = mi->src[0].app;
            }
            if (opc == OP_and || opc == OP_test) {
                if (mi->load || mi->store) {
                    PRE(bb, marker1, INSTR_CREATE_cmp
                        (drcontext, app_val, opnd_create_immed_int
                         (0, opnd_get_size(app_val))));
                } else
                    PRE(bb, marker1, INSTR_CREATE_test(drcontext, app_val, app_val));
            } else {
                PRE(bb, marker1, INSTR_CREATE_cmp
                    (drcontext, app_val, opnd_create_immed_int
                     (~0, opnd_get_size(app_val))));
            }
            add_jcc_slowpath(drcontext, bb, marker1,
                             (IF_X64(true ||) check_ignore_unaddr) ?
                             OP_jne : OP_jne_short, mi);
            /* having mi->num_to_propagate == 0 implies mark_defined */
            PRE(bb, marker1, src2_defined);
        } else {
            add_jcc_slowpath(drcontext, bb, marker1,
                             (IF_X64(true ||) check_ignore_unaddr) ?
                             OP_jne : OP_jne_short, mi);
        }
        mi->num_to_propagate--;
        tmp = mi->src[1];
        mi->src[1] = mi->src[2]; /* copy shadow and app */
        mi->src[2].shadow = opnd_create_null();
        mi->src[2].app = tmp.app; /* for opnd_same check below */
        checked_src2 = true;
    }
    marker1 = instr_get_next(marker2);
    if (!opnd_is_null(mi->src[0].app) && !opnd_is_null(mi->src[0].shadow) &&
        !mark_defined &&
        /* Special case: we treat cmovcc like a cmp for checking the flags,
         * but we still want to propagate the src normally to the dest if
         * the condition is triggered (i#1456).
         */
        !opc_is_cmovcc(opc) && !opc_is_fcmovcc(opc) &&
        (mi->check_definedness ||
         (mi->opnum[0] != -1 &&
          always_check_definedness(inst, mi->opnum[0])))) {
        LOG(4, "\tchecking definedness of src1 => %d to propagate\n",
            mi->num_to_propagate-1);
        /* optimization: avoid duplicate check if both sources identical.
         * we check src2 since if checked_src2 we swapped 1 and 2
         */
        if (!checked_src2 || !opnd_same(mi->src[2].app, mi->src[0].app)) {
            insert_check_defined(drcontext, bb, marker1, mi, &mi->src[0],
                                 mi->src[0].app, mi->src[0].shadow);
            mark_eflags_used(drcontext, bb, mi->bb);
            ASSERT(opnd_is_null(heap_unaddr_shadow), "only 1 unaddr check");
            if (check_ignore_unaddr && opnd_is_null(heap_unaddr_shadow) &&
                /* i#1722: do not try to check unaddr for indirected shadow */
                mi->src[0].indir_size == OPSZ_NA) {
                /* PR 578892: fastpath heap routine unaddr accesses
                 * Can't do this for src1 and src2 b/c no support for more than
                 * one shadow value type to check down below: but this is enough
                 * for cmp/test/and/or w/ immed, which is the typical alloc code use.
                 */
                PRE(bb, marker1,
                    INSTR_CREATE_jcc(drcontext, OP_jne, opnd_create_instr(heap_unaddr)));
                mi->need_slowpath = true;
                heap_unaddr_shadow = mi->src[0].shadow;
            } else {
                add_jcc_slowpath(drcontext, bb, marker1,
                                 IF_X64_ELSE(OP_jne, OP_jne_short), mi);
            }
            if (mi->load)
                checked_memsrc = true;
        }
        mi->num_to_propagate--;
        mi->src[0] = mi->src[1]; /* copy shadow and app */
        mi->src[1] = mi->src[2]; /* copy shadow and app */
        mi->src[2].shadow = opnd_create_null();
    }
    marker1 = instr_get_next(marker2); /* may as well check first */
    if (opc == OP_cmpxchg8b && options.check_uninitialized) {
        /* we keep on fastpath by hardcoding the 4th & 5th sources */
        opnd_t op4 = instr_get_src(inst, 3);
        opnd_t op5 = instr_get_src(inst, 4);
        insert_check_defined(drcontext, bb, marker1, mi, NULL, op4,
                             opnd_create_shadow_reg_slot(opnd_get_reg(op4)));
        mark_eflags_used(drcontext, bb, mi->bb);
        add_jcc_slowpath(drcontext, bb, marker1,
                         (IF_X64(true ||) check_ignore_unaddr) ?
                         OP_jne : OP_jne_short, mi);
        insert_check_defined(drcontext, bb, marker1, mi, NULL, op5,
                             opnd_create_shadow_reg_slot(opnd_get_reg(op5)));
        add_jcc_slowpath(drcontext, bb, marker1,
                         (IF_X64(true ||) check_ignore_unaddr) ?
                         OP_jne : OP_jne_short, mi);
    }
    ASSERT(mi->memsz <= sizeof(void*) || mi->num_to_propagate == 0 || mi->memsz ==16,
           "propagation not suported for odd-sized memops");
    /* optimization to avoid checks on jcc after cmp/test
     * we can't use mi->check_definedness b/c in fastpath it's used for "go
     * to slowpath" as well as "report error"
     */
    if (instr_check_definedness(inst) &&
        TESTALL(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_DEFAULT)))
        mi->bb->eflags_defined = true;
    else if (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)))
        mi->bb->eflags_defined = false;

    /* Check memory operand(s) for addressability.
     * For mem2mem/load2x we checked the source mem op/2nd source already.
     */
    if (mi->load &&
        /* if we checked memsrc for definedness we also checked for addressability */
        !checked_memsrc) {
        int jcc_unaddr = OP_jne;
        mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg2);

        if (!options.check_uninitialized) {
            jcc_unaddr = OP_je;
            /* all shadow de-refs need xl8 as Umbra uses page faults */
            PREXL8M(bb, inst, INSTR_XL8
                    (INSTR_CREATE_cmp(drcontext, mi->src[0].shadow,
                                      OPND_CREATE_INT8((char)SHADOW_DWORD_UNADDRESSABLE)),
                     mi->xl8));
        } else if (options.loads_use_table && mi->memsz <= 4) {
            int disp;
            /* Check for unaddressability via table lookup */
            if (mi->memsz < 4 && mi->need_offs) {
                /* PR 503782: check just the bytes referenced.  We've zeroed the
                 * rest of mi->memoffs and in 8h position it's doing x256 already.
                 */
                reg_id_t idx = reg_to_pointer_sized(opnd_get_reg(mi->memoffs));
                ptr_int_t table_addr = (ptr_int_t) ((mi->memsz == 1) ?
                                                    shadow_byte_addr_not_bit :
                                                    shadow_word_addr_not_bit);
                int disp = insert_table_access_pre(drcontext, bb, inst, table_addr,
                                                   mi->reg2.reg);
                ASSERT(mi->zero_rest_of_offs, "table lookup requires zeroing");
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext,
                                     opnd_create_base_disp(mi->reg2.reg, idx,
                                                           1, disp, OPSZ_1),
                                     OPND_CREATE_INT8(1)));
                insert_table_access_post(drcontext, bb, inst, table_addr, mi->reg2.reg);
            } else {
                ptr_int_t table_addr = (ptr_int_t)shadow_dword_is_addr_not_bit;
                disp = insert_table_access_pre(drcontext, bb, inst, table_addr,
                                               mi->reg2.reg);
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext,
                                     OPND_CREATE_MEM8(mi->reg2.reg, disp),
                                     OPND_CREATE_INT8(1)));
                insert_table_access_post(drcontext, bb, inst, table_addr, mi->reg2.reg);
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
                    INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi->reg2_8),
                                     OPND_CREATE_INT8((char)SHADOW_DWORD_DEFINED)));
            } else if (mi->memsz == 8) {
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi->reg2_16),
                                     OPND_CREATE_INT16((short)SHADOW_QWORD_DEFINED)));
            } else {
                ASSERT(mi->memsz == 16 || mi->memsz == 10, "invalid memsz");
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext, opnd_create_reg(mi->reg2.reg),
                                     OPND_CREATE_INT32(SHADOW_DQWORD_DEFINED)));
            }
        }
        mark_eflags_used(drcontext, bb, mi->bb);
        /* we only check for 1 unaddr shadow so only check if haven't already */
        if (check_ignore_unaddr && opnd_is_null(heap_unaddr_shadow)) {
            /* PR 578892: fastpath heap routine unaddr accesses */
            PRE(bb, inst,
                INSTR_CREATE_jcc(drcontext, jcc_unaddr, opnd_create_instr(heap_unaddr)));
            mi->need_slowpath = true;
            heap_unaddr_shadow = opnd_create_reg(mi->memsz <= 4 ? mi->reg2_8 :
                                                 (mi->memsz == 8 ? mi->reg2_16 :
                                                  reg_ptrsz_to_32(mi->reg2.reg)));
        } else {
            add_jcc_slowpath(drcontext, bb, inst,
                             (IF_X64(true ||) check_ignore_unaddr) ?
                             (jcc_unaddr == OP_jne ? OP_jne : OP_je)
                             : (jcc_unaddr == OP_jne ? OP_jne_short : OP_je_short), mi);
        }
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
                add_jcc_slowpath(drcontext, bb, inst,
                                 (IF_X64(true ||) check_ignore_unaddr || mi->memsz < 4) ?
                                 OP_jne : OP_jne_short, mi);
            }
        } else {
            if (!options.check_uninitialized) {
                /* all shadow de-refs need xl8 as Umbra uses page faults */
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_cmp(drcontext, mi->dst[0].shadow,
                                          OPND_CREATE_INT8
                                          ((char)SHADOW_DWORD_UNADDRESSABLE)),
                         mi->xl8));
                mark_eflags_used(drcontext, bb, mi->bb);
                /* we only check for 1 unaddr shadow so only check if haven't already */
                if (check_ignore_unaddr && opnd_is_null(heap_unaddr_shadow)) {
                    /* PR 578892: fastpath heap routine unaddr accesses */
                    PRE(bb, inst,
                        INSTR_CREATE_jcc(drcontext, OP_je,
                                         opnd_create_instr(heap_unaddr)));
                    mi->need_slowpath = true;
                    heap_unaddr_shadow = mi->dst[0].shadow;
                } else {
                    add_jcc_slowpath(drcontext, bb, inst,
                                     (IF_X64(true ||) check_ignore_unaddr) ?
                                     OP_je : OP_je_short, mi);
                }
            } else if (options.stores_use_table && mi->memsz <= 4) {
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
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_movzx(drcontext, opnd_create_reg(scratch),
                                            OPND_CREATE_MEM8(mi->reg1.reg, 0)), mi->xl8));
                /* optimization: avoid redundant load below for mi->num_to_propagate>1 */
                if (opnd_same(mi->src[0].shadow, OPND_CREATE_MEM8(mi->reg1.reg, 0)))
                    mi->src[0].shadow = opnd_create_reg(reg_ptrsz_to_8(scratch));
                if (mi->memsz < 4 && mi->need_offs) {
                    /* PR 503782: check just the bytes referenced.  We've zeroed the
                     * rest of mi->memoffs and in 8h position it's doing x256 already.
                     */
                    reg_id_t idx = reg_to_pointer_sized(opnd_get_reg(mi->memoffs));
                    ptr_int_t table_addr = (ptr_int_t)
                        ((mi->memsz == 1) ? shadow_byte_addr_not_bit :
                         shadow_word_addr_not_bit);
                    int disp = insert_table_access_pre(drcontext, bb, inst, table_addr,
                                                       scratch);
                    ASSERT(mi->zero_rest_of_offs, "table lookup requires zeroing");
                    PRE(bb, inst,
                        INSTR_CREATE_cmp(drcontext,
                                         opnd_create_base_disp(scratch, idx,
                                                               1, disp, OPSZ_1),
                                         OPND_CREATE_INT8(1)));
                    insert_table_access_post(drcontext, bb, inst, table_addr, scratch);
                } else {
                    ptr_int_t table_addr = (ptr_int_t)shadow_dword_is_addr_not_bit;
                    int disp = insert_table_access_pre(drcontext, bb, inst, table_addr,
                                                       scratch);
                    PRE(bb, inst,
                        INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8
                                         (scratch, disp),
                                         OPND_CREATE_INT8(1)));
                    insert_table_access_post(drcontext, bb, inst, table_addr, scratch);
                }
                /* we only check for 1 unaddr shadow so only check if haven't already */
                if (check_ignore_unaddr && opnd_is_null(heap_unaddr_shadow)) {
                    /* PR 578892: fastpath heap routine unaddr accesses */
                    PRE(bb, inst,
                        INSTR_CREATE_jcc(drcontext, OP_jne,
                                         opnd_create_instr(heap_unaddr)));
                    mi->need_slowpath = true;
                    heap_unaddr_shadow = opnd_create_reg(reg_ptrsz_to_8(scratch));
                } else {
                    add_jcc_slowpath(drcontext, bb, inst,
                                     (IF_X64(true ||) check_ignore_unaddr ||
                                      mi->memsz < 4) ?
                                     OP_jne : OP_jne_short, mi);
                }
           } else {
                /* check for unaddressability by checking for definedness.
                 * see !options.loads_use_table comments above on dup src def checks.
                 */
                instr_t *ok_to_write = INSTR_CREATE_label(drcontext);
                ASSERT(mi->reg1.used, "internal reg spill error");
                PRE(bb, inst, INSTR_CREATE_cmp
                    (drcontext, mi->memsz <= 4 ? OPND_CREATE_MEM8(mi->reg1.reg, 0) :
                     (mi->memsz == 8 ? OPND_CREATE_MEM16(mi->reg1.reg, 0) :
                      OPND_CREATE_MEM32(mi->reg1.reg, 0)),
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
                if (!mi->check_definedness ||
                    !opnd_same(mi->src[0].app, mi->dst[0].app)) {
                    /* would be nice to check for subsets of undefined but we have to rule
                     * out any byte being unaddressable so we require all-undefined
                     */
                    PRE(bb, inst, INSTR_CREATE_cmp
                        (drcontext, mi->memsz <= 4 ? OPND_CREATE_MEM8(mi->reg1.reg, 0) :
                         (mi->memsz == 8 ? OPND_CREATE_MEM16(mi->reg1.reg, 0) :
                          OPND_CREATE_MEM32(mi->reg1.reg, 0)),
                         shadow_immed(mi->memsz, SHADOW_UNDEFINED)));
                    add_check_partial_undefined(drcontext, bb, inst, mi, false/*dst*/,
                                                ok_to_write);
                }
                add_jcc_slowpath(drcontext, bb, inst, OP_jne_short, mi);
                PRE(bb, inst, ok_to_write);
            }
        }
    }

    if (mi->pushpop && mi->load /* pop into a reg */ &&
        (options.check_uninitialized || options.check_stack_bounds)) {
        /* reg1 still has our address and we have the src memop value in reg2,
         * so go ahead and write to the shadow table so we can trash reg2
         * FIXME: if do 2-byte pop, wouldn't mi->reg2_8 be clobbered and
         * then src memop propagation to reg below would be wrong?  we
         * need reg2 for below!
         */
        opnd_info_t dst, src;
        initialize_opnd_info(&dst);
        initialize_opnd_info(&src);
        dst.shadow = OPND_CREATE_MEM8(mi->reg1.reg, 0);
        src.shadow = OPND_CREATE_INT8((char)SHADOW_DWORD_UNADDRESSABLE);
        ASSERT(mi->reg2.used, "internal reg spill error");
        add_dst_shadow_write(drcontext, bb, inst, mi, dst, src, mi->src_opsz,
                             instr_is_return(inst) ? mi->src_opsz : mi->opsz,
                             mi->reg2_8, &mi->reg2,
                             /* for popf don't write UNADDR to eflags: we handle below */
                             false/*skip eflags*/, false/*!alu_uncombined*/,
                             false/*!preserve -- doesn't matter since src is const*/);
        if (options.check_uninitialized &&
            opc == OP_popf && !opnd_is_null(mi->src[0].shadow)) {
            /* special-cased b/c eflags is not handled as a regular dest
             * so there's no propagation below
             * XXX: actually isn't there now?  writing eflags twice then?
             */
            write_shadow_eflags(drcontext, bb, inst, REG_NULL, mi->src[0].shadow);
        }
    }

    /* Combine sources and write result to the dests, including eflags.
     */

    if (opnd_uses_reg(mi->dst[0].shadow, mi->reg1.reg) ||
        opnd_uses_reg(mi->src[0].shadow, mi->reg2.reg)) {
        ASSERT(!opnd_uses_reg(mi->dst[0].shadow, mi->reg2.reg), "scratch reg error");
        scratch = reg_to_size(mi->reg2.reg, (mi->opsz > 8) ? OPSZ_4 :
                              ((mi->opsz == 8) ? OPSZ_2 : OPSZ_1));
        si = &mi->reg2;
    } else {
        ASSERT(!opnd_uses_reg(mi->dst[0].shadow, mi->reg1.reg), "scratch reg error");
        scratch = reg_to_size(mi->reg1.reg, (mi->opsz > 8) ? OPSZ_4 :
                              ((mi->opsz == 8) ? OPSZ_2 : OPSZ_1));
        si = &mi->reg1;
    }
    scratch3 = mi->reg3.reg == REG_NULL ? REG_NULL :
        reg_to_size(mi->reg3.reg, (mi->opsz > 8) ? OPSZ_4 :
                    ((mi->opsz == 8) ? OPSZ_2 : OPSZ_1));
    if (mi->src_opsz > 4 && !mi->check_definedness/*eflags*/ &&
        mi->num_to_propagate > 0) {
        /* we're going to use the whole register */
        ASSERT(!mi->need_offs, "assuming don't need mi->reg2_8h");
        /* XXX i#243: once we have drreg we should be able to do a better job here
         * and can use reg3 instead of scratch and thus keep sharing on
         * (currently disabled in should_share_addr_helper()).
         * How can we guarantee add_dstx2_shadow_write won't use scratch?
         * Then we can use reg3, which we went to pains to get.
         */
        ASSERT(!mi->use_shared, "we're clobbering reg1 potentially");
        if (mi->src_opsz == 16) /* xmm */
            src_val_reg = reg_ptrsz_to_32(reg_to_pointer_sized(scratch));
        else if (mi->src_opsz == 8) /* mmx */
            src_val_reg = reg_ptrsz_to_16(reg_to_pointer_sized(scratch));
        else {
            ASSERT_NOT_IMPLEMENTED();
            src_val_reg = DR_REG_NULL;
        }
    } else
        src_val_reg = scratch;

    ASSERT(mi->num_to_propagate >= 0, "propagation count error");
    ASSERT(options.check_uninitialized || mi->num_to_propagate == 0,
           "only prop for uninits");
    if (mi->num_to_propagate == 0) {
        if (options.check_uninitialized ||
            (options.check_stack_bounds && mi->pushpop && mi->store)) {
            int effective_opsz = mi->opsz/*not src*/;
            if (mi->check_definedness && mi->opsz < 4) {
                /* If we're checking definedness for sub-dword we didn't ask for
                 * a 3rd scratch reg and we don't need it since we can write the
                 * whole dword's shadow to eflags.  The x64 code can handle a
                 * size 4 immed for its size-8 eflags.
                 */
                effective_opsz = 4;
            }
            mi->src[0].shadow = shadow_immed(effective_opsz, SHADOW_DEFINED);
            mi->src[0].offs = opnd_create_immed_int(0, OPSZ_1);
            add_dstX2_shadow_write(drcontext, bb, inst, mi, mi->src[0],
                                   effective_opsz, effective_opsz,
                                   scratch, si, true, false);
        }
    } else if (mi->num_to_propagate == 1) {
        /* copy src shadow to eflags shadow and dst shadow */
        mark_scratch_reg_used(drcontext, bb, mi->bb, si);
        if (load_reg_shadow_val(drcontext, bb, inst, mi, src_val_reg, &mi->src[0]))
            mi->src[0].shadow = opnd_create_reg(src_val_reg);
        if (!needs_shadow_op(inst) && opnd_same(mi->src[0].app, mi->dst[0].app)) {
            /* only propagate eflags.  example here: "add $1, mem -> mem" */
            mi->dst[0].shadow = opnd_create_null();
            mi->dst[0].offs = opnd_create_immed_int(0, OPSZ_1); /* for eflags */
        }
        add_dstX2_shadow_write(drcontext, bb, inst, mi, mi->src[0], mi->src_opsz,
                               mi->opsz, scratch3, &mi->reg3, true, false);
        ASSERT(!mi->reg3.used || mi->reg3.reg != REG_NULL, "spill error");
    } else {
        /* combine the N sources and then write to the dest + eflags.
         * in general we want U+D=>U, U+U=>U, and D+D=>D: so we want bitwise or.
         * even if this instr is sub-dword, we manipulate the full shadow byte
         * but then only propagate the bits that matter to shadow memory.
         * FIXME: for ops that promote bits we need to promote undefinedness
         */
        /* For sub-dword ALU it is more efficient to combine inside
         * add_dstX2_shadow_write since need to shift shadow vals.
         */
        bool alu_uncombined = mi->opsz < 4 && is_alu(mi);

        mark_scratch_reg_used(drcontext, bb, mi->bb, si);
        mark_eflags_used(drcontext, bb, mi->bb);

        if (alu_uncombined) {
            /* src and dst are combined inside add_dstX2_shadow_write */
            alu_uncombined = true;
            if (mi->store) {
                /* swap so src1 is what we ignore since == dst */
                opnd_info_t tmp = mi->src[0];
                mi->src[0] = mi->src[1];
                mi->src[1] = tmp;
            }
            if (load_reg_shadow_val(drcontext, bb, inst, mi, src_val_reg, &mi->src[0]))
                mi->src[0].shadow = opnd_create_reg(src_val_reg);
            ASSERT(opnd_same(mi->src[1].app, mi->dst[0].app), "invalid ALU");
            if (!opnd_is_null(mi->src[2].shadow)) {
                /* offs not same for {div,idiv}w but for those we do check_definedness */
                ASSERT(opnd_same(mi->src[0].offs, mi->src[2].offs),
                       "multi-src different offsets on fastpath NYI");
                ASSERT(mi->src[2].indir_size == OPSZ_NA, "should be !alu_uncombined");
                merge_src_shadows(drcontext, bb, mi, inst, mi->src[2].shadow,
                                  src_val_reg, si);
            }
        } else {
            /* We used to optimize for 4-byte ALU ops by or-ing src into dst instead
             * of or-ing both into a temp and then moving that to dst.  But when we
             * need to write the result to eflags, we have to load back into a reg
             * anyway.  Plus, for stores, with -stores_use_table, the dst shadow
             * value is already in a register, making the regular path shorter than
             * the ALU path.  For loads or reg-to-reg, it is exactly the same length
             * and has the same number of memory references.  Writing to eflags
             * happens for all GPR ALU except cmovcc.  Thus, we no longer optimize
             * for 4-byte ALU (not worth keeping extra code paths just for
             * -no_stores_use_tables).
             */
            if (load_reg_shadow_val(drcontext, bb, inst, mi, src_val_reg, &mi->src[0]))
                mi->src[0].shadow = opnd_create_reg(src_val_reg);
            /* combine sources now.  must be same offs, which isn't true for
             * 1-byte {mul,imul} but for those we do check_definedness
             */
            ASSERT(opnd_same(mi->src[1].offs, mi->src[0].offs) ||
                   /* indir_size uses offs to mean something else */
                   mi->src[0].indir_size != OPSZ_NA ||
                   mi->src[1].indir_size != OPSZ_NA,
                   "combining srcs w/ different sub-dword offs NYI");
            if (mi->src[1].indir_size != OPSZ_NA) {
                ASSERT(mi->reg3.reg != DR_REG_NULL, "spill error");
                mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg3);
                PRE(bb, inst,
                    INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(mi->reg3.reg),
                                        mi->src[1].shadow));
                mi->src[1].shadow = shadow_reg_indir_opnd(&mi->src[1], mi->reg3.reg);
            }
            merge_src_shadows(drcontext, bb, mi, inst, mi->src[1].shadow,
                              src_val_reg, &mi->reg3);
            if (!opnd_is_null(mi->src[2].shadow)) {
                ASSERT(opnd_same(mi->src[2].offs, mi->src[0].offs),
                       "combining srcs w/ different sub-dword offs NYI");
                if (mi->src[2].indir_size != OPSZ_NA) {
                    ASSERT(mi->reg3.reg != DR_REG_NULL, "spill error");
                    mark_scratch_reg_used(drcontext, bb, mi->bb, &mi->reg3);
                    PRE(bb, inst,
                        INSTR_CREATE_mov_ld(drcontext, opnd_create_reg(mi->reg3.reg),
                                            mi->src[2].shadow));
                    mi->src[2].shadow = shadow_reg_indir_opnd(&mi->src[2], mi->reg3.reg);
                }
                merge_src_shadows(drcontext, bb, mi, inst, mi->src[2].shadow,
                                  src_val_reg, &mi->reg3);
            }
        }
        add_dstX2_shadow_write(drcontext, bb, inst, mi, mi->src[0],
                               mi->src_opsz, mi->opsz, scratch3, &mi->reg3,
                               true, alu_uncombined);
        ASSERT(!mi->reg3.used || mi->reg3.reg != REG_NULL, "spill error");

        /* FIXME: for insert_shadow_op() for shifts, need to
         * either do the bitwise or into mi->reg1_8, then call:
         *   insert_shadow_op(drcontext, bb, inst, mi->reg1_8,
         *                    reg_ptrsz_to_8h(mi->reg1.reg));
         * and then store into dst_reg?  lots of work if not a shift, so have
         * insert_shadow_op() handle both mem8 or reg8?
         */
    }
#else /* TOOL_DR_MEMORY */
    add_shadow_table_lookup(drcontext, bb, inst, mi, false/*addr not value*/,
                            false, false/*!need_offs*/, false/*!zero_rest*/,
                            mi->reg1.reg, mi->reg2.reg, mi->reg3.reg,
                            true/*check_alignment*/);
    ASSERT(mi->reg1_8 != REG_NULL && mi->reg1.used, "reg spill error");
    /* shadow lookup left reg1 holding address */
    if (!options.stale_blind_store) {
        /* FIXME: measure perf to see which is better */
        /* cmp and avoid store can be faster than blindly storing */
        /* all shadow de-refs need xl8 as Umbra uses page faults */
        PREXL8M(bb, inst, INSTR_XL8
                (INSTR_CREATE_cmp(drcontext, OPND_CREATE_MEM8(mi->reg1.reg, 0),
                                  OPND_CREATE_INT8(0)),
                 mi->xl8));
        mark_eflags_used(drcontext, bb, mi->bb);
        /* too bad there's no cmovcc from immed to memory! */
        PRE(bb, inst,
            INSTR_CREATE_jcc(drcontext, OP_jnz_short,
                             opnd_create_instr(fastpath_restore)));
    }
    PRE(bb, inst,
        INSTR_CREATE_mov_st(drcontext, OPND_CREATE_MEM8(mi->reg1.reg, 0),
                            OPND_CREATE_INT8(1)));
#endif /* TOOL_DR_MEMORY */

    PRE(bb, inst, fastpath_restore);
#ifdef STATISTICS
    if (options.statistics) {
        int disp;
        ASSERT_TRUNCATE(disp, int, (ptr_int_t)&push4_fastpath);
        ASSERT_TRUNCATE(disp, int, (ptr_int_t)&pop4_fastpath);
        ASSERT_TRUNCATE(disp, int, (ptr_int_t)&write4_fastpath);
        ASSERT_TRUNCATE(disp, int, (ptr_int_t)&read4_fastpath);
        disp = (int)(ptr_int_t)(mi->pushpop ?
                                (mi->store ? &push4_fastpath  : &pop4_fastpath) :
                                (mi->store ? &write4_fastpath : &read4_fastpath));
        PRE(bb, inst,
            INSTR_CREATE_inc(drcontext, OPND_CREATE_MEM32(REG_NULL, disp)));
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
        tls_util_t *pt = PT_GET(drcontext);
        if (instru_start == NULL)
            in = instrlist_first(bb);
        else
            in = instr_get_next(instru_start);
        for (; in != inst; in = instr_get_next(in)) {
            if (TESTANY(EFLAGS_WRITE_6, instr_get_eflags(in, DR_QUERY_INCLUDE_ALL)) &&
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
        bool ignore_unaddr_pre_slow =
            IF_DRMEM_ELSE((check_ignore_unaddr && !opnd_is_null(heap_unaddr_shadow)),
                          false);
        add_jmp_done_with_fastpath(drcontext, bb, inst, mi, nextinstr,
                                   ignore_unaddr_pre_slow, &fastpath_restore);
#ifdef TOOL_DR_MEMORY
        /* PR 578892: fastpath heap routine unaddr accesses */
        if (mi->need_slowpath) /* may have decided we don't need slowpath */
            PRE(bb, inst, heap_unaddr);
        if (ignore_unaddr_pre_slow) {
            if (check_ignore_tls) {
                PRE(bb, inst,
                    INSTR_CREATE_cmp(drcontext, opnd_create_shadow_inheap_slot(),
                                     OPND_CREATE_INT8(0)));
                if (options.check_uninitialized) {
                    add_jcc_slowpath(drcontext, bb, inst, OP_je_short, mi);
                } else {
                    PRE(bb, inst, INSTR_CREATE_jcc
                        (drcontext, OP_jne_short, opnd_create_instr(fastpath_restore)));
                }
            }
            if (options.check_uninitialized) {
                /* all shadow de-refs need xl8 as Umbra uses page faults */
                PREXL8M(bb, inst, INSTR_XL8
                        (INSTR_CREATE_cmp(drcontext, heap_unaddr_shadow,
                                          shadow_immed(mi->memsz, SHADOW_UNADDRESSABLE)),
                         mi->xl8));
                if (check_ignore_resume != NULL) {
                    PRE(bb, inst,
                        INSTR_CREATE_jcc(drcontext, OP_je,
                                         opnd_create_instr(check_ignore_resume)));
                } else if (!mi->store && !opnd_is_null(mi->dst[0].shadow)) {
                    /* follow slowpath's lead and propagate defined.
                     * we only propagate to a register here: mem2mem is handled
                     * via check_ignore_resume.  and in fact we can't write to
                     * shadow_table here b/c shadow fault handling code won't
                     * recognize this sequence.
                     * xref i#922.
                     *
                     * XXX: ideally we'd go back to the main code and just have
                     * the src be SHADOW_DEFINED, but it's not general enough:
                     * we'd have to pay in indirection, or have a dup copy.
                     */
                    instr_t *not_inheap = INSTR_CREATE_label(drcontext);
                    ASSERT(opnd_is_reg(mi->dst[0].app), "should be marked store");
                    PRE(bb, inst,
                        INSTR_CREATE_jcc(drcontext, OP_jne_short,
                                         opnd_create_instr(not_inheap)));
                    mi->src[0].shadow = shadow_immed(mi->opsz, SHADOW_DEFINED);
                    mi->src[0].offs = opnd_create_immed_int(0, OPSZ_1);
                    add_dstX2_shadow_write(drcontext, bb, inst, mi, mi->src[0],
                                           mi->opsz/*not src*/, mi->opsz,
                                           scratch, si, false/*no eflags*/, false);
                    PRE(bb, inst,
                        INSTR_CREATE_jmp_short(drcontext,
                                               opnd_create_instr(fastpath_restore)));
                    PRE(bb, inst, not_inheap);
                } else {
                    /* just skip check.  we don't want to mark memory as defined
                     * b/c that would lead to false negatives.
                     */
                    PRE(bb, inst,
                        INSTR_CREATE_jcc(drcontext, OP_je_short,
                                         opnd_create_instr(fastpath_restore)));
                }
            } else if (!check_ignore_tls) {
                if (check_ignore_resume != NULL) {
                    PRE(bb, inst, INSTR_CREATE_jmp
                        (drcontext, opnd_create_instr(check_ignore_resume)));
                } else {
                    PRE(bb, inst, INSTR_CREATE_jmp_short
                        (drcontext, opnd_create_instr(fastpath_restore)));
                }
            }
        }
#endif
    }
    /* check again b/c no-uninits may have removed regular slowpath */
    if (mi->need_slowpath) {
        PRE(bb, inst, mi->slowpath);
        if (!instr_can_use_shared_slowpath(inst, mi)) {
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
            insert_spill_or_restore(drcontext, bb, inst, &mi->reg3,false/*restore*/,false);
            insert_spill_or_restore(drcontext, bb, inst, &mi->reg2,false/*restore*/,false);
            insert_spill_or_restore(drcontext, bb, inst, &mi->reg1,false/*restore*/,false);
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
#ifdef TOOL_DR_MEMORY
        PRE(bb, inst, heap_unaddr);
#endif
        PRE(bb, inst, mi->slowpath);
    }
    PRE(bb, inst, nextinstr);
}

/***************************************************************************
 * Fault handling
 */

#ifdef TOOL_DR_MEMORY

static bool
instr_is_restore_eflags(void *drcontext, instr_t *inst)
{
    return (instr_get_opcode(inst) == OP_mov_ld &&
            opnd_is_far_base_disp(instr_get_src(inst, 0)) &&
            /* opnd_same fails b/c of force_full_disp differences */
            opnd_get_disp(instr_get_src(inst, 0)) ==
            opnd_get_disp(spill_slot_opnd(drcontext, SPILL_SLOT_EFLAGS_EAX)));
}

static bool
instr_is_spill_reg(void *drcontext, instr_t *inst)
{
    return (instr_get_opcode(inst) == OP_mov_st &&
            opnd_is_far_base_disp(instr_get_dst(inst, 0)) &&
            /* distinguish our pop store of 0x55 from slow slot eax spill */
            opnd_get_size(instr_get_src(inst, 0)) == OPSZ_PTR);
}

/* PR 448701: handle fault on write to a special shadow block.
 * Restores mc to app values and returns a pointer to app instr,
 * which caller must free.
 */
instr_t *
restore_mcontext_on_shadow_fault(void *drcontext,
                                 dr_mcontext_t *raw_mc, dr_mcontext_t *mc,
                                 byte *pc_post_fault, bb_saved_info_t *save)
{
    app_pc pc;
    instr_t inst;
    instr_t *app_inst;
#ifdef DEBUG
    tls_util_t *pt = PT_GET(drcontext);
#endif

    /* We need to restore the app registers in order to emulate the app instr
     * and obtain the original address referenced.  We assume all shadow table
     * writes involve a single base register and are followed by no ctis prior
     * to restoring the registers.
     */
    /* We're re-executing from raw_mc, so we change mc, which we did NOT fix up
     * in our restore_state event for non-whole-bb registers: we did restore
     * the two whole-bb.  Note that our restore_state event has
     * restored eflags, but that doesn't hurt anything.
     */
    DOLOG(3, {
        LOG(3, "faulting cache instr:\n");
        disassemble_with_info(drcontext, raw_mc->pc, pt->f, true/*pc*/, true/*bytes*/);
        LOG(3, "original app instr:\n");
        disassemble_with_info(drcontext, mc->pc, pt->f, true/*pc*/, true/*bytes*/);
    });
    app_inst = instr_create(drcontext);
    /* i#268: mc->pc might be in the middle of a hooked region so call
     * dr_app_pc_for_decoding()
     */
    decode(drcontext, dr_app_pc_for_decoding(mc->pc), app_inst);
    pc = pc_post_fault;
    instr_init(drcontext, &inst);

    /* First we look for eflags restore.  We could try and work it into the
     * regular loop to be more efficient but it gets messy.  We want to skip
     * the whole thing (i#533).
     */
    if (instr_needs_eflags_restore(app_inst,
                                   /* not worth storing liveness for bb or decoding
                                    * whole bb here, so we may have false pos
                                    */
                                   instr_get_eflags(app_inst, DR_QUERY_INCLUDE_ALL)) ||
        mc->pc == save->last_instr /* bottom of bb restores */) {
        /* Skip what's added by restore_aflags_if_live() prior to GPR restores */
        bool has_eflags_restore = false;
        pc = decode(drcontext, pc, &inst);
        if (instr_valid(&inst)) {
            bool has_spill_eax = false;
            if (instr_get_opcode(&inst) == OP_xchg ||
                instr_is_spill_reg(drcontext, &inst)) {
                has_spill_eax = true;
                instr_reset(drcontext, &inst);
                pc = decode(drcontext, pc, &inst);
            }
            if (instr_is_restore_eflags(drcontext, &inst)) {
                has_eflags_restore = true;
                /* skip it and any add+sahf */
                instr_reset(drcontext, &inst);
                pc = decode(drcontext, pc, &inst);
                if (instr_get_opcode(&inst) == OP_add) {
                    instr_reset(drcontext, &inst);
                    pc = decode(drcontext, pc, &inst);
                }
                ASSERT(instr_get_opcode(&inst) == OP_sahf, "invalid flags restore");
                if (has_spill_eax) {
                    /* skip restore */
                    instr_reset(drcontext, &inst);
                    pc = decode(drcontext, pc, &inst);
                    ASSERT(instr_get_opcode(&inst) == OP_xchg ||
                           instr_get_opcode(&inst) == OP_mov_ld, "invalid restore");
                }
            }
        } else
            ASSERT(false, "unknown restore instr"); /* we'll reset below for release */
        if (!has_eflags_restore) {
            /* since we didn't have bb liveness we could come here and not find it */
            pc = pc_post_fault;
        }
        instr_reset(drcontext, &inst);
    }

    while (true) {
        pc = decode(drcontext, pc, &inst);
        DOLOG(3, {
            LOG(3, "considering potential restore instr: ");
            instr_disassemble(drcontext, &inst, pt->f);
            LOG(3, "\n");
        });
        ASSERT(instr_valid(&inst), "unknown suspect instr");
        if (!options.check_uninitialized && instr_same(&inst, app_inst)) {
            /* for -no_check_uninitialized slowpath faults we do not have
             * a cti between the faulting instr and the app instr, so we
             * stop when we see the app instr (i#456).
             * XXX: if the app instr looks just like our xchg or load
             * instrs we could mess up the app state: will affect
             * the address considered for the unaddr error so could
             * lead to a false negative or misleading error.
             */
            break;
        }
        if (instr_get_opcode(&inst) == OP_xchg) {
            reg_t val1, val2;
            reg_id_t reg1, reg2;
            bool swap = true;
            ASSERT(opnd_is_reg(instr_get_src(&inst, 0)) &&
                   opnd_is_reg(instr_get_src(&inst, 1)), "unknown xchg!");
            reg1 = opnd_get_reg(instr_get_src(&inst, 0));
            reg2 = opnd_get_reg(instr_get_src(&inst, 1));
            /* If one of the regs is a whole-bb spill, its real value is
             * in the TLS slot, so don't swap (PR 501740).
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
                        LOG(3, "\tsetting %s to "PFX"\n",
                            get_register_name(reg2), val2);
                        reg_set_value(reg2, mc, val2);
                    }
                } else if (reg2 == save->scratch1 || reg2 == save->scratch2) {
                    swap = false;
                    /* The app's value was in the global's mcxt slot */
                    val1 = reg_get_value(reg2, raw_mc);
                    LOG(3, "\tsetting %s to "PFX"\n",
                        get_register_name(reg1), val1);
                    reg_set_value(reg1, mc, val1);
                }
            }
            if (swap) {
                val1 = reg_get_value(reg1, mc);
                val2 = reg_get_value(reg2, mc);
                LOG(3, "\tsetting %s to "PFX" and %s to "PFX"\n",
                    get_register_name(reg2), val1,
                    get_register_name(reg1), val2);
                reg_set_value(reg2, mc, val1);
                reg_set_value(reg1, mc, val2);
            }
        } else if (instr_get_opcode(&inst) == OP_mov_ld &&
                   opnd_is_far_base_disp(instr_get_src(&inst, 0))) {
            opnd_t src = instr_get_src(&inst, 0);
            int offs = opnd_get_disp(src);
            IF_DEBUG(opnd_t flag_slot = spill_slot_opnd(drcontext, SPILL_SLOT_EFLAGS_EAX);)
            ASSERT(opnd_get_index(src) == REG_NULL, "unknown tls");
            ASSERT(opnd_get_segment(src) == seg_tls, "unknown tls");
            ASSERT(opnd_is_reg(instr_get_dst(&inst, 0)), "unknown tls");
            /* We read directly from the tls slot regardless of whether ours or
             * DR's: no easy way to translate to DR spill slot # and use C
             * interface.
             */
            LOG(3, "\tsetting %s to "PFX"\n",
                get_register_name(opnd_get_reg(instr_get_dst(&inst, 0))),
                get_raw_tls_value(offs));
            /* XXX: opnd_same() fails b/c we have force_full_disp set, which is
             * not set on decoding
             */
            ASSERT(offs != opnd_get_disp(flag_slot), "failed to skip eflags restore");
            reg_set_value(opnd_get_reg(instr_get_dst(&inst, 0)), mc,
                          get_raw_tls_value(offs));
        } else if (instr_is_spill_reg(drcontext, &inst)) {
            /* Start of non-fast DR spill slot sequence.
             * We skip eflags restore so this can't be a local store of eax.
             */
            reg_t val;
            int offs;
            if (opnd_get_disp(instr_get_dst(&inst, 0)) <
                opnd_get_disp(spill_slot_opnd(drcontext, SPILL_SLOT_1))) {
                /* this is ecx spill for DR's own mangling */
                break;
            }
            /* FIXME: NOT TESTED: not easy since we now require our own spill slots */
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
            LOG(3, "\tsetting %s to "PFX"\n",
                get_register_name(opnd_get_reg(instr_get_dst(&inst, 0))), val);
            reg_set_value(opnd_get_reg(instr_get_dst(&inst, 0)), mc, val);

            instr_reset(drcontext, &inst);
            pc = decode(drcontext, pc, &inst);
            ASSERT(instr_get_opcode(&inst) == OP_mov_ld &&
                   opnd_is_far_base_disp(instr_get_src(&inst, 0)), "unknown slow spill");
        } else if (instr_get_opcode(&inst) == OP_sahf) {
            ASSERT(false, "should have skipped eflags restore");
        } else if (instr_is_cti(&inst) ||
                   /* for no uninits our instru has no cti before app instr */
                   !options.check_uninitialized) {
            break;
        }
        instr_reset(drcontext, &inst);
    }
    instr_free(drcontext, &inst);

    /* Adjust (esp) => (esp-X).  Xref i#164/PR 214976 where DR should adjust for us. */
    if (opc_is_push(instr_get_opcode(app_inst))) {
        mc->xsp -= adjust_memop_push_offs(app_inst);
    }
    return app_inst;
}

/* For !options.check_uninitialized we use a fault instead of explicit
 * slowpath jump.
 */
bool
handle_slowpath_fault(void *drcontext, dr_mcontext_t *raw_mc, dr_mcontext_t *mc,
                      void *tag)
{
    app_pc pc;
    instr_t fault_inst;
    instr_t *app_inst;
    bb_saved_info_t *save;
    byte buf[5];

    /* quick check: must be preceded by jnz over load == 75 02.
     * since using ud2a now and not a fault (where we were checking
     * various aspects of the address) we also check the prior cmp to
     * try and rule out app ud2a.
     */
    if (options.check_uninitialized ||
        !options.fault_to_slowpath ||
        !options.shadowing ||
        !whole_bb_spills_enabled() ||
        !safe_read(raw_mc->pc - JNZ_SHORT_LENGTH - CMP_BASE_IMM1_LENGTH,
                   BUFFER_SIZE_BYTES(buf), buf) ||
        buf[0] != CMP_OPCODE ||
        buf[2] != SHADOW_UNADDRESSABLE ||
        buf[3] != JNZ_SHORT_OPCODE
        /* We no longer check the jnz offset as the clear of the xl8 sharing
         * is also skipped, leading to several possible offsets.
         */
        )
        return false;

    DOLOG(3, {
        LOG(3, "checking whether fault is to enter slowpath: raw mc:\n");
        print_mcontext(LOGFILE_LOOKUP(), mc);
        LOG(3, "app mc:\n");
        print_mcontext(LOGFILE_LOOKUP(), mc);
    });
#ifdef TOOL_DR_HEAPSTAT
    ASSERT(false, "should not get here");
#endif

    instr_init(drcontext, &fault_inst);
    pc = decode(drcontext, raw_mc->pc, &fault_inst);
    if (instr_get_opcode(&fault_inst) != OP_ud2a) {
        instr_free(drcontext, &fault_inst);
        return false;
    }
    instr_free(drcontext, &fault_inst);
    STATS_INC(num_slowpath_faults);

    hashtable_lock(&bb_table);
    save = (bb_saved_info_t *) hashtable_lookup(&bb_table, tag);
    app_inst = restore_mcontext_on_shadow_fault(drcontext, raw_mc, mc, pc, save);
    instr_destroy(drcontext, app_inst);
    hashtable_unlock(&bb_table);

    slow_path_with_mc(drcontext, mc->pc, dr_app_pc_for_decoding(mc->pc), mc);

    /* now resume by skipping ud2a */
    raw_mc->pc += UD2A_LENGTH;
    DOLOG(3, {
        LOG(3, "resuming post-ud2a at "PFX" raw mc:\n", raw_mc->pc);
        print_mcontext(LOGFILE_LOOKUP(), mc);
        LOG(3, "app mc:\n");
        print_mcontext(LOGFILE_LOOKUP(), mc);
    });

    return true;
}

#endif /* TOOL_DR_MEMORY */
