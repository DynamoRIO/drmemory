/* **********************************************************
 * Copyright (c) 2010-2020 Google, Inc.  All rights reserved.
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
 * instru.c: Dr. Memory top-level instrumentation control routines
 */

#include "dr_api.h"
#include "drreg.h"
#include "drutil.h"
#include "drmemory.h"
#include "slowpath.h"
#include "memlayout.h"
#include "spill.h"
#include "fastpath.h"
#include "stack.h"
#include "annotations.h"
#include "replace.h"
#include "report.h"
#include "syscall.h"
#include "shadow.h"
#include "alloc.h"
#include "alloc_drmem.h"
#include "pattern.h"
#include "heap.h"

/* State restoration: need to record which bbs have eflags-save-at-top.
 * We store the app pc of the last instr in the bb.
 */
#define BB_HASH_BITS 12
hashtable_t bb_table;

/* PR 493257: share shadow translation across multiple instrs.  But, abandon
 * sharing for memrefs that cross 64K boundaries and keep exiting to slowpath.
 * This table tracks slowpath exits and whether to share.
 */
#define XL8_SHARING_HASH_BITS 10
hashtable_t xl8_sharing_table;

/* alloca handling in fastpath (i#91) */
#define IGNORE_UNADDR_HASH_BITS 6
hashtable_t ignore_unaddr_table;

#ifdef X86
/* Handle slowpath for OP_loop in repstr_to_loop properly (i#391).
 * We map the address of an allocated OP_loop to the app_pc of the original
 * app rep-stringop instr.  We also map the reverse so we can delete it
 * (we don't want to pay the cost of storing this in bb_saved_info_t for
 * every single bb).  We're helped there b/c repstr_to_loop always
 * has single-instr bbs so the tag is the rep-stringop instr pc.
 */
# define STRINGOP_HASH_BITS 6
hashtable_t stringop_us2app_table;
static hashtable_t stringop_app2us_table;
void *stringop_lock; /* protects both tables */
/* Entry in stringop_app2us_table */
typedef struct _stringop_entry_t {
    /* an OP_loop encoding, decoded by slow_path */
    byte loop_instr[LOOP_INSTR_LENGTH];
    /* This is used to handle non-precise flushing */
    byte ignore_next_delete;
} stringop_entry_t;
#endif

#ifdef TOOL_DR_MEMORY
/* We wait until 1st bb to set thread data structs, as we want the mcxt
 * and DR doesn't provide it at initial thread init (i#117).
 */
bool first_bb = true;
#endif

#ifdef TOOL_DR_MEMORY
static dr_emit_flags_t
instru_event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                        bool for_trace, bool translating, OUT void **user_data);

static dr_emit_flags_t
instru_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                         bool for_trace, bool translating, void *user_data);

static dr_emit_flags_t
instru_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                       bool for_trace, bool translating, void *user_data);

static dr_emit_flags_t
instru_event_bb_instru2instru(void *drcontext, void *tag, instrlist_t *bb,
                              bool for_trace, bool translating, void *user_data);
#endif

/***************************************************************************
 * FRAGMENT DELETION
 */

void
instrument_fragment_delete(void *drcontext/*may be NULL*/, void *tag)
{
    bb_saved_info_t *save;
    IF_X86(stringop_entry_t *stringop;)
    uint bb_size = 0;
#ifdef TOOL_DR_MEMORY
    if (!INSTRUMENT_MEMREFS())
        return;
#endif

    hashtable_lock(&bb_table);
    save = (bb_saved_info_t *) hashtable_lookup(&bb_table, tag);
    if (save != NULL) {
        /* PR 495787: handle non-precise flushing where new bbs can be created
         * before the old ones are fully deleted
         */
        LOG(2, "event_fragment_delete "PFX" ignore_next_delete=%d\n",
            tag, save->ignore_next_delete);
        if (save->ignore_next_delete == 0) {
            bb_size = save->bb_size;
            hashtable_remove(&bb_table, tag);
        } else /* hashtable lock is held so no race here */
            save->ignore_next_delete--;
    }
    hashtable_unlock(&bb_table);

    if (options.shadowing && bb_size > 0) {
        /* i#260: remove xl8_sharing_table entries.  We can't
         * decode forward (not always safe) and query every app pc, so we store the
         * bb size and assume bbs are contiguous (no elision) and there are no traces
         * (already assuming that for i#114 and dr_fragment_exists_at()).  We assume
         * walking these hashtables is faster than switching to an rbtree, and it's
         * not worth storing pointers in bb_saved_info_t.
         *
         * Without removing, new code that replaces old code at the same address can
         * fail to be optimized b/c it will use the old code's history: so a perf
         * failure, not a correctness failure.
         */
        /* i#768: We used to invalidate entries from ignore_unaddr_table here,
         * but that ends up thrashing the code cache.  Instead we remove stale
         * entries in the new bb event if the alloca pattern no longer matches.
         */
        app_pc start = dr_fragment_app_pc(tag);
        /* It turns out that hashtable_remove_range() is really slow: xl8_sharing_table
         * gets quite large (12 bits on chrome ui_tests single test) and walking
         * it on every single fragment delete is quite slow.
         * This is faster:
         */
        int i;
        for (i = 0; i < bb_size; i++) {
            hashtable_remove(&xl8_sharing_table, (void *)(start + i));
        }
    }

#ifdef X86
    dr_mutex_lock(stringop_lock);
    /* We rely on repstr_to_loop arranging the repstr to be the only
     * instr and thus the tag (i#391) (and we require -disable_traces)
     */
    stringop = (stringop_entry_t *) hashtable_lookup(&stringop_app2us_table, tag);
    if (stringop != NULL) {
        if (stringop->ignore_next_delete == 0) {
            IF_DEBUG(bool found;)
            hashtable_remove(&stringop_app2us_table, tag);
            IF_DEBUG(found =)
                hashtable_remove(&stringop_us2app_table, (void *)stringop);
            LOG(2, "removing tag "PFX" and stringop entry "PFX"\n",
                tag, stringop);
            ASSERT(found, "entry should be in both tables");
        } else {
            LOG(2, "stringop entry "PFX" for tag "PFX" nextdel=%d\n",
                stringop, tag, stringop->ignore_next_delete);
            stringop->ignore_next_delete--;
        }
    }
    dr_mutex_unlock(stringop_lock);
#endif
}

static void
bb_table_free_entry(void *entry)
{
    bb_saved_info_t *save = (bb_saved_info_t *) entry;
    ASSERT(save->ignore_next_delete == 0, "premature deletion");
    global_free(save, sizeof(*save), HEAPSTAT_PERBB);
}

#ifdef X86
static void
stringop_free_entry(void *entry)
{
    stringop_entry_t *e = (stringop_entry_t *) entry;
    ASSERT(e->loop_instr[0] == LOOP_INSTR_OPCODE, "invalid entry");
    LOG(3, "freeing stringop entry "PFX" ignore_next_delete %d\n",
        e, e->ignore_next_delete);
    global_free(e, sizeof(*e), HEAPSTAT_PERBB);
}
#endif

/***************************************************************************
 * TOP-LEVEL
 */

#ifdef TOOL_DR_MEMORY
# ifdef WINDOWS
static ptr_uint_t note_base;
enum {
    NOTE_NULL = 0,
    NOTE_SEH_EPILOG_RETADDR,
    NOTE_CHKSTK_RETADDR,
    NOTE_MAX_VALUE,
};
# endif
#endif

void
instrument_init(void)
{
    drmgr_priority_t priority = {sizeof(priority), "drmemory.instru", NULL, NULL,
                                 DRMGR_PRIORITY_INSTRU};
    drutil_init();
    annotate_init();

#ifdef TOOL_DR_MEMORY
    /* XXX: at some point we should design a cleaner interaction between
     * various drmemory/ components and drheapstat/.
     * For now sticking w/ the original where drheapstat's bb events
     * call into here.
     */
    if (!drmgr_register_bb_instrumentation_ex_event
        (instru_event_bb_app2app, instru_event_bb_analysis,
         instru_event_bb_insert, instru_event_bb_instru2instru,
         &priority)) {
        ASSERT(false, "drmgr registration failed");
    }
#  ifdef WINDOWS
    note_base = drmgr_reserve_note_range(NOTE_MAX_VALUE);
    ASSERT(note_base != DRMGR_NOTE_NONE, "failed to get note value");
#  endif /* WINDOWS */
#endif

    /* we need bb event for leaks_only */
    if (!INSTRUMENT_MEMREFS())
        return;

    instru_tls_init();

    if (options.shadowing) {
        gencode_init();
        hashtable_init(&xl8_sharing_table, XL8_SHARING_HASH_BITS, HASH_INTPTR,
                       false/*!strdup*/);
        hashtable_init(&ignore_unaddr_table, IGNORE_UNADDR_HASH_BITS, HASH_INTPTR,
                       false/*!strdup*/);
    }
    hashtable_init_ex(&bb_table, BB_HASH_BITS, HASH_INTPTR, false/*!strdup*/,
                      false/*!synch*/, bb_table_free_entry, NULL, NULL);
#ifdef X86
    stringop_lock = dr_mutex_create();
    hashtable_init_ex(&stringop_app2us_table, STRINGOP_HASH_BITS, HASH_INTPTR,
                      false/*!strdup*/, false/*!synch*/,
                      stringop_free_entry, NULL, NULL);
    hashtable_init_ex(&stringop_us2app_table, STRINGOP_HASH_BITS, HASH_INTPTR,
                      false/*!strdup*/, false/*!synch*/, NULL, NULL, NULL);
#endif

#ifdef TOOL_DR_MEMORY
    if (INSTRUMENT_MEMREFS())
        replace_init();
#endif
}

void
instrument_exit(void)
{
    annotate_exit();
    drutil_exit();
    if (!INSTRUMENT_MEMREFS())
        return;
    if (options.shadowing) {
        gencode_exit();
    }
    if (options.shadowing) {
        hashtable_delete_with_stats(&xl8_sharing_table, "xl8_sharing");
        hashtable_delete_with_stats(&ignore_unaddr_table, "ignore_unaddr");
    }
    hashtable_delete_with_stats(&bb_table, "bb_table");
#ifdef X86
    dr_mutex_destroy(stringop_lock);
    hashtable_delete(&stringop_app2us_table);
    hashtable_delete(&stringop_us2app_table);
#endif
#ifdef TOOL_DR_MEMORY
    if (INSTRUMENT_MEMREFS())
        replace_exit();
#endif
    instru_tls_exit();
}

void
instrument_thread_init(void *drcontext)
{
    if (!INSTRUMENT_MEMREFS())
        return;
    instru_tls_thread_init(drcontext);
}

void
instrument_thread_exit(void *drcontext)
{
    if (!INSTRUMENT_MEMREFS())
        return;
    instru_tls_thread_exit(drcontext);
}

size_t
instrument_persist_ro_size(void *drcontext, void *perscxt)
{
    size_t sz = 0;
    if (!INSTRUMENT_MEMREFS())
        return 0;
    LOG(2, "persisting bb table "PFX"-"PFX"\n", dr_persist_start(perscxt),
        dr_persist_start(perscxt) + dr_persist_size(perscxt));
    sz += hashtable_persist_size(drcontext, &bb_table, sizeof(bb_saved_info_t),
                                 perscxt, DR_HASHPERS_REBASE_KEY  |
                                 DR_HASHPERS_ONLY_IN_RANGE |
                                 DR_HASHPERS_ONLY_PERSISTED);
    if (options.shadowing) {
        LOG(2, "persisting xl8 table\n");
        sz += hashtable_persist_size(drcontext, &xl8_sharing_table, sizeof(uint),
                                     perscxt, DR_HASHPERS_REBASE_KEY |
                                     DR_HASHPERS_ONLY_IN_RANGE);
        LOG(2, "persisting unaddr table\n");
        sz += hashtable_persist_size(drcontext, &ignore_unaddr_table, sizeof(uint),
                                     perscxt, DR_HASHPERS_REBASE_KEY |
                                     DR_HASHPERS_ONLY_IN_RANGE);
    }
#ifdef X86
    LOG(2, "persisting string table\n");
    sz += hashtable_persist_size(drcontext, &stringop_app2us_table,
                                 sizeof(stringop_entry_t), perscxt,
                                 DR_HASHPERS_REBASE_KEY  |
                                 DR_HASHPERS_ONLY_IN_RANGE | DR_HASHPERS_ONLY_PERSISTED);
    /* the stringop_us2app_table is composed of heap-allocated entries in
     * stringop_app2us_table, which will change on resurrection: so rather than
     * persist we rebuild at resurrect time
     */
#endif
    return sz;
}

bool
instrument_persist_ro(void *drcontext, void *perscxt, file_t fd)
{
    bool ok = true;
    if (!INSTRUMENT_MEMREFS())
        return ok;
    LOG(2, "persisting bb table\n");
    ok = ok && hashtable_persist(drcontext, &bb_table, sizeof(bb_saved_info_t), fd,
                                 perscxt, DR_HASHPERS_PAYLOAD_IS_POINTER |
                                 DR_HASHPERS_REBASE_KEY | DR_HASHPERS_ONLY_IN_RANGE |
                                 DR_HASHPERS_ONLY_PERSISTED);
    if (options.shadowing) {
        LOG(2, "persisting xl8 table\n");
        /* these two tables don't just contain tags so we can't do ONLY_PERSISTED */
        ok = ok && hashtable_persist(drcontext, &xl8_sharing_table, sizeof(uint), fd,
                                     perscxt, DR_HASHPERS_REBASE_KEY |
                                     DR_HASHPERS_ONLY_IN_RANGE);
        LOG(2, "persisting unaddr table\n");
        ok = ok && hashtable_persist(drcontext, &ignore_unaddr_table, sizeof(uint), fd,
                                     perscxt, DR_HASHPERS_REBASE_KEY |
                                     DR_HASHPERS_ONLY_IN_RANGE);
    }
#ifdef X86
    LOG(2, "persisting string table\n");
    ok = ok && hashtable_persist(drcontext, &stringop_app2us_table,
                                 sizeof(stringop_entry_t), fd, perscxt,
                                 DR_HASHPERS_PAYLOAD_IS_POINTER | DR_HASHPERS_REBASE_KEY |
                                 DR_HASHPERS_ONLY_IN_RANGE | DR_HASHPERS_ONLY_PERSISTED);
#endif
    return ok;
}

/* caller should hold bb_table lock */
void
bb_save_add_entry(app_pc key, bb_saved_info_t *save)
{
    bb_saved_info_t *old = (bb_saved_info_t *)
        hashtable_add_replace(&bb_table, (void *)key, (void *)save);
    ASSERT(hashtable_lock_self_owns(&bb_table), "missing lock");
    if (old != NULL) {
        ASSERT(old->ignore_next_delete < UCHAR_MAX, "ignore_next_delete overflow");
        save->ignore_next_delete = old->ignore_next_delete + 1;
        global_free(old, sizeof(*old), HEAPSTAT_PERBB);
        LOG(2, "bb "PFX" duplicated: assuming non-precise flushing\n", key);
    }
}

/* caller should hold bb_table lock */
static bool
bb_save_resurrect_entry(void *key, void *payload, ptr_int_t shift)
{
    /* last_instr could be changed to last_instr_offs but then we'd need to call
     * dr_fragment_app_pc(tag) in a few places which doesn't seem worth it
     */
    bb_saved_info_t *save = (bb_saved_info_t *) payload;
    ASSERT(hashtable_lock_self_owns(&bb_table), "missing lock");
    save->first_restore_pc =
        save->first_restore_pc == NULL ?
        NULL : (app_pc) ((ptr_int_t)save->first_restore_pc + shift);
    save->last_instr = (app_pc) ((ptr_int_t)save->last_instr + shift);
    bb_save_add_entry((app_pc) key, save);
    return true;
}

static bool
xl8_sharing_resurrect_entry(void *key, void *payload, ptr_int_t shift)
{
    /* we can have dups b/c of non-precise flushing on re-loaded modules,
     * so we use our own callback here to ignore them (perf, not correctness,
     * on dup entries)
     */
    hashtable_add(&xl8_sharing_table, key, payload);
    return true;
}

#ifdef X86
/* caller should hold hashtable lock */
static void
stringop_app2us_add_entry(app_pc xl8, stringop_entry_t *entry)
{
    stringop_entry_t *old = (stringop_entry_t *)
        hashtable_add_replace(&stringop_app2us_table, (void *)xl8, (void *)entry);
    ASSERT(dr_mutex_self_owns(stringop_lock), "caller must hold lock");
    if (old != NULL) {
        IF_DEBUG(bool found;)
            LOG(2, "stringop xl8 "PFX" duplicated at "PFX
                ": assuming non-precise flushing\n", xl8, old);
        ASSERT(old->ignore_next_delete < UCHAR_MAX, "ignore_next_delete overflow");
        entry->ignore_next_delete = old->ignore_next_delete + 1;
        global_free(old, sizeof(*old), HEAPSTAT_PERBB);
        IF_DEBUG(found =)
            hashtable_remove(&stringop_us2app_table, (void *)old);
        ASSERT(found, "entry should be in both tables");
    }
}

/* caller should hold hashtable lock */
static bool
stringop_app2us_resurrect_entry(void *key, void *payload, ptr_int_t shift)
{
    stringop_app2us_add_entry((app_pc) key, (stringop_entry_t *) payload);
    return true;
}

static bool
populate_us2app_table(void)
{
    uint i;
    for (i = 0; i < HASHTABLE_SIZE(stringop_app2us_table.table_bits); i++) {
        hash_entry_t *he;
        for (he = stringop_app2us_table.table[i]; he != NULL; he = he->next) {
            hashtable_add(&stringop_us2app_table, (void *)he->payload, he->key);
            /* we're going through whole table so we will re-add prior entries */
        }
    }
    return true;
}
#endif

bool
instrument_resurrect_ro(void *drcontext, void *perscxt, byte **map INOUT)
{
    bool ok = true;
    if (!INSTRUMENT_MEMREFS())
        return ok;
    LOG(2, "resurrecting bb table\n");
    hashtable_lock(&bb_table);
    ok = ok && hashtable_resurrect(drcontext, map, &bb_table, sizeof(bb_saved_info_t),
                                   perscxt, DR_HASHPERS_PAYLOAD_IS_POINTER |
                                   DR_HASHPERS_REBASE_KEY | DR_HASHPERS_CLONE_PAYLOAD,
                                   bb_save_resurrect_entry);
    hashtable_unlock(&bb_table);
    if (options.shadowing) {
        LOG(2, "resurrecting xl8 table\n");
        ok = ok && hashtable_resurrect(drcontext, map, &xl8_sharing_table, sizeof(uint),
                                       perscxt, DR_HASHPERS_REBASE_KEY,
                                       xl8_sharing_resurrect_entry);
        LOG(2, "resurrecting unaddr table\n");
        ok = ok && hashtable_resurrect(drcontext, map, &ignore_unaddr_table, sizeof(uint),
                                       perscxt, DR_HASHPERS_REBASE_KEY, NULL);
    }
#ifdef X86
    LOG(2, "resurrecting string table\n");
    dr_mutex_lock(stringop_lock);
    ok = ok && hashtable_resurrect(drcontext, map, &stringop_app2us_table,
                                   sizeof(stringop_entry_t), perscxt,
                                   DR_HASHPERS_PAYLOAD_IS_POINTER |
                                   DR_HASHPERS_REBASE_KEY |
                                   DR_HASHPERS_CLONE_PAYLOAD,
                                   stringop_app2us_resurrect_entry);
    /* the stringop_us2app_table is composed of heap-allocated entries in
     * stringop_app2us_table, which will change on resurrection: so rather than
     * persist we rebuild at resurrect time
     */
    ok = ok && populate_us2app_table();
    dr_mutex_unlock(stringop_lock);
#endif

    /* FIXME: if a later one fails, we'll abort the pcache load but we'll have entries
     * added to the earlier tables.  we should invalidate them.
     */
    ASSERT(ok, "aborted pcache load leaves tables inconsistent");
    return ok;
}

void
instru_insert_mov_pc(void *drcontext, instrlist_t *bb, instr_t *inst,
                     opnd_t dst, opnd_t pc_opnd)
{
    if (opnd_is_instr(pc_opnd)) {
        /* This does insert meta instrs */
        instrlist_insert_mov_instr_addr(drcontext, opnd_get_instr(pc_opnd),
                                        NULL /* in code cache */,
                                        dst, bb, inst, NULL, NULL);
    } else {
        ASSERT(opnd_is_immed_int(pc_opnd), "invalid opnd");
        /* This does insert meta instrs */
        instrlist_insert_mov_immed_ptrsz(drcontext, opnd_get_immed_int(pc_opnd),
                                         dst, bb, inst, NULL, NULL);
    }
}

#ifdef TOOL_DR_MEMORY

# ifdef WINDOWS
/* i#1371: _SEH_epilog4 returns at different stack spot instead of actual retaddr
 * USER32!_SEH_epilog4:
 * 74af616a 8b4df0           mov     ecx, [ebp-0x10]
 * 74af616d 64890d00000000   mov     fs:[00000000], ecx
 * 74af6174 59               pop     ecx
 * 74af6175 5f               pop     edi
 * 74af6176 5f               pop     edi
 * 74af6177 5e               pop     esi
 * 74af6178 5b               pop     ebx
 * 74af6179 8be5             mov     esp, ebp
 * 74af617b 5d               pop     ebp
 * 74af617c 51               push    ecx
 * 74af617d c3               ret
 */
static void
bb_check_SEH_epilog(void *drcontext, app_pc tag, instrlist_t *ilist)
{
    instr_t *instr, *next_pop;
    opnd_t   opnd;
    reg_id_t ret_reg; /* register that holds return addr */

    /* ret */
    instr = instrlist_last_app_instr(ilist);
    if (instr == NULL || !instr_is_return(instr))
        return;
    /* push  ecx */
    instr = instr_get_prev_app_instr(instr);
    if (instr == NULL || instr_get_opcode(instr) != OP_push)
        return;
    /* opnd must be reg */
    opnd = instr_get_src(instr, 0);
    if (!opnd_is_reg(opnd))
        return;
    ret_reg = opnd_get_reg(opnd);

    /* mov  ecx, [ebp-0x10] */
    instr = instrlist_first_app_instr(ilist);
    if (instr == NULL || instr_get_opcode(instr) != OP_mov_ld)
        return;
    /* mov  [fs:00000000], ecx */
    instr = instr_get_next_app_instr(instr);
    if (instr == NULL || instr_get_opcode(instr) != OP_mov_st)
        return;
    /* opnd must be [fs:00000000] */
    opnd = instr_get_dst(instr, 0);
    if (!opnd_is_far_base_disp(opnd) ||
        !opnd_is_abs_addr(opnd)  /* rule out base or index */||
        opnd_get_disp(opnd) != 0 /* disp must be 0 */)
        return;
    /* pop ecx */
    instr = instr_get_next_app_instr(instr);
    if (instr == NULL || instr_get_opcode(instr) != OP_pop)
        return;
    opnd = instr_get_dst(instr, 0);
    /* opnd must be the same reg used by the push above */
    if (!opnd_is_reg(opnd) || opnd_get_reg(opnd) != ret_reg)
        return;
    /* reg opnd must be pointer size */
    ASSERT(opnd_get_size(opnd) == OPSZ_PTR, "wrong opnd size");
    /* pop edi */
    instr = instr_get_next_app_instr(instr);
    if (instr == NULL || instr_get_opcode(instr) != OP_pop)
        return;
    next_pop = instr;
#  ifdef DEBUG
    /* pop edi */
    instr = instr_get_next_app_instr(instr);
    ASSERT(instr != NULL && instr_get_opcode(instr) == OP_pop,
           "need more check to identify SEH_epilog");
#  endif
    instr = INSTR_CREATE_label(drcontext);
    instr_set_note(instr, (void *)(note_base + NOTE_SEH_EPILOG_RETADDR));
    PRE(ilist, next_pop, instr);
    LOG(1, "found SEH_epilog at "PFX"\n", dr_fragment_app_pc(tag));
}

#  ifndef X64
/* handle!_chkstk:
 * ...
 * 00a6cc4b 94               xchg    eax,esp
 * 00a6cc4c 8b00             mov     eax,[eax]
 * 00a6cc4e 890424           mov     [esp],eax
 * 00a6cc51 c3               ret
 * or
 * ntdll!_alloca_probe
 * ...
 * 7d610434 8500             test    [eax],eax
 * 7d610436 94               xchg    eax,esp
 * 7d610437 8b00             mov     eax,[eax]
 * 7d610439 50               push    eax
 * 7d61043a c3               ret
 * or
 * hello!_alloca_probe+0x20 [intel\chkstk.asm @ 85]:
 * 85 0040db70 2bc8             sub     ecx,eax
 * 86 0040db72 8bc4             mov     eax,esp
 * 88 0040db74 8501             test    [ecx],eax
 * 90 0040db76 8be1             mov     esp,ecx
 * 92 0040db78 8b08             mov     ecx,[eax]
 * 93 0040db7a 8b4004           mov     eax,[eax+0x4]
 * 95 0040db7d 50               push    eax
 * 97 0040db7e c3               ret
 */
static void
bb_handle_chkstk(void *drcontext, app_pc tag, instrlist_t *ilist)
{
    instr_t *instr, *load = NULL;
    int opc;
    opnd_t opnd;

    /* ret */
    instr = instrlist_last_app_instr(ilist);
    if (instr == NULL || !instr_is_return(instr))
        return;

    /* mov [esp],eax  or  push eax */
    instr = instr_get_prev_app_instr(instr);
    if (instr == NULL)
        return;
    opc = instr_get_opcode(instr);
    if (opc != OP_push && opc != OP_mov_st)
        return;
    /* dst: [esp] */
    if (opc == OP_mov_st &&
        !opnd_same(OPND_CREATE_MEMPTR(DR_REG_XSP, 0), instr_get_dst(instr, 0)))
        return;
    /* src: eax */
    opnd = instr_get_src(instr, 0);
    if (!opnd_is_reg(opnd) || opnd_get_reg(opnd) != DR_REG_XAX)
        return;

    /* mov eax,[eax]  or  mov eax,[eax+0x4] */
    instr = instr_get_prev_app_instr(instr);
    if (instr == NULL || instr_get_opcode(instr) != OP_mov_ld)
        return;
    /* dst: eax */
    if (opnd_get_reg(instr_get_dst(instr, 0)) != DR_REG_XAX)
        return;
    /* src: [eax]/[eax+4] */
    opnd = instr_get_src(instr, 0);
    if (!opnd_is_near_base_disp(opnd)       ||
        opnd_get_base(opnd)  != DR_REG_XAX  ||
        opnd_get_index(opnd) != DR_REG_NULL)
        return;
    if (opnd_get_disp(opnd) != 0 && opnd_get_disp(opnd) != 4)
        WARN("WARNING: disp in [eax, disp] is not 0 or 4\n");
    load = instr;
#   ifdef DEBUG
    instr = instr_get_prev_app_instr(instr); /* go to prev before we kill load */
#   endif

    /* We might start a bb right here due to relocation, so we pattern match
     * up till here.
     *
     * To zero the return address, we need the original stack pointer value,
     * which will be clobbered by the app instruction "mov eax,[eax]".
     * We have no dead registers (not even edx, as some calling conventions
     * have it live: i#1405).  We could use some clever rewrites of the
     * original code to use a push or pop through memory (see i#1405c#3) to
     * perform the memory-to-memory copy the app is doing here, but
     * those result in us reporting unaddrs due to accessing beyond TOS.
     * Instead, we note that we don't need to zero: we just need a non-retaddr
     * in the slot.  Thus, we replace the load with xchg, which will place
     * a stack address in the slot, which does not look like a retaddr.
     * The xchg locks the bus, but that's compared to 2 extra stores (spill
     * reg plus zero slot) and 1 extra load (restore reg).  Plus, it's much
     * simpler.
     *
     *   A: mov     eax,dword ptr [eax]
     *   B: mov     dword ptr [esp],eax  (OR push eax)
     *   C: ret
     * =>
     *   A: xchg    eax,dword ptr [eax]
     *   B: mov     dword ptr [esp],eax  (OR push eax)
     *   C: ret
     *
     * If we decide to go to a register-spilling solution, we should move this
     * to the insert phase (and integrate properly with register stealing).
     */

    /* This is pattern-matched in instr_shared_slowpath_decode_pc().
     * XXX: this may confuse a client/user when a fault happens there,
     * as its translation is the load instruction "mov eax, [eax+X]".
     */
    PREXL8(ilist, load,
           INSTR_XL8(INSTR_CREATE_xchg(drcontext, opnd, opnd_create_reg(DR_REG_XAX)),
                     instr_get_app_pc(load)));
    instrlist_remove(ilist, load);
    instr_destroy(drcontext, load);

    LOG(2, "found _chkstk at "PFX"\n", dr_fragment_app_pc(tag));

#   ifdef DEBUG
    /* debug-only extra pattern verification */
    /* skip newly inserted "lea edx, [eax]" */
    ASSERT(instr != NULL, "instrumented code is gone");
    if (instr == NULL)
        return;
    if (instr_get_opcode(instr) == OP_xchg) {
        /* xchg eax,esp */
        if (!(instr_writes_to_exact_reg(instr, DR_REG_XSP, DR_QUERY_DEFAULT) &&
              instr_writes_to_exact_reg(instr, DR_REG_XAX, DR_QUERY_DEFAULT))) {
            WARN("Wrong xchg instr\n");
        }
        return;
    } else {
        /* find any instr writing to stack pointer before reading from it */
        for (instr  = instr_get_prev_app_instr(instr);
             instr != NULL;
             instr  = instr_get_prev_app_instr(instr)) {
            ASSERT(!instr_reads_from_reg(instr, DR_REG_XSP, DR_QUERY_DEFAULT),
                   "see wrong pattern");
            if (instr_writes_to_exact_reg(instr, DR_REG_XSP, DR_QUERY_DEFAULT))
                return;
        }
    }
#   endif /* DEBUG */
}
#  endif /* !X64 */
# endif /* WINDOWS */

static void
insert_zero_retaddr(void *drcontext, instrlist_t *bb, instr_t *inst, bb_info_t *bi)
{
    if (instr_is_return(inst)) {
        dr_clobber_retaddr_after_read(drcontext, bb, inst, 0);
        LOG(2, "zero retaddr for normal ret\n");
# ifdef WINDOWS
    } else if (instr_get_opcode(inst) == OP_pop) {
        /* SEH_epilog */
        /* Assuming it is forward instrumentation, i.e., there is no instruction
         * inserted between the pop and the label yet.
         */
        instr_t *label = instr_get_next(inst);
        if (label != NULL && instr_is_label(label) &&
            instr_get_note(label) == (void *)(note_base+NOTE_SEH_EPILOG_RETADDR)) {
            PRE(bb, label,
                INSTR_CREATE_mov_st(drcontext,
                                    OPND_CREATE_MEMPTR(REG_XSP, -XSP_SZ),
                                    OPND_CREATE_INT32(0)));
            LOG(2, "zero retaddr in SEH_epilog\n");
        }
# endif /* WINDOWS */
# ifdef ARM
    } else if (instr_get_opcode(inst) == OP_ldr &&
               opnd_get_base(instr_get_src(inst, 0)) == DR_REG_SP &&
               opnd_get_reg(instr_get_dst(inst, 0)) == DR_REG_LR) {
        /* We handle this idiom here which thwarts the other retaddr clobbering code
         * as the pop is prior to the indirect branch (i#1856):
         *
         *      f85d eb04  ldr    (%sp)[4byte] $0x00000004 %sp -> %lr %sp
         *      b003       add    %sp $0x0000000c -> %sp
         *      4770       bx     %lr
         */
        bool writeback = instr_num_srcs(inst) > 1;
        if (writeback && opnd_is_immed_int(instr_get_src(inst, 1))) {
            opnd_t memop = instr_get_src(inst, 0);
            opnd_set_disp(&memop, -opnd_get_immed_int(instr_get_src(inst, 1)));
            /* See above: we just write our stolen reg value */
            /* XXX: is this against drmgr rules? */
            POST(bb, inst, XINST_CREATE_store
                 (drcontext, memop, opnd_create_reg(dr_get_stolen_reg())));
        }
#endif
    }
}

/* i#1412: raise an error on executing invalid memory.  We check every instr to
 * handle page boundaries, at the risk of raising errors on instrs that are
 * never reached due to prior faults and other corner cases.
 *
 * The pc param should equal the result of instr_get_app_pc(inst).
 */
static void
check_program_counter(void *drcontext, app_pc pc, instr_t *inst)
{
    umbra_shadow_memory_info_t info;
    if (!options.check_pc || !options.shadowing)
        return;
    umbra_shadow_memory_info_init(&info);
    if (shadow_get_byte(&info, pc) == SHADOW_UNADDRESSABLE &&
        !is_in_realloc_gencode(pc) &&
        !in_replace_routine(pc)
        /* On Unix replace_* routines call into PIC routines elsewhere in the library.
         * Plus, we execute code from replace_native_ret as the app.
         */
        IF_UNIX(&& !is_in_client_or_DR_lib(pc))) {
        size_t sz = instr_length(drcontext, inst);
        app_loc_t loc;
        dr_mcontext_t mc;
        pc_to_loc(&loc, pc);
        mc.size = sizeof(mc);
        mc.flags = DR_MC_INTEGER | DR_MC_CONTROL;
        dr_get_mcontext(drcontext, &mc);
        report_unaddressable_access(&loc, pc, sz, DR_MEMPROT_EXEC, pc, pc + sz, &mc);
        /* XXX: unlike data accesses, legitimate execution from memory we consider
         * unaddressable would likely involve many instrs in a row and could result
         * in many error reports.  Avoiding that is complex, however, as marking
         * unaddr memory (likely via shadow_set_non_matching_range() to undef if
         * !def) as valid for the whole page or the whole region has downsides, and
         * we certainly don't want to do that for redzones on the heap or beyond TOS.
         * We do nothing today: users can always turn off -check_pc, and it seems very
         * unlikely for a legitimate case to occur in an app.
         */
    }
}

#ifdef X86
/* PR 580123: add fastpath for rep string instrs by converting to normal loop */
static void
convert_repstr_to_loop(void *drcontext, instrlist_t *bb, bb_info_t *bi,
                       bool translating)
{
    bool expanded;
    instr_t *string;
    ASSERT(options.repstr_to_loop, "shouldn't be called");
    /* The bulk of the code here is now in the drutil library */
    if (!drutil_expand_rep_string_ex(drcontext, bb, &expanded, &string))
        ASSERT(false, "drutil failed");
    if (expanded) {
        stringop_entry_t *entry;
        app_pc xl8 = instr_get_app_pc(string);
        IF_DEBUG(bool ok;)
        LOG(3, "converting rep string into regular loop\n");

        /* we handle the jecxz skipping lazy spill in the insert routine */

        /* We could point instr_can_use_shared_slowpath() at the final byte of the
         * instr (i.e., past the rep prefix) and have shared_slowpath fix up the pc
         * if it reports an error, and perhaps assume the string instr is immediately
         * after the return from slowpath (should be true since shouldn't pick edi or
         * esi as scratch regs, and none of the string instrs read aflags) so it can
         * look for data16 prefix.  But it's simpler to handle data16 prefix by
         * pointing at the start of the instr and having shared_slowpath assume there
         * are no repstrs doing loops so no loop emulation is needed.  This means the
         * slowpath will consider xcx an operand here in addition to at the loop
         * instr below but that shouldn't be a problem: if xcx is uninit it will get
         * reported once and w/ the right pc.  Xref i#353.
         */
        bi->fake_xl8_override_instr = string;
        bi->fake_xl8_override_pc = xl8;

        /* We need to tell instr_can_use_shared_slowpath() what app pc to use
         * while pointing it at an OP_loop instr.
         * For -fastpath, we should go to slowpath only if ecx is uninit, but
         * even then we can't afford to treat as a string op: will read wrong
         * mem addr b/c the just-executed string op adjusted edi/esi (i#391).
         * Solution is to allocate some memory and create a fake OP_loop there.
         * We use a hashtable to map from that to the app_pc.
         * We free by relying on the stringop being the first instr and thus
         * the tag (=> no trace support).
         */
        if (translating) {
            dr_mutex_lock(stringop_lock);
            entry = (stringop_entry_t *) hashtable_lookup(&stringop_app2us_table, xl8);
            ASSERT(entry != NULL, "stringop entry should exit on translation");
            dr_mutex_unlock(stringop_lock);
        } else {
            entry = (stringop_entry_t *) global_alloc(sizeof(*entry), HEAPSTAT_PERBB);
            entry->loop_instr[0] = LOOP_INSTR_OPCODE;
            entry->loop_instr[1] = 0;
            entry->ignore_next_delete = 0;
            dr_mutex_lock(stringop_lock);
            stringop_app2us_add_entry(xl8, entry);
            IF_DEBUG(ok = )
                hashtable_add(&stringop_us2app_table, (void *)entry, xl8);
            LOG(2, "adding stringop entry "PFX" for xl8 "PFX"\n",
                entry, xl8);
            /* only freed for heap reuse on hashtable removal */
            ASSERT(ok, "not possible to have existing from-heap entry");
            dr_mutex_unlock(stringop_lock);
        }

        /* we have the jecxz, mov $1, 2 jmps, and this loop all treated as OP_loop by
         * slowpath.  not a problem: ok to treat all as reading xcx.
         */
        bi->fake_xl8 = (app_pc) entry;

        bi->is_repstr_to_loop = true;
    }
}
#endif

/* Conversions to app code itself that should happen before instrumentation */
static dr_emit_flags_t
instru_event_bb_app2app(void *drcontext, void *tag, instrlist_t *bb,
                        bool for_trace, bool translating, OUT void **user_data)
{
    bb_info_t *bi;

    if (go_native)
        return DR_EMIT_GO_NATIVE;

#ifdef STATISTICS
    if (!translating && !for_trace)
        STATS_INC(num_bbs);
#endif

#ifdef TOOL_DR_MEMORY
    /* No way to get app xsp at init or thread init (i#117) so we do it here */
    if (first_bb) {
        if (options.native_until_thread == 0)
            set_initial_layout();
        first_bb = false;
    }
#endif

    /* we pass bi among all 4 phases */
    bi = thread_alloc(drcontext, sizeof(*bi), HEAPSTAT_PERBB);
    memset(bi, 0, sizeof(*bi));
    *user_data = (void *) bi;

    if (options.check_uninitialized &&
        options.check_uninit_blacklist[0] != '\0') {
        /* We assume no elision across modules here, so we can just pass the tag */
        bi->mark_defined = module_is_on_check_uninit_blacklist(dr_fragment_app_pc(tag));
        DOLOG(3, {
            if (bi->mark_defined)
                LOG(3, "module is on uninit blacklist: always defined\n");
        });
    }

#ifdef DEBUG
    /* To diagnose fastpath vs slowpath issues on a whole-bb level,
     * set bi->force_slowpath here (xref i#1458).
     */
#endif

    LOG(SYSCALL_VERBOSE, "in event_basic_block(tag="PFX")%s%s\n", tag,
        for_trace ? " for trace" : "", translating ? " translating" : "");
    DOLOG(3, instrlist_disassemble(drcontext, tag, bb, LOGFILE_GET(drcontext)););

#ifdef X86
    if (options.repstr_to_loop && INSTRUMENT_MEMREFS())
        convert_repstr_to_loop(drcontext, bb, bi, translating);
#endif

#if defined(WINDOWS) && !defined(X64)
    /* i#1374: we need insert non-meta instr for handling zero_retaddr in _chkstk */
    if (options.zero_retaddr)
        bb_handle_chkstk(drcontext, tag, bb);
#endif /* WINDOWS && !X64 */

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
instru_event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                         bool for_trace, bool translating, void *user_data)
{
    bb_info_t *bi = (bb_info_t *) user_data;

    if (go_native)
        return DR_EMIT_GO_NATIVE;

    LOG(4, "ilist before analysis:\n");
    DOLOG(4, instrlist_disassemble(drcontext, tag, bb, LOGFILE_GET(drcontext)););

    memlayout_handle_new_block(drcontext, tag);

#ifdef USE_DRSYMS
    /* symbol of each bb is very useful for debugging */
    DOLOG(3, {
        char buf[128];
        size_t sofar = 0;
        ssize_t len;
        if (!translating) {
            BUFPRINT(buf, BUFFER_SIZE_ELEMENTS(buf), sofar, len,
                     "new basic block @"PFX" ==", tag);
            print_symbol(tag, buf, BUFFER_SIZE_ELEMENTS(buf), &sofar,
                         true, PRINT_SYMBOL_OFFSETS);
            LOG(1, "%s\n", buf);
        }
    });
#endif
#ifdef TOOL_DR_MEMORY
    DOLOG(4, {
        if (options.shadowing) {
            LOG(4, "shadow register values:\n");
            print_shadow_registers();
        }
    });
#endif

#ifdef TOOL_DR_MEMORY
    if (INSTRUMENT_MEMREFS())
        fastpath_top_of_bb(drcontext, tag, bb, bi);
#endif

    /* Rather than having DR store translations, it takes less space for us to
     * use the bb table we already have
     */
    if (INSTRUMENT_MEMREFS()) {
        if (translating) {
            bb_saved_info_t *save;
            hashtable_lock(&bb_table);
            save = (bb_saved_info_t *) hashtable_lookup(&bb_table, tag);
            ASSERT(save != NULL, "missing bb info");
            if (save->check_ignore_unaddr)
                bi->check_ignore_unaddr = true;
            /* setting this pattern field here is sort of abstraction violation,
             * but more efficient.
             */
            bi->pattern_4byte_check_only = save->pattern_4byte_check_only;
            IF_DEBUG(bi->pattern_4byte_check_field_set = true);
            bi->share_xl8_max_diff = save->share_xl8_max_diff;
            hashtable_unlock(&bb_table);
        } else {
            /* We want to ignore unaddr refs by heap routines (when touching headers,
             * etc.).  We want to stay on the fastpath so we put checks there.
             * We decide up front since in_heap_routine changes dynamically
             * and if we recreate partway into the first bb we'll get it wrong:
             * though now that we're checking the first bb from alloc_instrument
             * it doesn't matter.
             */
            bi->check_ignore_unaddr = (options.check_ignore_unaddr &&
                                       alloc_in_heap_routine(drcontext));
            DOLOG(2, {
                if (bi->check_ignore_unaddr)
                    LOG(2, "inside heap routine: adding nop-if-mem-unaddr checks\n");
            });
            /* i#826: share_xl8_max_diff changes over time, so save it. */
            bi->share_xl8_max_diff = options.share_xl8_max_diff;
#ifdef TOOL_DR_MEMORY
            if (options.check_memset_unaddr &&
                in_replace_memset(dr_fragment_app_pc(tag))) {
                /* since memset is later called by heap routines, add in-heap checks
                 * now (i#234).  we add them to other mem and string routines as well
                 * rather than try
                 */
                bi->check_ignore_unaddr = true;
                LOG(2, "inside memset routine @"PFX": adding nop-if-mem-unaddr checks\n",
                    tag);
            }
#endif
        }
    }

    bi->first_instr = true;
#ifdef WINDOWS
    if (options.zero_retaddr)
        bb_check_SEH_epilog(drcontext, tag, bb);
#endif

    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
instru_event_bb_insert(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst,
                       bool for_trace, bool translating, void *user_data)
{
    bb_info_t *bi = (bb_info_t *) user_data;
    uint i;
    app_pc pc = instr_get_app_pc(inst);
    uint opc;
    bool has_shadowed_reg, has_mem, has_noignorable_mem;
    bool used_fastpath = false;
    fastpath_info_t mi;

    /* i#2402: Temporarily disable auto predication globally due to poor
     * interaction with internal control flow we emit.
     */
    drmgr_disable_auto_predication(drcontext, bb);

    if (go_native)
        return DR_EMIT_GO_NATIVE;

    if (instr_is_meta(inst))
        goto instru_event_bb_insert_done;

    if (!translating && !for_trace && options.check_pc)
        check_program_counter(drcontext, pc, inst);

    memset(&mi, 0, sizeof(mi));

    /* We can't change bi->check_ignore_unaddr in the middle b/c of recreation
     * so only set if entering/exiting on first
     */
    if (bi->first_instr && INSTRUMENT_MEMREFS() && options.check_ignore_unaddr) {
        if (alloc_entering_alloc_routine(pc)) {
            bi->check_ignore_unaddr = true;
            LOG(2, "entering heap routine: adding nop-if-mem-unaddr checks\n");
        } else if (alloc_exiting_alloc_routine(pc)) {
            /* we wait until post-call so pt->in_heap_routine >0 in post-call
             * bb event, so avoid adding checks there
             */
            bi->check_ignore_unaddr = false;
            LOG(2, "exiting heap routine: NOT adding nop-if-mem-unaddr checks\n");
        }
    }

    if (bi->first_instr && bi->is_repstr_to_loop) {
        /* if xcx is 0 we'll skip ahead and will restore the whole-bb regs
         * at the bottom of the bb so make sure we save first.
         * this is a case of internal control flow messing up code that
         * was taking advantage of the simplicity of linear block code!
         */
        if (whole_bb_spills_enabled() &&
            !(options.pattern != 0 && options.pattern_opt_repstr)) {
            if (options.pattern != 0) { /* pattern uses drreg */
                IF_DEBUG(drreg_status_t res =)
                    drreg_reserve_aflags(drcontext, bb, inst);
                ASSERT(res == DRREG_SUCCESS, "reserve of aflags should work");
                IF_DEBUG(res =)
                    drreg_unreserve_aflags(drcontext, bb, inst);
                ASSERT(res == DRREG_SUCCESS, "reserve of aflags should work");
            } else {
                mark_scratch_reg_used(drcontext, bb, bi, &bi->reg1);
                mark_scratch_reg_used(drcontext, bb, bi, &bi->reg2);
                mark_eflags_used(drcontext, bb, bi);
                /* eflag saving may have clobbered xcx, which we need for jecxz, but
                 * jecxz is an app instr now so we should naturally restore it
                 */
            }
        }
    }

    if (INSTRUMENT_MEMREFS()) {
        /* We want to spill AFTER any clean call in case it changes mcontext */
        /* XXX: examine this: how make it more in spirit of drmgr? */
        bi->spill_after = instr_get_prev(inst);

        /* update liveness of whole-bb spilled regs */
        fastpath_pre_instrument(drcontext, bb, inst, bi);
    }

    opc = instr_get_opcode(inst);
    if (instr_is_syscall(inst)) {
        /* new syscall events mean we no longer have to add a clean call
         */
        /* we treat interrupts and syscalls, including the call*
         * for a wow64 syscall, as though they do not write to the
         * stack or esp (for call*, since we never see the
         * corresponding ret instruction), including for sysenter
         * now that we have DRi#537.
         */
        goto instru_event_bb_insert_done;
    }
#ifdef WINDOWS
    ASSERT(!instr_is_wow64_syscall(inst), "syscall identification error");
#endif
    if (!INSTRUMENT_MEMREFS() && (!options.leaks_only || !options.count_leaks)) {
        if (options.zero_retaddr)
            insert_zero_retaddr(drcontext, bb, inst, bi);
        goto instru_event_bb_insert_done;
    }
    if (instr_is_interrupt(inst))
        goto instru_event_bb_insert_done;
    if (instr_is_nop(inst))
        goto instru_event_bb_insert_done;
    if (options.pattern != 0 && instr_is_prefetch(inst))
        goto instru_event_bb_insert_done;

    /* if there are no shadowed reg or mem operands, we can ignore it */
    has_shadowed_reg = false;
    has_mem = false;
    has_noignorable_mem = false;
    for (i = 0; i < instr_num_dsts(inst); i++) {
        opnd_t opnd = instr_get_dst(inst, i);
        if (opnd_is_memory_reference(opnd) IF_X86(&& instr_get_opcode(inst) != OP_lea))
            has_mem = true;
#ifdef TOOL_DR_MEMORY
        if (has_mem && opnd_uses_nonignorable_memory(opnd))
            has_noignorable_mem = true;
#endif
        if (options.shadowing && opnd_is_reg(opnd) &&
            reg_is_shadowed(opc, opnd_get_reg(opnd))) {
            has_shadowed_reg = true;
            if (reg_is_gpr(opnd_get_reg(opnd))) {
                /* written to => no longer known to be addressable,
                 * unless modified by const amt: we look for push/pop
                 */
                if (!(opc_is_push(opc) || (opc_is_pop(opc) && i > 0))) {
                    bi->addressable[reg_to_pointer_sized(opnd_get_reg(opnd)) -
                                    DR_REG_START_GPR] = false;
                }
            }
        }
    }
    if (!has_shadowed_reg || !has_mem) {
        for (i = 0; i < instr_num_srcs(inst); i++) {
            opnd_t opnd = instr_get_src(inst, i);
            if (opnd_is_memory_reference(opnd)
                IF_X86(&& instr_get_opcode(inst) != OP_lea))
                has_mem = true;
#ifdef TOOL_DR_MEMORY
            if (has_mem && opnd_uses_nonignorable_memory(opnd))
                has_noignorable_mem = true;
#endif
            if (options.shadowing && opnd_is_reg(opnd) &&
                reg_is_shadowed(opc, opnd_get_reg(opnd)))
                has_shadowed_reg = true;
        }
    }
    if (!has_shadowed_reg && !has_mem &&
        !TESTANY(EFLAGS_READ_ARITH|EFLAGS_WRITE_ARITH,
                 instr_get_eflags(inst, DR_QUERY_INCLUDE_ALL)))
        goto instru_event_bb_insert_done;

    /* for cmp/test+jcc -check_uninit_cmps don't need to instrument jcc */
    if ((options.pattern != 0 ||
         (options.shadowing && bi->eflags_defined)) &&
        instr_is_jcc(inst))
        goto instru_event_bb_insert_done;

    if (options.pattern != 0) {
        if (!(bi->is_repstr_to_loop && options.pattern_opt_repstr)) {
            /* aggressive optimization of repstr for pattern mode will
             * be handled separately in pattern_instrument_repstr
             */
            pattern_instrument_check(drcontext, bb, inst, bi, translating);
        }
    } else if (options.shadowing &&
               (options.check_uninitialized || has_noignorable_mem)) {
        if (instr_ok_for_instrument_fastpath(inst, &mi, bi)) {
            instrument_fastpath(drcontext, bb, inst, &mi, bi->check_ignore_unaddr);
            used_fastpath = true;
            bi->added_instru = true;
        } else {
            LOG(3, "fastpath unavailable "PFX": ", pc);
            DOLOG(3, { instr_disassemble(drcontext, inst, LOGFILE_GET(drcontext)); });
            LOG(3, "\n");
            bi->shared_memop = opnd_create_null();
            /* Restore whole-bb spilled regs (PR 489221)
             * FIXME: optimize via liveness analysis
             */
            mi.reg1 = bi->reg1;
            mi.reg2 = bi->reg2;
            memset(&mi.reg3, 0, sizeof(mi.reg3));
            instrument_slowpath(drcontext, bb, inst,
                                whole_bb_spills_enabled() ? &mi : NULL);
            /* for whole-bb slowpath does interact w/ global regs */
            bi->added_instru = whole_bb_spills_enabled();
        }
    }
    /* do esp adjust last, for ret immed; leave wants it the
     * other way but we compensate in adjust_memop() */
    /* -leaks_only co-opts esp-adjust code to zero out newly allocated stack
     * space to avoid stale pointers from prior frames from misleading our
     * leak scan (PR 520916).  yes, I realize it may not be perfectly
     * transparent.
     */
    if ((options.leaks_only || options.shadowing) &&
        instr_writes_esp(inst)) {
        bool shadow_xsp = options.shadowing &&
            (options.check_uninitialized || options.check_stack_bounds);
        bool zero_stack = ZERO_STACK();
        if (shadow_xsp || zero_stack) {
            /* any new spill must be after the fastpath instru */
            bi->spill_after = instr_get_prev(inst);
            if (shadow_xsp) {
                sp_adjust_action_t sp_action = SP_ADJUST_ACTION_SHADOW;
                if (should_mark_stack_frames_defined(pc)) {
                    sp_action = SP_ADJUST_ACTION_DEFINED;
                }
                if (instrument_esp_adjust(drcontext, bb, inst, bi, sp_action)) {
                    /* instru clobbered reg1 so no sharing across it */
                    bi->shared_memop = opnd_create_null();
                }
            }
            if (zero_stack) {
                /* w/o definedness info we need to zero as well to find leaks */
                instrument_esp_adjust(drcontext, bb, inst, bi, SP_ADJUST_ACTION_ZERO);
            }
        }
        bi->added_instru = true;
    }
    if (options.zero_retaddr && !ZERO_STACK() && !options.check_uninitialized)
        insert_zero_retaddr(drcontext, bb, inst, bi);

    /* None of the "goto instru_event_bb_insert_dones" above need to be processed here */
    if (INSTRUMENT_MEMREFS())
        fastpath_pre_app_instr(drcontext, bb, inst, bi, &mi);

 instru_event_bb_insert_done:
    if (bi->first_instr && instr_is_app(inst))
        bi->first_instr = false;
    if (!used_fastpath && options.shadowing) {
        /* i#1870: sanity check in case we bail out of instrumenting the next instr
         * when we're sharing.
         */
        bi->shared_memop = opnd_create_null();
    }
    /* We store whether bi->check_ignore_unaddr in our own data struct to avoid
     * DR having to store translations, so we can recreate deterministically
     * => DR_EMIT_DEFAULT
     */
    if (persistence_supported())
        return DR_EMIT_DEFAULT | DR_EMIT_PERSISTABLE;
    else
        return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
instru_event_bb_instru2instru(void *drcontext, void *tag, instrlist_t *bb,
                              bool for_trace, bool translating, void *user_data)
{
    bb_info_t *bi = (bb_info_t *) user_data;

    if (go_native)
        return DR_EMIT_GO_NATIVE;

#ifdef TOOL_DR_MEMORY
# ifdef X86
    if (options.pattern != 0 && options.pattern_opt_repstr &&
        bi->is_repstr_to_loop)
        pattern_instrument_repstr(drcontext, bb, bi, translating);
# endif
#endif

    if (INSTRUMENT_MEMREFS()) {
        fastpath_bottom_of_bb(drcontext, tag, bb, bi, bi->added_instru, translating,
                              bi->check_ignore_unaddr);
    }

    LOG(4, "final ilist:\n");
    DOLOG(4, instrlist_disassemble(drcontext, tag, bb, LOGFILE_GET(drcontext)););

    thread_free(drcontext, bi, sizeof(*bi), HEAPSTAT_PERBB);
    return DR_EMIT_DEFAULT;
}
#endif /* TOOL_DR_MEMORY */

/***************************************************************************
 * LOCATION SHARED CODE
 */

app_pc
loc_to_pc(app_loc_t *loc)
{
    ASSERT(loc != NULL && loc->type == APP_LOC_PC, "invalid param");
    ASSERT(loc->u.addr.valid, "-single_arg_slowpath was removed so should be valid");
    return loc->u.addr.pc;
}

app_pc
loc_to_print(app_loc_t *loc)
{
    ASSERT(loc != NULL, "invalid param");
    if (loc->type == APP_LOC_PC) {
        /* perf hit to translate so only at high loglevel */
        DOLOG(3, { return loc_to_pc(loc); });
        return loc->u.addr.valid ? loc->u.addr.pc : NULL;
    } else {
        ASSERT(loc->type == APP_LOC_SYSCALL, "unknown type");
        /* we ignore secondary sysnum (used only for logging) */
        return (app_pc)(ptr_uint_t) loc->u.syscall.sysnum.number;
    }
}
