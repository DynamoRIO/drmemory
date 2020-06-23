/* **********************************************************
 * Copyright (c) 2020 Google, Inc.  All rights reserved.
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
#include "drx.h"
#include "drmemory.h"
#include "utils.h"
#include "memlayout.h"
#include "alloc.h"
#include "heap.h"
#include "redblack.h"
#ifdef TOOL_DR_MEMORY
# include "shadow.h"
#endif

static app_pc app_main_addr;
static bool reached_main; /* Assumed atomic enough to write to it. */
byte *xsp_at_main;

/* Bump this whenever the format changes. */
#define MEMLAYOUT_FILE_VERSION 2

/* We claim the 5th malloc client flag */
enum {
    MALLOC_BEFORE_MAIN  = MALLOC_CLIENT_5,
};

typedef struct _layout_data_t {
    file_t outf;
    /* Tree for lookup and iteration of the heap. */
    rb_tree_t *heap_tree;
    /* Tree for lookup and iteration of the valid stack regions. */
    rb_tree_t *stack_tree;
    /* Used to distinguish in memory_layout_rb_iter. */
    bool walking_heap;
    /* Used to prevent a trailing JSON comma. */
    bool entry_count;
} layout_data_t;

void
memlayout_init(void)
{
    module_data_t *exe = dr_get_main_module();
    app_main_addr = lookup_symbol(exe, "main");
    if (app_main_addr == NULL) {
        NOTIFY_ERROR("ERROR: Failed to find \"main\" for limiting memory dump"NL);
        reached_main = true; /* just dump everything */
    }
    LOG(1, "main is at " PFX "\n", app_main_addr);
    dr_free_module_data(exe);
}

void
memlayout_handle_new_block(void *drcontext, void *tag)
{
    if (!reached_main && dr_fragment_app_pc(tag) == app_main_addr) {
        reached_main = true;
        LOG(1, "reached main\n");
        dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
        mc.size = sizeof(mc);
        mc.flags = DR_MC_CONTROL;
        dr_get_mcontext(drcontext, &mc);
        xsp_at_main = (byte *)mc.xsp;
    }
}

/* User must call from client_handle_malloc() and client_handle_realloc() */
void
memlayout_handle_alloc(void *drcontext, app_pc base, size_t size)
{
    if (!reached_main)
        malloc_set_client_flag(base, MALLOC_BEFORE_MAIN);
}

static bool
memory_layout_malloc_iter(malloc_info_t *info, void *iter_data)
{
    layout_data_t *data = (layout_data_t *)iter_data;
    if (info->pre_us || TEST(MALLOC_BEFORE_MAIN, info->client_flags))
        return true;
    rb_insert(data->heap_tree, info->base, info->request_size, NULL);
    return true;
}

static void
memory_layout_walk_chunk(layout_data_t *data, byte *base, size_t size)
{
    for (byte *addr = base; addr < base + size; ) {
        /* We assume it's safe to deref these selected regions, and
         * to de-ref off the end of any non-aligned object.
         */
        if (addr > base)
            ELOGF(0, data->outf, ",\n");
        ELOGF(0, data->outf, "        {\n");
        ELOGF(0, data->outf, "          \"address\": \"" PFX "\",\n", addr);
        size_t sz = base + size - addr;
        if (sz >= sizeof(void*)) {
            byte *value = *(byte**)addr;
            /* No trailing commas on final item! */
            ELOGF(0, data->outf, "          \"value\": \"" PFX "\"", value);
            addr += sizeof(void*);
            rb_node_t *target = rb_in_node(data->heap_tree, value);
            bool tgt_stack = false;
            if (target == NULL) {
                target = rb_in_node(data->stack_tree, value);
                tgt_stack = true;
            }
            if (target != NULL) {
                byte *tgt_base;
                rb_node_fields(target, &tgt_base, NULL, NULL);
                ELOGF(0, data->outf, ",\n          \"points-to-type\": \"%s\",\n",
                      tgt_stack ? "stack" : "heap");
                ELOGF(0, data->outf, "          \"points-to-base\": \"" PFX "\",\n",
                      tgt_base);
                ELOGF(0, data->outf, "          \"points-to-offset\": \"0x%zx\"",
                       value - tgt_base);
            }
            ELOGF(0, data->outf, "\n");
        } else if (sz >= sizeof(int)) {
            ELOGF(0, data->outf, "          \"value\": \"0x%08x\"\n", *(int*)addr);
            addr += sizeof(int);
        } else if (sz >= sizeof(short)) {
            ELOGF(0, data->outf, "          \"value\": \"0x%04x\"\n", (short)*(int*)addr);
            addr += sizeof(short);
        } else {
            ELOGF(0, data->outf, "          \"value\": \"0x%02x\"\n", (char)*(int*)addr);
            addr += sizeof(char);
        }
        ELOGF(0, data->outf, "        }");
    }
    ELOGF(0, data->outf, "\n");
}

static bool
memory_layout_rb_iter(rb_node_t *node, void *iter_data)
{
    layout_data_t *data = (layout_data_t *)iter_data;
    byte *base;
    size_t size;
    void *val;
    thread_id_t id;
    rb_node_fields(node, &base, &size, &val);
    id = (thread_id_t)(ptr_uint_t)val;
    if (data->entry_count++ > 0)
        ELOGF(0, data->outf, ",\n");
    if (data->walking_heap) {
        ELOGF(0, data->outf, "    {\n      \"address\": \"" PFX "\",\n", base);
        ELOGF(0, data->outf, "      \"size\": \"%d\",\n", size);
    } else {
        ELOGF(0, data->outf,
              "    {\n      \"thread_id\": \"" PFX "\",\n", id);
        ELOGF(0, data->outf, "      \"address\": \"" PFX "\",\n", base);
        ELOGF(0, data->outf, "      \"size\": \"%d\",\n", size);
    }
    ELOGF(0, data->outf, "      \"contents\": [\n");
    memory_layout_walk_chunk(data, base, size);
    ELOGF(0, data->outf, "      ]\n");
    ELOGF(0, data->outf, "    }");
    return true;
}

static void
memlayout_dump_function(layout_data_t *data, app_pc pc)
{
    char buf[MAX_SYMBOL_LEN];
    size_t sofar = 0;
    print_symbol(pc, buf, BUFFER_SIZE_ELEMENTS(buf), &sofar, false, 0);
    char *toprint = buf;
    if (*toprint == ' ')
        ++toprint;
    ELOGF(0, data->outf, "          \"function\": \"%s\"\n", toprint);
}

static bool
memlayout_dump_frame(app_pc pc, byte *fp, void *user_data)
{
    layout_data_t *data = (layout_data_t *)user_data;
    ELOGF(0, data->outf,
          "        },\n        {\n          \"program_counter\": \"" PFX "\",\n", pc);
    ELOGF(0, data->outf, "          \"frame_pointer\": \"" PFX "\",\n", fp);
    memlayout_dump_function(data, pc);
    return rb_in_node(data->stack_tree, fp) != NULL;
}

static void
memory_layout_record_stack_region(void *drcontext,
                                  layout_data_t *data, app_pc cur_thread_pc)
{
    dr_mcontext_t mc; /* do not init whole thing: memset is expensive */
    mc.size = sizeof(mc);
    mc.flags = DR_MC_CONTROL | DR_MC_INTEGER;
    dr_get_mcontext(drcontext, &mc);
    byte *stack_res_base;
    size_t stack_sz = allocation_size((byte *)mc.xsp, &stack_res_base);
    size_t record_sz = (size_t)(stack_res_base + stack_sz - mc.xsp);
    if (xsp_at_main > stack_res_base && xsp_at_main < stack_res_base + stack_sz)
        record_sz = xsp_at_main - (byte*)mc.xsp;
    else {
        /* TODO i#2266: Record the high-level thread-func xsp point and use here. */
    }
    if (dr_get_thread_id(dr_get_current_drcontext()) == dr_get_thread_id(drcontext))
        mc.pc = cur_thread_pc;
    rb_insert(data->stack_tree, (byte*)mc.xsp, record_sz,
              (void*)(ptr_uint_t)dr_get_thread_id(drcontext));

    /* XXX: It's easier to make a temp buffer than to change print_callstack to not
     * need either a buffer or pcs.
     */
    size_t bufsz = max_callstack_size();
    char *buf = (char *) global_alloc(bufsz, HEAPSTAT_CALLSTACK);
    size_t sofar = 0;
    ELOGF(0, data->outf, "    {\n      \"thread_id\": \"" PFX "\",\n",
          dr_get_thread_id(drcontext));
    ELOGF(0, data->outf, "      \"stack_frames\": [\n");
    ELOGF(0, data->outf,
          "        {\n          \"program_counter\": \"" PFX "\",\n", mc.pc);
    ELOGF(0, data->outf,
          "          \"frame_pointer\": \"" PFX "\",\n", MC_FP_REG(&mc));
    memlayout_dump_function(data, mc.pc);
    print_callstack(buf, bufsz, &sofar, &mc, false/*no fps*/, NULL, 0, false,
                    options.callstack_max_frames, memlayout_dump_frame, data);
    ELOGF(0, data->outf, "        }\n");
    ELOGF(0, data->outf, "      ]\n");
    ELOGF(0, data->outf, "    }\n");
    global_free(buf, bufsz, HEAPSTAT_CALLSTACK);
}

void
memlayout_dump_layout(app_pc pc)
{
    char fname[MAXIMUM_PATH];
    file_t outf = drx_open_unique_file(logsubdir,
                                       "memlayout", "json",
#ifndef WINDOWS
                                       DR_FILE_CLOSE_ON_FORK |
#endif
                                       DR_FILE_ALLOW_LARGE,
                                       fname, BUFFER_SIZE_ELEMENTS(fname));
    if (outf == INVALID_FILE) {
        NOTIFY_ERROR("Failed to open layout output file"NL);
        dr_abort();
    }
    NOTIFY("Memory layout written to: %s" NL, fname);
    LOG(1, "Memory layout written to: %s\n", fname);

    layout_data_t data;
    memset(&data, 0, sizeof(data));
    data.outf = outf;
    data.heap_tree = rb_tree_create(NULL);
    data.stack_tree = rb_tree_create(NULL);

    void **drcontexts = NULL;
    uint num_threads = 0;
    if (!dr_suspend_all_other_threads(&drcontexts, &num_threads, NULL)) {
        NOTIFY_ERROR("Failed to suspend threads for memory layout dump"NL);
        dr_abort();
    }

    malloc_iterate(memory_layout_malloc_iter, &data);

    ELOGF(0, data.outf, "{\n  \"version\": \"%d\",\n", MEMLAYOUT_FILE_VERSION);
    ELOGF(0, data.outf, "  \"threads\": [\n");
    for (uint i = 0; i < num_threads; i++) {
        memory_layout_record_stack_region(drcontexts[i], &data, NULL);
    }
    memory_layout_record_stack_region(dr_get_current_drcontext(), &data, pc);

    ELOGF(0, data.outf, "  ],\n  \"heap objects\": [\n");
    data.walking_heap = true;
    data.entry_count = 0;
    rb_iterate(data.heap_tree, memory_layout_rb_iter, &data);
    if (data.entry_count > 0)
        ELOGF(0, data.outf, "\n");
    ELOGF(0, data.outf, "  ],\n  \"thread stacks\": [\n");
    data.walking_heap = false;
    data.entry_count = 0;
    rb_iterate(data.stack_tree, memory_layout_rb_iter, &data);
    if (data.entry_count > 0)
        ELOGF(0, data.outf, "\n");
    ELOGF(0, data.outf, "  ]\n}\n");

    if (drcontexts != NULL) {
        IF_DEBUG(bool ok =)
            dr_resume_all_other_threads(drcontexts, num_threads);
        ASSERT(ok, "failed to resume after leak scan");
    }

    rb_tree_destroy(data.heap_tree);
    rb_tree_destroy(data.stack_tree);
    dr_close_file(outf);
}
