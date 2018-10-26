/* **********************************************************
 * Copyright (c) 2010-2015 Google, Inc.  All rights reserved.
 * Copyright (c) 2007-2010 VMware, Inc.  All rights reserved.
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

/* umbra_x86.c
 *
 * Umbra x86 architecture specific code.
 * In x86 architecture, we used a lookup table based approach.
 */

#include "dr_api.h"
#include "umbra.h"
#include "umbra_private.h"
#include "drmemory_framework.h"
#include "../framework/drmf.h"
#include "utils.h"
#include <string.h> /* for memchr */

#ifdef X64
# error x86 only
#endif

/***************************************************************************
 * Umbra x86 Shadow Memory Mapping Scheme Description:
 *
 * We implement a table lookup based shadow memory framework here:
 * - the address space is uniformly divided into 16-bit (64KB) units
 * - a shadow table with 64K entries stores the displacement
 *   (i.e., disp = addr_shdw - addr_app) from the base, which is to shrink
 *   the instrumentation size.
 * - a special default_block is to created for all application memory that
 *   does not have shadow memory allocated.
 * - optimization: for saving memory usage, we allow the user to create special
 *   read-only blocks for all-identical 64KB chunks.
 * - XXX: we do not support allocating a shadow memory across 64KB
 *   boundary to simplify the code.
 */

/***************************************************************************
 * SHADOW TABLE DATA STRUCTURES
 */
/* We divide the address space into 16-bit (64KB) chunk units */
#define APP_BLOCK_BITS 16
#define APP_BLOCK_SIZE (1 << APP_BLOCK_BITS)

#define SHADOW_TABLE_ENTRIES (1 << (32 - APP_BLOCK_BITS))
#define SHADOW_TABLE_SIZE    (sizeof(ptr_int_t)*SHADOW_TABLE_ENTRIES)
#define SHADOW_TABLE_OFFSET(addr)  ((ptr_uint_t)(addr) & (APP_BLOCK_SIZE-1))
#define SHADOW_TABLE_INDEX(addr)   ((ptr_uint_t)(addr) >> APP_BLOCK_BITS)
#define SHADOW_TABLE_APP_BASE(idx) ((ptr_uint_t)(idx)  << APP_BLOCK_BITS)

static ptr_int_t static_shadow_table[SHADOW_TABLE_ENTRIES];
static bool      static_shadow_table_unused = false;

/***************************************************************************
 * SHADOW TABLE ROUTINES
 */

/* get the offset in a block */
static inline ptr_uint_t
shadow_table_get_block_offset(umbra_map_t *map, app_pc app_addr)
{
    ptr_uint_t offset = SHADOW_TABLE_OFFSET(app_addr);
    return umbra_map_scale_app_to_shadow(map, offset);
}

static void
shadow_table_delete_block(umbra_map_t *map, byte *shadow_start)
{
    global_free(shadow_start - map->options.redzone_size,
                map->shadow_block_alloc_size, HEAPSTAT_SHADOW);
}

static byte *
shadow_table_init_redzone(umbra_map_t *map, byte *block)
{
    if (map->options.redzone_size != 0)
        memset(block, map->options.redzone_value, map->options.redzone_size);
    block += map->options.redzone_size;
    if (map->options.redzone_size != 0) {
        memset(block + map->shadow_block_size,
               map->options.redzone_value,
               map->options.redzone_size);
    }
    return block;
}

static byte *
shadow_table_create_block(umbra_map_t *map)
{
    byte *block;
    block = global_alloc(map->shadow_block_alloc_size, HEAPSTAT_SHADOW);
    block = shadow_table_init_redzone(map, block);
    LOG(UMBRA_VERBOSE, "created new shadow block "PFX"\n", block);
    return block;
}

/* Should only be called on destroying the umbra map, b/c we can't handle
 * deletion during execution.
 */
static void
shadow_table_delete_special_block(umbra_map_t *map,
                                  special_block_t *block)
{
    nonheap_free(block->start - map->options.redzone_size,
                 map->shadow_block_alloc_size,
                 HEAPSTAT_SHADOW);
    memset(block, 0, sizeof(*block));
}

static void
shadow_table_delete_default_block(umbra_map_t *map)
{
    /* we did not use default block for CREATE_ON_TOUCH */
    if (TEST(UMBRA_MAP_CREATE_SHADOW_ON_TOUCH, map->options.flags)) {
        ASSERT(map->default_block.start      == NULL &&
               map->default_block.value      == 0 &&
               map->default_block.value_size == 0,
               "default block must be 0");
        return;
    }
    shadow_table_delete_special_block(map, &map->default_block);
}

static void
shadow_table_create_special_block_helper(umbra_map_t     *map,
                                         ptr_uint_t       value,
                                         size_t           value_size,
                                         special_block_t *special_block)
{
    IF_DEBUG(bool ok;)
    byte *block;

    /* assuming nonheap_alloc will handle unaligned size */
    block = (byte *) nonheap_alloc(map->shadow_block_alloc_size,
                                   DR_MEMPROT_READ|DR_MEMPROT_WRITE,
                                   HEAPSTAT_SHADOW);
    ASSERT(block != NULL && ALIGNED(block, PAGE_SIZE),
           "fail to alloc special block");
    ASSERT(value_size == 1 && value <= UCHAR_MAX,
           "NYI: we only support byte-size value now");
    block = shadow_table_init_redzone(map, block);
    memset(block, value, map->shadow_block_size);

    /* we will never write to the special */
    IF_DEBUG(ok = )
        dr_memory_protect(block - map->options.redzone_size,
                          map->shadow_block_alloc_size, DR_MEMPROT_READ);
    ASSERT(ok, "-w failed: will have inconsistencies in shadow data");
    LOG(UMBRA_VERBOSE, "created new shadow special block "PFX"\n", block);
    special_block->start = block;
    special_block->value = value;
    special_block->value_size = value_size;
}

static void
shadow_table_create_default_block(umbra_map_t *map)
{
    shadow_table_create_special_block_helper(map,
                                             map->options.default_value,
                                             map->options.default_value_size,
                                             &map->default_block);
}

static byte *
shadow_table_lookup_special_block(umbra_map_t *map,
                                  ptr_uint_t   value,
                                  size_t       value_size)
{
    int i, num_blks;
    /* assuming we never update or delete a special block, so it is ok
     * to do the racy lookup
     */
    num_blks = map->num_special_blocks;
    for (i = 0; i < num_blks; i++) {
        if (map->special_blocks[i].value == value &&
            map->special_blocks[i].value_size == value_size) {
            return map->special_blocks[i].start;
        }
    }
    return NULL;
}

static byte *
shadow_table_create_special_block(umbra_map_t *map,
                                  ptr_uint_t   value,
                                  size_t       value_size)
{
    byte *block;
    int   num_blks;

    umbra_map_lock(map);
    num_blks = map->num_special_blocks;
    block    = shadow_table_lookup_special_block(map, value, value_size);
    if (block != NULL || num_blks >= MAX_NUM_SPECIAL_BLOCKS) {
        umbra_map_unlock(map);
        return block;
    }
    shadow_table_create_special_block_helper(map, value, value_size,
                                             &map->special_blocks[num_blks]);
    /* update the num_special_blocks */
    map->num_special_blocks = num_blks + 1;
    block = map->special_blocks[num_blks].start;
    umbra_map_unlock(map);
    return block;
}

static void
shadow_table_set_block(umbra_map_t *map, uint idx, byte *block)
{
    /* We store the displacement (shadow minus app) (PR 553724). */
    ptr_uint_t base = SHADOW_TABLE_APP_BASE(idx);
    base = umbra_map_scale_app_to_shadow(map, base);
    map->shadow_table[idx] = (ptr_uint_t)block - base;
    LOG(UMBRA_VERBOSE,
        "setting shadow table idx %d for block "PFX" to "PFX"\n",
        idx, block, map->shadow_table[idx]);
}

static inline byte *
shadow_table_get_block(umbra_map_t *map, uint idx)
{
    ptr_uint_t base = SHADOW_TABLE_APP_BASE(idx);
    base = umbra_map_scale_app_to_shadow(map, base);
    return (byte *)(map->shadow_table[idx] + base);
}

static inline byte *
shadow_table_app_to_shadow(umbra_map_t *map, app_pc app_addr)
{
    return (shadow_table_get_block(map, SHADOW_TABLE_INDEX(app_addr)) +
            shadow_table_get_block_offset(map, app_addr));
}

int
umbra_num_scratch_regs_for_translation_arch(void)
{
    return 1;
}

#if defined(X86)
/* code sequence:
 * %reg_index   = %reg_addr;
 * %reg_index >>= 16;
 * %reg_addr  >>= map->scale;
 * %reg_addr   += table[%reg_index];
 */
static void
shadow_table_insert_app_to_shadow_arch(void *drcontext, umbra_map_t *map,
                                       instrlist_t *ilist, instr_t *where,
                                       reg_id_t reg_addr, reg_id_t reg_idx)
{
    uint disp;

    /* %reg_index = %reg_addr */
    PRE(ilist, where, XINST_CREATE_move(drcontext,
                                        opnd_create_reg(reg_idx),
                                        opnd_create_reg(reg_addr)));
    /* %reg_index >>= 16 */
    PRE(ilist, where, INSTR_CREATE_shr(drcontext,
                                       opnd_create_reg(reg_idx),
                                       OPND_CREATE_INT8(APP_BLOCK_BITS)));
    /* We assume that the addr is aligned and won't keep the offset in byte. */
    if (UMBRA_MAP_SCALE_IS_DOWN(map->options.scale)) {
        /* %reg_addr >>= map->scale*/
        PRE(ilist, where, INSTR_CREATE_shr(drcontext,
                                           opnd_create_reg(reg_addr),
                                           OPND_CREATE_INT8(map->shift)));
    } else if (UMBRA_MAP_SCALE_IS_UP(map->options.scale)) {
        /* %reg_addr <<= map->scale*/
        PRE(ilist, where, INSTR_CREATE_shl(drcontext,
                                           opnd_create_reg(reg_addr),
                                           OPND_CREATE_INT8(map->shift)));
    }

    /* %reg_addr += table[%reg_index] */
    disp = (uint)(map->shadow_table);
    PRE(ilist, where, INSTR_CREATE_add(drcontext,
                                       opnd_create_reg(reg_addr),
                                       opnd_create_base_disp(REG_NULL,
                                                             reg_idx,
                                                             sizeof(ptr_int_t),
                                                             disp,
                                                             OPSZ_PTR)));
}
#elif defined(ARM)
/* code sequence:
 * %reg_idx   = table
 * %reg_idx  += (%reg_addr >> 14)
 * %reg_idx  &= 0xfffffffc
 * %reg_idx   = 0x0(%reg_idx)
 * %reg_addr  = %reg_idx + (%reg_addr >> map->scale)
 */
static void
shadow_table_insert_app_to_shadow_arch(void *drcontext, umbra_map_t *map,
                                       instrlist_t *ilist, instr_t *where,
                                       reg_id_t reg_addr, reg_id_t reg_idx)
{
    /* %reg_idx = table */
    instrlist_insert_mov_immed_ptrsz(drcontext, (uint)(map->shadow_table),
                                     opnd_create_reg(reg_idx), ilist, where,
                                     NULL, NULL);

    /* %reg_idx += (%reg_addr >> 14) */
    PRE(ilist, where, INSTR_CREATE_add_shimm(drcontext,
                                             opnd_create_reg(reg_idx),
                                             opnd_create_reg(reg_idx),
                                             opnd_create_reg(reg_addr),
                                             OPND_CREATE_INT(DR_SHIFT_LSR),
                                             OPND_CREATE_INT(14)));

    /* Can't specify a bitmask of 0xfffffffc, so instead we use its inverse, BIC.
     * %reg_idx &= 0xfffffffc
     */
    PRE(ilist, where, INSTR_CREATE_bic(drcontext,
                                       opnd_create_reg(reg_idx),
                                       opnd_create_reg(reg_idx),
                                       OPND_CREATE_INT8(0x03)));

    /* %reg_idx = 0x0(%reg_idx) */
    PRE(ilist, where, XINST_CREATE_load(drcontext,
                                        opnd_create_reg(reg_idx),
                                        OPND_CREATE_MEMPTR(reg_idx, 0)));

    /* %reg_addr = %reg_idx + (%reg_addr >> map->scale) */
    if (UMBRA_MAP_SCALE_IS_DOWN(map->options.scale)) {
        PRE(ilist, where, INSTR_CREATE_add_shimm(drcontext,
                                                 opnd_create_reg(reg_addr),
                                                 opnd_create_reg(reg_idx),
                                                 opnd_create_reg(reg_addr),
                                                 OPND_CREATE_INT(DR_SHIFT_LSR),
                                                 OPND_CREATE_INT(map->shift)));
    } else if (UMBRA_MAP_SCALE_IS_UP(map->options.scale)) {
        PRE(ilist, where, INSTR_CREATE_add_shimm(drcontext,
                                                 opnd_create_reg(reg_addr),
                                                 opnd_create_reg(reg_idx),
                                                 opnd_create_reg(reg_addr),
                                                 OPND_CREATE_INT(DR_SHIFT_LSL),
                                                 OPND_CREATE_INT(map->shift)));
    } else {
        PRE(ilist, where, XINST_CREATE_add(drcontext,
                                           opnd_create_reg(reg_addr),
                                           opnd_create_reg(reg_idx)));
    }
}
#else
# error NYI
#endif

static bool
shadow_table_is_in_default_block(umbra_map_t *map, byte *shadow_addr,
                                 bool *redzone OUT)
{
    if (shadow_addr >= map->default_block.start - map->options.redzone_size &&
        shadow_addr < (map->default_block.start + map->shadow_block_size +
                       map->options.redzone_size)) {
        if (redzone != NULL) {
            if (map->options.redzone_size != 0 &&
                (shadow_addr <  map->default_block.start ||
                 shadow_addr >= (map->default_block.start +
                                 map->shadow_block_size)))
                *redzone = true;
            else
                *redzone = false;
        }
        return true;
    }
    return false;
}

static bool
shadow_table_use_default_block(umbra_map_t *map, app_pc app_addr)
{
    return shadow_table_is_in_default_block
        (map, shadow_table_app_to_shadow(map, app_addr), NULL);
}

static bool
shadow_table_is_in_special_block(umbra_map_t *map, byte *shadow_addr,
                                 ptr_uint_t *value, size_t *value_size,
                                 bool *redzone OUT)
{
    uint i;
    for (i = 0; i < map->num_special_blocks; i++) {
        if (shadow_addr >=
            (map->special_blocks[i].start - map->options.redzone_size) &&
            shadow_addr <
            (map->special_blocks[i].start + map->shadow_block_size +
             map->options.redzone_size)) {
            if (value != NULL)
                *value = map->special_blocks[i].value;
            if (value_size != NULL)
                *value_size = map->special_blocks[i].value_size;
            if (redzone != NULL) {
                if (map->options.redzone_size != 0 &&
                    (shadow_addr <   map->special_blocks[i].start ||
                     shadow_addr >= (map->special_blocks[i].start +
                                     map->shadow_block_size))) {
                    /* XXX: we still use special block value instead of
                     * redzone value here.
                     */
                    *redzone = true;
                } else
                    *redzone = false;
            }
            return true;
        }
    }
    return false;
}

static bool
shadow_table_use_special_block(umbra_map_t *map, app_pc app_addr,
                               ptr_uint_t *value, size_t *value_size)
{
    return shadow_table_is_in_special_block
        (map, shadow_table_app_to_shadow(map, app_addr),
         value, value_size, NULL);
}

static bool
shadow_table_is_in_normal_block(umbra_map_t *map, byte *shadow_addr)
{
    return (!shadow_table_is_in_default_block(map, shadow_addr, NULL) &&
            !shadow_table_is_in_special_block(map, shadow_addr,
                                              NULL, NULL, NULL));
}

static void
shadow_table_replace_block(umbra_map_t *map, app_pc app_base)
{
    ptr_uint_t value;
    size_t value_size;
    byte *block;

    value = map->options.default_value;
    value_size = map->options.default_value_size;
    umbra_map_lock(map);
    if (shadow_table_use_default_block(map, app_base) ||
        shadow_table_use_special_block(map, app_base, &value, &value_size)) {
        ASSERT(value <= USHRT_MAX && value_size == 1,
               "value_size > 1 is not supported");
        block = shadow_table_create_block(map);
        memset(block, value, map->shadow_block_size);
        shadow_table_set_block(map, SHADOW_TABLE_INDEX(app_base), block);
    }
    umbra_map_unlock(map);
}

static void
shadow_table_init(umbra_map_t *map)
{
    uint i;
    LOG(UMBRA_VERBOSE, "shadow_table_init\n");
    if (static_shadow_table_unused) {
        map->shadow_table = nonheap_alloc(SHADOW_TABLE_SIZE,
                                          DR_MEMPROT_READ | DR_MEMPROT_WRITE,
                                          HEAPSTAT_SHADOW);
    } else {
        map->shadow_table = static_shadow_table;
    }
    /* sets the whole address space to default special block first */
    if (!TEST(UMBRA_MAP_CREATE_SHADOW_ON_TOUCH, map->options.flags)) {
        /* default block means the app memory does not have shadow memory */
        shadow_table_create_default_block(map);
        for (i = 0; i < SHADOW_TABLE_ENTRIES; i++)
            shadow_table_set_block(map, i, map->default_block.start);
    } else {
        byte *start =
            shadow_table_create_special_block(map, map->options.default_value,
                                              map->options.default_value_size);
        for (i = 0; i < SHADOW_TABLE_ENTRIES; i++)
            shadow_table_set_block(map, i, start);
        memset(&map->default_block, 0, sizeof(map->default_block));
    }
}

static void
shadow_table_exit(umbra_map_t *map)
{
    uint i;
    LOG(UMBRA_VERBOSE, "shadow_table_exit\n");
    /* free all the shadow memory */
    umbra_map_lock(map);
    for (i = 0; i < SHADOW_TABLE_ENTRIES; i++) {
        byte *shadow_addr = shadow_table_get_block(map, i);
        if (shadow_table_is_in_normal_block(map, shadow_addr)) {
            LOG(UMBRA_VERBOSE, "freeing shadow block idx=%d "PFX"\n",
                i, shadow_addr);
            shadow_table_delete_block(map, shadow_addr);
        }
    }
    /* free all special blocks */
    for (i = 0; i < map->num_special_blocks; i++) {
        if (map->special_blocks[i].start != NULL) {
            shadow_table_delete_special_block(map, &map->special_blocks[i]);
        }
    }
    shadow_table_delete_default_block(map);
    if (map->shadow_table != static_shadow_table)
        nonheap_free(map->shadow_table, SHADOW_TABLE_SIZE, HEAPSTAT_SHADOW);
    umbra_map_unlock(map);
}

/***************************************************************************
 * EXPORT UMBRA X86 SPECIFIC CODE
 */

drmf_status_t
umbra_arch_init()
{
    return DRMF_SUCCESS;
}

void
umbra_arch_exit()
{
}

drmf_status_t
umbra_map_arch_init(umbra_map_t *map, umbra_map_options_t *ops)
{
    if (ops->redzone_size != 0) {
        if (ops->redzone_value_size != 1 || ops->redzone_value > UCHAR_MAX) {
            ASSERT(false, "NYI: we only support byte-size value now");
            return DRMF_ERROR_NOT_IMPLEMENTED;
        }
        if (!ALIGNED(ops->redzone_size, 256)) {
            return DRMF_ERROR_INVALID_PARAMETER;
        }
    }

    map->app_block_size = APP_BLOCK_SIZE;
    map->shadow_block_size = umbra_map_scale_app_to_shadow(map, APP_BLOCK_SIZE);
    map->shadow_block_alloc_size =
        map->shadow_block_size + 2 * map->options.redzone_size;
    shadow_table_init(map);
    return DRMF_SUCCESS;
}

void
umbra_map_arch_exit(umbra_map_t *map)
{
    shadow_table_exit(map);
}

drmf_status_t
umbra_create_shadow_memory_arch(umbra_map_t *map,
                                uint   flags,
                                app_pc app_addr,
                                size_t app_size,
                                ptr_uint_t value,
                                size_t value_size)
{
    /* i#1260: end pointers are all closed (i.e., inclusive) to handle overflow */
    app_pc app_blk_base, app_blk_end, app_src_end;
    app_pc start, end;
    size_t size, iter_size;
    byte  *shadow_blk;
    drmf_status_t res;

    if (value_size != 1 || value >= UCHAR_MAX)
        return DRMF_ERROR_FEATURE_NOT_AVAILABLE;

    if (POINTER_OVERFLOW_ON_ADD(app_addr, app_size-1)) /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;

    umbra_map_lock(map);
    APP_RANGE_LOOP(app_addr, app_size, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        if (shadow_table_use_default_block(map, app_blk_base)) {
            /* no shadow memory created yet */
            if (TEST(flags, UMBRA_CREATE_SHADOW_SHARED_READONLY) &&
                ((app_blk_base >= app_addr && app_blk_end <= app_src_end) ||
                 (map->options.default_value == value &&
                  map->options.default_value_size == value_size))) {
                /* We can use a special block if either it is a whole block
                 * or the block value is the same as the default value.
                 */
                shadow_blk = shadow_table_create_special_block(map,
                                                               value,
                                                               value_size);
                if (shadow_blk != NULL) {
                    shadow_table_set_block(map,
                                           SHADOW_TABLE_INDEX(app_blk_base),
                                           shadow_blk);
                    continue;
                }
            }
            /* cannot use a special block, need create normal block */
            shadow_table_replace_block(map, app_blk_base);
        }
        res = umbra_shadow_set_range_arch(map,
                                          start,
                                          iter_size,
                                          &size,
                                          value,
                                          value_size);
        if (res != DRMF_SUCCESS) {
            /* We do not de-allocte the block as it is either fail to allocate
             * or fail to set new value. In either case, we do not have to do
             * anything since umbra_delete_shadow_memory simply sets value back.
             */
            umbra_map_unlock(map);
            return res;
        }
    });
    umbra_map_unlock(map);
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_delete_shadow_memory_arch(umbra_map_t *map,
                                app_pc       app_addr,
                                size_t       app_size)
{
    size_t shadow_size;
    /* XXX: we can optimize it by replace it with default block */
    return umbra_shadow_set_range_arch(map, app_addr, app_size,
                                       &shadow_size,
                                       map->options.default_value,
                                       map->options.default_value_size);
}

drmf_status_t
umbra_read_shadow_memory_arch(IN    umbra_map_t *map,
                              IN    app_pc  app_addr,
                              IN    size_t  app_size,
                              INOUT size_t *shadow_size,
                              IN    byte   *buffer)
{
    /* i#1260: end pointers are all closed (i.e., inclusive) to handle overflow */
    app_pc app_blk_base, app_blk_end, app_src_end;
    app_pc start, end;
    size_t size, iter_size;
    byte  *shadow_start;
    size_t shdw_size;

    if (*shadow_size < umbra_map_scale_app_to_shadow(map, app_size)) {
        *shadow_size = 0;
        return DRMF_ERROR_INVALID_SIZE;
    }
    if (POINTER_OVERFLOW_ON_ADD(app_addr, app_size-1)) /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;
    shdw_size = 0;
    APP_RANGE_LOOP(app_addr, app_size, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        shadow_start  = shadow_table_app_to_shadow(map, start);
        if (shadow_table_is_in_default_block(map, shadow_start, NULL))
            return DRMF_ERROR_INVALID_PARAMETER;
        size = umbra_map_scale_app_to_shadow(map, iter_size);
        memcpy(buffer, shadow_start, size);
        shdw_size += size;
        buffer    += size;
    });
    *shadow_size = shdw_size;
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_write_shadow_memory_arch(IN    umbra_map_t *map,
                               IN    app_pc  app_addr,
                               IN    size_t  app_size,
                               INOUT size_t *shadow_size,
                               IN    byte   *buffer)
{
    /* i#1260: end pointers are all closed (i.e., inclusive) to handle overflow */
    app_pc app_blk_base, app_blk_end, app_src_end;
    app_pc start, end;
    size_t size, iter_size;
    byte  *shadow_start;
    size_t shdw_size;

    if (*shadow_size < umbra_map_scale_app_to_shadow(map, app_size)) {
        *shadow_size = 0;
        return DRMF_ERROR_INVALID_SIZE;
    }
    if (POINTER_OVERFLOW_ON_ADD(app_addr, app_size-1)) /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;
    shdw_size = 0;
    APP_RANGE_LOOP(app_addr, app_size, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        shadow_start  = shadow_table_app_to_shadow(map, start);
        if (shadow_table_is_in_default_block(map, shadow_start, NULL))
            return DRMF_ERROR_INVALID_PARAMETER;
        if (shadow_table_is_in_special_block(map, shadow_start,
                                             NULL, NULL, NULL)) {
            shadow_table_replace_block(map, app_blk_base);
            shadow_start = shadow_table_app_to_shadow(map, start);
        }
        size = umbra_map_scale_app_to_shadow(map, iter_size);
        memmove(shadow_start, buffer, size);
        shdw_size += size;
        buffer    += size;
    });
    *shadow_size = shdw_size;
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_shadow_set_range_arch(IN   umbra_map_t *map,
                            IN   app_pc       app_addr,
                            IN   size_t       app_size,
                            OUT  size_t      *shadow_size,
                            IN   ptr_uint_t   value,
                            IN   size_t       value_size)
{
    /* i#1260: end pointers are all closed (i.e., inclusive) to handle overflow */
    app_pc app_blk_base, app_blk_end, app_src_end;
    app_pc start, end;
    size_t size, iter_size;
    byte  *shadow_start;
    size_t shdw_size;
    ptr_uint_t blk_val;
    size_t     blk_val_sz;

    if (value_size != 1 || value > UCHAR_MAX) {
        *shadow_size = 0;
        return DRMF_ERROR_NOT_IMPLEMENTED;
    }
    if (POINTER_OVERFLOW_ON_ADD(app_addr, app_size-1)) /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;
    shdw_size = 0;
    APP_RANGE_LOOP(app_addr, app_size, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        shadow_start = shadow_table_app_to_shadow(map, start);
        if (shadow_table_is_in_default_block(map, shadow_start, NULL))
            return DRMF_ERROR_INVALID_PARAMETER;
        size = umbra_map_scale_app_to_shadow(map, iter_size);
        if (shadow_table_is_in_special_block(map, shadow_start,
                                             &blk_val, &blk_val_sz, NULL)) {
            shadow_table_replace_block(map, app_blk_base);
            shadow_start = shadow_table_app_to_shadow(map, start);
        }
        memset(shadow_start, value, size);
        shdw_size += size;
    });
    *shadow_size = shdw_size;
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_shadow_copy_range_arch(IN  umbra_map_t *map,
                             IN  app_pc  app_src,
                             IN  app_pc  app_dst,
                             IN  size_t  app_size_in,
                             OUT size_t *shadow_size_out)
{
    /* i#1260: end pointers are all closed (i.e., inclusive) to handle overflow */
    app_pc app_blk_base, app_blk_end, app_src_end;
    app_pc start, end;
    size_t app_sz, shadow_sz, tot_shadow_sz, iter_size, tail_size = 0;
    byte *shadow_start, *overlap_tail = NULL;
    drmf_status_t res = DRMF_SUCCESS;

    app_sz = app_size_in;
    if (POINTER_OVERFLOW_ON_ADD(app_src, app_sz-1) || /* just hitting top is ok */
        POINTER_OVERFLOW_ON_ADD(app_dst, app_sz-1))   /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;

    if (app_src < app_dst && app_src + (app_sz-1) >= app_dst) {
        /* overlap that must be handled */
        tail_size = app_src + (app_sz-1) - app_dst + 1;
        overlap_tail = global_alloc(tail_size, HEAPSTAT_SHADOW);
        shadow_sz = umbra_map_scale_app_to_shadow(map, tail_size);
        if (umbra_read_shadow_memory_arch(map, app_dst, tail_size,
                                          &shadow_sz, overlap_tail) != DRMF_SUCCESS)
            ASSERT(false, "fail to read shadow memory");
        app_sz = app_dst - app_src;
    }
    /* XXX, assuming the overlap with the other way is ok */
    tot_shadow_sz = 0;
    APP_RANGE_LOOP(app_src, app_sz, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        shadow_start = shadow_table_app_to_shadow(map, start);
        if (shadow_table_is_in_default_block(map, shadow_start, NULL)) {
            res = DRMF_ERROR_INVALID_PARAMETER;
            break;
        }
        shadow_sz = umbra_map_scale_app_to_shadow(map, iter_size);
        res = umbra_write_shadow_memory_arch(map,
                                             app_dst,
                                             iter_size,
                                             &shadow_sz,
                                             shadow_start);
        if (res != DRMF_SUCCESS) {
            tot_shadow_sz += shadow_sz;
            break;
        } else {
            ASSERT(shadow_sz == umbra_map_scale_app_to_shadow(map, iter_size),
                   "copy size mismatch");
        }
        app_dst   += iter_size;
        tot_shadow_sz += shadow_sz;
    });
    if (overlap_tail != NULL) {
        if (res == DRMF_SUCCESS) {
            shadow_sz = umbra_map_scale_app_to_shadow(map, tail_size);
            res = umbra_write_shadow_memory_arch(map,
                                                 app_dst + (app_dst - app_src),
                                                 tail_size,
                                                 &shadow_sz,
                                                 overlap_tail);
            tot_shadow_sz += shadow_sz;
        }
        global_free(overlap_tail, tail_size, HEAPSTAT_SHADOW);
    }
    *shadow_size_out = tot_shadow_sz;
    return res;
}

drmf_status_t
umbra_value_in_shadow_memory_arch(IN    umbra_map_t *map,
                                  INOUT app_pc *app_addr,
                                  IN    size_t  app_size,
                                  IN    ptr_uint_t value,
                                  IN    size_t value_size,
                                  OUT   bool  *found)
{
    /* i#1260: end pointers are all closed (i.e., inclusive) to handle overflow */
    app_pc app_blk_base, app_blk_end, app_src_end;
    app_pc start, end;
    size_t iter_size;
    byte  *shadow_start, *shadow_addr;
    ptr_uint_t val;
    size_t valsz, shadow_size;

    if (value > USHRT_MAX || value_size != 1)
        return DRMF_ERROR_NOT_IMPLEMENTED;
    if (POINTER_OVERFLOW_ON_ADD(*app_addr, app_size-1)) /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;

    *found  = false;
    APP_RANGE_LOOP(*app_addr, app_size, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        if (shadow_table_use_default_block(map, app_blk_base))
            return DRMF_ERROR_INVALID_PARAMETER;
        if (shadow_table_use_special_block(map, app_blk_base, &val, &valsz)) {
            if (val == value && valsz == value_size) {
                *app_addr = start;
                *found = true;
                return DRMF_SUCCESS;
            }
            continue;
        }
        shadow_start = shadow_table_app_to_shadow(map, start);
        shadow_size  = umbra_map_scale_app_to_shadow(map, iter_size);
        shadow_addr  = memchr(shadow_start, (int)value, shadow_size);
        if (shadow_addr != NULL) {
            *app_addr = start +
                umbra_map_scale_shadow_to_app(map, shadow_addr - shadow_start);
            *found = true;
            return DRMF_SUCCESS;
        }
    });
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_insert_app_to_shadow_arch(void *drcontext,
                                umbra_map_t *map,
                                instrlist_t *ilist,
                                instr_t *where,
                                reg_id_t addr_reg,
                                reg_id_t *scratch_regs,
                                int num_scratch_regs)
{
    if (num_scratch_regs < umbra_num_scratch_regs_for_translation_arch() ||
        scratch_regs == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    shadow_table_insert_app_to_shadow_arch(drcontext, map, ilist, where,
                                           addr_reg, scratch_regs[0]);
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_iterate_shadow_memory_arch(umbra_map_t *map,
                                 void *user_data,
                                 shadow_iterate_func_t iter_func)
{
    uint i;
    umbra_shadow_memory_info_t info;

    for (i = 0; i < SHADOW_TABLE_ENTRIES; i++) {
        info.app_base    = (app_pc)SHADOW_TABLE_APP_BASE(i);
        info.shadow_base = shadow_table_app_to_shadow(map, info.app_base);
        if (shadow_table_is_in_default_block(map, info.shadow_base, NULL))
            continue;
        info.app_size    = map->app_block_size;
        info.shadow_size = map->shadow_block_size;
        if (shadow_table_is_in_special_block(map, info.shadow_base,
                                             NULL, NULL, NULL))
            info.shadow_type = UMBRA_SHADOW_MEMORY_TYPE_SHARED;
        else
            info.shadow_type = UMBRA_SHADOW_MEMORY_TYPE_NORMAL;
        if (!iter_func(map, &info, user_data))
            break;
    }
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_shadow_memory_is_shared_arch(IN  umbra_map_t *map,
                                   IN  byte *shadow_addr,
                                   OUT umbra_shadow_memory_type_t *shadow_type)
{
    bool redzone;
    if (shadow_table_is_in_special_block(map, shadow_addr,
                                         NULL, NULL, &redzone)) {
        *shadow_type = UMBRA_SHADOW_MEMORY_TYPE_SHARED;
        if (redzone)
            *shadow_type |= UMBRA_SHADOW_MEMORY_TYPE_REDZONE;
        return DRMF_SUCCESS;
    } else
        *shadow_type = UMBRA_SHADOW_MEMORY_TYPE_UNKNOWN;
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_get_shadow_memory_type_arch(umbra_map_t *map,
                                  byte *shadow_addr,
                                  umbra_shadow_memory_type_t *shadow_type)
{
    uint i;
    bool redzone;
    byte *shadow_blk, *shadow_end;

    umbra_shadow_memory_is_shared_arch(map, shadow_addr, shadow_type);
    if (shadow_table_is_in_default_block(map, shadow_addr, &redzone)) {
        *shadow_type = UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC;
        if (redzone)
            *shadow_type |= UMBRA_SHADOW_MEMORY_TYPE_REDZONE;
        return DRMF_SUCCESS;
    }
    if (*shadow_type == UMBRA_SHADOW_MEMORY_TYPE_SHARED)
        return DRMF_SUCCESS;
    if (umbra_address_is_app_memory(shadow_addr)) {
        *shadow_type = UMBRA_SHADOW_MEMORY_TYPE_UNKNOWN;
        return DRMF_SUCCESS;
    }
    /* now we have to walk the whole table */
    for (i = 0; i < SHADOW_TABLE_ENTRIES; i++) {
        shadow_blk = shadow_table_get_block(map, i);
        shadow_end = shadow_blk + map->shadow_block_size;
        if (shadow_addr >= shadow_blk - map->options.redzone_size &&
            shadow_addr <  shadow_end + map->options.redzone_size) {
            *shadow_type = UMBRA_SHADOW_MEMORY_TYPE_NORMAL;
            if (shadow_addr < shadow_blk || shadow_addr >= shadow_end)
                *shadow_type |= UMBRA_SHADOW_MEMORY_TYPE_REDZONE;
            return DRMF_SUCCESS;
        }
    }
    *shadow_type = UMBRA_SHADOW_MEMORY_TYPE_NOT_SHADOW;
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_get_shadow_memory_arch(umbra_map_t *map,
                             app_pc app_addr,
                             byte **shadow_addr,
                             umbra_shadow_memory_info_t *shadow_info)
{
    if (shadow_addr != NULL)
        *shadow_addr = shadow_table_app_to_shadow(map, app_addr);
    if (shadow_info != NULL) {
        shadow_info->app_base = (app_pc)ALIGN_BACKWARD(app_addr,
                                                       map->app_block_size);
        shadow_info->app_size = map->app_block_size;
        shadow_info->shadow_size = map->shadow_block_size;
        shadow_info->shadow_base =
            shadow_table_app_to_shadow(map, shadow_info->app_base);
        if (shadow_table_use_default_block(map, app_addr)) {
            shadow_info->shadow_type =
                UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC;
            return DRMF_SUCCESS;
        }
        if (shadow_table_use_special_block(map, app_addr, NULL, NULL)) {
            shadow_info->shadow_type = UMBRA_SHADOW_MEMORY_TYPE_SHARED;
            return DRMF_SUCCESS;
        }
        shadow_info->shadow_type = UMBRA_SHADOW_MEMORY_TYPE_NORMAL;
        return DRMF_SUCCESS;
    }
    return DRMF_SUCCESS;
}

bool
umbra_address_is_app_memory(app_pc pc)
{
    /* in x86, shadow memory is allocated within DR */
    if (dr_memory_is_dr_internal(pc) || dr_memory_is_in_client(pc))
        return false;
    return true;
}

drmf_status_t
umbra_replace_shared_shadow_memory_arch(umbra_map_t *map,
                                        app_pc app_addr,
                                        byte **shadow_addr)
{
    shadow_table_replace_block(map, app_addr);
    *shadow_addr = shadow_table_app_to_shadow(map, app_addr);
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_create_shared_shadow_block_arch(IN  umbra_map_t *map,
                                      IN  ptr_uint_t   value,
                                      IN  size_t       value_size,
                                      OUT byte       **block)
{
    *block = shadow_table_create_special_block(map, value, value_size);
    if (*block == NULL)
        return DRMF_ERROR_NOMEM;
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_get_shared_shadow_block_arch(IN  umbra_map_t *map,
                                   IN  ptr_uint_t   value,
                                   IN  size_t       value_size,
                                   OUT byte       **block)
{
    uint i;
    for (i = 0; i < map->num_special_blocks; i++) {
        if (map->special_blocks[i].value == value &&
            map->special_blocks[i].value_size == value_size) {
            *block = map->special_blocks[i].start;
            return DRMF_SUCCESS;
        }
    }
    return DRMF_SUCCESS;
}

bool
umbra_handle_fault(void *drcontext, byte *target, dr_mcontext_t *raw_mc,
                   dr_mcontext_t *mc)
{
    return false;
}
