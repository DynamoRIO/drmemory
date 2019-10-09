/* **********************************************************
 * Copyright (c) 2010-2019 Google, Inc.  All rights reserved.
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

#include "dr_api.h"
#include "drmemory.h"
#include "utils.h"
#include "shadow.h"
#include "umbra.h"
#include "spill.h"
#include "instru.h"
#include <limits.h> /* UINT_MAX */
#include <stddef.h>
#ifdef TOOL_DR_HEAPSTAT
# include "../drheapstat/staleness.h"
#endif

#include "slowpath.h" /* get_own_seg_base */

#ifdef TOOL_DR_MEMORY /* around whole shadow table */

/***************************************************************************
 * BITMAP SUPPORT
 */

typedef uint* bitmap_t;

/* 1 bit per byte */
#define BITMAP_UNIT     32
#define BITMAP_MASK(i)  (1 << ((i) % BITMAP_UNIT))
#define BITMAP_IDX(i)  ((i) / BITMAP_UNIT)

/* if a shadow memory type is special shared block, could be redzone */
#define SHADOW_IS_SHARED(type) TEST(UMBRA_SHADOW_MEMORY_TYPE_SHARED, type)
/* if a shadow memory type is special shared block, but not redzone */
#define SHADOW_IS_SHARED_ONLY(type)  (UMBRA_SHADOW_MEMORY_TYPE_SHARED == type)

/* 2 bits of shadow per real byte: or 4 real bytes shadowed by one shadow byte */
#define BITMAPx2_UNIT     16 /* one uint shadows 16 real bytes */
#define BITMAPx2_SHIFT(i) (((i) % BITMAPx2_UNIT) * 2)
#define BITMAPx2_MASK(i)  (3 << BITMAPx2_SHIFT)
#define BITMAPx2_IDX(i)   ((i) / BITMAPx2_UNIT)
#define BLOCK_AS_BYTE_ARRAY_IDX(i) (BITMAPx2_IDX(i*sizeof(uint)))

/* returns the two bits corresponding to offset i */
static inline uint
bitmapx2_get(bitmap_t bm, uint i)
{
    LOG(6, "bitmapx2_get 0x%04x [%d] => "PFX" == %d\n", i, BITMAPx2_IDX(i),
          bm[BITMAPx2_IDX(i)], ((bm[BITMAPx2_IDX(i)] >> BITMAPx2_SHIFT(i)) & 3));
    return ((bm[BITMAPx2_IDX(i)] >> BITMAPx2_SHIFT(i)) & 3);
}

/* SHADOW_DWORD2BYTE() == "get_2bits" */
static inline uint
set_2bits_inline(uint orig, uint val, uint shift)
{
    ASSERT(val <= 3, "set_2bits usage error");
    ASSERT(shift % 2 == 0, "set_2bits usage error");
    orig &= (((0xfffffffc | val) << shift) | (~(0xffffffff << shift)));
    orig |= (val << shift);
    return orig;
}

/* SHADOW_DWORD2BYTE() == "get_2bits" */
uint
set_2bits(uint orig, uint val, uint shift)
{
    return set_2bits_inline(orig, val, shift);
}

static inline void
bitmapx2_set(bitmap_t bm, uint i, uint val)
{
    uint shift = BITMAPx2_SHIFT(i);
    ASSERT(val <= 3, "internal error");
    /* It's a pain to set 2 bits: first we have to clear in case either
     * of the two is a zero; then we have to set in case either is a 1.
     */
    LOG(6, "bitmapx2_set 0x%04x [%d] to %d: from "PFX" ", i, BITMAPx2_IDX(i),
          val, bm[BITMAPx2_IDX(i)]);
    bm[BITMAPx2_IDX(i)] = set_2bits_inline(bm[BITMAPx2_IDX(i)], val, shift);
    LOG(6, "to "PFX"\n", bm[BITMAPx2_IDX(i)]);
}

/* returns the byte corresponding to offset i */
static inline uint
bitmapx2_byte(bitmap_t bm, uint i)
{
    ASSERT(BITMAPx2_SHIFT(i) %8 == 0, "bitmapx2_byte: index not aligned");
    return (bm[BITMAPx2_IDX(i)] >> BITMAPx2_SHIFT(i)) & 0xff;
}

#ifdef X64
/* returns the ushort corresponding to offset i */
static inline uint
bitmapx2_ushort(bitmap_t bm, uint i)
{
    ASSERT(BITMAPx2_SHIFT(i) %16 == 0, "bitmapx2_ushort: index not aligned");
    return (bm[BITMAPx2_IDX(i)] >> BITMAPx2_SHIFT(i)) & 0xffff;
}
#endif

/* returns the uint corresponding to offset i */
static inline uint
bitmapx2_dword(bitmap_t bm, uint i)
{
    ASSERT(BITMAPx2_SHIFT(i) == 0, "bitmapx2_dword: index not aligned");
    return bm[BITMAPx2_IDX(i)];
}

/***************************************************************************
 * BYTE-TO-BYTE SHADOWING SUPPORT
 */

/* It would be simpler to use a char[] for shadow_block_t but for simpler
 * runtime parametrization we stick with uint[] and extract bytes.
 */

static inline void
bytemap_4to1_set(bitmap_t bm, uint i, uint val)
{
    char *bytes = (char *) bm;
    ASSERT(val <= UCHAR_MAX, "internal error");
    bytes[BLOCK_AS_BYTE_ARRAY_IDX(i)] = val;
}

/* returns the byte corresponding to offset i */
static inline uint
bytemap_4to1_byte(bitmap_t bm, uint i)
{
    char *bytes = (char *) bm;
    return bytes[BLOCK_AS_BYTE_ARRAY_IDX(i)];
}

#ifdef X64
/* returns the ushort corresponding to offset i */
static inline uint
bytemap_4to1_ushort(bitmap_t bm, uint i)
{
    char *bytes = (char *) bm;
    return *(ushort*)(&bytes[BLOCK_AS_BYTE_ARRAY_IDX(i)]);
}
#endif

/***************************************************************************
 * MEMORY SHADOWING DATA STRUCTURES
 */

umbra_map_t *umbra_map;

/* 2 shadow bits per app byte */
/* we use Umbra's 4B-to-1B and layer 1B-to-2b on top of that */
#define SHADOW_MAP_SCALE   UMBRA_MAP_SCALE_DOWN_4X
#define SHADOW_DEFAULT_VALUE SHADOW_DWORD_UNADDRESSABLE
#define SHADOW_DEFAULT_VALUE_SIZE 1
#define SHADOW_REDZONE_VALUE SHADOW_DWORD_BITLEVEL
#define SHADOW_REDZONE_VALUE_SIZE 1
#define REDZONE_SIZE 512

typedef struct _saved_region_t {
    app_pc start;
    size_t size;
    bitmap_t shadow;
} saved_region_t;

/* extend size to uint boundary if the exact required size is not already aligned */
#define SIZEOF_SAVED_BUFFER_SHADOW(size) \
    (ALIGN_FORWARD((size), SHADOW_GRANULARITY) / SHADOW_GRANULARITY)

/* single allocation for saved_region_t and its shadow buffer */
#define SIZEOF_SAVED_BUFFER(size) \
    (sizeof(saved_region_t) + SIZEOF_SAVED_BUFFER_SHADOW(size))

#ifndef X64
static byte *special_unaddressable;
static byte *special_undefined;
static byte *special_defined;
static byte *special_bitlevel;
#endif

#ifdef STATISTICS
uint shadow_block_alloc;
/* b/c of PR 580017 we no longer free any non-specials so this is always 0 */
uint shadow_block_free;
uint num_special_unaddressable;
uint num_special_undefined;
uint num_special_defined;
#endif

/* these are filled in in shadow_table_init() b/c the consts vary dynamically */
uint val_to_dword[4];
uint val_to_qword[4];
uint val_to_dqword[4];

#ifdef X64
# define VAL_TO_PTRSZ val_to_qword
#else
# define VAL_TO_PTRSZ val_to_dword
#endif

const char * const shadow_name[] = {
    "defined",
    "unaddressable",
    "bitlevel",
    "undefined",
    "mixed", /* SHADOW_MIXED */
    "unknown", /* SHADOW_UNKNOWN */
};

static inline uint
shadow_value_byte_2_dword(uint val)
{
    if (val == SHADOW_UNADDRESSABLE)
        return SHADOW_DWORD_UNADDRESSABLE;
    if (val == SHADOW_UNDEFINED)
        return SHADOW_DWORD_UNDEFINED;
    if (val == SHADOW_DEFINED)
        return SHADOW_DWORD_DEFINED;
    if (val == SHADOW_DEFINED_BITLEVEL)
        return SHADOW_DWORD_BITLEVEL;
    ASSERT(false, "wrong shadow value");
    return SHADOW_DWORD_UNADDRESSABLE;
}

bool
is_in_special_shadow_block(app_pc pc)
{
    umbra_shadow_memory_type_t shadow_type;
    if (umbra_shadow_memory_is_shared(umbra_map, pc,
                                      &shadow_type) != DRMF_SUCCESS)
        ASSERT(false, "fail to get shadow memory type");
    /* excluding redzone */
    return SHADOW_IS_SHARED_ONLY(shadow_type);
}

/* we can call umbra_scale_app_to_shadow, which would be slower */
static inline ptr_uint_t
shadow_scale_app_to_shadow(ptr_uint_t value)
{
    return (value >> 2);
}

static void
shadow_table_init(void)
{
    umbra_map_options_t umbra_map_ops;

    LOG(2, "shadow_table_init\n");

    val_to_dword[0] = SHADOW_DWORD_DEFINED;
    val_to_dword[1] = SHADOW_DWORD_UNADDRESSABLE;
    val_to_dword[2] = SHADOW_DWORD_BITLEVEL;
    val_to_dword[3] = SHADOW_DWORD_UNDEFINED;

    val_to_qword[0] = SHADOW_QWORD_DEFINED;
    val_to_qword[1] = SHADOW_QWORD_UNADDRESSABLE;
    val_to_qword[2] = SHADOW_QWORD_BITLEVEL;
    val_to_qword[3] = SHADOW_QWORD_UNDEFINED;

    val_to_dqword[0] = SHADOW_DQWORD_DEFINED;
    val_to_dqword[1] = SHADOW_DQWORD_UNADDRESSABLE;
    val_to_dqword[2] = SHADOW_DQWORD_BITLEVEL;
    val_to_dqword[3] = SHADOW_DQWORD_UNDEFINED;

    memset(&umbra_map_ops, 0, sizeof(umbra_map_ops));
    umbra_map_ops.flags =
        UMBRA_MAP_CREATE_SHADOW_ON_TOUCH |
        UMBRA_MAP_SHADOW_SHARED_READONLY;
    umbra_map_ops.scale = SHADOW_MAP_SCALE;
    umbra_map_ops.default_value = SHADOW_DEFAULT_VALUE;
    umbra_map_ops.default_value_size = SHADOW_DEFAULT_VALUE_SIZE;
#ifndef X64
    umbra_map_ops.redzone_size = REDZONE_SIZE;
    umbra_map_ops.redzone_value = SHADOW_REDZONE_VALUE;
    umbra_map_ops.redzone_value_size = 1;
#endif
    if (umbra_create_mapping(&umbra_map_ops, &umbra_map) != DRMF_SUCCESS)
        ASSERT(false, "fail to create shadow memory mapping");
#ifndef X64
    umbra_create_shared_shadow_block(umbra_map, SHADOW_DWORD_UNADDRESSABLE,
                                     1, &special_unaddressable);
    umbra_create_shared_shadow_block(umbra_map, SHADOW_DWORD_UNDEFINED,
                                     1, &special_undefined);
    umbra_create_shared_shadow_block(umbra_map, SHADOW_DWORD_DEFINED,
                                     1, &special_defined);
    umbra_create_shared_shadow_block(umbra_map, SHADOW_DWORD_BITLEVEL,
                                     1, &special_bitlevel);
#endif
}

static void
shadow_table_exit(void)
{
    LOG(2, "shadow_table_exit\n");
    if (umbra_destroy_mapping(umbra_map) != DRMF_SUCCESS)
        ASSERT(false, "fail to destroy shadow memory");
}

bool
shadow_create_shadow_memory(app_pc base, size_t size, uint value)
{
    uint flags = UMBRA_CREATE_SHADOW_SHARED_READONLY; /* allow special block */
    if (umbra_create_shadow_memory(umbra_map, flags,
                                   base, size, value, 1) == DRMF_SUCCESS)
        return true;
    return false;
}

size_t
get_shadow_block_size(void)
{
    size_t size;
    if (umbra_get_shadow_block_size(umbra_map, &size) != DRMF_SUCCESS) {
        ASSERT(false, "fail to get shadow block size");
        return PAGE_SIZE;
    }
    return size;
}

bool
shadow_get_special(app_pc addr, uint *val)
{
    umbra_shadow_memory_info_t info;
    uint value;
    umbra_shadow_memory_info_init(&info);
    value = shadow_get_byte(&info, addr);
    if (val != NULL)
        *val = value;
    /* the shadow memory is get from application address, so shadow_type
     * should has no redzone set.
     */
    return SHADOW_IS_SHARED_ONLY(info.shadow_type);
}

/* return the two bits for the byte at the passed-in address */
/* umbra_shadow_memory_info must be first zeroed out by the caller prior to
 * calling the first time for any series of calls. It will be filled out
 * and can be used for a series of calls for better performance.
 * On the subsequent calls, if the passed in umbra_shadow_memory_info has
 * the right range, we assume the the shadow memory info is correct and
 * will access the cached shadow memory directly without querying
 * Umbra.
 * However, the info may have stale info as Umbra may replace it, and
 * the caller must be able to handle or tolerate that situation.
 */
/* it also has the racy problem on accessing partial byte, xref i#271 */
uint
shadow_get_byte(INOUT umbra_shadow_memory_info_t *info, app_pc addr)
{
    ptr_uint_t idx;
    if (addr < info->app_base || addr >= info->app_base + info->app_size) {
        ASSERT(info->struct_size == sizeof(*info),
               "shadow memory info is not initialized properly");
        if (umbra_get_shadow_memory(umbra_map, addr,
                                    NULL, info) != DRMF_SUCCESS) {
            ASSERT(false, "fail to get shadow memory info");
            return 0;
        }
    }
    /* avoid a fault: if no shadow yet, it's unaddr */
    if (info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC)
        return SHADOW_UNADDRESSABLE;
    /* if non-app-memory (no shadow supported there for x64), it's unaddr */
    if (info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_NOT_SHADOW)
        return SHADOW_UNADDRESSABLE;
    idx = addr - info->app_base;
    if (!MAP_4B_TO_1B)
        return bitmapx2_get((bitmap_t)info->shadow_base, idx);
    else
        return bytemap_4to1_byte((bitmap_t)info->shadow_base, idx);
}

/* Returns the byte that shadows the 4-byte-aligned address */
/* see comment in shadow_get_byte about using umbra_shadow_memory_info_t */
uint
shadow_get_dword(INOUT umbra_shadow_memory_info_t *info, app_pc addr)
{
    ptr_uint_t idx;
    if (addr < info->app_base || addr >= info->app_base + info->app_size) {
        ASSERT(info->struct_size == sizeof(*info),
               "shadow memory info is not initialized properly");
        if (umbra_get_shadow_memory(umbra_map, addr,
                                    NULL, info) != DRMF_SUCCESS) {
            ASSERT(false, "fail to get shadow memory info");
            return 0;
        }
    }
    /* avoid a fault: if no shadow yet, it's unaddr */
    if (info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC)
        return SHADOW_DWORD_UNADDRESSABLE;
    /* if non-app-memory (no shadow supported there for x64), it's unaddr */
    if (info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_NOT_SHADOW)
        return SHADOW_DWORD_UNADDRESSABLE;
    idx = ((ptr_uint_t)ALIGN_BACKWARD(addr, 4)) - (ptr_uint_t)info->app_base;
    if (!MAP_4B_TO_1B)
        return bitmapx2_byte((bitmap_t)info->shadow_base, idx);
    else /* just return byte */
        return bytemap_4to1_byte((bitmap_t)info->shadow_base, idx);
}

#ifdef X64
uint
shadow_get_qword(INOUT umbra_shadow_memory_info_t *info, app_pc addr)
{
    ptr_uint_t idx;
    if (addr < info->app_base || addr >= info->app_base + info->app_size) {
        ASSERT(info->struct_size == sizeof(*info),
               "shadow memory info is not initialized properly");
        if (umbra_get_shadow_memory(umbra_map, addr,
                                    NULL, info) != DRMF_SUCCESS) {
            ASSERT(false, "fail to get shadow memory info");
            return 0;
        }
    }
    /* avoid a fault: if no shadow yet, it's unaddr */
    if (info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC)
        return SHADOW_DWORD_UNADDRESSABLE;
    /* if non-app-memory (no shadow supported there for x64), it's unaddr */
    if (info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_NOT_SHADOW)
        return SHADOW_DWORD_UNADDRESSABLE;
    idx = ((ptr_uint_t)ALIGN_BACKWARD(addr, 8)) - (ptr_uint_t)info->app_base;
    if (!MAP_4B_TO_1B)
        return bitmapx2_ushort((bitmap_t)info->shadow_base, idx);
    else /* just return byte */
        return bytemap_4to1_ushort((bitmap_t)info->shadow_base, idx);
}
#endif

uint
shadow_get_ptrsz(INOUT umbra_shadow_memory_info_t *info, app_pc addr)
{
#ifdef X64
    return shadow_get_qword(info, addr);
#else
    return shadow_get_dword(info, addr);
#endif
}

/* Sets the two bits for the byte at the passed-in address */
/* see comment in shadow_get_byte about using umbra_shadow_memory_info_t */
void
shadow_set_byte(INOUT umbra_shadow_memory_info_t *info, app_pc addr, uint val)
{
    ASSERT(val <= 4, "invalid shadow value");
    if (addr < info->app_base || addr >= info->app_base + info->app_size) {
        ASSERT(info->struct_size == sizeof(*info),
               "shadow memory info is not initialized properly");
        if (umbra_get_shadow_memory(umbra_map, addr,
                                    NULL, info) != DRMF_SUCCESS) {
            ASSERT(false, "fail to get shadow memory info");
        }
    }
    /* If non-app-memory (no shadow supported there for x64), we can't recover
     * (FIXME i#1640: umbra should be more robust).
     */
    if (info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_NOT_SHADOW) {
        NOTIFY_ERROR("unhandled application memory @"PFX NL, addr);
        dr_abort();
    }
    /* Note that we can come here for SHADOW_SPECIAL_DEFINED, for mmap
     * regions used for calloc (we mark headers as unaddressable), etc.
     */
    if (info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_SHARED ||
        /* Lazily allocated */
        info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC) {
        /* Avoid replacing special on nop write */
        if (val == shadow_get_byte(info, addr)) {
            LOG(5, "writing "PFX" => nop (already special %d)\n", addr, val);
            return;
        }
        /* If it's special shared shadow memory, recreate normal shadow memory.
         * If it's lazily allocated, allocate the shadow (umbra_write_shadow_memory()
         * would do that for us).
         */
        if (umbra_create_shadow_memory(umbra_map, 0,
                                       info->app_base, info->app_size,
                                       (info->shadow_type ==
                                        UMBRA_SHADOW_MEMORY_TYPE_SHARED) ?
                                       (ptr_uint_t)*(info->shadow_base) :
                                       SHADOW_DEFAULT_VALUE,
                                       SHADOW_DEFAULT_VALUE_SIZE) != DRMF_SUCCESS) {
            NOTIFY_ERROR("unhandled application memory @"PFX NL, addr);
            dr_abort();
        }
        if (umbra_get_shadow_memory(umbra_map, addr,
                                    NULL, info) != DRMF_SUCCESS)
            ASSERT(false, "fail to get shadow memory info");
    }
    ASSERT(info->shadow_type != UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC, "will fault");
    LOG(5, "writing "PFX" ("PIFX") => %d\n", addr, addr - info->app_base, val);
    if (!MAP_4B_TO_1B) {
        bitmapx2_set((bitmap_t)info->shadow_base,
                     addr - info->app_base,
                     val);
    } else {
        bytemap_4to1_set((bitmap_t)info->shadow_base,
                         addr - info->app_base,
                         val);
    }
}

byte *
shadow_translation_addr(app_pc addr)
{
    umbra_shadow_memory_info_t info;
    byte *shadow_addr;
    info.struct_size = sizeof(info);
    if (umbra_get_shadow_memory(umbra_map, addr,
                                &shadow_addr, &info) != DRMF_SUCCESS) {
        ASSERT(false, "fail to get shadow memory");
        return NULL;
    }
    return shadow_addr;
}

/* Returns a pointer to an always-bitlevel shadow block */
byte *
shadow_bitlevel_addr(void)
{
    /* For PR 493257 we need this pointer to have redzone bitlevel on both sides */
#ifdef X64
    return NULL;
#else
    return special_bitlevel + SHADOW_REDZONE_SIZE;
#endif
}

byte *
shadow_replace_special(app_pc addr)
{
    byte *shadow_addr;
    if (umbra_replace_shared_shadow_memory(umbra_map, addr,
                                           &shadow_addr) != DRMF_SUCCESS) {
        ASSERT(false, "fail to replace special shadow memory");
        return NULL;
    }
    return shadow_addr;
}

/* Saves the shadow values for the specified app memory region into a newly allocated
 * buffer. The caller must free the returned shadow buffer using shadow_free_buffer(),
 */
shadow_buffer_t *
shadow_save_region(app_pc start, size_t size)
{
    uint i, shadow_value;
    size_t saved_buffer_size = SIZEOF_SAVED_BUFFER(size);
    saved_region_t *saved = global_alloc(saved_buffer_size, HEAPSTAT_SHADOW);
    umbra_shadow_memory_info_t shadow_info;

    if (MAP_4B_TO_1B) {
        ASSERT_NOT_IMPLEMENTED();
        return NULL;
    }

    /* single allocation: struct at the front, buffer at the back */
    saved->start = start;
    saved->size = size;
    saved->shadow = (bitmap_t)((byte *) saved + sizeof(saved_region_t));

    /* XXX i#1734: this can be optimized for better performance on large buffers */
    umbra_shadow_memory_info_init(&shadow_info);
    for (i = 0; i < saved->size; i++) {
        shadow_value = shadow_get_byte(&shadow_info, (byte *) start + i);
        bitmapx2_set(saved->shadow, i, shadow_value);
    }
    return (shadow_buffer_t *) saved;
}

/* Restore the shadow state for a region that was saved using shadow_save_buffer(). */
void
shadow_restore_region(shadow_buffer_t *shadow_buffer)
{
    uint i;
    saved_region_t *saved = (saved_region_t *) shadow_buffer;
    umbra_shadow_memory_info_t shadow_info;

    umbra_shadow_memory_info_init(&shadow_info);
    for (i = 0; i < saved->size; i++)
        shadow_set_byte(&shadow_info, saved->start + i, bitmapx2_get(saved->shadow, i));
}

/* Free a shadow buffer that was allocated in shadow_save_buffer(). */
void
shadow_free_buffer(shadow_buffer_t *shadow_buffer)
{
    saved_region_t *saved = (saved_region_t *) shadow_buffer;

    global_free(saved, SIZEOF_SAVED_BUFFER(saved->size), HEAPSTAT_SHADOW);
}

/* Sets the two bits for each byte in the range [start, end) */
void
shadow_set_range(app_pc start, app_pc end, uint val)
{
    umbra_shadow_memory_info_t info;
    app_pc aligned_start, aligned_end;
    app_pc pc;
    size_t shadow_size;
    ASSERT(options.shadowing, "shadowing disabled");
    ASSERT(val <= 4, "invalid shadow value");
    LOG(2, "set range "PFX"-"PFX" => 0x%x\n", start, end, val);
    umbra_shadow_memory_info_init(&info);
    DOLOG(2, {
        if (end - start > 0x10000000)
            LOG(2, "WARNING: set range of very large range "PFX"-"PFX"\n",
                start, end);
    });
    if (start >= end)
        return;
    /* for case like [0x1001, 0x1003]: align_start=0x1004, align_end=0x1000 */
    aligned_start = (app_pc)ALIGN_FORWARD(start, SHADOW_GRANULARITY);
    aligned_end   = (app_pc)ALIGN_BACKWARD(end, SHADOW_GRANULARITY);
    /* set unaligned start */
    pc = start;
    while (pc < aligned_start && pc < end) {
        shadow_set_byte(&info, pc, val);
        LOG(4, "\tset byte "PFX"\n", pc);
        if (POINTER_OVERFLOW_ON_ADD(pc, 1))
            break;
        pc++;
    }
    /* set aligned byte */
    if (aligned_end > aligned_start &&
        umbra_shadow_set_range(umbra_map,
                               aligned_start,
                               aligned_end-aligned_start,
                               &shadow_size,
                               shadow_value_byte_2_dword(val),
                               1) != DRMF_SUCCESS) {
        ASSERT(false, "fail to set shadow memory");
    }
    /* set unaligned end */
    if (aligned_end >= aligned_start) {
        pc = aligned_end;
        while (pc < end) {
            shadow_set_byte(&info, pc, val);
            LOG(4, "\tset byte "PFX"\n", pc);
            if (POINTER_OVERFLOW_ON_ADD(pc, 1))
                break;
            pc++;
        }
    }
}

/* Copies the values for each byte in the range [old_start, old_start+size) to
 * [new_start, new_start+size).  The two ranges can overlap.
 */
void
shadow_copy_range(app_pc old_start, app_pc new_start, size_t size)
{
    size_t shdw_size;
    app_pc old_pc, new_pc, old_end;
    umbra_shadow_memory_info_t info_src;
    umbra_shadow_memory_info_t info_dst;
    uint head_val[SHADOW_GRANULARITY], tail_val[SHADOW_GRANULARITY];
    uint head_bit, tail_bit, i;

    LOG(2, "copy range "PFX"-"PFX" to "PFX"-"PFX"\n",
         old_start, old_start+size, new_start, new_start+size);
    umbra_shadow_memory_info_init(&info_src);
    umbra_shadow_memory_info_init(&info_dst);

    head_bit = (ptr_uint_t)old_start % SHADOW_GRANULARITY;
    if (head_bit != ((ptr_uint_t)new_start % SHADOW_GRANULARITY)) {
        /* Alignments don't match (e.g., 0x...3 and 0x...1).  We use a slow,
         * brute-force appraoch as this should be rare.  We handle overlap by
         * copying to a temp, with the assumption that anything big like an mmap
         * will be page-aligned and won't come here.
         *
         * XXX: we should add a unit test framework so we can easily write
         * a test for this.
         */
        /* For simplicity we store each pair of 2 bits in one byte */
        byte *temp = global_alloc(size, HEAPSTAT_SHADOW);
        for (i = 0; i < size; i++)
            temp[i] = (byte) shadow_get_byte(&info_src, old_start + i);
        for (i = 0; i < size; i++)
            shadow_set_byte(&info_dst, new_start + i, temp[i]);
        global_free(temp, size, HEAPSTAT_SHADOW);
        return;
    }
    old_end  = old_start + size;
    tail_bit = (ptr_uint_t)old_end % SHADOW_GRANULARITY;
    /* It is 1B-2-2b mapping and umbra only support full byte copy, so we have
     * to handle the unaligned byte copy.
     */
    /* XXX: maybe umbra should support partial byte update and the code can be
     * moved into umbra.
     */
    if (head_bit != 0) {
        for (i = 0; i+head_bit < SHADOW_GRANULARITY; i++)
            head_val[i+head_bit] = shadow_get_byte(&info_src, old_start+i);
    }
    if (tail_bit != 0) {
        old_end = (app_pc)ALIGN_BACKWARD(old_end, SHADOW_GRANULARITY);
        for (i = 0; i < tail_bit; i++)
            tail_val[i] = shadow_get_byte(&info_src, old_end+i);
    }
    old_pc  = (app_pc)ALIGN_FORWARD(old_start, SHADOW_GRANULARITY);
    if (old_end > old_pc) {
        size_t copy_size = old_end - old_pc;
        new_pc = (app_pc)ALIGN_FORWARD(new_start, SHADOW_GRANULARITY);
        if (umbra_shadow_copy_range(umbra_map, old_pc, new_pc, copy_size,
                                    &shdw_size) != DRMF_SUCCESS ||
            shdw_size != shadow_scale_app_to_shadow(copy_size))
            ASSERT(false, "fail to copy shadow memory");
    }
    if (head_bit != 0) {
        for (i = 0; i+head_bit < SHADOW_GRANULARITY; i++)
            shadow_set_byte(&info_dst, new_start+i, head_val[i+head_bit]);
    }
    if (tail_bit != 0) {
        app_pc new_end =
            (app_pc)ALIGN_BACKWARD(new_start + size, SHADOW_GRANULARITY);
        for (i = 0; i < tail_bit; i++)
            shadow_set_byte(&info_dst, new_end+i, tail_val[i]);
    }
}

void
shadow_set_non_matching_range(app_pc start, size_t size, uint val, uint val_not)
{
    umbra_shadow_memory_info_t info;
    app_pc end = start + size;
    app_pc cur;

    ASSERT(!MAP_4B_TO_1B, "invalid shadow mode");
    LOG(2, "Marking non-%s bytes in range "PFX"-"PFX" as %s\n",
        shadow_name[val_not], start, end, shadow_name[val]);
    /* XXX: We could try to be clever for perf, but these calls are rare, so we
     * go byte by byte.
     */
    umbra_shadow_memory_info_init(&info);
    for (cur = start; cur != end; cur++) {
        uint shadow = shadow_get_byte(&info, cur);
        if (shadow != val_not) {
            shadow_set_byte(&info, cur, val);
        }
    }
}

static uint dqword_to_val(uint dqword)
{
    if (dqword == SHADOW_DQWORD_UNADDRESSABLE)
        return SHADOW_UNADDRESSABLE;
    if (dqword == SHADOW_DQWORD_UNDEFINED)
        return SHADOW_UNDEFINED;
    if (dqword == SHADOW_DQWORD_DEFINED)
        return SHADOW_DEFINED;
    if (dqword == SHADOW_DQWORD_BITLEVEL)
        return SHADOW_DEFINED_BITLEVEL;
    return UINT_MAX;
}

const char *
shadow_dqword_name(uint dqword)
{
    if (dqword == SHADOW_DQWORD_UNADDRESSABLE)
        return shadow_name[SHADOW_UNADDRESSABLE];
    if (dqword == SHADOW_DQWORD_UNDEFINED)
        return shadow_name[SHADOW_UNDEFINED];
    if (dqword == SHADOW_DQWORD_DEFINED)
        return shadow_name[SHADOW_DEFINED];
    if (dqword == SHADOW_DQWORD_BITLEVEL)
        return shadow_name[SHADOW_DEFINED_BITLEVEL];
    return "<mixed>";
}

/* Compares every byte in [start, start+size) to expect.
 * Stops and returns the pc of the first non-matching value.
 * If all bytes match, returns start+size.
 * bad_state is a dqword value.
 */
bool
shadow_check_range(app_pc start, size_t size, uint expect,
                   app_pc *bad_start, app_pc *bad_end, uint *bad_state)
{
    umbra_shadow_memory_info_t info;
    app_pc pc = start;
    uint val;
    uint bad_val = 0;
    bool res = true;
    size_t incr;
    ASSERT(expect <= 4, "invalid shadow value");
    ASSERT(start+size > start, "invalid param");
    umbra_shadow_memory_info_init(&info);
    while (pc < start+size) {
        val = shadow_get_byte(&info, pc);
        if (!ALIGNED(pc, 16)) {
            incr = 1;
        } else if (SHADOW_IS_SHARED_ONLY(info.shadow_type)) {
            incr = info.app_base + info.app_size - pc;
        } else {
            val = bitmapx2_dword((bitmap_t)info.shadow_base, pc-info.app_base);
            val = dqword_to_val(val);
            if (val == UINT_MAX) {
                /* mixed: have to drop to per-byte */
                val = shadow_get_byte(&info, pc);
                incr = 1;
            } else /* all identical */
                incr = 16;
        }
        if (!res) {
            /* we know we have some non-matching bytes, but we want to know
             * the full extent of them (if identical) (if bad_end is non-NULL)
             */
            if (val != bad_val || bad_end == NULL) {
                if (bad_end != NULL)
                    *bad_end = pc;
                break;
            }
        } else if (val != expect) {
            res = false;
            bad_val = val;
            if (bad_start != NULL)
                *bad_start = pc;
            if (bad_state != NULL)
                *bad_state = val;
        }
        pc += incr;
    }
    if (!res && val == bad_val && bad_end != NULL)
        *bad_end = pc;
    return res;
}

/* Walks backward from start comparing each byte to expect.
 * If a non-matching value is reached, stops and returns false with the
 * non-matching addr in bad_addr.
 * If all bytes match when it reaches start-size, returns true.
 * N.B.: if this finds more important uses, should generalize and give
 * all the features of the forward version.
 */
bool
shadow_check_range_backward(app_pc start, size_t size, uint expect,
                            app_pc *bad_addr)
{
    umbra_shadow_memory_info_t info;
    app_pc pc = start;
    uint val;
    bool res = true;
    ASSERT(expect <= 4, "invalid shadow value");
    ASSERT(size < (size_t)start, "invalid param");
    umbra_shadow_memory_info_init(&info);
    while (pc > start-size) {
        /* For simplicity and since performance is not critical for current
         * callers, walking one byte at a time
         */
        val = shadow_get_byte(&info, pc);
        if (val != expect) {
            res = false;
            if (bad_addr != NULL)
                *bad_addr = pc;
            break;
        }
        pc--;
    }
    return res;
}

/* Finds the next aligned dword, starting at start and stopping at
 * end, whose shadow equals expect expanded to a dword.
 */
app_pc
shadow_next_dword(app_pc start, app_pc end, uint expect)
{
    bool found;
    app_pc app_addr = start;
    uint expect_dword = val_to_dword[expect];

    if (umbra_value_in_shadow_memory(umbra_map,
                                     (app_pc *)&app_addr,
                                     end - app_addr,
                                     expect_dword, 1,
                                     &found) != DRMF_SUCCESS)
        ASSERT(false, "failed to check value in shadow memory");
    if (found)
        return app_addr;
    return NULL;
}

/* Finds the previous aligned dword, starting at start and stopping at
 * end (end < start), whose shadow equals expect expanded to a dword.
 */
app_pc
shadow_prev_dword(app_pc start, app_pc end, uint expect)
{
    umbra_shadow_memory_info_t info;
    app_pc pc = start;
    uint expect_dword = val_to_dword[expect];
    ASSERT(expect <= 4, "invalid shadow value");
    ASSERT(ALIGNED(start, 4), "invalid start pc");
    ASSERT(end < start, "invalid end pc");
    umbra_shadow_memory_info_init(&info);
    while (pc > end) {
        uint blockval = shadow_get_byte(&info, pc);
        LOG(5, "shadow_prev_dword: checking "PFX"\n", pc);
        if (SHADOW_IS_SHARED_ONLY(info.shadow_type)) {
            uint dwordval = val_to_dword[blockval];
            if (dwordval == expect_dword)
                return pc;
        } else {
            byte *base = info.shadow_base;
            size_t mod = pc - info.app_base;
            byte *start_shadow = base + BLOCK_AS_BYTE_ARRAY_IDX(mod);
            byte *shadow = start_shadow;
            while (shadow >= base && *shadow != expect_dword)
                shadow--;
            if (shadow >= base) {
                pc = pc - ((start_shadow - shadow)*4);
                if (pc > end)
                    return pc;
                else
                    return NULL;
            }
        }
        ASSERT(!POINTER_UNDERFLOW_ON_SUB(info.app_base, 1),
               "application address underflow");
        pc = info.app_base - 1;
    }
    return NULL;
}

/* Finds the next pointer-sized aligned address, starting at start and stopping at
 * end, whose shadow equals expect expanded to a pointer.
 */
app_pc
shadow_next_ptrsz(app_pc start, app_pc end, uint expect)
{
    bool found;
    app_pc app_addr = start;
    uint expect_val = VAL_TO_PTRSZ[expect];
    if (end < start)
        return NULL;

    if (umbra_value_in_shadow_memory(umbra_map,
                                     (app_pc *)&app_addr,
                                     end - app_addr,
                                     expect_val, sizeof(void*)/SHADOW_GRANULARITY,
                                     &found) != DRMF_SUCCESS)
        ASSERT(false, "failed to check value in shadow memory");
    if (found)
        return app_addr;
    return NULL;
}

/* Caller does a lea or equivalent:
 *   0x4d1cd047  8d 8e 84 00 00 00    lea    0x00000084(%esi) -> %ecx
 * And this routine adds:
 *   0x4d1cd04d  8b d1                mov    %ecx -> %edx
 *   0x4d1cd04f  c1 ea 10             shr    $0x00000010 %edx -> %edx
 *   0x4d1cd052  c1 e9 02             shr    $0x00000002 %ecx -> %ecx
 *   0x4d1cd055  03 0c 95 40 26 96 73 add    0x73962640(,%edx,4) %ecx -> %ecx
 * And now the shadow addr is in %ecx.
 */
void
shadow_gen_translation_addr(void *drcontext, instrlist_t *bb, instr_t *inst,
                            reg_id_t addr_reg, reg_id_t scratch_reg)
{
#ifdef DEBUG
    int num_regs;
#endif
    ASSERT(umbra_num_scratch_regs_for_translation(&num_regs) == DRMF_SUCCESS &&
           num_regs <= 1, "not enough scratch registers");
    umbra_insert_app_to_shadow(drcontext, umbra_map, bb, inst, addr_reg,
                               &scratch_reg, 1);
}

bool
shadow_memory_is_shadow(app_pc addr)
{
    umbra_shadow_memory_type_t shadow_type;
    umbra_shadow_memory_type_t match_shadow =
        UMBRA_SHADOW_MEMORY_TYPE_NORMAL |
        UMBRA_SHADOW_MEMORY_TYPE_SHARED |
#ifndef X64
        UMBRA_SHADOW_MEMORY_TYPE_REDZONE |
#endif
        UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC;
    if (!options.shadowing)
        return false;
    if (umbra_get_shadow_memory_type(umbra_map, addr,
                                     &shadow_type) == DRMF_SUCCESS &&
        TESTANY(match_shadow, shadow_type))
        return true;
    return false;
}

/***************************************************************************
 * TABLES
 *
 * Table lookup is most performant way to do many operations, when we're
 * instrumenting so much code that code size is a bottleneck.
 */

/*
0000
0001
0010
0011
0100
0101
0110
0111
1000
1001
1010
1011
1100
1101
1110
1111
*/

/* If any 2-bit sequence is 01, return 0 */
const byte shadow_dword_is_addressable[256] = {
    1, 0, 1, 1,  0, 0, 0, 0,  1, 0, 1, 1,  1, 0, 1, 1,  /* 0 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    1, 0, 1, 1,  0, 0, 0, 0,  1, 0, 1, 1,  1, 0, 1, 1,  /* 2 */
    1, 0, 1, 1,  0, 0, 0, 0,  1, 0, 1, 1,  1, 0, 1, 1,  /* 3 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    1, 0, 1, 1,  0, 0, 0, 0,  1, 0, 1, 1,  1, 0, 1, 1,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    1, 0, 1, 1,  0, 0, 0, 0,  1, 0, 1, 1,  1, 0, 1, 1,  /* A */
    1, 0, 1, 1,  0, 0, 0, 0,  1, 0, 1, 1,  1, 0, 1, 1,  /* B */

    1, 0, 1, 1,  0, 0, 0, 0,  1, 0, 1, 1,  1, 0, 1, 1,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    1, 0, 1, 1,  0, 0, 0, 0,  1, 0, 1, 1,  1, 0, 1, 1,  /* E */
    1, 0, 1, 1,  0, 0, 0, 0,  1, 0, 1, 1,  1, 0, 1, 1,  /* F */
};

/* If any 2-bit sequence is 01 or 10, return 0 */
const byte shadow_dword_is_addr_not_bit[256] = {
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 0 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 3 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* F */
};

/* Expand a 2-bit sequence, with the other bits 0 */
const byte shadow_2_to_dword[256] = {
    0x00,0x55,0xaa,0xff,  0x55,0,0,0,  0xaa,0,0,0,  0xff,0,0,0,  /* 0 */
    0x55,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* 1 */
    0xaa,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* 2 */
    0xff,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* 3 */

    0x55,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* 4 */
    0,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* 5 */
    0,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* 6 */
    0,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* 7 */

    0xaa,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* 8 */
    0,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* 9 */
    0,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* A */
    0,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* B */

    0xff,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* C */
    0,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* D */
    0,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* E */
    0,0,0,0,  0,0,0,0,  0,0,0,0,  0,0,0,0,  /* F */
};

/* Expand a 4-bit sequence, with the other bits 0, for movsx.
 * The higher 2-bit propagates, the lower stays.
 * The other half being non-0 is an error so we return bitlevel 0xaa.
 */
const byte shadow_4_to_dword[256] = {
    0x00,0x01,0x02,0x03,0x54,0x55,0x56,0x57,0xa8,0xa9,0xaa,0xab,0xfc,0xfd,0xfe,0xff,/*0*/
    0x01,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*1*/
    0x02,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*2*/
    0x03,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*3*/

    0x54,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*4*/
    0x55,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*5*/
    0x56,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*6*/
    0x57,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*7*/

    0xa8,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*8*/
    0xa9,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*9*/
    0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*A*/
    0xab,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*B*/

    0xfc,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*C*/
    0xfd,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*D*/
    0xfe,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*E*/
    0xff,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,0xaa,/*F*/
};

/* Returns 1 iff the selected 2-bit sequence is 00 */
const byte shadow_byte_defined[4][256] = {
{ /* offs = 0 => bits 0-1 */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* 0 */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* 1 */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* 2 */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* 3 */

    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* 4 */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* 5 */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* 6 */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* 7 */

    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* 8 */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* 9 */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* A */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* B */

    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* C */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* D */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* E */
    1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  1, 0, 0, 0,  /* F */
},
{ /* offs = 1 => bits 2-3 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 0 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 3 */

    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* F */
},
{ /* offs = 2 => bits 4-5 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 0 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 3 */

    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* F */
},
{ /* offs = 3 => bits 6-7 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 0 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 1 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 2 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 3 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* F */
},
};

/* Returns 1 iff the selected 4-bit sequence is 0000.
 * We should already be checking alignment so we expect
 * either 0 or 2 for the offs.
 */
const byte shadow_word_defined[4][256] = {
{ /* offs = 0 => bits 0-3 */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 0 */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 3 */

    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    1, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* F */
},
{ /* offs = 1 => unaligned */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 0 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 3 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* F */
},
{ /* offs = 2 => bits 4-7 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 0 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 3 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* F */
},
{ /* offs = 3 => unaligned */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 0 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 3 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* F */
},
};

/* Returns 1 iff the selected 2-bit sequence is 00 or 11 */
const byte shadow_byte_addr_not_bit[4][256] = {
{ /* offs = 0 => bits 0-1 */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* 0 */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* 1 */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* 2 */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* 3 */

    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* 4 */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* 5 */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* 6 */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* 7 */

    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* 8 */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* 9 */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* A */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* B */

    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* C */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* D */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* E */
    1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  1, 0, 0, 1,  /* F */
},
{ /* offs = 1 => bits 2-3 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* 0 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* 1 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* 2 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* 3 */

    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* 4 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* 5 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* 6 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* 7 */

    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* 8 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* 9 */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* A */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* B */

    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* C */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* D */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* E */
    1, 1, 1, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 1, 1, 1,  /* F */
},
{ /* offs = 2 => bits 4-5 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 0 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 3 */

    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 7 */

    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* B */

    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* F */
},
{ /* offs = 3 => bits 6-7 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 0 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 1 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 2 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 3 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* C */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* D */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* E */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* F */
},
};

/* Returns 1 iff the selected 4-bit sequence is 0000, 1100, 0011, or 1111.
 * We should already be checking alignment so we expect
 * either 0 or 2 for the offs.
 */
const byte shadow_word_addr_not_bit[4][256] = {
{ /* offs = 0 => bits 0-3 */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 0 */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 1 */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 2 */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 3 */

    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 4 */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 5 */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 6 */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 7 */

    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 8 */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* 9 */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* A */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* B */

    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* C */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* D */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* E */
    1, 0, 0, 1,  0, 0, 0, 0,  0, 0, 0, 0,  1, 0, 0, 1,  /* F */
},
{ /* offs = 1 => unaligned */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 0 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 3 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* F */
},
{ /* offs = 2 => bits 4-7 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 0 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* 3 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  1, 1, 1, 1,  /* F */
},
{ /* offs = 3 => unaligned */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 0 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 1 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 2 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 3 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 4 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 5 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 6 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 7 */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 8 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* 9 */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* A */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* B */

    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* C */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* D */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* E */
    0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  /* F */
},
};

#endif /* TOOL_DR_MEMORY around whole shadow table */

/***************************************************************************
 * SHADOWING THE GPR REGISTERS
 */

#ifdef X64
# define NUM_XMM_REGS 16
#else
# define NUM_XMM_REGS 8
#endif
#define NUM_MMX_REGS 8

typedef struct _shadow_aux_registers_t {
    /* i#243: shadow xmm registers */
    int xmm[NUM_XMM_REGS];
    int ymmh[NUM_XMM_REGS];
    /* i#1473: shadow mmx registers */
    short mm[NUM_MMX_REGS];
    /* XXX i#471: add floating-point registers here as well */
} shadow_aux_registers_t;

#ifdef X64
typedef unsigned short shadow_reg_type_t;
#else
typedef byte shadow_reg_type_t;
#endif

/* We keep our shadow register bits in TLS */
typedef struct _shadow_registers_t {
#ifdef TOOL_DR_MEMORY
    /* First 8-byte TLS slot */
    shadow_reg_type_t xax;
    shadow_reg_type_t xcx;
    shadow_reg_type_t xdx;
    shadow_reg_type_t xbx;
    /* Second 8-byte TLS slot */
    shadow_reg_type_t xsp;
    shadow_reg_type_t xbp;
    shadow_reg_type_t xsi;
    shadow_reg_type_t xdi;
# ifdef X64
    /* Third 8-byte TLS slot */
    shadow_reg_type_t r8;
    shadow_reg_type_t r9;
    shadow_reg_type_t r10;
    shadow_reg_type_t r11;
    /* Fourth 8-byte TLS slot */
    shadow_reg_type_t r12;
    shadow_reg_type_t r13;
    shadow_reg_type_t r14;
    shadow_reg_type_t r15;
# endif
    /* Third/fifth TLS slot.  We go ahead and write GPR-sized values here
     * for simplicity in our fastpath even though we treat this as
     * a single tracked value.
     */
    shadow_reg_type_t eflags;
    /* Used for PR 578892.  Should remain a very small integer so byte is fine. */
    byte in_heap_routine;
    byte padding[IF_X64_ELSE(4,2)];
    /* Fourth/sixth TLS slot, which provides indirection to additional
     * shadow memory.
     */
    shadow_aux_registers_t *aux;
#else
    /* Avoid empty struct.  FIXME: this is a waste of a tls slot */
    void *bogus;
#endif
} shadow_registers_t;

#define NUM_SHADOW_TLS_SLOTS (sizeof(shadow_registers_t)/sizeof(reg_t))

static reg_id_t tls_shadow_seg;

static uint tls_shadow_base;

/* we store a pointer for finding shadow regs for other threads */
static int tls_idx_shadow = -1;

#ifdef TOOL_DR_MEMORY
/* For xmm this points at the shadow aux ptr: need a de-ref */
opnd_t
opnd_create_shadow_reg_slot(reg_id_t reg)
{
    uint offs;
    opnd_size_t opsz;
    ASSERT(options.shadowing, "incorrectly called");
    if (reg_is_gpr(reg)) {
        reg_id_t r = reg_to_pointer_sized(reg);
        offs = (r - DR_REG_START_GPR) * sizeof(shadow_reg_type_t);
        opsz = IF_X64(!reg_is_64bit(reg) ? OPSZ_1 :) SHADOW_GPR_OPSZ;
    } else {
        ASSERT(reg_is_xmm(reg) || reg_is_mmx(reg), "internal shadow reg error");
        offs = offsetof(shadow_registers_t, aux);
        opsz = OPSZ_PTR;
    }
    return opnd_create_far_base_disp_ex
        (tls_shadow_seg, REG_NULL, REG_NULL, 1, tls_shadow_base + offs, opsz,
         /* we do NOT want an addr16 prefix since most likely going to run on
          * Core or Core2, and P4 doesn't care that much */
         false, true, false);
}

#ifdef X64
opnd_t
opnd_create_shadow_reg_slot_high_dword(reg_id_t reg)
{
    uint offs;
    reg_id_t r = reg_to_pointer_sized(reg);
    ASSERT(options.shadowing && reg_is_gpr(reg), "incorrectly called");
    offs = (r - DR_REG_START_GPR) * sizeof(shadow_reg_type_t) + 1/*little-endian*/;
    return opnd_create_far_base_disp_ex
        (tls_shadow_seg, REG_NULL, REG_NULL, 1, tls_shadow_base + offs, OPSZ_1,
         false, true, false);
}
#endif

uint
get_shadow_xmm_offs(reg_id_t reg)
{
#ifdef X86
    if (reg_is_ymm(reg))
        return offsetof(shadow_aux_registers_t, ymmh) + sizeof(int)*(reg - DR_REG_YMM0);
    if (reg_is_xmm(reg))
        return offsetof(shadow_aux_registers_t, xmm) + sizeof(int)*(reg - DR_REG_XMM0);
    else {
        ASSERT(reg_is_mmx(reg), "invalid reg");
        return offsetof(shadow_aux_registers_t, mm) + sizeof(short)*(reg - DR_REG_MM0);
    }
#else
    /* FIXME i#1726: port to ARM: shadow SIMD regs */
    ASSERT_NOT_IMPLEMENTED();
    return 0;
#endif
}

opnd_t
opnd_create_shadow_eflags_slot(void)
{
    ASSERT(options.shadowing, "incorrectly called");
    return opnd_create_far_base_disp_ex
        (tls_shadow_seg, REG_NULL, REG_NULL, 1, tls_shadow_base +
         offsetof(shadow_registers_t, eflags), SHADOW_GPR_OPSZ,
         /* we do NOT want an addr16 prefix since most likely going to run on
          * Core or Core2, and P4 doesn't care that much */
         false, true, false);
}

/* Opnd to acquire in_heap_routine TLS counter. Used for PR 578892. */
opnd_t
opnd_create_shadow_inheap_slot(void)
{
    ASSERT(options.shadowing, "incorrectly called");
    return opnd_create_far_base_disp_ex
        (tls_shadow_seg, REG_NULL, REG_NULL, 1, tls_shadow_base +
         offsetof(shadow_registers_t, in_heap_routine), OPSZ_1,
         /* we do NOT want an addr16 prefix since most likely going to run on
          * Core or Core2, and P4 doesn't care that much */
         false, true, false);
}
#endif /* TOOL_DR_MEMORY */

#if defined(TOOL_DR_MEMORY) || defined(WINDOWS)
static shadow_registers_t *
get_shadow_registers(void)
{
    byte *seg_base;
    ASSERT(options.shadowing, "incorrectly called");
    seg_base = get_own_seg_base();
    return (shadow_registers_t *)(seg_base + tls_shadow_base);
}
#endif /* TOOL_DR_MEMORY || WINDOWS */

static void
shadow_registers_thread_init(void *drcontext)
{
#ifdef TOOL_DR_MEMORY
    static bool first_thread = true;
    shadow_aux_registers_t *aux;
#endif
    shadow_registers_t *sr;
#ifdef UNIX
    sr = (shadow_registers_t *)
        (dr_get_dr_segment_base(tls_shadow_seg) + tls_shadow_base);
#else
    sr = get_shadow_registers();
#endif
#ifdef TOOL_DR_MEMORY
    aux = thread_alloc(drcontext, sizeof(*sr->aux), HEAPSTAT_SHADOW);
    if (first_thread ||
        /* If the app created other threads early before DR took over, we
         * have to treat everything as defined.
         */
        !first_bb) {
        first_thread = false;
        /* since we're in late, we consider everything defined
         * (if we were in at init APC, only stack pointer would be defined) */
        memset(sr, SHADOW_DWORD_DEFINED, sizeof(*sr));
        sr->aux = aux;
        memset(sr->aux, SHADOW_DWORD_DEFINED, sizeof(*sr->aux));
        sr->eflags = SHADOW_DEFINED;
    } else {
        /* we are in at start for new threads */
        uint init_shadow = SHADOW_DWORD_UNDEFINED;
#ifdef MACOS
        /* With current late thread takeover (DRi#1403 covers moving it earlier),
         * we have to mark all as defined.
         */
        init_shadow = SHADOW_DWORD_DEFINED;
#endif
        memset(sr, init_shadow, sizeof(*sr));
        sr->aux = aux;
        memset(sr->aux, init_shadow, sizeof(*sr->aux));
        sr->eflags = init_shadow;
#ifdef LINUX
        /* PR 426162: post-clone, esp and eax are defined */
        sr->xsp = SHADOW_PTRSZ_DEFINED;
        sr->xax = SHADOW_PTRSZ_DEFINED;
#elif defined(WINDOWS)
        /* new thread on Windows has esp defined */
        sr->xsp = SHADOW_PTRSZ_DEFINED;
#endif
    }
    sr->in_heap_routine = 0;
#endif /* TOOL_DR_MEMORY */

    /* store in per-thread data struct so we can access from another thread */
    drmgr_set_tls_field(drcontext, tls_idx_shadow, (void *) sr);
}

static void
shadow_registers_thread_exit(void *drcontext)
{
#ifdef TOOL_DR_MEMORY
    shadow_registers_t *sr = (shadow_registers_t *)
        drmgr_get_tls_field(drcontext, tls_idx_shadow);
    thread_free(drcontext, sr->aux, sizeof(*sr->aux), HEAPSTAT_SHADOW);
#endif
    drmgr_set_tls_field(drcontext, tls_idx_shadow, NULL);
}

static void
shadow_registers_init(void)
{
    /* XXX: could save space by not allocating shadow regs for -no_check_uninitialized */
    IF_DEBUG(bool ok =)
        dr_raw_tls_calloc(&tls_shadow_seg, &tls_shadow_base, NUM_SHADOW_TLS_SLOTS, 0);
    tls_idx_shadow = drmgr_register_tls_field();
    ASSERT(tls_idx_shadow > -1, "failed to reserve TLS slot");
    LOG(2, "TLS shadow base: "PIFX"\n", tls_shadow_base);
    ASSERT(ok, "fatal error: unable to reserve tls slots");
#ifdef X86
    ASSERT(tls_shadow_seg == EXPECTED_SEG_TLS, "unexpected tls segment");
#endif
}

static void
shadow_registers_exit(void)
{
    IF_DEBUG(bool ok =)
        dr_raw_tls_cfree(tls_shadow_base, NUM_SHADOW_TLS_SLOTS);
    ASSERT(ok, "WARNING: unable to free tls slots");
    drmgr_unregister_tls_field(tls_idx_shadow);
}

#ifdef TOOL_DR_MEMORY
void
print_shadow_registers(void)
{
    uint i;
    IF_DEBUG(shadow_registers_t *sr = get_shadow_registers());
    ASSERT(options.shadowing, "shouldn't be called");
#ifdef X64
    LOG(0, "    rax=%04x rcx=%04x rdx=%04x rbx=%04x "
        "rsp=%04x rbp=%04x rsi=%04x rdi=%04x\n"
        "    r8 =%04x r9 =%04x r10=%04x r11=%04x "
        "r12=%04x r13=%04x r14=%04x r15=%04x efl=%04x\n",
        sr->xax, sr->xcx, sr->xdx, sr->xbx, sr->xsp, sr->xbp, sr->xsi, sr->xdi,
        sr->r8,  sr->r9,  sr->r10, sr->r11, sr->r12, sr->r13, sr->r14, sr->r15,
        sr->eflags);
#else
    LOG(0, "    eax=%02x ecx=%02x edx=%02x ebx=%02x "
        "esp=%02x ebp=%02x esi=%02x edi=%02x efl=%x\n",
        sr->xax, sr->xcx, sr->xdx, sr->xbx, sr->xsp, sr->xbp,
        sr->xsi, sr->xdi, sr->eflags);
#endif
    for (i = 0; i < NUM_XMM_REGS; i++) {
        if (i % 4 == 0)
            LOG(0, "    ");
        LOG(0, "xmm%d=%08x ", i, sr->aux->xmm[i]);
        if (i % 4 == 3)
            LOG(0, "\n");
    }
    LOG(0, "    ");
    for (i = 0; i < NUM_MMX_REGS; i++) {
        LOG(0, "mm%d=%04x ", i, (unsigned short)sr->aux->mm[i]);
    }
    LOG(0, "\n");
}

static byte *
reg_shadow_addr(shadow_registers_t *sr, reg_id_t reg)
{
    /* REG_NULL means eflags */
    if (reg == REG_NULL)
        return ((byte *)sr) + offsetof(shadow_registers_t, eflags);
    else if (reg_is_gpr(reg)) {
        return ((byte *)sr) +
            (reg_to_pointer_sized(reg) - DR_REG_START_GPR)*sizeof(shadow_reg_type_t);
    } else {
#ifdef X86
        /* Caller must ask for xmm to get low bits (won't all fit in uint) */
        if (reg_is_ymm(reg))
            return (byte *) &sr->aux->ymmh[reg - DR_REG_YMM0];
        if (reg_is_xmm(reg))
            return (byte *) &sr->aux->xmm[reg - DR_REG_XMM0];
        else {
            ASSERT(reg_is_mmx(reg), "invalid reg");
            return (byte *) &sr->aux->mm[reg - DR_REG_MM0];
        }
#else
        /* FIXME i#1726: port to ARM: shadow SIMD regs */
        ASSERT_NOT_IMPLEMENTED();
        return NULL;
#endif
    }
}

static uint
get_shadow_register_common(shadow_registers_t *sr, reg_id_t reg)
{
    uint val;
    opnd_size_t sz = reg_get_size(reg);
    byte *addr = reg_shadow_addr(sr, reg);
    ASSERT(options.shadowing, "incorrectly called");
    if (reg_is_xmm(reg) || reg_is_mmx(reg))
        return *(uint *)addr;
    ASSERT(reg_is_gpr(reg), "internal shadow reg error");
    if (sz == OPSZ_1) {
        val = *addr;
        if (reg_is_8bit_high(reg))
            val = (val & 0xc) >> 2;
        else
            val &= 0x3;
    } else if (sz == OPSZ_2) {
        val = *addr;
        val &= 0xf;
    } else if (sz == OPSZ_4) {
        val = *addr;
    } else if (sz == OPSZ_8) {
        IF_NOT_X86(ASSERT_NOT_REACHED());
        val = *(ushort*)addr;
    } else {
        val = 0;
        ASSERT_NOT_REACHED();
    }
    return val;
}

/* Note that any SHADOW_UNADDRESSABLE bit pairs simply mean it's
 * a sub-register.
 * For ymm registers, returns only the shadow for the high 128 bits --
 * ask for the corresponding xmm to get the low bits.
 */
uint
get_shadow_register(reg_id_t reg)
{
    shadow_registers_t *sr = get_shadow_registers();
    ASSERT(options.shadowing, "incorrectly called");
    return get_shadow_register_common(sr, reg);
}

/* Note that any SHADOW_UNADDRESSABLE bit pairs simply mean it's
 * a sub-register
 */
uint
get_thread_shadow_register(void *drcontext, reg_id_t reg)
{
    shadow_registers_t *sr = (shadow_registers_t *)
        drmgr_get_tls_field(drcontext, tls_idx_shadow);
    ASSERT(options.shadowing, "incorrectly called");
    return get_shadow_register_common(sr, reg);
}

void
register_shadow_set_byte(reg_id_t reg, uint bytenum, uint val)
{
    shadow_registers_t *sr = get_shadow_registers();
    uint shift = bytenum*2;
    byte *addr = reg_shadow_addr(sr, reg);
    ASSERT(options.shadowing, "incorrectly called");
    while (shift > 7) {
        ASSERT(reg_is_xmm(reg) ||
               (shift < 16 IF_NOT_X64(&& reg_is_mmx(reg))), "shift too big for reg");
        addr++;
        shift -= 8;
    }
    *addr = set_2bits_inline(*addr, val, shift);
}

void
register_shadow_set_dword(reg_id_t reg, uint val)
{
    shadow_registers_t *sr = get_shadow_registers();
    byte *addr = reg_shadow_addr(sr, reg);
    ASSERT(options.shadowing, "incorrectly called");
    ASSERT(reg_is_gpr(reg), "internal shadow reg error");
    *addr = (byte) val;
}

#ifdef X64
void
register_shadow_set_qword(reg_id_t reg, uint val)
{
    shadow_registers_t *sr = get_shadow_registers();
    byte *addr = reg_shadow_addr(sr, reg);
    ASSERT(options.shadowing, "incorrectly called");
    ASSERT(reg_is_gpr(reg), "internal shadow reg error");
    *(ushort *)addr = (ushort) val;
}

void
register_shadow_set_high_dword(reg_id_t reg, uint val)
{
    shadow_registers_t *sr = get_shadow_registers();
    byte *addr = reg_shadow_addr(sr, reg);
    ASSERT(options.shadowing, "incorrectly called");
    ASSERT(reg_is_gpr(reg), "internal shadow reg error");
    *(addr+1) = (byte) val; /* little-endian */
}
#endif

void
register_shadow_set_ptrsz(reg_id_t reg, uint val)
{
#ifdef X64
    register_shadow_set_qword(reg, val);
#else
    register_shadow_set_dword(reg, val);
#endif
}

void
register_shadow_set_dqword(reg_id_t reg, uint val)
{
    shadow_registers_t *sr = get_shadow_registers();
    byte *addr = reg_shadow_addr(sr, reg);
    ASSERT(options.shadowing, "incorrectly called");
    ASSERT(reg_is_xmm(reg), "internal shadow reg error");
    *(uint *)addr = val;
}

uint
get_shadow_eflags(void)
{
    shadow_registers_t *sr = get_shadow_registers();
    ASSERT(options.shadowing, "incorrectly called");
    return sr->eflags;
}

void
set_shadow_eflags(uint val)
{
    shadow_registers_t *sr = get_shadow_registers();
    ASSERT(options.shadowing, "incorrectly called");
    sr->eflags = (byte) val;
}

byte
get_shadow_inheap(void)
{
    shadow_registers_t *sr;
    ASSERT(options.shadowing, "incorrectly called");
    sr = get_shadow_registers();
    return sr->in_heap_routine;
}

void
set_shadow_inheap(uint val)
{
    shadow_registers_t *sr;
    ASSERT(options.shadowing, "incorrectly called");
    sr = get_shadow_registers();
    sr->in_heap_routine = (byte) val;
}

/* assumes val was obtained from get_shadow_register(),
 * but should never have unaddressable anyway
 */
bool
is_shadow_register_defined(uint val)
{
    ASSERT(SHADOW_DEFINED == SHADOW_WORD_DEFINED &&
           SHADOW_DEFINED == SHADOW_DWORD_DEFINED &&
           SHADOW_DEFINED == SHADOW_QWORD_DEFINED &&
           SHADOW_DEFINED == SHADOW_DQWORD_DEFINED,
           "if change bit patterns, change here");
    return (val == SHADOW_DEFINED);
}
#endif /* TOOL_DR_MEMORY */

/***************************************************************************/

void
shadow_thread_init(void *drcontext)
{
    shadow_registers_thread_init(drcontext);
}

void
shadow_thread_exit(void *drcontext)
{
    shadow_registers_thread_exit(drcontext);
}

void
shadow_init(void)
{
    ASSERT(options.shadowing, "shadowing disabled");
    shadow_registers_init();
    shadow_table_init();
}

void
shadow_exit(void)
{
    shadow_registers_exit();
    shadow_table_exit();
}

