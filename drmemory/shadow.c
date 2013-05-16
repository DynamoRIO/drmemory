/* **********************************************************
 * Copyright (c) 2010-2013 Google, Inc.  All rights reserved.
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
#include <limits.h> /* UINT_MAX */
#include <stddef.h>
#ifdef TOOL_DR_HEAPSTAT
# include "../drheapstat/staleness.h"
#endif

#include "readwrite.h" /* get_own_seg_base */

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

/* returns non-zero value if bit is set */
static inline bool
bitmap_test(bitmap_t bm, uint i)
{
    return bm[BITMAP_IDX(i)] & BITMAP_MASK(i);
}

static inline void
bitmap_set(bitmap_t bm, uint i)
{
    bm[BITMAP_IDX(i)] |= BITMAP_MASK(i);
}

static inline void
bitmap_clear(bitmap_t bm, uint i)
{
    bm[BITMAP_IDX(i)] &= ~BITMAP_MASK(i);
}

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

/* returns the uint corresponding to offset i */
static inline uint
bytemap_4to1_dword(bitmap_t bm, uint i)
{
    ASSERT(BITMAPx2_SHIFT(i) == 0, "bytemap_4to1_dword: index not aligned");
    return bm[BITMAPx2_IDX(i)];
}

/***************************************************************************
 * MEMORY SHADOWING DATA STRUCTURES
 */

umbra_map_t *umbra_map;

/* 2 shadow bits per app byte */
/* we use Umbra's 4B-to-1B and layer 1B-to-2b on top of that */
#define SHADOW_GRANULARITY 4
#define SHADOW_MAP_SCALE   UMBRA_MAP_SCALE_DOWN_4X
#define SHADOW_DEFAULT_VALUE SHADOW_DWORD_UNADDRESSABLE
#define SHADOW_DEFAULT_VALUE_SIZE 1
#define SHADOW_REDZONE_VALUE SHADOW_DWORD_BITLEVEL
#define SHADOW_REDZONE_VALUE_SIZE 1
#define REDZONE_SIZE 512

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
    uint shadow_type;
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
    idx = ((ptr_uint_t)ALIGN_BACKWARD(addr, 4)) - (ptr_uint_t)info->app_base;
    if (!MAP_4B_TO_1B)
        return bitmapx2_byte((bitmap_t)info->shadow_base, idx);
    else /* just return byte */
        return bytemap_4to1_byte((bitmap_t)info->shadow_base, idx);
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
    /* Note that we can come here for SHADOW_SPECIAL_DEFINED, for mmap
     * regions used for calloc (we mark headers as unaddressable), etc.
     */
    if (info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_SHARED) {
        /* Avoid replacing special on nop write */
        if (val == shadow_get_byte(info, addr)) {
            LOG(5, "writing "PFX" => nop (already special %d)\n", addr, val);
            return;
        }
        /* it is special shared shadow memory, recreate normal shadow memory */
        if (umbra_create_shadow_memory(umbra_map, 0,
                                       info->app_base, info->app_size,
                                       (ptr_uint_t)*(info->shadow_base),
                                       1) != DRMF_SUCCESS)
            ASSERT(false, "fail to create shadow memory");
        if (umbra_get_shadow_memory(umbra_map, addr,
                                    NULL, info) != DRMF_SUCCESS)
            ASSERT(false, "fail to get shadow memory info");
    }
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
    LOG(2, "set range "PFX"-"PFX" => "PIFX"\n", start, end, val);
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

/* Copies the values for each byte in the range [old_start, old_start+end) to
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
    head_bit = (ptr_uint_t)old_start % SHADOW_GRANULARITY;
    /* special case like shadow_copy_range(0x1003, 0x1001, 100),
     * cannot be handled using shadow_set_byte(.. shadow_get_byte) or copy.
     */
    ASSERT(head_bit == ((ptr_uint_t)new_start % SHADOW_GRANULARITY),
           "miss aligned app address");
    old_end  = old_start + size;
    tail_bit = (ptr_uint_t)old_end % SHADOW_GRANULARITY;
    /* It is 1B-2-2b mapping and umbra only support full byte copy, so we have
     * to handle the unaligned byte copy.
     */
    /* XXX: maybe umbra should support partial byte update and the code can be
     * moved into umbra.
     */
    umbra_shadow_memory_info_init(&info_src);
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
            ASSERT(false, "fale to copy shadow memory");
    }
    umbra_shadow_memory_info_init(&info_dst);
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
        ASSERT(false, "fail to check value in shadow mmeory");
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

/* We keep our shadow register bits in TLS */
typedef struct _shadow_registers_t {
#ifdef TOOL_DR_MEMORY
    /* First 4-byte TLS slot */
    byte eax;
    byte ecx;
    byte edx;
    byte ebx;
    /* Second 4-byte TLS slot */
    byte esp;
    byte ebp;
    byte esi;
    byte edi;
    /* Third 4-byte TLS slot.  We go ahead and write DWORD values here
     * for simplicity in our fastpath even though we treat this as
     * a single tracked value.
     */
    byte eflags;
    /* Used for PR 578892.  Should remain a very small integer so byte is fine. */
    byte in_heap_routine;
    byte padding[2];
#else
    /* Avoid empty struct.  FIXME: this is a waste of a tls slot */
    void *bogus;
#endif
} shadow_registers_t;

#define NUM_SHADOW_TLS_SLOTS (sizeof(shadow_registers_t)/sizeof(reg_t))

static uint tls_shadow_base;

/* we store a pointer for finding shadow regs for other threads */
static int tls_idx_shadow = -1;

#ifdef TOOL_DR_MEMORY
opnd_t
opnd_create_shadow_reg_slot(reg_id_t reg)
{
    reg_id_t r = reg_to_pointer_sized(reg);
    ASSERT(options.shadowing, "incorrectly called");
    ASSERT(reg_is_gpr(reg), "internal shadow reg error");
    return opnd_create_far_base_disp_ex
        (SEG_FS, REG_NULL, REG_NULL, 1, tls_shadow_base + (r - REG_EAX), OPSZ_1,
         /* we do NOT want an addr16 prefix since most likely going to run on
          * Core or Core2, and P4 doesn't care that much */
         false, true, false);
}

opnd_t
opnd_create_shadow_eflags_slot(void)
{
    ASSERT(options.shadowing, "incorrectly called");
    return opnd_create_far_base_disp_ex
        (SEG_FS, REG_NULL, REG_NULL, 1, tls_shadow_base +
         offsetof(shadow_registers_t, eflags), OPSZ_1,
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
        (SEG_FS, REG_NULL, REG_NULL, 1, tls_shadow_base +
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
#endif
    shadow_registers_t *sr;
#ifdef LINUX
    sr = (shadow_registers_t *)
        (dr_get_dr_segment_base(IF_X64_ELSE(SEG_GS, SEG_FS)) + tls_shadow_base);
#else
    sr = get_shadow_registers();
#endif
#ifdef TOOL_DR_MEMORY
    if (first_thread) {
        first_thread = false;
        /* since we're in late, we consider everything defined
         * (if we were in at init APC, only stack pointer would be defined) */
        memset(sr, SHADOW_DWORD_DEFINED, sizeof(*sr));
        sr->eflags = SHADOW_DEFINED;
    } else {
        /* we are in at start for new threads */
        memset(sr, SHADOW_DWORD_UNDEFINED, sizeof(*sr));
        sr->eflags = SHADOW_UNDEFINED;
#ifdef LINUX
        /* PR 426162: post-clone, esp and eax are defined */
        sr->esp = SHADOW_DWORD_DEFINED;
        sr->eax = SHADOW_DWORD_DEFINED;
#else
        /* new thread on Windows has esp defined */
        sr->esp = SHADOW_DWORD_DEFINED;
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
    drmgr_set_tls_field(drcontext, tls_idx_shadow, NULL);
}

static void
shadow_registers_init(void)
{
    reg_id_t seg;
    /* XXX: could save space by not allocating shadow regs for -no_check_uninitialized */
    IF_DEBUG(bool ok =)
        dr_raw_tls_calloc(&seg, &tls_shadow_base, NUM_SHADOW_TLS_SLOTS, 0);
    tls_idx_shadow = drmgr_register_tls_field();
    ASSERT(tls_idx_shadow > -1, "failed to reserve TLS slot");
    LOG(2, "TLS shadow base: "PIFX"\n", tls_shadow_base);
    ASSERT(ok, "fatal error: unable to reserve tls slots");
    ASSERT(seg == IF_X64_ELSE(SEG_GS, SEG_FS), "unexpected tls segment");
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
    IF_DEBUG(shadow_registers_t *sr = get_shadow_registers());
    ASSERT(options.shadowing, "shouldn't be called");
    LOG(0, "    eax=%02x ecx=%02x edx=%02x ebx=%02x "
        "esp=%02x ebp=%02x esi=%02x edi=%02x efl=%x\n",
        sr->eax, sr->ecx, sr->edx, sr->ebx, sr->esp, sr->ebp,
        sr->esi, sr->edi, sr->eflags);
}

static uint
reg_shadow_offs(reg_id_t reg)
{
    /* REG_NULL means eflags */
    if (reg == REG_NULL)
        return offsetof(shadow_registers_t, eflags);
    else
        return (reg_to_pointer_sized(reg) - REG_EAX);
}

static byte
get_shadow_register_common(shadow_registers_t *sr, reg_id_t reg)
{
    byte val;
    opnd_size_t sz = reg_get_size(reg);
    ASSERT(options.shadowing, "incorrectly called");
    ASSERT(reg_is_gpr(reg), "internal shadow reg error");
    val = *(((byte*)sr) + reg_shadow_offs(reg));
    if (sz == OPSZ_1)
        val &= 0x3;
    else if (sz == OPSZ_2)
        val &= 0xf;
    else
        ASSERT(sz == OPSZ_4, "internal shadow reg error");
    return val;
}

/* Note that any SHADOW_UNADDRESSABLE bit pairs simply mean it's
 * a sub-register
 */
byte
get_shadow_register(reg_id_t reg)
{
    shadow_registers_t *sr = get_shadow_registers();
    ASSERT(options.shadowing, "incorrectly called");
    return get_shadow_register_common(sr, reg);
}

/* Note that any SHADOW_UNADDRESSABLE bit pairs simply mean it's
 * a sub-register
 */
byte
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
    byte *addr;
    ASSERT(options.shadowing, "incorrectly called");
    ASSERT(reg_is_gpr(reg), "internal shadow reg error");
    addr = ((byte*)sr) + reg_shadow_offs(reg);
    *addr = set_2bits_inline(*addr, val, shift);
}

void
register_shadow_set_dword(reg_id_t reg, uint val)
{
    shadow_registers_t *sr = get_shadow_registers();
    byte *addr;
    ASSERT(options.shadowing, "incorrectly called");
    ASSERT(reg_is_gpr(reg), "internal shadow reg error");
    addr = ((byte*)sr) + reg_shadow_offs(reg);
    *addr = (byte) val;
}

byte
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
is_shadow_register_defined(byte val)
{
    return (val == SHADOW_DEFINED ||
            val == SHADOW_WORD_DEFINED ||
            val == SHADOW_DWORD_DEFINED);
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

