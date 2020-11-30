/* **********************************************************
 * Copyright (c) 2013-2020 Google, Inc.  All rights reserved.
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

/* umbra_x64.c
 *
 * Umbra x64 architecture specific code.
 * In x64 architecture, we used a direct mapping approach.
 */

#include "dr_api.h"
#include "umbra.h"
#include "umbra_private.h"
#include "drmemory_framework.h"
#include "../framework/drmf.h"
#include "utils.h"
#include <string.h> /* for memchr */

#ifndef X64
# error x64 only
#endif

/***************************************************************************
 * x64 Shadow Memory Mapping Scheme Description:
 *
 * The usual application memory layout is shown below:
 * Windows 8 and below:
 *   app1: [0x00000000'00000000, 0x00000010'00000000): exec, heap, data
 *   app2: [0x000007F0'00000000, 0x00000800'00000000): lib ...
 * 1B-to-1B mapping:
 *   SHDW(app) = (app & 0x000000FF'FFFFFFFF) + 0x00000020'00000000)
 * and the result:
 *   shdw1 = SHDW(app1): [0x00000020'00000000, 0x00000030'00000000)
 *   shdw2 = SHDW(app2): [0x00000110'00000000, 0x00000120'00000000)
 * and
 *   shdw1'= SHDW(shdw1): [0x00000040'00000000, 0x00000050'00000000)
 *   shdw2'= SHDW(shdw2): [0x00000030'00000000, 0x00000040'00000000)
 * Here we call [0x00000000'00000000, 0x00000100'00000000) a unit, and each unit
 * has 16 (NUM_SEGMENTS = 0x100'00000000/0x10'00000000) segments
 * with size of 0x10'00000000.
 *
 * Windows 8.1 and above have locale.nls and stacks at locations above
 * 0x10' (i#1810): they carve out two regions inside 0x10'-0x300' which
 * we merge with the bottom region:
 *   app1: [0x00000000'00000000, 0x00000300'00000000): exec, heap, data
 *   app2: [0x00007C00'00000000, 0x00008000'00000000): libs
 * 1B-to-1B mapping:
 *   SHDW(app) = (app & 0x00000FFF'FFFFFFFF) + 0x00000700'00000000)
 * and the result:
 *   shdw1 = SHDW(app1): [0x00000700'00000000, 0x00000a00'00000000)
 *   shdw2 = SHDW(app2): [0x00001300'00000000, 0x00001700'00000000)
 * and
 *   shdw1'= SHDW(shdw1): [0x00000e00'00000000, 0x00001100'00000000)
 *   shdw2'= SHDW(shdw2): [0x00000a00'00000000, 0x00000e00'00000000)
 * Here we call [0x00000000'00000000, 0x00001000'00000000) a unit, and each
 * unit has 16 segments with size of 0x100'00000000.  Note that we do allow
 * multi-segment regions.
 *
 * Linux:
 * app1: [0x00000000'00000000, 0x00000100'00000000): exec, heap, data
 * app2: [0x00005500'00000000, 0x00005700'00000000): pie
 * app3: [0x00007F00'00000000, 0x00008000'00000000): lib, map, stack, vdso
 * app4: [0xFFFFFFFF'FF600000, 0xFFFFFFFF'FF601000]: vsyscall
 * With newer kernels, the PIE range is [0x5555'55555000, 0x5655'55555000) minus
 * the PT_LOAD base, which presumably could be anything.  However, we assume we're
 * doing full-control mode where DR itself is the PIE and that DR's PT_LOAD is
 * something small with top 32 bits all 0.
 *
 * 1B-to-1B mapping:
 *   SHDW(app) = (app & 0x00000FFF'FFFFFFFF) + 0x00001200'00000000)
 * and the result:
 * shdw1 = SHDW(app1): [0x00001200'00000000, 0x00001300'00000000)
 * shdw2 = SHDW(app2): [0x00001700'00000000, 0x00001900'00000000)
 * shdw3 = SHDW(app3): [0x00002100'00000000, 0x00002200'00000000)
 * shdw4 = SHDW(app4): [0x000021FF'F0000000, 0x000021FF'FF601000]
 * and
 * shdw1'= SHDW(shdw1): [0x00001400'00000000, 0x00001500'00000000)
 * shdw2'= SHDW(shdw2): [0x00001900'00000000, 0x00001B00'00000000)
 * shdw3'= SHDW(shdw3): [0x00001300'00000000, 0x00001400'00000000]
 * shdw4'= SHDW(shdw4): [0x000013FF'F0000000, 0x000013FF'FF601000]
 *
 * Here we call [0x00000000'00000000, 0x00001000'00000000) a unit, and each
 * unit has 16 segments with size of 0x100'00000000.
 * It is possible to adjust the number of segments per unit or the
 * unit/segment size.
 *
 *
 * If we pack the application memory into one unit by zeroing out the higher
 * bits:
 * - the application data are in two segments without conflict;
 * - their shadow data are in two segments without conflict;
 * - the shadow's shadow are in another two segments.
 * In other words, there is no conflict if we zero out the high bits and
 * only keep the low bits.
 * Moreover, the shadow address of a shadow address is an invalid address!
 * An extra layer of protection.
 *
 * For scaling up or down:
 * Windows 8.1+:
 * For scale down 2X:
 *  SHDW(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00000800'00000000) >> 1
 *   SHDW(app1): [0x00000400'00000000, 0x00000580'00000000)
 *   SHDW(app2): [0x00000a00'00000000, 0x00000c00'00000000)
 *   SHDW(shdw1): [0x00000600'00000000, 0x000006c0'00000000)
 *   SHDW(shdw2): [0x00000900'00000000, 0x00000a00'00000000)
 * For scale down 4X:
 *  SHDW(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00001c00'00000000) >> 2
 *   SHDW(app1): [0x00000700'00000000, 0x000007c0'00000000)
 *   SHDW(app2): [0x00000a00'00000000, 0x00000b00'00000000)
 *   SHDW(shdw1): [0x000008c0'00000000, 0x000008f0'00000000)
 *   SHDW(shdw2): [0x00000980'00000000, 0x000009c0'00000000)
 * For scale down 8X:
 *  SHDW(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00003800'00000000) >> 3
 *   SHDW(app1): [0x00000700'00000000, 0x00000760'00000000)
 *   SHDW(app2): [0x00000880'00000000, 0x00000900'00000000)
 *   SHDW(shdw1): [0x000007e0'00000000, 0x000007ec'00000000)
 *   SHDW(shdw2): [0x00000810'00000000, 0x00000820'00000000)
 * For scale up 2X:
 *  SHDW(app) = ((app & 0x000001FF'FFFFFFFF) + 0x00000580'00000000) << 1
 *   SHDW(app1): [0x00000b00'00000000, 0x00001100'00000000)
 *   SHDW(app2): [0x00004300'00000000, 0x00004b00'00000000)
 *   SHDW(shdw1): [0x00001100'00000000, 0x00002100'00000000)
 *   SHDW(shdw2): [0x00002100'00000000, 0x00002d00'00000000)
 *
 * Similar for Linux: xref i#1782 about the disp value
 * For scale down 2X:
 *  SHDW(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00002200'00000000) >> 1
 * For scale down 4X:
 *  SHDW(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00004400'00000000) >> 2
 * For scale down 8X:
 *  SHDW(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00009000'00000000) >> 3
 * For scale up 2X:
 *  if the PIE in 0x5500' segment:
 *  SHDW(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00000480'00000000) << 1
 *  if the PIE in 0x5600' segment
 *  SHDW(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00000380'00000000) << 1
 *  xref i#1799 about the PIE spanning the segment gap.
 *
 * For multiple maps:
 *  We only need put them into different units.
 *  If only one unit apart, there might be conflict for supporting
 *  different scale mappings, so at least 2 units apart is necessary.
 *  For example, on Windows:
 *  Two 1B-to-1B mapping:
 *    SHDW1(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00000020'00000000)
 *    SHDW2(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00000220'00000000)
 *  Two 8B-to-1B mapping:
 *    SHDW1(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00000100'00000000) >> 3
 *    SHDW2(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00001100'00000000) >> 3
 *  Two 4B-to-1B mapping:
 *    SHDW1(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00000080'00000000) >> 2
 *    SHDW2(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00000880'00000000) >> 2
 *  Two 2B-to-1B mapping:
 *    SHDW1(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00000040'00000000) >> 1
 *    SHDW2(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00000440'00000000) >> 1
 *  Two 1B-to-2B mapping:
 *    SHDW1(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00000018'00000000) << 1
 *    SHDW2(app) = ((app & 0x000000FF'FFFFFFFF) + 0x00000118'00000000) << 1
 *
 *  Similarly, on Linux:
 *  Two 1B-to-1B mapping:
 *    SHDW1(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00001200'00000000)
 *    SHDW2(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00003200'00000000)
 *    app1: [000, 100)   => [1200, 1300) => [1400, 1500)
 *                          [3200, 3300) => [3400, 3500)
 *    app2: [500, 700)   => [1700, 1900) => [1900, 1B00)
 *                          [3700, 3900) => [3900, 3B00)
 *    app3: [7F00, 8000) => [2100, 2200) => [1300, 1400)
 *                          [4100, 4200) => [4300, 4400)
 *  Two 8B-to-1B mapping:
 *    SHDW1(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00009000'00000000) >> 3
 *    SHDW2(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00019000'00000000) >> 3
 *    app1: [000, 100)   => [1200, 1220) => [1240, 1244)
 *                          [3200, 3220) => [3240, 3244)
 *    app2: [500, 700)   => [12A0, 12E0) => [1254, 125C)
 *                          [32A0, 32E0) => [3254, 325C)
 *    app3: [7F00, 8000) => [13E0, 1400) => [127C, 1280)
 *                          [33E0, 3400) => [327C, 3280)
 *  Two 4B-to-1B mapping:
 *    SHDW1(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00004400'00000000) >> 2
 *    SHDW2(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x0000c400'00000000) >> 2
 *    app1: [000, 100)   => [1100, 1140) => [1140, 1150)
 *                          [3100, 3140) => [3340, 3350)
 *    app2: [500, 700)   => [1240, 12C0) => [1190, 11B0)
 *                          [3240, 32C0) => [3190, 31B0)
 *    app3: [7F00, 8000) => [14C0, 1500) => [1230, 1240)
 *                          [36C0, 3500) => [3230, 3240)
 *  Two 2B-to-1B mapping:
 *    SHDW1(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00002200'00000000) >> 1
 *    SHDW2(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00006200'00000000) >> 1
 *    app1: [000, 100)   => [1100, 1180) => [1180, 11C0)
 *                          [3100, 3180) => [3180, 31C0)
 *    app2: [500, 700)   => [1380, 1480) => [12C0, 1340)
 *                          [3380, 3480) => [32C0, 3340)
 *    app3: [7F00, 8000) => [1880, 1900) => [1540, 1580)
 *                          [3880, 3900) => [3540, 3580)
 *  Two 1B-to-2B mapping:
 *    if pie in 0x5500' segment:
 *    SHDW1(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00000480'00000000) << 1
 *    SHDW2(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00001480'00000000) << 1
 *    app1: [000, 100)   => [ 900,  B00) => [1B00, 1F00)
 *                          [2900, 2B00) => [3B00, 3F00)
 *    app2: [500, 600)   => [1300, 1500) => [ F00, 1300)
 *                          [3300, 3500) => [2F00, 3300)
 *    app3: [7F00, 8000) => [2700, 2900) => [1700, 1B00)
 *                          [4700, 4900) => [3700, 3B00)
 *    if pie at 0x5600' segment:
 *    SHDW1(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00000580'00000000) << 1
 *    SHDW2(app) = ((app & 0x00000FFF'FFFFFFFF) + 0x00001580'00000000) << 1
 *    app1: [000, 100)   => [ B00,  D00) => [2100, 1500)
 *                          [2B00, 2D00) => [4100, 4500)
 *    app2: [600, 700)   => [1700, 1900) => [1900, 1D00)
 *                          [3700, 3900) => [3900, 3D00)
 *    app3: [7F00, 8000) => [2900, 2B00) => [1D00, 2100)
 *                          [4900, 4B00) => [3D00, 4100)
 */

/***************************************************************************
 * ENUM AND DATA STRUCTURES
 */

#ifdef UNIX
/* For SHDW(app) = (app & 0x00000FFF'FFFFFFFF) + 0x00001200'00000000),
 * the segment size is: 0x100'00000000, i.e., 40 bits,
 * and there are 16 (0x1000'00000000/0x100'00000000) segments per unit.
 */
# define NUM_SEG_BITS     40
#else
/* For SHDW(app) = (app & 0x000000FF'FFFFFFFF) + 0x00000020'00000000),
 * the segment size is: 0x10'00000000, i.e., 36 bits.
 * and there are 16 (0x100'00000000/0x10'00000000) segments per unit.
 */
# define NUM_SEG_BITS_WIN8     36
# define NUM_SEG_BITS_WIN8_1   40
#endif

static uint num_seg_bits;

#ifdef WINDOWS
static dr_os_version_info_t os_version = {sizeof(os_version),};
#endif

/* Each unit has 16 segments, which could be used for app or shadow. */
#define NUM_SEGMENTS      16 /* 16 segments per unit */

static ptr_uint_t seg_index_mask(uint num_seg_bits)
{
    return (ptr_uint_t)(NUM_SEGMENTS - 1) << num_seg_bits;
}

static ptr_uint_t segment_size(uint num_seg_bits)
{
    return (ptr_uint_t)0x1 << num_seg_bits;
}

static ptr_uint_t segment_mask(uint num_seg_bits)
{
    return segment_size(num_seg_bits) - 1;
}

static ptr_uint_t segment_base(uint num_seg_bits, app_pc pc)
{
    return (ptr_uint_t)pc & ~segment_mask(num_seg_bits);
}

/* we pick 64KB because it is the minmal Windows kernel alloc size */
#define ALLOC_UNIT_SIZE   (1 << 16) /* 64KB */

#define BIT_PER_BYTE 8
#define BITMAP_BYTE_INDEX(map, addr, base) \
    (((addr) - (base)) / ((map)->shadow_block_size * BIT_PER_BYTE))
#define BITMAP_BIT_INDEX(map, addr, base)  \
    ((ptr_uint_t)(((addr) - (base)) / (ptr_uint_t)(map)->shadow_block_size) & \
     (ptr_uint_t)(BIT_PER_BYTE - 1))

typedef struct _app_segment_t {
    /* app segment range */
    app_pc app_base;
    app_pc app_end;
    bool   app_used; /* is this segment used */
    /* shadow memory range */
    byte  *shadow_base[MAX_NUM_MAPS];
    byte  *shadow_end[MAX_NUM_MAPS];
    /* We do not allocate all shadow memory up front to reduce memory usage,
     * instead, we allocate a chunk (64KB or lager) at a time and use
     * bitmap to track if shadow memory is allocated.
     */
    byte  *shadow_bitmap[MAX_NUM_MAPS];
    /* for shadow's shadow */
    byte  *reserve_base[MAX_NUM_MAPS];
    byte  *reserve_end[MAX_NUM_MAPS];
    umbra_map_t *map[MAX_NUM_MAPS];
} app_segment_t;

#ifdef UNIX /* TODO i#1438: Update for Mac64. */
# define PIE_DEF_SEGMENT       (app_pc)((ptr_uint_t)0x55 << NUM_SEG_BITS)
# define PIE_DEF_SEG_2X_DISP   ((ptr_uint_t)0x48 << 36)
# define PIE_ALT_SEGMENT       (app_pc)((ptr_uint_t)0x56 << NUM_SEG_BITS)
# define PIE_ALT_SEG_2X_DISP   ((ptr_uint_t)0x58 << 36)
#endif

static ptr_uint_t map_disp[] = {
#ifdef WINDOWS
# define WIN8_BASE_DISP  0x02000000000
    /* These are for up through Win8. */
    (WIN8_BASE_DISP)<<3, /* UMBRA_MAP_SCALE_DOWN_8X */
    (WIN8_BASE_DISP)<<2, /* UMBRA_MAP_SCALE_DOWN_4X */
    (WIN8_BASE_DISP)<<1, /* UMBRA_MAP_SCALE_DOWN_2X */
    (WIN8_BASE_DISP),    /* UMBRA_MAP_SCALE_SAME_1X */
    (0x03000000000)>>1,  /* UMBRA_MAP_SCALE_UP_2X */
#else /* UNIX */
    0x0000900000000000,  /* UMBRA_MAP_SCALE_DOWN_8X */
    0x0000440000000000,  /* UMBRA_MAP_SCALE_DOWN_4X */
    0x0000220000000000,  /* UMBRA_MAP_SCALE_DOWN_2X */
    0x0000120000000000,  /* UMBRA_MAP_SCALE_SAME_1X */
    PIE_DEF_SEG_2X_DISP, /* UMBRA_MAP_SCALE_UP_2X */
#endif
};

#ifdef WINDOWS
# define WIN81_BASE_DISP 0x70000000000
/* 0x700' does not work for DOWN_2X where reserve overlaps shadow. */
# define WIN81_BASE_DISP_DOWN2 0x40000000000
/* 0x700' also does not work for UP_2X. */
# define WIN81_BASE_DISP_UP2 0xb0000000000
static ptr_uint_t map_disp_win81[] = {
    (WIN81_BASE_DISP)<<3, /* UMBRA_MAP_SCALE_DOWN_8X */
    (WIN81_BASE_DISP)<<2, /* UMBRA_MAP_SCALE_DOWN_4X */
    (WIN81_BASE_DISP_DOWN2)<<1, /* UMBRA_MAP_SCALE_DOWN_2X */
    (WIN81_BASE_DISP),    /* UMBRA_MAP_SCALE_SAME_1X */
    (WIN81_BASE_DISP_UP2)>>1, /* UMBRA_MAP_SCALE_UP_2X */
};
#endif

/* List all the mappings we support, no other app segment is allowed.
 * We check conflicts later when creating shadow memory.
 */
#ifdef LINUX
static const app_segment_t app_segments_initial[] = {
    /* We split app3 [0x7F0000000000, 0x800000000000) into two parts:
     * [0x7F0000000000, 0x7FFFFF400000) and [0x7FFFFF800000, 0x800000000000).
     * And we skip [0x7FFFFF400000-0x7FFFFF800000)
     * for app4 [0xFFFFFFFFFF400000,  0xFFFFFFFFFF800000) because current
     * mapping schema maps app3 and app4 to the same segment.
     * We cannot use smaller size due to the block allocation size
     * (ALLOC_UNIT_SIZE) and the correspoinding bitmap for the shadow memory
     * allocation tracking.
     *
     * We assume [0x7FFFFF400000-0x7FFFFF800000) will not be used by app.
     * If app allocates memory from that region, umbra_add_app_segment
     * will fail because umbra_add_shadow_segment fails to add corresponding
     * shadow memory segment.
     * FIXME i#1782, i#1798: we can proactively track memory allocation and
     * use more expensive instrumentation when necessary to get rid of the
     * assumption and segment split.
     */
    /* app3: part 1 */
    {(app_pc)0x00007F0000000000,  (app_pc)0x00007FFFFF400000, 0},
    /* app4: [0xFFFFFFFF'FF600000, 0xFFFFFFFF'FF601000] */
    {(app_pc)0xFFFFFFFFFF400000,  (app_pc)0xFFFFFFFFFF800000, 0},
    /* app3: part 2 */
    {(app_pc)0x00007FFFFF800000,  (app_pc)0x0000800000000000, 0},
    /* for all additional segments */
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
};
#else
static const app_segment_t app_segments_initial[] = {
    /* for all additional segments */
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
};
# ifdef WINDOWS
static const app_segment_t app_segments_initial_81[] = {
    {(app_pc)0x0000000000000000,  (app_pc)0x0000030000000000, 0},
    /* To ensure we cover large mappings such as from Control Flow Guard without
     * first creating too-small entries, we have one large upper region covering
     * multiple segments.  We only support this for Win8.1+.
     */
    {(app_pc)0x00007C0000000000,  (app_pc)0x0000800000000000, 0},
    /* for all additional segments */
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
    { NULL, NULL, 0 },
};
# endif
#endif
#define MAX_NUM_APP_SEGMENTS sizeof(app_segments_initial)/sizeof(app_segments_initial[0])
static app_segment_t app_segments[MAX_NUM_APP_SEGMENTS];

/***************************************************************************
 * UTILITY ROUTINES
 */
static byte *
umbra_xl8_app_to_shadow(const umbra_map_t *map, app_pc pc)
{
    ptr_uint_t addr;
    addr = ((ptr_uint_t)pc & map->mask) + map->disp;
    /* special handling on case like 0x800'00000000 & 0xff'ffffffff */
    if (pc != 0 && addr == map->disp)
        addr += (map->mask + 1);
    switch (map->options.scale) {
    case UMBRA_MAP_SCALE_DOWN_8X:
        addr >>= 3;
        break;
    case UMBRA_MAP_SCALE_DOWN_4X:
        addr >>= 2;
        break;
    case UMBRA_MAP_SCALE_DOWN_2X:
        addr >>= 1;
        break;
    case UMBRA_MAP_SCALE_SAME_1X:
        break;
    case UMBRA_MAP_SCALE_UP_2X:
        addr <<= 1;
        break;
    default:
        ASSERT(false, "invalid scale");
    }
    return (byte *)addr;
}

/***************************************************************************
 * SEGMENT ROUTINES
 */
static bool
segment_overlap(app_pc base1, app_pc end1, app_pc base2, app_pc end2)
{
    /* one of the segment is not initialized yet */
    if (end1 == NULL || end2 == NULL)
        return false;
    ASSERT(end1 > base1 && end2 > base2, "invalid segment range");
    return !(base1 >= end2 || base2 >= end1);
}

static bool
umbra_add_shadow_segment(umbra_map_t *map, app_segment_t *seg)
{
    size_t size;
    uint i, seg_map_idx = map->index;
    seg->shadow_base[seg_map_idx] =
        umbra_xl8_app_to_shadow(map, seg->app_base);
    seg->shadow_end[seg_map_idx]  =
        umbra_xl8_app_to_shadow(map, seg->app_end);
    ASSERT(seg->shadow_end[seg_map_idx] > seg->shadow_base[seg_map_idx],
           "wrong shadow segment range");
    size = seg->shadow_end[seg_map_idx] - seg->shadow_base[seg_map_idx];
    size = size / map->shadow_block_size / BIT_PER_BYTE;
    seg->shadow_bitmap[seg_map_idx] = global_alloc(size, HEAPSTAT_SHADOW);
    memset(seg->shadow_bitmap[seg_map_idx], 0, size);
    seg->reserve_base[seg_map_idx] =
        umbra_xl8_app_to_shadow(map, seg->shadow_base[seg_map_idx]);
    seg->reserve_end[seg_map_idx] =
        umbra_xl8_app_to_shadow(map, seg->shadow_end[seg_map_idx]);
    seg->map[seg_map_idx] = map;
    /* check conflicts:
     * we only check conflicts in the same umbra map and assume no conflict
     * cross maps since they should be in different units.
     */
    for (i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        app_pc base, end;
        uint   map_idx;
        if (!app_segments[i].app_used)
            continue;
        /* new app-seg vs other app-seg's shadow and reserve */
        base = seg->app_base;
        end  = seg->app_end;
        for (map_idx = 0; map_idx < MAX_NUM_MAPS; map_idx++) {
            if (app_segments[i].map[map_idx] == NULL)
                continue;
            if (segment_overlap(base, end,
                                app_segments[i].shadow_base[map_idx],
                                app_segments[i].shadow_end[map_idx]) ||
                segment_overlap(base, end,
                                app_segments[i].reserve_base[map_idx],
                                app_segments[i].reserve_end[map_idx])) {
                ELOG(1, "ERROR: new app segment ["PFX", "PFX")"
                     " conflicts with app seg ["PFX", "PFX") or its "
                     "shadow ["PFX", "PFX") or reserve ["PFX", "PFX")\n",
                     seg->app_base, seg->app_end,
                     app_segments[i].app_base, app_segments[i].app_end,
                     app_segments[i].shadow_base[map_idx],
                     app_segments[i].shadow_end[map_idx],
                     app_segments[i].reserve_base[map_idx],
                     app_segments[i].reserve_end[map_idx]);
                return false;
            }
        }
        /* new app-seg's shadow vs other app-seg's app, shadow and reserve */
        base = seg->shadow_base[seg_map_idx];
        end  = seg->shadow_end[seg_map_idx];
        for (map_idx = 0; map_idx < MAX_NUM_MAPS; map_idx++) {
            if (app_segments[i].map[map_idx] == NULL)
                continue;
            if (segment_overlap(base, end,
                                app_segments[i].app_base,
                                app_segments[i].app_end) ||
                (seg != &app_segments[i] &&
                 segment_overlap(base, end,
                                 app_segments[i].shadow_base[map_idx],
                                 app_segments[i].shadow_end[map_idx])) ||
                segment_overlap(base, end,
                                app_segments[i].reserve_base[map_idx],
                                app_segments[i].reserve_end[map_idx])) {
                ELOG(1, "ERROR: new app segment ["PFX", "PFX")'s shadow segment "
                     "["PFX", "PFX") conflicts with app seg ["PFX", "PFX") or its "
                     "shadow ["PFX", "PFX") or reserve ["PFX", "PFX")\n",
                     seg->app_base, seg->app_end, base, end,
                     app_segments[i].app_base, app_segments[i].app_end,
                     app_segments[i].shadow_base[map_idx],
                     app_segments[i].shadow_end[map_idx],
                     app_segments[i].reserve_base[map_idx],
                     app_segments[i].reserve_end[map_idx]);
                return false;
            }
        }
        /* new app-seg's reserve vs other app-seg's app and shadow
         * it is ok to overlap with other's reserve.
         */
        base = seg->reserve_base[seg_map_idx];
        end  = seg->reserve_end[seg_map_idx];
        for (map_idx = 0; map_idx < MAX_NUM_MAPS; map_idx++) {
            if (app_segments[i].map[map_idx] == NULL)
                continue;
            if (segment_overlap(base, end,
                                app_segments[i].app_base,
                                app_segments[i].app_end) ||
                segment_overlap(base, end,
                                app_segments[i].shadow_base[map_idx],
                                app_segments[i].shadow_end[map_idx])) {
                ELOG(1, "ERROR: new app segment ["PFX", "PFX")'s reserve segment "
                     "["PFX", "PFX") conflicts with app seg ["PFX", "PFX") or its "
                     "shadow ["PFX", "PFX")\n",
                     seg->app_base, seg->app_end, base, end,
                     app_segments[i].app_base, app_segments[i].app_end,
                     app_segments[i].shadow_base[map_idx],
                     app_segments[i].shadow_end[map_idx]);
                return false;
            }
        }
    }
    LOG(1, "new segment: app ["PFX", "PFX"), shadow ["PFX", "PFX"), "
        "reserve ["PFX", "PFX")\n", seg->app_base, seg->app_end,
        seg->shadow_base[seg_map_idx], seg->shadow_end[seg_map_idx],
        seg->reserve_base[seg_map_idx], seg->reserve_end[seg_map_idx]);
    return true;
}

static bool
umbra_add_app_segment(app_pc base, size_t size, umbra_map_t *map)
{
    uint i;

    LOG(UMBRA_VERBOSE, "add new app segment for ["PFX", "PFX")\n", base, base + size);
    for (i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        if (app_segments[i].app_used) {
            if (base >= app_segments[i].app_base &&
                base + size <= app_segments[i].app_end)
                return true;
        } else {
            if (app_segments[i].app_end != NULL) {
                /* a pre-defined app segment */
                if (base >= app_segments[i].app_base &&
                    base + size <= app_segments[i].app_end) {
                    app_segments[i].app_used = true;
                    return true;
                }
            } else {
                app_segments[i].app_base = (app_pc)segment_base(num_seg_bits, base);
                /* We do support a memory range spanning multiple segments, since it
                 * happens in practice with Control Flow Guard (i#2184).
                 */
                app_segments[i].app_end =
                    (app_pc)ALIGN_FORWARD(base + size, segment_size(num_seg_bits));
                LOG(1, "adding app segment ["PFX", "PFX")\n", app_segments[i].app_base,
                    app_segments[i].app_end);
                /* Adding a not pre-defined segment.
                 * We call umbra_add_shadow_segment to check if it is valid.
                 */
                if (map != NULL && !umbra_add_shadow_segment(map, &app_segments[i])) {
                    app_segments[i].app_end = NULL;
                    LOG(1, "failed to add shadow segment for ["PFX", "PFX")\n",
                        base, base + size);
                    return false;
                }
                app_segments[i].app_used = true;
                return true;
            }
        }
    }
    LOG(1, "no room for new app segment ["PFX", "PFX")\n",
        base, base + size);
    return false;
}

/* scan the address space to check if it is valid */
static bool
umbra_address_space_init()
{
    dr_mem_info_t info;
    app_pc pc = NULL;
    /* now we assume all the memory are application memory and need */
    while (pc < (app_pc)POINTER_MAX && dr_query_memory_ex(pc, &info)) {
        if (info.type != DR_MEMTYPE_FREE &&
            !umbra_add_app_segment(info.base_pc, info.size, NULL)) {
            LOG(1, "ERROR: %s failed for " PFX "-" PFX "\n", __FUNCTION__,
                info.base_pc, info.base_pc + info.size);
            return false;
        }
        if (POINTER_OVERFLOW_ON_ADD(pc, info.size)) {
            LOG(UMBRA_VERBOSE, "bailing on loop: "PFX" + "PFX" => "PFX"\n",
                pc, info.size, pc + info.size);
            break;
        }
        pc = info.base_pc + info.size;
    }
#ifdef LINUX
    bool pie_def_used = false, pie_alt_used = false;;
    for (int i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        if (app_segments[i].app_used && app_segments[i].app_base == PIE_DEF_SEGMENT)
            pie_def_used = true;
        if (app_segments[i].app_used && app_segments[i].app_base == PIE_ALT_SEGMENT) {
            map_disp[UMBRA_MAP_SCALE_UP_2X] = PIE_ALT_SEG_2X_DISP;
            pie_alt_used = true;
        }
    }
    if (pie_def_used && pie_alt_used) {
        /* FIXME i#1799: relocate DynamoRIO to avoid the PIE spanning segments */
        ELOG(1, "ERROR: both PIE segments "PFX" and "PFX" are used\n",
             PIE_DEF_SEGMENT, PIE_ALT_SEGMENT);
        return false;
    }
#endif
    return true;
}

static void
umbra_set_shadow_bitmap(umbra_map_t *map, app_pc shdw_addr)
{
    uint i, map_idx = map->index;
    for (i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        if (app_segments[i].app_used &&
            app_segments[i].map[map_idx] == map &&
            app_segments[i].shadow_base[map_idx] <= shdw_addr &&
            app_segments[i].shadow_end[map_idx]  >  shdw_addr) {
            uint byte_idx =
                BITMAP_BYTE_INDEX(map, shdw_addr,
                                  app_segments[i].shadow_base[map_idx]);
            uint bit_idx =
                BITMAP_BIT_INDEX(map, shdw_addr,
                                 app_segments[i].shadow_base[map_idx]);
            app_segments[i].shadow_bitmap[map_idx][byte_idx] |= (1<<bit_idx);
            return;
        }
    }
}

static bool
umbra_shadow_block_exist(umbra_map_t *map, app_pc shdw_addr)
{
    uint i, map_idx = map->index;
    for (i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        if (app_segments[i].app_used &&
            app_segments[i].map[map_idx] == map &&
            app_segments[i].shadow_base[map_idx] <= shdw_addr &&
            app_segments[i].shadow_end[map_idx]  >  shdw_addr) {
            uint byte_idx =
                BITMAP_BYTE_INDEX(map, shdw_addr,
                                  app_segments[i].shadow_base[map_idx]);
            uint bit_idx =
                BITMAP_BIT_INDEX(map, shdw_addr,
                                 app_segments[i].shadow_base[map_idx]);
            if (TEST(1 << bit_idx,
                     app_segments[i].shadow_bitmap[map_idx][byte_idx]))
                return true;
            else
                return false;
        }
    }
    return false;
}

/***************************************************************************
 * EXPORT UMBRA X64 SPECIFIC CODE
 */

drmf_status_t
umbra_arch_init()
{
#ifdef WINDOWS
    if (!dr_get_os_version(&os_version))
        return DRMF_ERROR;
    if (os_version.version >= DR_WINDOWS_VERSION_8_1) {
        num_seg_bits = NUM_SEG_BITS_WIN8_1;
        memcpy(&app_segments, &app_segments_initial_81, sizeof(app_segments));
    } else {
        num_seg_bits = NUM_SEG_BITS_WIN8;
        memcpy(&app_segments, &app_segments_initial, sizeof(app_segments));
    }
#else
    num_seg_bits = NUM_SEG_BITS;
    memcpy(&app_segments, &app_segments_initial, sizeof(app_segments));
#endif
    if (!umbra_address_space_init())
        return DRMF_ERROR;
    return DRMF_SUCCESS;
}

void
umbra_arch_exit()
{
    memset(&app_segments, 0, sizeof(app_segments));
}

drmf_status_t
umbra_map_arch_init(umbra_map_t *map, umbra_map_options_t *ops)
{
    uint i;
    if (UMBRA_MAP_SCALE_IS_UP(map->options.scale)) {
        map->app_block_size    = ALLOC_UNIT_SIZE;
        map->shadow_block_size =
            umbra_map_scale_app_to_shadow(map, ALLOC_UNIT_SIZE);
    } else {
        map->shadow_block_size = ALLOC_UNIT_SIZE;
        map->app_block_size    =
            umbra_map_scale_shadow_to_app(map, ALLOC_UNIT_SIZE);
    }
    ASSERT(map->shadow_block_size >= ALLOC_UNIT_SIZE &&
           map->app_block_size    >= ALLOC_UNIT_SIZE,
           "block size too small");
    map->mask = segment_mask(num_seg_bits) | seg_index_mask(num_seg_bits);
#ifdef WINDOWS
    if (UMBRA_MAP_SCALE_IS_UP(map->options.scale)) {
        /* The only way we can avoid reserves from wrapping around or overlapping
         * is to pull one higher-level bit.
         */
        map->mask |= 0x0000100000000000;
    }
#endif
    map->disp = IF_WINDOWS((os_version.version >= DR_WINDOWS_VERSION_8_1) ?
                           map_disp_win81[map->options.scale] :)
        map_disp[map->options.scale];
    if (map->index > 0) {
        /* 2 units apart from two mappings, xref comment at top about
         * multiple maps.
         */
        map->disp += umbra_map_scale_shadow_to_app
            (map, map->index * 2*NUM_SEGMENTS*segment_size(num_seg_bits));
    }
    /* now we add shadow memory segment */
    for (i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        if (app_segments[i].app_used &&
            !umbra_add_shadow_segment(map, &app_segments[i])) {
            LOG(1, "ERROR: shadow segment failed for " PFX "-" PFX "\n",
                app_segments[i].app_base, app_segments[i].app_end);
            return DRMF_ERROR_DETAILS_UNKNOWN;
        }
    }
    return DRMF_SUCCESS;
}

static bool
umbra_map_shadow_free(umbra_map_t *map,
                      umbra_shadow_memory_info_t *info,
                      void *user_data)
{
    dr_raw_mem_free(info->shadow_base, info->shadow_size);
    return true;
}

void
umbra_map_arch_exit(umbra_map_t *map)
{
    uint i;
    umbra_iterate_shadow_memory(map, NULL, umbra_map_shadow_free);
    for (i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        if (app_segments[i].app_used && app_segments[i].map[map->index] == map) {
            size_t size;
            app_segment_t *seg = &app_segments[i];
            size = seg->shadow_end[map->index] - seg->shadow_base[map->index];
            size = size / map->shadow_block_size / BIT_PER_BYTE;
            global_free(seg->shadow_bitmap[map->index], size, HEAPSTAT_SHADOW);
            seg->shadow_bitmap[map->index] = NULL;
            seg->shadow_base[map->index] = NULL;
            seg->shadow_end[map->index] = NULL;
            seg->reserve_base[map->index] = NULL;
            seg->reserve_end[map->index] = NULL;
        }
        /* We never disable the app_used field (except on umbra_arch_exit()). */
    }
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
    byte  *shadow_blk, *res;

    if (value_size != 1 || value >= UCHAR_MAX)
        return DRMF_ERROR_FEATURE_NOT_AVAILABLE;
    if (POINTER_OVERFLOW_ON_ADD(app_addr, app_size-1)) /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;
    /* check if the new app memory will violate the memory layout */
    if (!umbra_add_app_segment(app_addr, app_size, map))
        return DRMF_ERROR_INVALID_ADDRESS;
    umbra_map_lock(map);
    APP_RANGE_LOOP(app_addr, app_size, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        shadow_blk  = (byte *)umbra_xl8_app_to_shadow(map, app_blk_base);
        if (!umbra_shadow_block_exist(map, shadow_blk)) {
            umbra_map_lock(map);
            if (!umbra_shadow_block_exist(map, shadow_blk)) {
                res = dr_raw_mem_alloc(map->shadow_block_size,
                                       DR_MEMPROT_READ | DR_MEMPROT_WRITE,
                                       shadow_blk);
                if (res == NULL || res != shadow_blk) {
                    if (res != NULL)
                        dr_raw_mem_free(res, map->shadow_block_size);
                    res = NULL;
                } else {
                    umbra_set_shadow_bitmap(map, res);
                    ASSERT(umbra_shadow_block_exist(map, res),
                           "fail to set shadow bitmap");
                }
            }
            umbra_map_unlock(map);
        }
        if (umbra_shadow_set_range_arch(map, start, iter_size, &size,
                                        value, value_size) != DRMF_SUCCESS) {
            umbra_map_unlock(map);
            return DRMF_ERROR;
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
                              IN    byte    *buffer)
{
    /* i#1260: end pointers are all closed (i.e., inclusive) to handle overflow */
    app_pc app_blk_base, app_blk_end, app_src_end;
    app_pc start, end;
    size_t size, shdw_size, iter_size;
    byte *shadow_start;

    if (*shadow_size < umbra_map_scale_app_to_shadow(map, app_size)) {
        *shadow_size = 0;
        return DRMF_ERROR_INVALID_SIZE;
    }
    if (POINTER_OVERFLOW_ON_ADD(app_addr, app_size-1)) /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;
    shdw_size = 0;
    APP_RANGE_LOOP(app_addr, app_size, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        shadow_start = umbra_xl8_app_to_shadow(map, start);
        if (!umbra_shadow_block_exist(map, shadow_start)) {
            drmf_status_t res;
            if (!TEST(UMBRA_MAP_CREATE_SHADOW_ON_TOUCH, map->options.flags))
                return DRMF_ERROR_INVALID_PARAMETER;
            res = umbra_create_shadow_memory_arch(map, 0, app_blk_base,
                                                  map->app_block_size,
                                                  map->options.default_value,
                                                  map->options.default_value_size);
            if (res != DRMF_SUCCESS)
                return res;
        }
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
    size_t size, shdw_size, iter_size;
    byte  *shadow_start;

    if (*shadow_size < umbra_map_scale_app_to_shadow(map, app_size)) {
        *shadow_size = 0;
        return DRMF_ERROR_INVALID_SIZE;
    }
    if (POINTER_OVERFLOW_ON_ADD(app_addr, app_size-1)) /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;
    shdw_size = 0;
    APP_RANGE_LOOP(app_addr, app_size, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        shadow_start = umbra_xl8_app_to_shadow(map, start);
        if (!umbra_shadow_block_exist(map, shadow_start)) {
            drmf_status_t res;
            if (!TEST(UMBRA_MAP_CREATE_SHADOW_ON_TOUCH, map->options.flags))
                return DRMF_ERROR_INVALID_PARAMETER;
            res = umbra_create_shadow_memory_arch(map, 0, app_blk_base,
                                                  map->app_block_size,
                                                  map->options.default_value,
                                                  map->options.default_value_size);
            if (res != DRMF_SUCCESS)
                return res;
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
    size_t size, shdw_size, iter_size;
    byte  *shadow_start;

    if (value_size != 1 || value > UCHAR_MAX)
        return DRMF_ERROR_NOT_IMPLEMENTED;
    if (POINTER_OVERFLOW_ON_ADD(app_addr, app_size-1)) /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;

    shdw_size = 0;
    APP_RANGE_LOOP(app_addr, app_size, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        shadow_start = umbra_xl8_app_to_shadow(map, start);
        if (!umbra_shadow_block_exist(map, shadow_start)) {
            drmf_status_t res;
            if (!TEST(UMBRA_MAP_CREATE_SHADOW_ON_TOUCH, map->options.flags))
                return DRMF_ERROR_INVALID_PARAMETER;
            res = umbra_create_shadow_memory_arch(map, 0, app_blk_base,
                                                  map->app_block_size,
                                                  map->options.default_value,
                                                  map->options.default_value_size);
            if (res != DRMF_SUCCESS)
                return res;
        }
        size = umbra_map_scale_app_to_shadow(map, iter_size);
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
    tot_shadow_sz = 0;
    /* the other side overlap is covered by memmove */
    APP_RANGE_LOOP(app_src, app_sz, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        shadow_start = umbra_xl8_app_to_shadow(map, start);
        if (!umbra_shadow_block_exist(map, shadow_start)) {
            drmf_status_t res;
            if (!TEST(UMBRA_MAP_CREATE_SHADOW_ON_TOUCH, map->options.flags))
                return DRMF_ERROR_INVALID_PARAMETER;
            res = umbra_create_shadow_memory_arch(map, 0, app_blk_base,
                                                  map->app_block_size,
                                                  map->options.default_value,
                                                  map->options.default_value_size);
            if (res != DRMF_SUCCESS)
                return res;
        }
        shadow_sz = umbra_map_scale_app_to_shadow(map, iter_size);
        if (umbra_write_shadow_memory_arch(map,
                                           app_dst,
                                           iter_size,
                                           &shadow_sz,
                                           shadow_start) != DRMF_SUCCESS) {
            tot_shadow_sz += shadow_sz;
            res = DRMF_ERROR_INVALID_PARAMETER;
            break;
        } else {
            ASSERT(shadow_sz == umbra_map_scale_app_to_shadow(map, iter_size),
                   "copy size mismatch");
        }
        app_dst += iter_size;
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
    byte  *shadow_start, *shadow_addr = NULL;
    size_t shadow_size, iter_size;

    if (value > USHRT_MAX || (value_size != 1 && value_size != 2))
        return DRMF_ERROR_NOT_IMPLEMENTED;
    if (POINTER_OVERFLOW_ON_ADD(*app_addr, app_size-1)) /* just hitting top is ok */
        return DRMF_ERROR_INVALID_SIZE;

    *found  = false;
    APP_RANGE_LOOP(*app_addr, app_size, app_blk_base, app_blk_end, app_src_end,
                   start, end, iter_size, {
        shadow_start = umbra_xl8_app_to_shadow(map, start);
        if (!umbra_shadow_block_exist(map, shadow_start)) {
            drmf_status_t res;
            if (!TEST(UMBRA_MAP_CREATE_SHADOW_ON_TOUCH, map->options.flags))
                return DRMF_ERROR_INVALID_PARAMETER;
            res = umbra_create_shadow_memory_arch(map, 0, app_blk_base,
                                                  map->app_block_size,
                                                  map->options.default_value,
                                                  map->options.default_value_size);
            if (res != DRMF_SUCCESS)
                return res;
            if (value == map->options.default_value &&
                value_size == map->options.default_value_size) {
                *app_addr = start;
                *found = true;
                return DRMF_SUCCESS;
            }
            continue;
        }
        shadow_size = umbra_map_scale_app_to_shadow(map, iter_size);
        if (value_size == 1) {
            shadow_addr = memchr(shadow_start, (int)value, shadow_size);
        } else if (shadow_size > 0) {
            byte *first_byte = shadow_start;
            while (first_byte != NULL) {
                first_byte = memchr(first_byte, (char)value,
                                    shadow_size - 1 - (first_byte - shadow_start));
                if (first_byte != NULL) {
                    if (*(first_byte + 1) == (char)(value>>8)) {
                        shadow_addr = first_byte;
                        break;
                    } else
                        first_byte++;
                }
            }
        }
        if (shadow_addr != NULL) {
            app_pc found_addr = start +
                umbra_map_scale_shadow_to_app(map, shadow_addr - shadow_start);
            /* We can go beyond the app size due to shadow size rounding up. */
            if (found_addr > *app_addr + app_size)
                return DRMF_SUCCESS; /* not found */
            *app_addr = found_addr;
            *found = true;
            return DRMF_SUCCESS;
        }
    });
    return DRMF_SUCCESS;
}

int
umbra_num_scratch_regs_for_translation_arch()
{
    return 0;
}

/* code sequence:
 *
 */
drmf_status_t
umbra_insert_app_to_shadow_arch(void *drcontext,
                                umbra_map_t *map,
                                instrlist_t *ilist,
                                instr_t *where,
                                reg_id_t reg_addr,
                                reg_id_t *scratch_regs,
                                int num_scratch_regs)
{
    PRE(ilist, where, INSTR_CREATE_and(drcontext,
                                       opnd_create_reg(reg_addr),
                                       OPND_CREATE_ABSMEM(&map->mask,
                                                          OPSZ_PTR)));
    PRE(ilist, where, INSTR_CREATE_add(drcontext,
                                       opnd_create_reg(reg_addr),
                                       OPND_CREATE_ABSMEM(&map->disp,
                                                          OPSZ_PTR)));
    if (map->options.scale == UMBRA_MAP_SCALE_UP_2X) {
        PRE(ilist, where, INSTR_CREATE_shl(drcontext,
                                           opnd_create_reg(reg_addr),
                                           OPND_CREATE_INT8(map->shift)));
    } else if (map->options.scale <= UMBRA_MAP_SCALE_DOWN_2X) {
        PRE(ilist, where, INSTR_CREATE_shr(drcontext,
                                           opnd_create_reg(reg_addr),
                                           OPND_CREATE_INT8(map->shift)));
    }
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_iterate_shadow_memory_arch(umbra_map_t *map,
                                 void *user_data,
                                 shadow_iterate_func_t iter_func)
{
    uint i;
    umbra_shadow_memory_info_t info;

    for (i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        byte *shdw_addr;
        dr_mem_info_t mem_info;
        if (!app_segments[i].app_used)
            continue;
        shdw_addr = app_segments[i].shadow_base[map->index];
        while (shdw_addr < app_segments[i].shadow_end[map->index] &&
               dr_query_memory_ex(shdw_addr, &mem_info)) {
            if (mem_info.type != DR_MEMTYPE_FREE) {
                ptr_uint_t delta;
                ASSERT(mem_info.type == DR_MEMTYPE_DATA &&
                       mem_info.base_pc >=
                       app_segments[i].shadow_base[map->index],
                       "wrong shadow memory");
                delta = mem_info.base_pc -
                    app_segments[i].shadow_base[map->index];
                info.app_base = app_segments[i].app_base +
                    umbra_map_scale_shadow_to_app(map, delta);
                info.app_size = umbra_map_scale_shadow_to_app(map,
                                                              mem_info.size);
                info.shadow_base = mem_info.base_pc;
                info.shadow_size = mem_info.size;
                info.shadow_type = UMBRA_SHADOW_MEMORY_TYPE_NORMAL;
                if (!iter_func(map, &info, user_data))
                    break;
            }
            shdw_addr = mem_info.base_pc + mem_info.size;
        }
        ASSERT(shdw_addr >= app_segments[i].shadow_end[map->index],
               "fail to query shadow memory");
    }
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_shadow_memory_is_shared_arch(IN  umbra_map_t *map,
                                   IN  byte *shadow_addr,
                                   OUT umbra_shadow_memory_type_t *shadow_type)
{
    *shadow_type = UMBRA_SHADOW_MEMORY_TYPE_UNKNOWN;
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_get_shadow_memory_type_arch(umbra_map_t *map,
                                  byte *shadow_addr,
                                  umbra_shadow_memory_type_t *shadow_type)
{
    uint i;
    *shadow_type = UMBRA_SHADOW_MEMORY_TYPE_NOT_SHADOW;
    for (i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        if ((shadow_addr >= app_segments[i].app_base &&
             shadow_addr <  app_segments[i].app_end) ||
            (shadow_addr >= app_segments[i].reserve_base[map->index] &&
             shadow_addr <= app_segments[i].reserve_end[map->index])) {
            break;
        } else if (shadow_addr >= app_segments[i].shadow_base[map->index] &&
                   shadow_addr <= app_segments[i].shadow_end[map->index]) {
            if (umbra_shadow_block_exist(map, shadow_addr))
                *shadow_type = UMBRA_SHADOW_MEMORY_TYPE_NORMAL;
            else
                *shadow_type = UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC;
            break;
        }
    }
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_get_shadow_memory_arch(umbra_map_t *map,
                             app_pc app_addr,
                             byte **shadow_addr,
                             umbra_shadow_memory_info_t *shadow_info)
{
    if (shadow_addr != NULL)
        *shadow_addr = umbra_xl8_app_to_shadow(map, app_addr);
    if (shadow_info != NULL) {
        shadow_info->app_base = (app_pc)ALIGN_BACKWARD(app_addr,
                                                       map->app_block_size);
        shadow_info->app_size = map->app_block_size;
        shadow_info->shadow_size = map->shadow_block_size;
        shadow_info->shadow_base =
            umbra_xl8_app_to_shadow(map, shadow_info->app_base);
        return umbra_get_shadow_memory_type_arch(map,
                                                 shadow_info->shadow_base,
                                                 &shadow_info->shadow_type);
    }
    return DRMF_SUCCESS;
}

bool
umbra_address_is_app_segment(app_pc pc)
{
    uint i;
    for (i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        if (app_segments[i].app_used &&
            pc >= app_segments[i].app_base &&
            pc <  app_segments[i].app_end)
            return true;
    }
    return false;
}

bool
umbra_address_is_app_memory(app_pc pc)
{
    if (!umbra_address_is_app_segment(pc))
        return false;
    if (dr_memory_is_dr_internal(pc) || dr_memory_is_in_client(pc))
        return false;
    return true;
}

drmf_status_t
umbra_replace_shared_shadow_memory_arch(umbra_map_t *map,
                                        app_pc app_addr,
                                        byte **shadow_addr)
{
    *shadow_addr = umbra_xl8_app_to_shadow(map, app_addr);
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_create_shared_shadow_block_arch(IN  umbra_map_t *map,
                                      IN  ptr_uint_t   value,
                                      IN  size_t       value_size,
                                      OUT byte       **block)
{
    return DRMF_ERROR_FEATURE_NOT_AVAILABLE;
}

drmf_status_t
umbra_get_shared_shadow_block_arch(IN  umbra_map_t *map,
                                   IN  ptr_uint_t   value,
                                   IN  size_t       value_size,
                                   OUT byte       **block)
{
    *block = NULL;
    return DRMF_ERROR_FEATURE_NOT_AVAILABLE;
}

bool
umbra_handle_fault(void *drcontext, byte *target, dr_mcontext_t *raw_mc,
                   dr_mcontext_t *mc)
{
    uint i, j;
    for (i = 0; i < MAX_NUM_APP_SEGMENTS; i++) {
        for (j = 0; j < MAX_NUM_MAPS; j++) {
            /* first check if it is in any shadow memory range */
            if (app_segments[i].map[j] != NULL &&
                target >= app_segments[i].shadow_base[j] &&
                target <  app_segments[i].shadow_end[j]) {
                umbra_map_t *map = app_segments[i].map[j];
                app_pc app_addr = (app_pc)
                    app_segments[i].app_base +
                    umbra_map_scale_shadow_to_app
                    (map, target - app_segments[i].shadow_base[j]);
                umbra_create_shadow_memory_arch(map, 0, app_addr, 8,
                                                map->options.default_value,
                                                map->options.default_value_size);
                return true;
            }
        }
    }
    return false;
}

drmf_status_t
umbra_clear_redundant_blocks(umbra_map_t *map, uint *count)
{
    /* No operation needed for x64. */
    return DRMF_ERROR_FEATURE_NOT_AVAILABLE;
}
