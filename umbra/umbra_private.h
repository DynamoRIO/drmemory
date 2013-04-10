/* **********************************************************
 * Copyright (c) 2012-2013 Google, Inc.  All rights reserved.
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

#ifndef _UMBRA_PRIVATE_H_
#define _UMBRA_PRIVATE_H_ 1

#include "umbra.h"

/***************************************************************************
 * ENUMS AND TYPES
 */

/* logging level */
#define UMBRA_VERBOSE 2

#define UMBRA_MAP_MAGIC 0x504d4255 /* UBMP */

/* maxium number of shadow memory mappings supported */
#define MAX_NUM_MAPS 2

/* Special read-only shared shadow blocks for all-identical chunks.
 * We support up to 8 different special blocks; (Dr.Memory needs 5).
 */
#define MAX_NUM_SPECIAL_BLOCKS 8
typedef struct _special_block_t {
    byte *start;        /* base of block excluding redzone */
    ptr_uint_t value;
    size_t value_size;
} special_block_t;

/* internal data type of umbra_map_t */
struct _umbra_map_t {
    uint magic;
    uint index;
    byte shift;
    umbra_map_options_t options;

    /* application and shadow block unit size on create/delete */
    size_t app_block_size;
    size_t shadow_block_size;

#ifndef X64
    /* shadow table base mapping */
    ptr_int_t *shadow_table;
    /* shadow_block_size + 2*redzone_size */
    size_t shadow_block_alloc_size;
    /* special shared blocks are used for saving memory on shadow memory
     * with identical value
     */
    uint num_special_blocks;
    special_block_t default_block;
    special_block_t special_blocks[MAX_NUM_SPECIAL_BLOCKS];
#else
    ptr_uint_t disp;
    ptr_uint_t mask;
#endif
    void *lock;
};


/***************************************************************************
 * UTILITY ROUTINES
 */

/* scale up/down the value based on the map->scale */
ptr_uint_t
umbra_map_scale_app_to_shadow(umbra_map_t *map, ptr_uint_t app_value);

ptr_uint_t
umbra_map_scale_shadow_to_app(umbra_map_t *map, ptr_uint_t shadow_value);

/* check if addr is application memory address */
bool
umbra_address_is_app_memory(app_pc addr);

void
umbra_lock();

void
umbra_unlock();

void
umbra_map_lock(umbra_map_t *map);

void
umbra_map_unlock(umbra_map_t *map);

/***************************************************************************
 * ARCHITECTURE SPECIFIC IMPLEMENTATION ROUTINES
 */

drmf_status_t
umbra_arch_init();

void
umbra_arch_exit();

drmf_status_t
umbra_map_arch_init(umbra_map_t *map, umbra_map_options_t *ops);

void
umbra_map_arch_exit(umbra_map_t *map);

drmf_status_t
umbra_create_shadow_memory_arch(umbra_map_t *map,
                                uint         flags,
                                app_pc       app_addr,
                                size_t       app_size,
                                ptr_uint_t   value,
                                size_t       value_size);

drmf_status_t
umbra_delete_shadow_memory_arch(umbra_map_t *map,
                                app_pc       app_addr,
                                size_t       app_size);

int
umbra_num_scratch_regs_for_translation_arch();

drmf_status_t
umbra_insert_app_to_shadow_arch(void *drcontext,
                                umbra_map_t *map,
                                instrlist_t *ilist,
                                instr_t *where,
                                reg_id_t reg_addr,
                                reg_id_t *scratch_regs,
                                int num_scratch_regs);

drmf_status_t
umbra_read_shadow_memory_arch(umbra_map_t *map,
                              app_pc  app_addr,
                              size_t  app_size,
                              size_t *shadow_size,
                              byte   *buffer);

drmf_status_t
umbra_write_shadow_memory_arch(umbra_map_t *map,
                               app_pc  app_addr,
                               size_t  app_size,
                               size_t *shadow_size,
                               byte   *buffer);

drmf_status_t
umbra_shadow_set_range_arch(IN   umbra_map_t *map,
                            IN   app_pc       app_addr,
                            IN   size_t       app_size,
                            OUT  size_t      *shadow_size,
                            IN   ptr_uint_t   value,
                            IN   size_t       value_size);

drmf_status_t
umbra_shadow_copy_range_arch(IN  umbra_map_t *map,
                             IN  app_pc  app_src,
                             IN  app_pc  app_dst,
                             IN  size_t  app_size,
                             OUT size_t *shadow_size);

drmf_status_t
umbra_iterate_shadow_memory_arch(umbra_map_t *map,
                                 void *user_data,
                                 shadow_iterate_func_t iter_func);

drmf_status_t
umbra_get_shadow_memory_type_arch(umbra_map_t *map,
                                  byte *shadow_addr,
                                  uint *shadow_type);

drmf_status_t
umbra_get_shadow_memory_arch(umbra_map_t *map,
                             app_pc app_addr,
                             byte **shadow_addr,
                             umbra_shadow_memory_info_t *shadow_info);

drmf_status_t
umbra_shadow_memory_is_shared_arch(umbra_map_t *map,
                                   byte *shadow_addr,
                                   bool *shared,
                                   uint *shadow_type);

drmf_status_t
umbra_value_in_shadow_memory_arch(umbra_map_t *map,
                                  byte **app_addr,
                                  size_t app_size,
                                  ptr_uint_t value,
                                  size_t value_size,
                                  bool *found);
drmf_status_t
umbra_replace_shared_shadow_memory_arch(umbra_map_t *map,
                                        app_pc app_addr,
                                        byte **shadow_addr);

drmf_status_t
umbra_create_shared_shadow_block_arch(IN  umbra_map_t *map,
                                      IN  ptr_uint_t   value,
                                      IN  size_t       value_size,
                                      OUT byte       **block);

drmf_status_t
umbra_get_shared_shadow_block_arch(IN  umbra_map_t *map,
                                   IN  ptr_uint_t   value,
                                   IN  size_t       value_size,
                                   OUT byte       **block);

bool
umbra_handle_fault(void *drcontext, byte *target, dr_mcontext_t *raw_mc,
                   dr_mcontext_t *mc);
#endif /* _UMBRA_PRIVATE_H_ */

