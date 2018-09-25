/* **********************************************************
 * Copyright (c) 2012-2018 Google, Inc.  All rights reserved.
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

/* Umbra top-level code */

#include "dr_api.h"
#include "drmgr.h"
#include "umbra.h"
#include "umbra_private.h"
#include "drmemory_framework.h"
#include "../framework/drmf.h"
#include "utils.h"
#ifdef UNIX
# include "sysnum_linux.h"
# include <sys/mman.h>
# include <signal.h>   /* for SIGSEGV */
#endif

/***************************************************************************
 * ENUMS AND TYPES
 */

static int umbra_init_count;
static uint num_umbra_maps;
static umbra_map_t *umbra_maps[MAX_NUM_MAPS];
static void  *umbra_global_lock;
static bool   umbra_initialized;

/***************************************************************************
 * UTLITY ROUTINES
 */

ptr_uint_t
umbra_map_scale_app_to_shadow(umbra_map_t *map, ptr_uint_t value)
{
    if (UMBRA_MAP_SCALE_IS_DOWN(map->options.scale))
        value >>= map->shift;
    else if (UMBRA_MAP_SCALE_IS_UP(map->options.scale))
        value <<= map->shift;
    return value;
}

ptr_uint_t
umbra_map_scale_shadow_to_app(umbra_map_t *map, ptr_uint_t value)
{
    if (UMBRA_MAP_SCALE_IS_DOWN(map->options.scale))
        value <<= map->shift;
    else if (UMBRA_MAP_SCALE_IS_UP(map->options.scale))
        value >>= map->shift;
    return value;
}

void
umbra_lock()
{
    dr_mutex_lock(umbra_global_lock);
}

void
umbra_unlock()
{
    dr_mutex_unlock(umbra_global_lock);
}

/***************************************************************************
 * UMBRA MAP ROUTINES
 */

void
umbra_map_lock(umbra_map_t *map)
{
    dr_recurlock_lock(map->lock);
}

void
umbra_map_unlock(umbra_map_t *map)
{
    dr_recurlock_unlock(map->lock);
}

static void
umbra_map_destroy(umbra_map_t *map)
{
    if (map == NULL)
        return;
    umbra_map_arch_exit(map);
    dr_recurlock_destroy(map->lock);
    global_free(map, sizeof(*map), HEAPSTAT_SHADOW);
}

static bool
umbra_map_compatible(umbra_map_t *map1, umbra_map_t *map2)
{
    /* we do not support multiple mappings with different scaling */
    if (map1->options.scale == map2->options.scale)
        return true;
    return false;
}

static drmf_status_t
umbra_map_create(umbra_map_t **map_out, umbra_map_options_t *ops, uint idx)
{
    umbra_map_t *map;

    ASSERT(map_out != NULL, "map_out must not be NULL");
    *map_out = NULL;

    if (ops->default_value_size != 1 || ops->default_value > UCHAR_MAX) {
        ASSERT(false, "NYI: we only support byte-size value now");
        return DRMF_ERROR_NOT_IMPLEMENTED;
    }

    map = (umbra_map_t *)global_alloc(sizeof(umbra_map_t), HEAPSTAT_SHADOW);
    if (map == NULL)
        return DRMF_ERROR_NOMEM;
    *map_out = map;

    memset(map, 0, sizeof(*map));
    map->magic = UMBRA_MAP_MAGIC;
    map->options = *ops;
    map->index = idx;
    if (ops->app_memory_create_cb != NULL ||
#ifdef UNIX
        ops->app_memory_mremap_cb != NULL ||
#endif
        ops->app_memory_pre_delete_cb  != NULL ||
        ops->app_memory_post_delete_cb != NULL) {
        /* FIXME: add support syscall handling */
        ASSERT(false, "NYI");
        return DRMF_ERROR_NOT_IMPLEMENTED;
    }
    switch (ops->scale) {
    case UMBRA_MAP_SCALE_DOWN_8X:
        map->shift = 3;
        break;
    case UMBRA_MAP_SCALE_DOWN_4X:
        map->shift = 2;
        break;
    case UMBRA_MAP_SCALE_DOWN_2X:
    case UMBRA_MAP_SCALE_UP_2X:
        map->shift = 1;
        break;
    case UMBRA_MAP_SCALE_SAME_1X:
        map->shift = 0;
        break;
    default:
        map->shift = 0;
        ASSERT(false, "unsupported mapping scale");
        return DRMF_ERROR_FEATURE_NOT_AVAILABLE;
    }

    map->lock = dr_recurlock_create();
    return umbra_map_arch_init(map, ops);
}

/* caller must hold umbra lock */
static drmf_status_t
umbra_map_add(umbra_map_t **map_out, umbra_map_options_t *ops)
{
    drmf_status_t res;
    uint i, idx;

    /* check if any slot available */
    for (idx = 0; idx < MAX_NUM_MAPS; idx++) {
        if (umbra_maps[idx] == NULL)
            break;
    }
    if (idx >= MAX_NUM_MAPS)
        return DRMF_ERROR_FEATURE_NOT_AVAILABLE;
    /* create a new mapping object */
    res = umbra_map_create(map_out, ops, idx);
    if (res != DRMF_SUCCESS)
        return res;
    ASSERT(*map_out != NULL, "fail to create umbra map");
    res = DRMF_SUCCESS;
    /* check compatibility */
    for (i = 0; i < num_umbra_maps; i++) {
        if (umbra_maps[i] != NULL &&
            !umbra_map_compatible(*map_out, umbra_maps[i])) {
            res = DRMF_ERROR_FEATURE_NOT_AVAILABLE;
            break;
        }
    }
    if (res == DRMF_SUCCESS) {
        ASSERT(umbra_maps[idx] == NULL, "racy usage on umbra_maps");
        umbra_maps[idx] = *map_out;
    } else {
        umbra_map_destroy(*map_out);
    }
    return res;
}

/* the caller must hold umbra lock */
static void
umbra_map_remove(umbra_map_t *map)
{
    uint i;
    for (i = 0; i < MAX_NUM_MAPS; i++) {
        if (umbra_maps[i] == map) {
            umbra_maps[i] = NULL;
            num_umbra_maps--;
            break;
        }
    }
    if (i >= MAX_NUM_MAPS) {
        ASSERT(false, "Wrong umbra map");
        return;
    }
    umbra_map_destroy(map);
}

/***************************************************************************
 * EVENT CALLBACKS
 */

static bool
umbra_event_filter_syscall(void *drcontext, int sysnum)
{
    /* NYI */
    return false;
}

static bool
umbra_event_pre_syscall(void *drcontext, int sysnum)
{
    /* NYI */
    return true;
}

static void
umbra_event_post_syscall(void *drcontext, int sysnum)
{
    /* NYI */
}

#ifdef WINDOWS
static void
umbra_event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    /* NYI */
}
#endif

#ifdef UNIX
dr_signal_action_t
umbra_event_signal(void *drcontext, dr_siginfo_t *info)
{
    /* i#1488: MacOS raises SIGBUS */
    if ((info->sig == SIGSEGV || info->sig == SIGBUS) &&
        umbra_handle_fault(drcontext, info->access_address,
                           info->raw_mcontext, info->mcontext)) {
        return DR_SIGNAL_SUPPRESS;
    }
    return DR_SIGNAL_DELIVER;
}
#else
bool
umbra_event_exception(void *drcontext, dr_exception_t *excpt)
{
    if (excpt->record->ExceptionCode == STATUS_ACCESS_VIOLATION) {
        app_pc target = (app_pc) excpt->record->ExceptionInformation[1];
        if (umbra_handle_fault(drcontext, target,
                               excpt->raw_mcontext, excpt->mcontext)) {
            return false;
        }
    }
    return true;
}
#endif

/***************************************************************************
 * EXPORT TOP-LEVEL
 */

DR_EXPORT
drmf_status_t
umbra_init(client_id_t client_id)
{
    drmf_status_t res;
    drmgr_priority_t pri_excpt =
        {sizeof(pri_excpt), DRMGR_PRIORITY_NAME_EXCPT_UMBRA, NULL, NULL,
         DRMGR_PRIORITY_EXCPT_UMBRA};
    /* handle multiple sets of init/exit calls */
    int count = dr_atomic_add32_return_sum(&umbra_init_count, 1);
    if (count > 1)
        return DRMF_SUCCESS;

    res = drmf_check_version(client_id);
    if (res != DRMF_SUCCESS)
        return res;

    umbra_global_lock = dr_mutex_create();
    res = umbra_arch_init();
    if (res != DRMF_SUCCESS)
        return res;

    /* register event callbacks */
    dr_register_filter_syscall_event(umbra_event_filter_syscall);
    drmgr_register_pre_syscall_event(umbra_event_pre_syscall);
    drmgr_register_post_syscall_event(umbra_event_post_syscall);
#ifdef WINDOWS
    drmgr_register_module_load_event(umbra_event_module_load);
    drmgr_register_exception_event_ex(umbra_event_exception, &pri_excpt);
#else
    drmgr_register_signal_event_ex(umbra_event_signal, &pri_excpt);
#endif

    /* now we finish the initialization */
    umbra_initialized = true;
    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
umbra_exit(void)
{
    int i;
    /* handle multiple sets of init/exit calls */
    int count = dr_atomic_add32_return_sum(&umbra_init_count, -1);
    if (count > 0)
        return DRMF_SUCCESS;
    if (count < 0)
        return DRMF_ERROR;
    umbra_lock();
    for (i = 0; i < MAX_NUM_MAPS; i++) {
        if (umbra_maps[i] != NULL) {
            ASSERT(false, "umbra map is not destroyed");
            umbra_destroy_mapping(umbra_maps[i]);
        }
    }
    umbra_unlock();
    umbra_arch_exit();
    dr_mutex_destroy(umbra_global_lock);
    umbra_initialized = false;
    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
umbra_create_mapping(IN  umbra_map_options_t *ops,
                     OUT umbra_map_t **map_out)
{
    drmf_status_t res;
    if (!umbra_initialized)
        return DRMF_ERROR_INVALID_CALL;
    if (map_out == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    umbra_lock();
    res = umbra_map_add(map_out, ops);
    umbra_unlock();
    return res;
}

DR_EXPORT
drmf_status_t
umbra_destroy_mapping(IN  umbra_map_t *map)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    umbra_lock();
    umbra_map_remove(map);
    umbra_unlock();
    return DRMF_SUCCESS;
}

/* PR 580017: We cannot replace a non-special with a special: more
 * accurately, we cannot free a non-special b/c we could have a
 * use-after-free in our own code.  Rather than a fancy delayed deletion
 * algorithm, or having specials be files that are mmapped at the same
 * address as non-specials thus supported swapping back and forth w/o
 * changing the address (which saves pagefile but not address space: so
 * should do it for 64-bit), we only replace specials with other specials.
 * This still covers the biggest win for specials, the initial unaddr and
 * the initial libraries.  Note that we do not want large stack
 * allocs/deallocs to use specials anyway as the subsequent faults are perf
 * hits (observed in gcc).
 */
DR_EXPORT
drmf_status_t
umbra_create_shadow_memory(IN  umbra_map_t *map,
                           IN  uint         flags,
                           IN  app_pc       app_addr,
                           IN  size_t       app_size,
                           IN  ptr_uint_t   value,
                           IN  size_t       value_size)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (app_size == 0)
        return DRMF_SUCCESS;
    return umbra_create_shadow_memory_arch(map,
                                           flags,
                                           app_addr,
                                           app_size,
                                           value,
                                           value_size);
}

DR_EXPORT
drmf_status_t
umbra_delete_shadow_memory(IN  umbra_map_t *map,
                           IN  app_pc       app_addr,
                           IN  size_t       app_size)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
   if (app_size == 0)
        return DRMF_SUCCESS;
    return umbra_delete_shadow_memory_arch(map, app_addr, app_size);
}

DR_EXPORT
drmf_status_t
umbra_num_scratch_regs_for_translation(OUT  int *num_regs)
{
    if (num_regs == NULL) {
        ASSERT(false, "num_regs must not be NULL");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    *num_regs = umbra_num_scratch_regs_for_translation_arch();
    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
umbra_insert_app_to_shadow(IN  void        *drcontext,
                           IN  umbra_map_t *map,
                           IN  instrlist_t *ilist,
                           IN  instr_t     *where,
                           IN  reg_id_t     addr_reg,
                           IN  reg_id_t    *scratch_regs,
                           IN  int          num_scratch_regs)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (ilist == NULL || addr_reg == DR_REG_NULL || num_scratch_regs < 0 ||
        (num_scratch_regs > 0 && scratch_regs == NULL))
        return DRMF_ERROR_INVALID_PARAMETER;
    return umbra_insert_app_to_shadow_arch(drcontext, map, ilist, where,
                                           addr_reg, scratch_regs,
                                           num_scratch_regs);
}

DR_EXPORT
drmf_status_t
umbra_read_shadow_memory(IN  umbra_map_t *map,
                         IN  app_pc  app_addr,
                         IN  size_t  app_size,
                         OUT size_t *shadow_size,
                         IN  byte    *buffer)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (buffer == NULL || shadow_size == NULL) {
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (app_size == 0) {
        *shadow_size = 0;
        return DRMF_SUCCESS;
    }
    return umbra_read_shadow_memory_arch(map,
                                         app_addr,
                                         app_size,
                                         shadow_size,
                                         buffer);
}

DR_EXPORT
drmf_status_t
umbra_write_shadow_memory(IN  umbra_map_t *map,
                          IN  app_pc  app_addr,
                          IN  size_t  app_size,
                          OUT size_t *shadow_size,
                          IN  byte   *buffer)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (buffer == NULL || shadow_size == NULL) {
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (app_size == 0) {
        *shadow_size = 0;
        return DRMF_SUCCESS;
    }
    return umbra_write_shadow_memory_arch(map, app_addr, app_size,
                                          shadow_size, buffer);
}

DR_EXPORT
drmf_status_t
umbra_shadow_set_range(IN   umbra_map_t *map,
                       IN   app_pc       app_addr,
                       IN   size_t       app_size,
                       OUT  size_t      *shadow_size,
                       IN   ptr_uint_t   value,
                       IN   size_t       value_size)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (shadow_size == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    /* overflow */
    if (app_addr + app_size < app_addr)
        return DRMF_ERROR_INVALID_PARAMETER;
    if (app_size == 0) {
        *shadow_size = 0;
        return DRMF_SUCCESS;
    }
    return umbra_shadow_set_range_arch(map, app_addr, app_size, shadow_size,
                                       value, value_size);
}

DR_EXPORT
drmf_status_t
umbra_shadow_copy_range(IN  umbra_map_t *map,
                        IN  app_pc  app_src,
                        IN  app_pc  app_dst,
                        IN  size_t  app_size,
                        OUT size_t *shadow_size)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (shadow_size == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    if (app_size == 0 || app_src == app_dst) {
        *shadow_size = 0;
        return DRMF_SUCCESS;
    }
    return umbra_shadow_copy_range_arch(map, app_src, app_dst,
                                        app_size, shadow_size);
}

DR_EXPORT
drmf_status_t
umbra_value_in_shadow_memory(IN    umbra_map_t *map,
                             INOUT app_pc *app_addr,
                             IN    size_t  app_size,
                             IN    ptr_uint_t value,
                             IN    size_t value_size,
                             OUT   bool   *found)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (app_addr == NULL || found == false)
        return DRMF_ERROR_INVALID_PARAMETER;
    if (app_size == 0) {
        *found = false;
        return DRMF_SUCCESS;
    }
    return umbra_value_in_shadow_memory_arch(map, app_addr, app_size,
                                             value, value_size, found);
}

DR_EXPORT
drmf_status_t
umbra_get_shadow_block_size(IN  umbra_map_t *map,
                            OUT size_t *size)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (size == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    *size = map->shadow_block_size;
    return DRMF_SUCCESS;
}

drmf_status_t
umbra_iterate_app_memory(IN  umbra_map_t *map,
                         IN  void *user_data,
                         IN  bool (*iter_func)(umbra_map_t *map,
                                               const dr_mem_info_t *info,
                                               void  *user_data))
{
    dr_mem_info_t info;
    app_pc pc;
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    pc = NULL;
    /* walk the address space */
    while (pc < (app_pc)POINTER_MAX && dr_query_memory_ex(pc, &info)) {
        if (info.type != DR_MEMTYPE_FREE &&
            umbra_address_is_app_memory(info.base_pc)) {
            if (!iter_func(map, &info, user_data))
                break;
        }
        if (POINTER_OVERFLOW_ON_ADD(pc, info.size)) {
            LOG(2, "bailing on loop: "PFX" + "PFX" => "PFX"\n",
                pc, info.size, pc + info.size);
            break;
        }
        pc = info.base_pc + info.size;
    }
    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
umbra_iterate_shadow_memory(umbra_map_t *map,
                            void *user_data,
                            shadow_iterate_func_t iter_func)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (iter_func == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    return umbra_iterate_shadow_memory_arch(map, user_data, iter_func);
}

DR_EXPORT
drmf_status_t
umbra_get_shadow_memory_type(IN  umbra_map_t *map,
                             IN  byte *shadow_addr,
                             OUT umbra_shadow_memory_type_t *shadow_type)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (shadow_type == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    return umbra_get_shadow_memory_type_arch(map, shadow_addr, shadow_type);
}

drmf_status_t
umbra_shadow_memory_is_shared(IN  umbra_map_t *map,
                              IN  byte *shadow_addr,
                              OUT umbra_shadow_memory_type_t *shadow_type)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (shadow_type == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    return umbra_shadow_memory_is_shared_arch(map, shadow_addr, shadow_type);
}

DR_EXPORT
drmf_status_t
umbra_get_shadow_memory(IN    umbra_map_t *map,
                        IN    app_pc app_addr,
                        OUT   byte **shadow_addr,
                        INOUT umbra_shadow_memory_info_t *shadow_info)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (shadow_addr == NULL && shadow_info == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    if (shadow_info != NULL && shadow_info->struct_size != sizeof(*shadow_info))
        return DRMF_ERROR_INVALID_PARAMETER;
    return umbra_get_shadow_memory_arch(map, app_addr,
                                        shadow_addr, shadow_info);
}

DR_EXPORT
drmf_status_t
umbra_replace_shared_shadow_memory(umbra_map_t *map,
                                   app_pc app_addr,
                                   byte **shadow_addr)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (shadow_addr == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    return umbra_replace_shared_shadow_memory_arch(map, app_addr, shadow_addr);
}

DR_EXPORT
drmf_status_t
umbra_create_shared_shadow_block(IN  umbra_map_t *map,
                                 IN  ptr_uint_t   value,
                                 IN  size_t       value_size,
                                 OUT byte       **block)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (block == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    return umbra_create_shared_shadow_block_arch(map, value, value_size, block);
}

DR_EXPORT
drmf_status_t
umbra_get_shared_shadow_block(IN  umbra_map_t *map,
                              IN  ptr_uint_t   value,
                              IN  size_t       value_size,
                              OUT byte       **block)
{
    if (map == NULL || map->magic != UMBRA_MAP_MAGIC) {
        ASSERT(false, "invalid umbra_map");
        return DRMF_ERROR_INVALID_PARAMETER;
    }
    if (block == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    return umbra_get_shared_shadow_block_arch(map, value, value_size, block);
}
