/* **********************************************************
 * Copyright (c) 2012-2014 Google, Inc.  All rights reserved.
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

#ifndef _UMBRA_H_
#define _UMBRA_H_ 1

/* Umbra: DynamoRIO Shadow Memory Extension */

/* The name of Umbra came from the CGO-2010 paper:
 * "Umbra: Efficient and Scalable Memory Shadowing",
 * while the design and implementation is completely different.
 */

/* Framework-shared header */
#include "drmemory_framework.h"

/**
 * @file umbra.h
 * @brief Header for Umbra: DynamoRIO Shadow Memory Extension
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup umbra Umbra: DynamoRIO Shadow Memory Extension
 */
/*@{*/ /* begin doxygen group */

/* Users of Umbra need to use the drmgr versions of these events to ensure
 * that Umbra's actions occur at the right time.
 */
#ifndef dr_get_tls_field
# define dr_get_tls_field DO_NOT_USE_tls_field_USE_drmgr_tls_field_instead
# define dr_set_tls_field DO_NOT_USE_tls_field_USE_drmgr_tls_field_instead
# define dr_insert_read_tls_field DO_NOT_USE_tls_field_USE_drmgr_tls_field_instead
# define dr_insert_write_tls_field DO_NOT_USE_tls_field_USE_drmgr_tls_field_instead
# define dr_register_thread_init_event DO_NOT_USE_thread_event_USE_drmgr_events_instead
# define dr_unregister_thread_init_event DO_NOT_USE_thread_event_USE_drmgr_events_instead
# define dr_register_thread_exit_event DO_NOT_USE_thread_event_USE_drmgr_events_instead
# define dr_unregister_thread_exit_event DO_NOT_USE_thread_event_USE_drmgr_events_instead
# define dr_register_pre_syscall_event DO_NOT_USE_pre_syscall_USE_drmgr_events_instead
# define dr_unregister_pre_syscall_event DO_NOT_USE_pre_syscall_USE_drmgr_events_instead
# define dr_register_post_syscall_event DO_NOT_USE_post_syscall_USE_drmgr_events_instead
# define dr_unregister_post_syscall_event DO_NOT_USE_post_syscall_USE_drmgr_events_instead
#endif /* dr_get_tls_field */

/***************************************************************************
 * ENUMS AND TYPES
 */

/** Priority of Umbra events. */
enum {
    /**
     * Priority of the Umbra signal/exception handling event.
     * This event must take place before any user of drsyscall
     * in order to allocate shadow memory if necessary.
     */
    DRMGR_PRIORITY_EXCPT_UMBRA = -100,
};

/** Name of Umbra signal/exception events. */
#define DRMGR_PRIORITY_NAME_EXCPT_UMBRA "umbra_except"

/**
 * Shadow memory mapping (scaling) schemes supported by Umbra.
 *
 * \note: Umbra does not support bit operations, so parameters passed to
 * any Umbra routine will be automatically aligned for proper translation.
 * For example, application memory address \p app_addr will be aligned to
 * 8 if using UMBRA_MAP_SCALE_DOWN_8X mapping scheme.
 */
typedef enum {
    UMBRA_MAP_SCALE_DOWN_8X, /** 8 app byte to 1 shadow byte */
    UMBRA_MAP_SCALE_DOWN_4X, /** 4 app byte to 1 shadow byte */
    UMBRA_MAP_SCALE_DOWN_2X, /** 2 app byte to 1 shadow byte */
    UMBRA_MAP_SCALE_SAME_1X, /** 1 app byte to 1 shadow byte */
    UMBRA_MAP_SCALE_UP_2X,   /** 1 app byte to 2 shadow byte */
} umbra_map_scale_t;

/** Check if a shadow memory mapping scale is scale up or down. */
#define UMBRA_MAP_SCALE_IS_UP(scale)   ((scale) >= UMBRA_MAP_SCALE_UP_2X)
#define UMBRA_MAP_SCALE_IS_DOWN(scale) ((scale) <= UMBRA_MAP_SCALE_DOWN_2X)

/** Umbra mapping creation flags for fine-grained control */
typedef enum {
    /**
     * If set, Umbra will try to create the shadow memory on the access
     * to shadow memory that is not yet.
     * When using this option, the user should handle exceptions
     * caused by referencing shadow memory that Umbra fails to handle.
     */
    UMBRA_MAP_CREATE_SHADOW_ON_TOUCH = 0x1,
    /**
     * This is an optimization hint for reducing memory usage by allowing
     * Umbra to map different application memory regions with identical shadow
     * value to the same shared shadow memory block.
     * Attempts to directly write shared shadow memory will cause
     * exceptions that should be handled by the user.
     */
    UMBRA_MAP_SHADOW_SHARED_READONLY = 0x2,
} umbra_map_flags_t;

/** Shadow memory creation flags used in umbra_create_shadow_memory. */
typedef enum {
    /**
     * This is an optimization hint for reducing memory usage by allowing
     * Umbra to map different application memory regions with identical shadow
     * value to the same shared shadow memory block.
     * Attempts to directly write shared shadow memory will cause
     * exceptions that should be handled by the user.
     * This allows user to control each individual shadow memory creation
     * whether using special shared block or not.
     */
    UMBRA_CREATE_SHADOW_SHARED_READONLY = 0x1,
} umbra_shadow_memory_flags_t;

/**
 * Shadow memory type.
 *
 * \note: A shadow memory may have more than one type, e.g.,
 * an address in redzone of shared special shadow memory block
 * will return value with both UMBRA_SHADOW_MEMORY_TYPE_SHARED
 * and UMBRA_SHADOW_MEMORY_TYPE_REDZONE being set.
 */
typedef enum {
    /** Unknown memory type */
    UMBRA_SHADOW_MEMORY_TYPE_UNKNOWN = 0x1,
    /**
     * Not a shadow memory: i.e., the address being translated is not from a valid
     * application memory region.  Umbra does not support storing metadata in
     * shadow memory for such addresses.
     */
    UMBRA_SHADOW_MEMORY_TYPE_NOT_SHADOW = 0x2,
    /** Normal writable shadow memory */
    UMBRA_SHADOW_MEMORY_TYPE_NORMAL = 0x4,
    /** Special read-only shadow memory */
    UMBRA_SHADOW_MEMORY_TYPE_SHARED = 0x8,
    /** Should be shadow memory, but not allocated yet */
    UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC = 0x10,
#ifndef X64 /* 32-bit only */
    /**
     * The redzone memory is allocated around the shadow memory
     * block for detecting cross block accesses.
     */
    UMBRA_SHADOW_MEMORY_TYPE_REDZONE = 0x20,
#endif
} umbra_shadow_memory_type_t;

/** Information about a shadow memory region. */
typedef struct _umbra_shadow_memory_info_t {
    /** For compatibility.  Set to sizeof(umbra_shadow_memory_info_t). */
    size_t struct_size;
    /** Base of the application memory block */
    app_pc app_base;
    /** Size of the application memory block */
    size_t app_size;
    /** Base of the shadow memory block */
    byte  *shadow_base;
    /** Size of the shadow memory block */
    size_t shadow_size;
    /** Type of the shadow memory block */
    umbra_shadow_memory_type_t shadow_type;
} umbra_shadow_memory_info_t;

/** Opaque "Umbra map handle" type.  See #umbra_map_t. */
struct _umbra_map_t;
/**
 * Opaque "Umbra map handle" type used to refer to a particular Umbra mapping
 * scheme object created by umbra_create_mapping(),
 */
typedef struct _umbra_map_t umbra_map_t;

/**
 * Application memory creation/deletion callback function type.
 * These callbacks are called when the application performs system calls to
 * allocate or delete memory.
 */
typedef void (*app_memory_create_cb_t)(umbra_map_t *map,
                                       app_pc start, size_t size);
typedef void (*app_memory_pre_delete_cb_t)(umbra_map_t *map,
                                           app_pc start, size_t size);
typedef void (*app_memory_post_delete_cb_t)(umbra_map_t *map,
                                            app_pc start, size_t size,
                                            bool success);
#ifdef UNIX
typedef void (*app_memory_mremap_cb_t)(umbra_map_t *map,
                                       app_pc old_base, size_t old_size,
                                       app_pc new_base, size_t new_size);
#endif

/** Specifies parameters controlling the behavior of umbra_create_map(). */
typedef struct _umbra_map_options_t {
    /** For compatibility.  Set to sizeof(umbra_map_options_t). */
    size_t struct_size;

    /** For shadow mapping scaling. */
    umbra_map_scale_t scale;

    /** For fine-grained control. */
    umbra_map_flags_t flags;

    /**
     * Specify the value of shadow memory that is allocated but not initialized
     * by the user; e.g., shadow memory padding or automatically allocated
     * shadow memory when UMBRA_MAP_CREATE_SHADOW_ON_TOUCH
     * (see #umbra_map_flags_t) is set.
     */
    ptr_uint_t default_value;
    /**
     * Specify the size of the default value, which could be 1, 2, 4 or 8 (x64).
     * We only support byte size (i.e., 1) now.
     */
    size_t default_value_size;

#ifndef X64
    /**
     * In shadow table based implementation, the redzone can be allocated
     * around each shadow memory block to detect cross block accesses.
     *
     * \note: The \p redzone_size must be multiple of 256, and 0 means no
     * redzone is used.
     */
    size_t     redzone_size;
    /** The value set in the redzone. */
    ptr_uint_t redzone_value;
    /** The redzone value size, only 1 is supported now */
    size_t     redzone_value_size;
    /**
     * Set to true to render redzones as faulty, i.e., access (both read and write)
     * to a redzone causes a fault.
     *
     * If a cross block access occurs, a fault is triggered. This is an
     * optimisation, because rather than requiring the user to perform explicit
     * checks on redzone access, a fault will indicate the case. The user may
     * then take further action by defining a fault handler, similar to
     * that done for shared block access (if enabled).
     *
     * Overrides redzone data specified in the struct, including redzone_size.
     * With this option enabled, the fields: #redzone_size, #redzone_value and
     * #redzone_value_size, are not considered. Redzone size is set to a page size
     * by default to set appropriate access permissions.
     */
    bool make_redzone_faulty;
#endif

    /** Application memory creation callback. */
    app_memory_create_cb_t app_memory_create_cb;

    /** Application memory pre deletion callback. */
    app_memory_pre_delete_cb_t app_memory_pre_delete_cb;

    /** Application memory post deletion callback. */
    app_memory_post_delete_cb_t app_memory_post_delete_cb;
#ifdef UNIX
    /** Application memory re-map callback. */
    app_memory_mremap_cb_t app_memory_mremap_cb;
#endif
} umbra_map_options_t;

/***************************************************************************
 * TOP-LEVEL
 */

DR_EXPORT
/**
 * Initialize the Umbra extension.  Must be called prior to any of the other
 * routines.  Can be called multiple times (by separate components, normally)
 * but each call must be paired with a corresponding call to umbra_exit().
 *
 * @param[in] client_id  The client id for version check.
 *
 * \return success code.
 */
drmf_status_t
umbra_init(client_id_t client_id);

DR_EXPORT
/**
 * Clean up the Umbra extension.
 */
drmf_status_t
umbra_exit(void);

DR_EXPORT
/**
 * Create a shadow memory mapping according to the mapping options \p ops,
 * and return the opaque pointer in \p map_out.
 * @param[in]   ops      The mapping object to use.
 * @param[out]  map_out  The mapping options.
 */
drmf_status_t
umbra_create_mapping(IN  umbra_map_options_t *ops,
                     OUT umbra_map_t **map_out);

DR_EXPORT
/**
 * Destroy a shadow memory mapping \p map created by umbra_create_mapping.
 */
drmf_status_t
umbra_destroy_mapping(IN  umbra_map_t *map);

DR_EXPORT
/**
 * Create shadow memory for application memory using mapping scheme \p map.
 *
 * @param[in] map         The mapping object to use.
 * @param[in] flags       Shadow memory creation options.
 * @param[in] app_addr    Application memory address.
 * @param[in] app_size    Application memory size.
 * @param[in] value       The initial value in shadow memory.
 * @param[in] value_size  The initial value size, could be 1, 2, 4, or 8 (x64).
 *                        Only 1 is supported now.
 *
 * \return success code.  If \p app_addr is not a valid application address
 * and the shadow mapping implementation does not support shadow memory
 * for invalid addresses, returns DRMF_ERROR_INVALID_ADDRESS.
 *
 * \note: If the newly created shadow memory overlaps with the existing shadow
 * memory, the value of overlapped part will be clobbered with new value.
 *
 * \note: The actual size of created shadow memory might be larger than the
 * required size, the extended part will be set as default value specified
 * on \p map creation.
 */
drmf_status_t
umbra_create_shadow_memory(IN  umbra_map_t *map,
                           IN  umbra_shadow_memory_flags_t flags,
                           IN  app_pc       app_addr,
                           IN  size_t       app_size,
                           IN  ptr_uint_t   value,
                           IN  size_t       value_size);

DR_EXPORT
/**
 * Delete shadow memory from mapping scheme \p map for application memory
 * at \p app_addr.
 *
 * @param[in] map         The mapping object to use.
 * @param[in] app_addr    Application memory address.
 * @param[in] app_size    Application memory size.
 *
 * \return success code.  If \p app_addr is not a valid application address
 * and the shadow mapping implementation does not support shadow memory
 * for invalid addresses, returns DRMF_ERROR_INVALID_ADDRESS.
 *
 * \note: part of the shadow memory might not be actually deleted,
 * which will be set to the value specified on \p map creation instead.
 */
drmf_status_t
umbra_delete_shadow_memory(IN  umbra_map_t *map,
                           IN  app_pc       app_addr,
                           IN  size_t       app_size);

DR_EXPORT
/**
 * Query the number of scratch registers needed (excluding the register holding
 * the application address) for address translation from application memory to
 * shadow memory.
 *
 * @param[out]  num_regs  Number of scratch register required for translation.
 */
drmf_status_t
umbra_num_scratch_regs_for_translation(OUT  int *num_regs);

DR_EXPORT
/**
 * Insert instructions into \p ilist before \p where to
 * translate application address stored in \p reg_addr to shadow address and
 * store it into \p reg_addr.
 *
 * Umbra may use page faults to implement lazy shadow memory allocation.  When
 * generating meta instructions to read shadow values, be sure to assign
 * translation values to the instructions.
 *
 * @param[in]  drcontext         The DynamoRIO context for current thread.
 * @param[in]  map               The mapping object to use.
 * @param[in]  ilist             The instruction list to be inserted into.
 * @param[in]  where             The instruction to be inserted before
 * @param[in]  addr_reg          The Register holding the application address
 *                               for translation, and holding the shadow memory
 *                               address after translation.
 * @param[in]  scratch_regs      The array of scratch registers for use.
 * @param[in]  num_scratch_regs  Number of scratch register
 *
 * \note: \p num_scratch_regs must not be smaller than the value returned from
 * umbra_num_scratch_regs_for_translation, otherwise error code
 * DRMF_ERROR_NOT_ENOUGH_REGS is returned.
 *
 * \note: This method destroys aflags. Be sure to save and restore aflags before
 * and after this method is called, e.g. with \p drreg_reserve_aflags().
 */
drmf_status_t
umbra_insert_app_to_shadow(IN  void        *drcontext,
                           IN  umbra_map_t *map,
                           IN  instrlist_t *ilist,
                           IN  instr_t     *where,
                           IN  reg_id_t     addr_reg,
                           IN  reg_id_t    *scratch_regs,
                           IN  int          num_scratch_regs);

DR_EXPORT
/**
 * Read shadow memory for application memory at \p app_addr to \p buffer.
 *
 * @param[in]     map          The mapping object to use.
 * @param[in]     app_addr     Application memory address.
 * @param[in]     app_size     Application memory size.
 * @param[in,out] shadow_size  The max buffer size.
 *                             Return the number of bytes actually read.
 * @param[out]    buffer       The buffer holds the read value.
 *
 * \return success code.  If \p app_addr is not a valid application address
 * and the shadow mapping implementation does not support shadow memory
 * for invalid addresses, returns DRMF_ERROR_INVALID_ADDRESS.
 */
drmf_status_t
umbra_read_shadow_memory(IN    umbra_map_t *map,
                         IN    app_pc  app_addr,
                         IN    size_t  app_size,
                         INOUT size_t *shadow_size,
                         OUT   byte   *buffer);

DR_EXPORT
/**
 * Write shadow memory for application memory at \p app_addr from \p buffer.
 *
 * @param[in]     map          The mapping object to use.
 * @param[in]     app_addr     Application memory address.
 * @param[in]     app_size     Application memory size.
 * @param[in,out] shadow_size  The max buffer size.
 *                             Return the number of bytes actually written.
 * @param[in]     buffer       The buffer holds the value to write.
 *
 * \return success code.  If \p app_addr is not a valid application address
 * and the shadow mapping implementation does not support shadow memory
 * for invalid addresses, returns DRMF_ERROR_INVALID_ADDRESS.
 */
drmf_status_t
umbra_write_shadow_memory(IN  umbra_map_t *map,
                          IN  app_pc  app_addr,
                          IN  size_t  app_size,
                          INOUT size_t *shadow_size,
                          IN  byte   *buffer);

DR_EXPORT
/**
 * Set a range of shadow memory for application memory at \p app_addr.
 *
 * @param[in]  map           The mapping object to use.
 * @param[in]  app_addr      Application memory address.
 * @param[in]  app_size      Application memory size.
 * @param[out] shadow_size   The number of bytes actually written.
 * @param[in]  value         The value to be set in shadow memory.
 * @param[in]  value_size    The value size for \p value, could be 1, 2, 4,
 *                           or 8 (x64). Only 1 is supported now.
 *
 * \return success code.  If \p app_addr is not a valid application address
 * and the shadow mapping implementation does not support shadow memory
 * for invalid addresses, returns DRMF_ERROR_INVALID_ADDRESS.
 */
drmf_status_t
umbra_shadow_set_range(IN   umbra_map_t *map,
                       IN   app_pc       app_addr,
                       IN   size_t       app_size,
                       OUT  size_t      *shadow_size,
                       IN   ptr_uint_t   value,
                       IN   size_t       value_size);

DR_EXPORT
/**
 * Copy value from shadow memory for application memory at \p app_src
 * to shadow memory for application memory at \p app_dst.
 *
 * @param[in]  map          The mapping object to use.
 * @param[in]  app_src      Source application memory address.
 * @param[in]  app_dst      Destination application memory address.
 * @param[in]  app_size     Application memory size.
 * @param[out] shadow_size  The number of bytes actually copied.
 *
 * \return success code.  If \p app_addr is not a valid application address
 * and the shadow mapping implementation does not support shadow memory
 * for invalid addresses, returns DRMF_ERROR_INVALID_ADDRESS.
 *
 * \note: Overlap is allowed.
 */
drmf_status_t
umbra_shadow_copy_range(IN  umbra_map_t *map,
                        IN  app_pc  app_src,
                        IN  app_pc  app_dst,
                        IN  size_t  app_size,
                        OUT size_t *shadow_size);

DR_EXPORT
/**
 * Check whether \p value is in the shadow memory for application memory at
 * \p app_addr.
 *
 * @param[in]     map         The mapping object to use.
 * @param[in,out] app_addr    Starting application memory address.
 *                            Return the application address at which if found.
 * @param[in]     app_size    Application memory size.
 * @param[in]     value       The value to be set in shadow memory.
 * @param[in]     value_size  The value size for \p value, could be 1, 2, 4,
 *                            or 8 (x64). Only 1 is supported now.
 * @param[out]    found       Return true if \p value found in the range.
 *
 * \return success code.  If \p app_addr is not a valid application address
 * and the shadow mapping implementation does not support shadow memory
 * for invalid addresses, returns DRMF_ERROR_INVALID_ADDRESS.
 */
drmf_status_t
umbra_value_in_shadow_memory(IN    umbra_map_t *map,
                             INOUT app_pc      *app_addr,
                             IN    size_t       app_size,
                             IN    ptr_uint_t   value,
                             IN    size_t       value_size,
                             OUT   bool        *found);

DR_EXPORT
/**
 * Get the shadow block size, which is the unit size Umbra allocates/frees
 * the shadow memory.
 *
 * @param[in]  map   The mapping object to use.
 * @param[out] size  The shadow memory block size.
 */
drmf_status_t
umbra_get_shadow_block_size(IN  umbra_map_t *map,
                            OUT size_t *size);

DR_EXPORT
/**
 * Iterate the application memory (i.e., any memory that are not part of
 * shadow memory, DynamoRIO internal memory, or DynamoRIO's client memory).
 *
 * @param[in]  map        The mapping object to use.
 * @param[in]  user_data  The user data passed to \p iter_func.
 * @param[in]  iter_func  The iterate callback function.
 *                        It can return false to stop the iteration.
 *
 * \note: the memory allocated by dr_raw_mem_alloc by client might be iterated
 * since they are not considered as part of DynamoRIO internal or client memory.
 */
drmf_status_t
umbra_iterate_app_memory(IN  umbra_map_t *map,
                         IN  void *user_data,
                         IN  bool (*iter_func)(umbra_map_t *map,
                                               const dr_mem_info_t *info,
                                               void  *user_data));

/**
 * Iterate callback function type for umbra_iterate_shadow_memory.
 *
 * @param[in]  map        The mapping object to use.
 * @param[in]  info       Information about the shadow memory.
 * @param[in]  user_data  User data passed during iteration.
 */
typedef bool (*shadow_iterate_func_t)(umbra_map_t *map,
                                      umbra_shadow_memory_info_t *info,
                                      void *user_data);

DR_EXPORT
/**
 * Iterate shadow memory and call \p iter_func on each shadow memory block.
 *
 * @param[in]  map        The mapping object to use.
 * @param[in]  user_data  The user data passed to \p iter_func.
 * @param[in]  iter_func  The iterate callback function.
 *                        It can return false to stop the iteration.
 */
drmf_status_t
umbra_iterate_shadow_memory(IN  umbra_map_t *map,
                            IN  void  *user_data,
                            IN  shadow_iterate_func_t iter_func);

DR_EXPORT
/**
 * Get shadow memory type for address \p shadow_addr.
 *
 * @param[in]  map          The mapping object to use.
 * @param[in]  shadow_addr  The shadow memory address for \p app_addr.
 * @param[out] shadow_type  The type of the shadow memory at \p shadow_addr.
 *
 * \note: this routine has high runtime overhead since it may need iterate all
 * shadow memory to determine the shadow memory type for \p shadow_addr.
 */
drmf_status_t
umbra_get_shadow_memory_type(IN  umbra_map_t *map,
                             IN  byte *shadow_addr,
                             OUT umbra_shadow_memory_type_t *shadow_type);

DR_EXPORT
/**
 * Similar to umbra_get_shadow_memory_type, but only check if \p shadow_addr
 * is in a special shared shadow memory block.
 * \p shadow_type is set to be UMBRA_SHADOW_MEMORY_TYPE_SHARED
 * (optionally with UMBRA_SHADOW_MEMORY_TYPE_REDZONE also set) if
 * \p shadow_addr is in any special shared shadow memory block
 * and UMBRA_SHADOW_MEMORY_TYPE_UNKNOWN otherwise.
 * If \p shadow_addr is in the redzone of a special shared shadow
 * memory block, UMBRA_SHADOW_MEMORY_TYPE_REDZONE is also set along with
 * UMBRA_SHADOW_MEMORY_TYPE_SHARED.
 *
 * @param[in]  map          The mapping object to use.
 * @param[in]  shadow_addr  The shadow memory address.
 * @param[out] shadow_type  The type of the shadow memory at \p shadow_addr.
 *
 * \note: This is a routine for efficient check if \p shadow_addr is in a
 * special shared shadow memory. UMBRA_SHADOW_MEMORY_TYPE_UNKNOWN is set
 * even \p shadow_addr could be normal writable shadow memory.
 *
 */
drmf_status_t
umbra_shadow_memory_is_shared(IN  umbra_map_t *map,
                              IN  byte *shadow_addr,
                              OUT umbra_shadow_memory_type_t *shadow_type);

DR_EXPORT
/**
 * Get shadow memory address for application memory address \p app_addr.
 *
 * @param[in]     map          The mapping object to use.
 * @param[in]     app_addr     The application memory address.
 * @param[out]    shadow_addr  The shadow memory address for \p app_addr.
 * @param[in,out] shadow_info  The information about the shadow memory for
 *                             \p app_addr.
 *
 * For lazily allocated shadow memory, this routine will not allocate
 * shadow memory that is not yet allocated.  The caller must
 * explicitly call umbra_create_shadow_memory() prior to
 * de-referencing the returned shadow address if the type is
 * UMBRA_SHADOW_MEMORY_TYPE_SHADOW_NOT_ALLOC.  Use
 * umbra_read_shadow_memory() or umbra_write_shadow_memory() if
 * automatic allocation is desired.
 *
 * \note: \p shadow_info->struct_size must be set to
 * \p sizeof(umbra_shadow_memory_info_t) for compatiblity.
 *
 * \note: \p shadow_info contains the information about the shadow memory block
 * and its application memory, so the caller can cache the information and
 * access the shadow memory later without querying Umbra again.
 * However, if the shadow memory is a special shared memory block, it may be
 * replaced with normal shadow memory and the caller will not see it,
 * and the caller will see the old special value if using cached information.
 * It is up to the caller to decide whether this is acceptable.
 *
 * \note: No redzone will be included in the \p shadow_info.
 *
 */
drmf_status_t
umbra_get_shadow_memory(IN    umbra_map_t *map,
                        IN    app_pc app_addr,
                        OUT   byte **shadow_addr,
                        INOUT umbra_shadow_memory_info_t *shadow_info);

DR_EXPORT
/**
 * Replace the special shared shadow memory for application address
 * \p app_addr with normal writable shadow memory.
 * Do nothing if it is already uses normal writable shadow memory or
 * not allocated yet.
 *
 * @param[in]  map          The mapping object to use.
 * @param[in]  app_addr     The application memory address to be replaced.
 * @param[out] shadow_addr  Return the replaced shadow memory address.
 */
drmf_status_t
umbra_replace_shared_shadow_memory(IN  umbra_map_t *map,
                                   IN  app_pc       app_addr,
                                   OUT byte       **shadow_addr);

DR_EXPORT
/**
 * Create special shared shadow memory that Umbra can map different
 * application regions with the same shadow value as \p value to it.
 *
 * @param[in]  map         The mapping object to use.
 * @param[in]  value       The value used by the shadow block.
 * @param[in]  value_size  The value size used by the shadow block.
 * @param[out] block       The pointer pointing to the base of the shadow block.
 *                         Returns NULL if Umbra fails to create one.
 *
 * \note: Umbra only creates special shared shadow memory if necessary.
 * This routine forces Umbra create one even Umbra may not use it.
 *
 * \note: Umbra does not use special shared shadow block in current x64
 * implementation and always returns DRMF_ERROR_FEATURE_NOT_AVAILABLE.
 */
drmf_status_t
umbra_create_shared_shadow_block(IN  umbra_map_t *map,
                                 IN  ptr_uint_t   value,
                                 IN  size_t       value_size,
                                 OUT byte       **block);

DR_EXPORT
/**
 * Get special shared shadow memory created by umbra_create_shared_shadow_block
 * or Umbra with identical \p value and \p value_size.
 *
 * @param[in]  map         The mapping object to use.
 * @param[in]  value       The value used by the shadow block.
 * @param[in]  value_size  The value size used by the shadow block.
 * @param[out] block       The pointer pointing to the base of the shadow block.
 *                         Returns NULL if Umbra fails to find one.
 *
 * \note: Umbra does not use special shared shadow block in current x64
 * implementation and always returns DRMF_ERROR_FEATURE_NOT_AVAILABLE.
 */
drmf_status_t
umbra_get_shared_shadow_block(IN  umbra_map_t *map,
                              IN  ptr_uint_t   value,
                              IN  size_t       value_size,
                              OUT byte       **block);

/** Convenience routine for initializing umbra_shadow_memory_info. */
static inline void
umbra_shadow_memory_info_init(umbra_shadow_memory_info_t *info)
{
    info->struct_size = sizeof(*info);
    info->app_base = NULL;
    info->app_size = 0;
}

DR_EXPORT
/**
 * Clears and deletes redundant blocks consisting of only default values for \p map.
 * This function is typically invoked when low on memory. It deletes normal blocks
 * and sets mapping entries to the special basic block.
 *
 * The number of redundant blocks destroyed is returned via \p count. This is an
 * optional parameter and can be set to NULL if the count is not wanted.
 *
 * Assumes that threads are suspended so that Umbra may safely modify shadow memory.
 * It is up to the caller to suspend and resume threads.
 *
 * This feature is only available on 32-bit and requires that the
 * create-on-touch optimization (#UMBRA_MAP_CREATE_SHADOW_ON_TOUCH) is enabled.
 */
drmf_status_t
umbra_clear_redundant_blocks(umbra_map_t *map, uint *count);

DR_EXPORT
/*
 * A convenience routine that returns granularity information of the passed Umbra map.
 *
 * Note that the returned scale is the numerical value representation, and not of
 * type #umbra_map_scale_t.
 *
 * @param[in]  map              The mapping object to use.
 * @param[out] scale            The pointer where to store the returned scale.
 * @param[out] is_scale_down    The pointer where to store the returned flag
 *                              indicating whether shadow memory is scaled down
 *                              or up.
 */
drmf_status_t
umbra_get_granularity(const umbra_map_t *map, OUT int *scale,
                      bool *is_scale_down);

/*@}*/ /* end doxygen group */

#ifdef __cplusplus
}
#endif

#endif /* _UMBRA_H_ */
