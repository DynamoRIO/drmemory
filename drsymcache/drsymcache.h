/* **********************************************************
 * Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
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

#ifndef _DRSYMCACHE_H_
#define _DRSYMCACHE_H_ 1

/* Dr. SymCache: Symbol Lookup Cache Extension */

/* Framework-shared header */
#include "drmemory_framework.h"
/* Ensure users are using drmgr's module events */
#include "drmgr.h"

/**
 * @file drsymcache.h
 * @brief Header for Dr. SymCache: Symbol Lookup Cache Extension
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \addtogroup drsymcache Dr. SymCache: Symbol Lookup Cache Extension
 */
/*@{*/ /* begin doxygen group */

/** Priority of drsymcache events. */
enum {
    /**
     * Priority of the drsymcache module load event action
     * that checks for a symbol cache file and reads it in.
     * This event must occur before any drsymcache API usage
     * in module load events of users of drsymcache.
     */
    DRMGR_PRIORITY_MODLOAD_DRSYMCACHE_READ = -150,
    /**
     * Priority of the drsymcache module load event action
     * that saves the current symbol cache from memory to disk.
     */
    DRMGR_PRIORITY_MODLOAD_DRSYMCACHE_SAVE = 150,
    /**
     * Priority of the drsymcache module unload event action
     * that saves the current symbol cache from memory to disk
     * and then frees the in-memory cache data structures.
     * This event must occur after any drsymcache API usage
     * in module unload events of users of drsymcache.
     */
    DRMGR_PRIORITY_MODUNLOAD_DRSYMCACHE    = -150,
};

/**
 * Name of drsymcache events #DRMGR_PRIORITY_MODLOAD_DRSYMCACHE_READ
 * and #DRMGR_PRIORITY_MODUNLOAD_DRSYMCACHE.
 */
#define DRMGR_PRIORITY_NAME_DRSYMCACHE "drsymcache"

/** Name of drsymcache events #DRMGR_PRIORITY_MODLOAD_DRSYMCACHE_SAVE. */
#define DRMGR_PRIORITY_NAME_DRSYMCACHE_SAVE "drsymcache_save"

DR_EXPORT
/**
 * Initializes drsymcache.    Can be called multiple times (by separate components,
 * normally) but each call must be paired with a corresponding call to
 * drsymcache_exit(), and only the first call's parameters are honored:
 * subsequent calls return DRMF_WARNING_ALREADY_INITIALIZED and ignore the parameters
 * passed in favor of those passed to the original call.
 * Libraries that use drsymcache should typically require that their callers
 * initialize drsymcache, as the location of the cache files is usually
 * a top-level tool property.
 *
 * @param[in]  client_id  The id of the client using drsymcache, as passed to dr_init().
 * @param[in]  drsymcache_dir  The directory in which to store symbol cache files.
 *    If this directory does not exist, drsymcache will attempt to create it,
 *    and return DRMF_ERROR_INVALID_PARAMETER on failure.
 * @param[in]  modsize_cache_threshold   The minimum module size for which symbols
 *    should be cached.  Normally there's little downside to caching, so passing 0
 *    here is reasonable.
 *
 * \return success code.
 */
drmf_status_t
drsymcache_init(client_id_t client_id,
                const char *drsymcache_dir,
                size_t modsize_cache_threshold);

DR_EXPORT
/**
 * Cleans up drsymcache.
 *
 * \return success code.
 */
drmf_status_t
drsymcache_exit(void);

DR_EXPORT
/**
 * Queries whether drsymcache has been initialized.
 *
 * @param[out] initialized  Whether drsymcache is initialized.
 *
 * \return success code.
 */
drmf_status_t
drsymcache_is_initialized(OUT bool *initialized);

DR_EXPORT
/**
 * Queries whether \p mod has a corresponding symbol cache.
 *
 * @param[in]  mod     The module being queried.
 * @param[out] cached  Whether the module has a symbol cache.
 *
 * \return success code.
 */
drmf_status_t
drsymcache_module_is_cached(const module_data_t *mod, OUT bool *cached);

DR_EXPORT
/**
 * Queries whether \p mod has debug information (any symbol information,
 * even if there is no line number information: i.e., whether the symbol
 * is stripped).
 *
 * @param[in]  mod        The module being queried.
 * @param[out] has_debug  Whether the module has debug information.
 *
 * \return success code.
 */
drmf_status_t
drsymcache_module_has_debug_info(const module_data_t *mod, OUT bool *has_debug);

DR_EXPORT
/**
 * Proactively writes the symbol cache file corresponding to \p mod to disk.
 * Symbol cache files are automatically saved at three points, without the user
 * needing to invoke this routine: after a module is loaded (with a late
 * priority DRMGR_PRIORITY_MODLOAD_DRSYMCACHE_SAVE), when a module is unloaded
 * (with priority DRMGR_PRIORITY_MODUNLOAD_DRSYMCACHE), and when the final
 * drsymcache_exit() is called.
 *
 * @param[in]  mod  The module to save.
 *
 * \return success code.
 */
drmf_status_t
drsymcache_module_save_symcache(const module_data_t *mod);

DR_EXPORT
/**
 * Adds a new entry for the symbol name \p symbol to the symbol cache for \p mod.
 * If an entry already exists and is 0, replaces it; else adds a new
 * value equal to \p offset for that symbol.
 *
 * @param[in]  mod     The module whose symcache should be updated.
 * @param[in]  symbol  The name of the symbol being added.
 * @param[in]  offs    The offset from the module base to add.
 *
 * \return success code.
 * If there is no cache for this module, returns DRMF_ERROR_NOT_FOUND.
 */
drmf_status_t
drsymcache_add(const module_data_t *mod, const char *symbol, size_t offs);

DR_EXPORT
/**
 * Queries the symbol cache for \p mod.  If \p symbol is not present in
 * the cache, returns DRMF_ERROR_NOT_FOUND.  If \p symbol is present,
 * allocates and returns an array of all entries found.  The size of
 * the array is returned in \p num.  The array must be freed by
 * calling drsymcache_free_lookup().
 *
 * @param[in]  mod    The module being queried.
 * @param[in]  symbol The name of the symbol being queried.
 * @param[out] offs_array  Returns a pointer to an array of offsets from the module
 *     base containing the locations of each instance of the symbol.  If the
 *     symbol is not present in the module, there will only be one entry with
 *     offset of 0.
 * @param[out] offs_single  Since many symbols have only one entry, to avoid
 *     the overhead of allocating memory the caller must pass in a single
 *     slot that offs_array will point to if num_entries is just 1.
 * @param[out] num_entries  The total count of instances of symbol within the module.
 *
 * \return success code.
 */
drmf_status_t
drsymcache_lookup(const module_data_t *mod, const char *symbol,
                  OUT size_t **offs_array, OUT uint *num_entries,
                  OUT size_t *offs_single);

DR_EXPORT
/**
 * Frees the array of offsets allocated by drsymcache_lookup().
 *
 * \return success code.
 */
drmf_status_t
drsymcache_free_lookup(size_t *offs, uint num);

/*@}*/ /* end doxygen group */

#ifdef __cplusplus
}
#endif

#endif /* _DRSYMCACHE_H_ */
