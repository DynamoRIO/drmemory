/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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
 * symcache.h: cache symbol name lookups
 */

#ifndef _SYMCACHE_H_
#define _SYMCACHE_H_ 1

void
symcache_init(const char *symcache_dir,
              size_t modsize_cache_threshold);

void
symcache_exit(void);

void
symcache_module_load(void *drcontext, const module_data_t *mod, bool loaded);

void
symcache_module_unload(void *drcontext, const module_data_t *mod);

bool
symcache_module_is_cached(const module_data_t *mod);

bool
symcache_module_save_symcache(const module_data_t *mod);

bool
symcache_module_has_debug_info(const module_data_t *mod);

/* If an entry already exists and is 0, replaces it; else adds a new
 * offset for that symbol.
 */
bool
symcache_add(const module_data_t *mod, const char *symbol, size_t offs);

/* Returns true if the symbol is in the cache, which contains positive and
 * negative entries.  offs==0 indicates the symbol does not exist in the module.
 */
bool
symcache_lookup(const module_data_t *mod, const char *symbol, uint idx,
                size_t *offs OUT, uint *num OUT);

#endif /* _SYMCACHE_H_ */
