/* **********************************************************
 * Copyright (c) 2011-2019 Google, Inc.  All rights reserved.
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
 * symcache.c: cache symbol name lookups
 */

#include "dr_api.h"
#include "drmgr.h"
#include "drsymcache.h"
#include "drmemory_framework.h"
#include "../framework/drmf.h"
#include "utils.h"
#include <string.h>

/* General comments:
 * - The file is not assumed to be complete and instead contains negative
 *   entries.  This means it doesn't need to store runtime options used
 *   or anything if there are differences in which symbols we care about
 *   from run to run.  It also means we can think of it as a cache
 *   for repeated queries during a run as well as between runs.
 * - Using just module name for the file and not worrying about
 *   conflicts since this is just a performance improvement: thus some
 *   SxS or other modules may end up w/ competing cache files.
 * - i#617: we assume that we have all the entries of a symbol
 *   if we can find one entry for that symbol in the symcache.
 * - Anyone creating synthetic symcaches (e.g., for i#192) needs to be aware
 *   of wildcard symcache entries.  i#722 added
 *   "std::_DebugHeapDelete<*>" whose matches are stored as
 *   "std::_DebugHeapDelete<>" duplicates.
 */

#define SYMCACHE_FILE_HEADER "Dr. Memory symbol cache version"

/* We need to bump the version number whenever we change the file format.
 * We do not need to bump it when we change the symbols we look up,
 * because we include negative entries in the file and make no assumptions
 * that it is a complete record of all lookups we'll need.
 */
#define SYMCACHE_VERSION 15

/* we need a separate hashtable per module */
#define SYMCACHE_MASTER_TABLE_HASH_BITS 6
#define SYMCACHE_MODULE_TABLE_HASH_BITS 6
#define SYMCACHE_OLIST_TABLE_HASH_BITS 5

/* Size of the buffer used to write the symbol cache.  This is stack allocated,
 * so it should not be increased.
 */
#define SYMCACHE_BUFFER_SIZE 4096

/* The number of digits used for the decimal representation of the file size of
 * the symcache file.
 */
#define SYMCACHE_SIZE_DIGITS 10

#define SYMCACHE_MAX_TMP_TRIES 1000

/* We key on full path to reduce chance of duplicate name (i#729).
 * If we do have duplicate preferred name, though, note that only one can
 * have a symcache file b/c our file namespace does not have versions
 * in it.
 */
static hashtable_t symcache_table;

/* simple synch scheme: hold this lock across all operations on outer or inner tables */
static void *symcache_lock;

static bool initialized;

static int symcache_init_count;

/* Entry in the outer table */
typedef struct _mod_cache_t {
    /* strdup-ed modname since key now holds path */
    const char *modname;
    bool from_file; /* came from a cache file */
    bool appended; /* added to since read from file? */
    /* Table of offset_list_t entries */
    hashtable_t table;
    /* Values for consistency that we cache until ready to write to file */
    uint64 module_file_size;
#ifdef WINDOWS
    version_number_t file_version;
    version_number_t product_version;
    uint checksum;
    uint timestamp;
    size_t module_internal_size;
#else
    /* XXX: may want more consistency checks as timestamp is not always set */
    uint timestamp;
# ifdef MACOS
    uint current_version;
    uint compatibility_version;
    byte uuid[16];
# endif
#endif
    bool has_debug_info; /* do we have DWARF/PECOFF/PDB symbols? */
} mod_cache_t;

typedef struct _offset_entry_t {
    size_t offs;
    struct _offset_entry_t *next;
} offset_entry_t;

/* For very few entries (which are the most common) we don't need a hashtable */
#define OFFSET_LIST_MIN_TABLE 3

/* Entry in the per-module table */
typedef struct _offset_list_t {
    uint num;
    /* We use both a linked list (for index-based iteration/lookup)
     * and a hashtable (to easily see whether an offset exists)
     */
    offset_entry_t *list;
    /* We want to append on add */
    offset_entry_t *list_last;
    /* The table is only allocated once we have OFFSET_LIST_MIN_TABLE entries.
     * Entries are offset+1 (b/c we have 0 offset).
     */
    hashtable_t *table;
    /* For improved iteration performance we cache the last index + entry */
    uint iter_idx;
    offset_entry_t *iter_entry;
} offset_list_t;

static char symcache_dir[MAXIMUM_PATH];
static size_t op_modsize_cache_threshold;

static void
symcache_module_load(void *drcontext, const module_data_t *mod, bool loaded);

static void
symcache_module_load_save(void *drcontext, const module_data_t *mod, bool loaded);

static void
symcache_module_unload(void *drcontext, const module_data_t *mod);

static bool
module_has_symbols(const module_data_t *mod)
{
    return (drsym_module_has_symbols(mod->full_path) == DRSYM_SUCCESS);
}

/* caller must hold symcache_lock, even at exit time */
static void
symcache_free_entry(void *v)
{
    mod_cache_t *modcache = (mod_cache_t *) v;
    ASSERT(dr_mutex_self_owns(symcache_lock), "missing symcache lock");
    if (modcache != NULL) {
        hashtable_delete(&modcache->table);
        if (modcache->modname != NULL) {
            global_free((void *)modcache->modname, strlen(modcache->modname) + 1,
                        HEAPSTAT_HASHTABLE);
        }
        global_free(modcache, sizeof(*modcache), HEAPSTAT_HASHTABLE);
    }
}

static void
symcache_get_filename(const char *modname, char *symfile, size_t symfile_count)
{
    dr_snprintf(symfile, symfile_count, "%s/%s.txt", symcache_dir, modname);
    symfile[symfile_count-1] = '\0';
}

/* If an entry already exists and is 0, replaces it; else adds a new
 * offset for that symbol.
 *
 * If symtable is visible outside of this thread, the caller must hold symcache_lock.
 */
static bool
symcache_symbol_add(const char *modname, hashtable_t *symtable,
                    const char *symbol, size_t offs)
{
    offset_list_t *olist;
    offset_entry_t *e;
    olist = (offset_list_t *) hashtable_lookup(symtable, (void *)symbol);
    if (olist != NULL) {
        if (olist->num == 1 && olist->list->offs == 0) {
            /* replace a single 0 entry */
            if (olist->table != NULL) {
                ASSERT(olist->num >= OFFSET_LIST_MIN_TABLE, "table should be NULL");
                hashtable_remove(olist->table, (void *)(olist->list->offs + 1));
                hashtable_add(olist->table, (void *)(offs + 1), (void *)(offs + 1));
            }
            olist->list->offs = offs;
            return true;
        } else if (olist->num == 1 && offs == 0) {
            /* XXX i#1465: temporary fatal error sanity check as we try to diagnose
             * our symbol cache errors.
             */
            NOTIFY_ERROR("SYMCACHE ERROR: appending 0 to non-0 for %s!%s"NL,
                         modname, symbol);
            dr_abort(); /* make sure we see this on bots */
        }
        if (olist->table != NULL) {
            if (hashtable_lookup(olist->table, (void *)(offs + 1)) != NULL) {
                LOG(2, "%s: ignoring dup entry %s\n", __FUNCTION__, symbol);
                return false;
            }
        } else {
            for (e = olist->list; e != NULL; e = e->next) {
                if (e->offs == offs) {
                    LOG(2, "%s: ignoring dup entry %s\n", __FUNCTION__, symbol);
                    return false;
                }
            }
        }
    } else {
        olist = (offset_list_t *) global_alloc(sizeof(*olist), HEAPSTAT_HASHTABLE);
        olist->num = 0;
        olist->list = NULL;
        olist->list_last = NULL;
        olist->table = NULL;
    }
    LOG(2, "%s: %s \"%s\" @ "PIFX"\n", __FUNCTION__, modname, symbol, offs);
    /* we could verify by an addr lookup but we still need consistency info
     * in the file for the negative entries so we don't bother
     */
    e = (offset_entry_t *) global_alloc(sizeof(*e), HEAPSTAT_HASHTABLE);
    e->offs = offs;
    e->next = NULL;
    /* append to avoid affecting iteration */
    if (olist->list_last == NULL) {
        ASSERT(olist->list == NULL, "last not set");
        olist->list = e;
        olist->list_last = e;
    } else {
        olist->list_last->next = e;
        olist->list_last = e;
    }
    olist->num++;
    if (olist->num >= OFFSET_LIST_MIN_TABLE) {
        if (olist->table == NULL) {
            /* enough entries that a table is worthwhile */
            olist->table = (hashtable_t *)
                global_alloc(sizeof(*olist->table), HEAPSTAT_HASHTABLE);
            hashtable_init(olist->table, SYMCACHE_OLIST_TABLE_HASH_BITS,
                           HASH_INTPTR, false/*strdup*/);
            for (e = olist->list; e != NULL; e = e->next)
                hashtable_add(olist->table, (void *)(e->offs + 1), (void *)(e->offs + 1));
        } else
            hashtable_add(olist->table, (void *)(offs + 1), (void *)(offs + 1));
    }
    hashtable_add(symtable, (void *)symbol, (void *)olist);
    /* clear any cached values */
    olist->iter_idx = 0;
    olist->iter_entry = NULL;
    return true;
}

/* caller must hold symcache_lock */
static void
symcache_write_symfile(const char *modname, mod_cache_t *modcache)
{
    uint i;
    file_t f;
    hashtable_t *symtable = &modcache->table;
    char buf[SYMCACHE_BUFFER_SIZE];
    size_t sofar = 0;
    ssize_t len;
    size_t bsz = BUFFER_SIZE_ELEMENTS(buf);
    size_t filesz_loc;
    char symfile[MAXIMUM_PATH];
    char symfile_tmp[MAXIMUM_PATH];
    int64 file_size;

    ASSERT(dr_mutex_self_owns(symcache_lock), "missing symcache lock");

    /* if from file, we assume it's a waste of time to re-write file:
     * the version matched after all, unless we appended to it.
     */
    if (modcache->from_file && !modcache->appended)
        return;
    if (symtable->entries == 0)
        return; /* nothing to write */

    /* Open the temp symcache that we will rename.  */
    symcache_get_filename(modname, symfile, BUFFER_SIZE_ELEMENTS(symfile));
    f = INVALID_FILE;
    i = 0;
    while (f == INVALID_FILE && i < SYMCACHE_MAX_TMP_TRIES) {
        dr_snprintf(symfile_tmp, BUFFER_SIZE_ELEMENTS(symfile_tmp),
                    "%s.%04d.tmp", symfile, i);
        NULL_TERMINATE_BUFFER(symfile_tmp);
        f = dr_open_file(symfile_tmp, DR_FILE_WRITE_REQUIRE_NEW);
        i++;
    }
    if (f == INVALID_FILE) {
        NOTIFY("WARNING: Unable to create symcache temp file %s"NL,
               symfile_tmp);
        return;
    }

    BUFFERED_WRITE(f, buf, bsz, sofar, len, "%s %d\n",
                   SYMCACHE_FILE_HEADER, SYMCACHE_VERSION);
    /* Leave room for file size for self-consistency check */
    filesz_loc = sofar;  /* XXX: Assumes that the buffer hasn't been flushed. */
    BUFFERED_WRITE(f, buf, bsz, sofar, len,
                   "%"STRINGIFY(SYMCACHE_SIZE_DIGITS)"u,", 0);
#ifdef WINDOWS
    BUFFERED_WRITE(f, buf, bsz, sofar, len,
                   UINT64_FORMAT_STRING","UINT64_FORMAT_STRING","
                   UINT64_FORMAT_STRING",%u,%u,%zu\n",
                   modcache->module_file_size, modcache->file_version.version,
                   modcache->product_version.version,
                   modcache->checksum, modcache->timestamp,
                   modcache->module_internal_size);
#else
    BUFFERED_WRITE(f, buf, bsz, sofar, len, UINT64_FORMAT_STRING",%u",
                   modcache->module_file_size, modcache->timestamp);
# ifdef MACOS
    BUFFERED_WRITE(f, buf, bsz, sofar, len, ",%u,%u,",
                   modcache->current_version, modcache->compatibility_version);
    /* For easy sscanf we print as 4 ints */
    for (i = 0; i < 4; i++)
        BUFFERED_WRITE(f, buf, bsz, sofar, len, "%08x,", *(int*)(&modcache->uuid[i*4]));
# endif
    BUFFERED_WRITE(f, buf, bsz, sofar, len, "\n");
#endif
    BUFFERED_WRITE(f, buf, bsz, sofar, len, "%u\n", modcache->has_debug_info);
    for (i = 0; i < HASHTABLE_SIZE(symtable->table_bits); i++) {
        hash_entry_t *he;
        for (he = symtable->table[i]; he != NULL; he = he->next) {
            offset_list_t *olist = (offset_list_t *) he->payload;
            offset_entry_t *e;
            if (olist == NULL)
                continue;
            /* skip symbol in dup entries to save space */
            BUFFERED_WRITE(f, buf, bsz, sofar, len, "%s", he->key);
            e = olist->list;
            while (e != NULL) {
                BUFFERED_WRITE(f, buf, bsz, sofar, len, ",0x%x\n", e->offs);
                e = e->next;
            }
        }
    }

    /* now update size */
    FLUSH_BUFFER(f, buf, sofar);
    if ((file_size = dr_file_tell(f)) < 0 ||
        dr_snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                    "%"STRINGIFY(SYMCACHE_SIZE_DIGITS)"u", (uint)file_size) < 0 ||
        !dr_file_seek(f, filesz_loc, DR_SEEK_SET) ||
        dr_write_file(f, buf, SYMCACHE_SIZE_DIGITS) != SYMCACHE_SIZE_DIGITS) {
        /* If any steps fail, warn and give up. */
        NOTIFY("WARNING: Unable to write symcache file size."NL);
        dr_close_file(f);
        dr_delete_file(symfile_tmp);
        return;
    } else {
        LOG(3, "Wrote symcache %s file size %u to pos "SZFMT"\n",
            modname, (uint)file_size, filesz_loc);
        ASSERT(strlen(buf) <= SYMCACHE_SIZE_DIGITS, "not enough space for file size");
    }

    dr_close_file(f);

    if (!dr_rename_file(symfile_tmp, symfile, /*replace*/true)) {
        NOTIFY_ERROR("WARNING: Failed to rename the symcache file."NL);
        dr_delete_file(symfile_tmp);
    }
}

#define MAX_SYMLEN 256

/* Sets modcache->has_debug_info.
 * No lock is needed as we assume the caller hasn't exposed modcache outside this
 * thread yet.
 */
static bool
symcache_read_symfile(const module_data_t *mod, const char *modname,
                      mod_cache_t *modcache)
{
    hashtable_t *symtable = &modcache->table;
    bool res = false;
    const char *line, *next_line;
    char symbol[MAX_SYMLEN];
    size_t offs;
    uint64 map_size;
    size_t actual_size;
    bool ok;
    void *map = NULL;
    char symfile[MAXIMUM_PATH];
    file_t f;

    symcache_get_filename(modname, symfile, BUFFER_SIZE_ELEMENTS(symfile));
    f = dr_open_file(symfile, DR_FILE_READ);
    if (f == INVALID_FILE)
        goto symcache_read_symfile_done;
    LOG(2, "processing symbol cache file for %s\n", modname);
    /* we avoid having to do our own buffering by just mapping the whole file */
    ok = dr_file_size(f, &map_size);
    if (ok) {
        actual_size = (size_t) map_size;
        ASSERT(actual_size == map_size, "file size too large");
        map = dr_map_file(f, &actual_size, 0, NULL, DR_MEMPROT_READ, 0);
    }
    if (!ok || map == NULL || actual_size < map_size) {
        NOTIFY_ERROR("Error mapping symcache file for %s"NL, modname);
        goto symcache_read_symfile_done;
    }
    if (strncmp((char *)map, SYMCACHE_FILE_HEADER, strlen(SYMCACHE_FILE_HEADER)) != 0) {
        WARN("WARNING: symbol cache file is corrupted\n");
        goto symcache_read_symfile_done;
    }
    /* i#1057: We use dr_sscanf() because sscanf() from ntdll will call strlen()
     * and read off the end of the mapped file if it doesn't hit a null.
     */
    if (dr_sscanf((char *)map + strlen(SYMCACHE_FILE_HEADER) + 1, "%d",
                  (uint *)&offs) != 1 ||
        /* neither forward nor backward compatible */
        offs != SYMCACHE_VERSION) {
        WARN("WARNING: symbol cache file has wrong version\n");
        goto symcache_read_symfile_done;
    }
    line = strchr((char *) map, '\n');
    if (line != NULL)
        line++;

    if (line != NULL) {
        /* Module consistency checks */
        uint cache_file_size;
        uint64 module_file_size;
        uint timestamp;
#ifdef WINDOWS
        version_number_t file_version;
        version_number_t product_version;
        uint checksum;
        size_t module_internal_size;
        if (dr_sscanf(line, "%u,"UINT64_FORMAT_STRING","UINT64_FORMAT_STRING","
                      UINT64_FORMAT_STRING",%u,%u,%zu",
                      &cache_file_size, &module_file_size, &file_version.version,
                      &product_version.version, &checksum, &timestamp,
                      &module_internal_size) != 7) {
            WARN("WARNING: %s symbol cache file has bad consistency header\n", modname);
            goto symcache_read_symfile_done;
        }
        if (module_file_size != modcache->module_file_size ||
            file_version.version != modcache->file_version.version ||
            product_version.version != modcache->product_version.version ||
            checksum != modcache->checksum ||
            timestamp != modcache->timestamp ||
            module_internal_size != modcache->module_internal_size) {
            LOG(1, "module version mismatch: %s symbol cache file is stale\n", modname);
            LOG(2, "\t"UINT64_FORMAT_STRING" vs "UINT64_FORMAT_STRING", "
                UINT64_FORMAT_STRING" vs "UINT64_FORMAT_STRING", "
                UINT64_FORMAT_STRING" vs "UINT64_FORMAT_STRING", "
                "%u vs %u, %u vs %u, %zu vs %zu\n",
                module_file_size, modcache->module_file_size,
                file_version.version, modcache->file_version.version,
                product_version.version, modcache->product_version.version,
                checksum, modcache->checksum,
                timestamp, modcache->timestamp,
                module_internal_size, modcache->module_internal_size);
            goto symcache_read_symfile_done;
        }
#elif defined(LINUX)
        if (dr_sscanf(line, "%u,"UINT64_FORMAT_STRING",%u",
                      &cache_file_size, &module_file_size, &timestamp) != 3) {
            WARN("WARNING: %s symbol cache file has bad consistency header\n", modname);
            goto symcache_read_symfile_done;
        }
        if (module_file_size != modcache->module_file_size ||
            timestamp != modcache->timestamp) {
            LOG(1, "module version mismatch: %s symbol cache file is stale\n", modname);
            goto symcache_read_symfile_done;
        }
#elif defined(MACOS)
        uint current_version;
        uint compatibility_version;
        byte uuid[16];
        /* XXX: if dr_sscanf supported %n maybe we could split these into
         * separate scans on the same string and share code w/ Linux.
         */
        if (dr_sscanf(line, "%u,"UINT64_FORMAT_STRING",%u,%u,%u,%x,%x,%x,%x",
                      &cache_file_size, &module_file_size, &timestamp,
                      &current_version, &compatibility_version,
                      (uint*)(&uuid[0]), (uint*)(&uuid[4]),
                      (uint*)(&uuid[8]), (uint*)(&uuid[12])) != 9) {
            WARN("WARNING: %s symbol cache file has bad consistency header B\n", modname);
            goto symcache_read_symfile_done;
        }
        if (current_version != modcache->current_version ||
            compatibility_version != modcache->compatibility_version ||
            memcmp(uuid, modcache->uuid, sizeof(uuid)) != 0) {
            LOG(1, "module version mismatch: %s symbol cache file is stale\n", modname);
            goto symcache_read_symfile_done;
        }
#endif
        /* We could go further w/ CRC or even MD5 but not worth it for dev tool */
        if (cache_file_size != (uint)map_size) {
            WARN("WARNING: %s symbol cache file is corrupted: map=%d vs file=%d\n",
                 modname, (uint)map_size, cache_file_size);
            goto symcache_read_symfile_done;
        }
    }
    line = strchr(line, '\n');
    if (line != NULL)
        line++;
    if (line != NULL) {
        uint has_debug_info;
        if (dr_sscanf(line, "%u", &has_debug_info) != 1) {
            WARN("WARNING: %s symbol cache file has bad consistency header\n", modname);
            goto symcache_read_symfile_done;
        }
        if (has_debug_info) {
            /* We assume that the current availability of debug info doesn't matter */
            modcache->has_debug_info = true;
        } else {
            /* We delay the costly check for symbols until we've read the symcache
             * b/c if its entry indicates symbols we don't need to look
             */
            if (module_has_symbols(mod)) {
                LOG(1, "module now has debug info: %s symbol cache is stale\n", modname);
                goto symcache_read_symfile_done;
            }
        }
    }
    line = strchr(line, '\n');
    if (line != NULL)
        line++;

    symbol[0] = '\0';
    for (; line != NULL && line < ((char *)map) + map_size; line = next_line) {
        const char *comma = strchr(line, ',');
        const char *newline = strchr(line, '\n');
        size_t symlen = (comma != NULL ? comma - line : 0);
        if (newline == NULL) {
            next_line = ((char *)map) + map_size + 1; /* handle EOF w/o trailing \n */
        } else {
            next_line = newline + 1;
        }
        if (symlen > 0 && symlen < MAX_SYMLEN) {
            strncpy(symbol, line, symlen);
            symbol[symlen] = '\0';
        }
        if (comma != NULL && symlen < MAX_SYMLEN && symbol[0] != '\0' &&
            dr_sscanf(comma, ",0x%x", (uint *)&offs) == 1) {
#ifdef WINDOWS
            /* Guard against corrupted files that cause DrMem to crash (i#1465) */
            if (offs >= modcache->module_internal_size) {
                /* This one we want to know about */
                NOTIFY("SYMCACHE ERROR: %s file has too-large entry "PIFX" for %s"NL,
                       modname, offs, symbol);
                goto symcache_read_symfile_done;
            }
#endif
            symcache_symbol_add(modname, symtable, symbol, offs);
        } else {
            WARN("WARNING: malformed symbol cache line \"%.*s\"\n",
                 next_line - line - 1, line);
            /* We abort in case there were two dueling writes to the file
             * and it somehow got past the self-consistency check,
             * putting a header in the middle of the file, and we can't
             * trust subsequent lines since they may belong to a different
             * version of the module
             */
            break; /* res should still be true */
        }
    }
    res = true;
 symcache_read_symfile_done:
    if (map != NULL)
        dr_unmap_file(map, actual_size);
    if (f != INVALID_FILE)
        dr_close_file(f);
    if (!res)
        modcache->has_debug_info = module_has_symbols(mod);

    return res;
}

DR_EXPORT
drmf_status_t
drsymcache_init(client_id_t client_id,
                const char *symcache_dir_in,
                size_t modsize_cache_threshold)
{
#ifdef WINDOWS
    module_data_t *mod;
#endif
    drmf_status_t res;
    drmgr_priority_t pri_mod_load_cache =
        {sizeof(pri_mod_load_cache), DRMGR_PRIORITY_NAME_DRSYMCACHE, NULL, NULL,
         DRMGR_PRIORITY_MODLOAD_DRSYMCACHE_READ};
    drmgr_priority_t pri_mod_unload_cache =
        {sizeof(pri_mod_unload_cache), DRMGR_PRIORITY_NAME_DRSYMCACHE, NULL, NULL,
         DRMGR_PRIORITY_MODUNLOAD_DRSYMCACHE};
    drmgr_priority_t pri_mod_save_cache =
        {sizeof(pri_mod_save_cache), DRMGR_PRIORITY_NAME_DRSYMCACHE_SAVE, NULL, NULL,
         DRMGR_PRIORITY_MODLOAD_DRSYMCACHE_SAVE};

    /* handle multiple sets of init/exit calls */
    int count = dr_atomic_add32_return_sum(&symcache_init_count, 1);
    if (count > 1)
        return DRMF_WARNING_ALREADY_INITIALIZED;

    res = drmf_check_version(client_id);
    if (res != DRMF_SUCCESS)
        return res;

    drmgr_init();
    drmgr_register_module_load_event_ex(symcache_module_load, &pri_mod_load_cache);
    drmgr_register_module_unload_event_ex(symcache_module_unload, &pri_mod_unload_cache);
    drmgr_register_module_load_event_ex(symcache_module_load_save, &pri_mod_save_cache);

    initialized = true;

    op_modsize_cache_threshold = modsize_cache_threshold;

    hashtable_init_ex(&symcache_table, SYMCACHE_MASTER_TABLE_HASH_BITS,
                      IF_WINDOWS_ELSE(HASH_STRING_NOCASE, HASH_STRING),
                      true/*strdup*/, false/*!synch*/,
                      symcache_free_entry, NULL, NULL);
    symcache_lock = dr_mutex_create();

    dr_snprintf(symcache_dir, BUFFER_SIZE_ELEMENTS(symcache_dir),
                "%s", symcache_dir_in);
    NULL_TERMINATE_BUFFER(symcache_dir);
    if (!dr_directory_exists(symcache_dir)) {
        if (!dr_create_dir(symcache_dir)) {
            /* check again in case of a race (i#616) */
            if (!dr_directory_exists(symcache_dir)) {
                NOTIFY_ERROR("Unable to create symcache dir %s"NL, symcache_dir);
                ASSERT(false, "unable to create symcache dir");
                dr_abort();
            }
        }
    }

#ifdef WINDOWS
    /* It's common for tools to query ntdll in their init routines so we add it
     * early here
     */
    mod = dr_lookup_module_by_name("ntdll.dll");
    if (mod != NULL) {
        symcache_module_load(dr_get_current_drcontext(), mod, true);
        dr_free_module_data(mod);
    }
#endif

    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
drsymcache_is_initialized(bool *is_initialized OUT)
{
    if (is_initialized == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    *is_initialized = initialized;
    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
drsymcache_exit(void)
{
    uint i;
    /* handle multiple sets of init/exit calls */
    int count = dr_atomic_add32_return_sum(&symcache_init_count, -1);
    if (count > 0)
        return DRMF_SUCCESS;
    if (count < 0)
        return DRMF_ERROR;
    if (!initialized)
        return DRMF_ERROR_NOT_INITIALIZED;

    dr_mutex_lock(symcache_lock);
    for (i = 0; i < HASHTABLE_SIZE(symcache_table.table_bits); i++) {
        hash_entry_t *he;
        for (he = symcache_table.table[i]; he != NULL; he = he->next) {
            mod_cache_t *modcache = (mod_cache_t *) he->payload;
            symcache_write_symfile(modcache->modname, modcache);
        }
    }
    hashtable_delete(&symcache_table);
    dr_mutex_unlock(symcache_lock);
    dr_mutex_destroy(symcache_lock);

    drmgr_unregister_module_load_event(symcache_module_load);
    drmgr_unregister_module_unload_event(symcache_module_unload);
    drmgr_unregister_module_load_event(symcache_module_load_save);
    drmgr_exit();

    return DRMF_SUCCESS;
}

static void
symcache_free_list(void *v)
{
    offset_list_t *olist = (offset_list_t *) v;
    offset_entry_t *tmp, *e = olist->list;
    if (olist->table != NULL) {
        hashtable_delete(olist->table);
        global_free(olist->table, sizeof(*olist->table), HEAPSTAT_HASHTABLE);
    }
    while (e != NULL) {
        tmp = e;
        e = e->next;
        global_free(tmp, sizeof(*tmp), HEAPSTAT_HASHTABLE);
    }
    global_free(olist, sizeof(*olist), HEAPSTAT_HASHTABLE);
}

static void
symcache_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
    /* look for cache file for this module.
     * fill in hashtable: key is string, value is list of offsets
     */
    mod_cache_t *modcache;
    const char *modname = dr_module_preferred_name(mod);
    file_t f;
    if (!initialized)
        return;
    if (modname == NULL)
        return; /* don't support caching */

    /* if smaller than threshold, not worth caching */
    /* XXX: this overcounts for non-contiguous modules */
    if (mod->end - mod->start < op_modsize_cache_threshold) {
        LOG(1, "%s: module %s too small to cache\n", __FUNCTION__, modname);
        return;
    }

    /* support initializing prior to module events => called twice */
    dr_mutex_lock(symcache_lock);
    modcache = (mod_cache_t *) hashtable_lookup(&symcache_table,
                                                (void *)mod->full_path);
    dr_mutex_unlock(symcache_lock);
    if (modcache != NULL) /* already there: e.g., ntdll, which we add early */
        return;

    modcache = (mod_cache_t *) global_alloc(sizeof(*modcache), HEAPSTAT_HASHTABLE);
    memset(modcache, 0, sizeof(*modcache));
    hashtable_init_ex(&modcache->table, SYMCACHE_MODULE_TABLE_HASH_BITS,
                      HASH_STRING, true/*strdup*/, false/*!synch: using global synch*/,
                      symcache_free_list, NULL, NULL);

    /* store consistency fields */
    f = dr_open_file(mod->full_path, DR_FILE_READ);
    if (f != INVALID_FILE) {
        bool ok = dr_file_size(f, &modcache->module_file_size);
        if (!ok)
            WARN("WARNING: unable to determine size of %s\n", mod->full_path);
        dr_close_file(f);
    } else
        WARN("WARNING: unable to open %s\n", mod->full_path);
#ifdef WINDOWS
    modcache->file_version = mod->file_version;
    modcache->product_version = mod->product_version;
    modcache->checksum = mod->checksum;
    modcache->timestamp = mod->timestamp;
    modcache->module_internal_size = mod->module_internal_size;
#else
    modcache->timestamp = mod->timestamp;
# ifdef MACOS
    modcache->current_version = mod->current_version;
    modcache->compatibility_version = mod->compatibility_version;
    memcpy(modcache->uuid, mod->uuid, sizeof(modcache->uuid));
# endif
#endif

    modcache->modname = drmem_strdup(modname, HEAPSTAT_HASHTABLE);
    modcache->from_file = symcache_read_symfile(mod, modname, modcache);

    dr_mutex_lock(symcache_lock);
    if (!hashtable_add(&symcache_table, (void *)mod->full_path, (void *)modcache)) {
        /* this should be really rare to have dup paths (xref i#729) -- and
         * actually we now have a lookup up above so we should only get here
         * on a race while we let go of the lock
         */
        WARN("WARNING: duplicate module paths: only caching symbols from first\n");
        hashtable_delete(&modcache->table);
        global_free(modcache, sizeof(*modcache), HEAPSTAT_HASHTABLE);
    }
    dr_mutex_unlock(symcache_lock);
}

static drmf_status_t
symcache_module_save_common(const module_data_t *mod, bool remove)
{
    mod_cache_t *modcache;
    const char *modname = dr_module_preferred_name(mod);
    if (modname == NULL)
        return DRMF_ERROR_INVALID_PARAMETER; /* don't support caching */
    if (!initialized)
        return DRMF_ERROR_NOT_INITIALIZED;
    dr_mutex_lock(symcache_lock);
    modcache = (mod_cache_t *) hashtable_lookup(&symcache_table, (void *)mod->full_path);
    if (modcache != NULL) {
        symcache_write_symfile(modname, modcache);
        if (remove)
            hashtable_remove(&symcache_table, (void *)mod->full_path);
    }
    dr_mutex_unlock(symcache_lock);
    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
drsymcache_module_save_symcache(const module_data_t *mod)
{
    if (mod == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    return symcache_module_save_common(mod, false/*keep*/);
}

static void
symcache_module_load_save(void *drcontext, const module_data_t *mod, bool loaded)
{
    /* Write out the symcache in case we crash or sthg before an at-exit write */
    symcache_module_save_common(mod, false/*keep*/);
}

static void
symcache_module_unload(void *drcontext, const module_data_t *mod)
{
    symcache_module_save_common(mod, true/*remove*/);
}

static drmf_status_t
symcache_module_has_data(const module_data_t *mod, bool require_syms, bool *res)
{
    mod_cache_t *modcache;
    const char *modname = dr_module_preferred_name(mod);
    if (modname == NULL)
        return DRMF_ERROR_INVALID_PARAMETER; /* don't support caching */
    if (!initialized)
        return DRMF_ERROR_NOT_INITIALIZED;
    dr_mutex_lock(symcache_lock);
    modcache = (mod_cache_t *) hashtable_lookup(&symcache_table, (void *)mod->full_path);
    if (modcache != NULL) {
        *res = (modcache->table.entries > 0 &&
                (!require_syms || modcache->has_debug_info));
    }
    dr_mutex_unlock(symcache_lock);
    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
drsymcache_module_is_cached(const module_data_t *mod, bool *res)
{
    if (mod == NULL || res == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    return symcache_module_has_data(mod, false/*don't need syms*/, res);
}

DR_EXPORT
drmf_status_t
drsymcache_module_has_debug_info(const module_data_t *mod, bool *res)
{
    if (mod == NULL || res == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    return symcache_module_has_data(mod, true/*need syms*/, res);
}

/* If an entry already exists and is 0, replaces it; else adds a new
 * offset for that symbol.
 */
DR_EXPORT
drmf_status_t
drsymcache_add(const module_data_t *mod, const char *symbol, size_t offs)
{
    mod_cache_t *modcache;
    const char *modname = dr_module_preferred_name(mod);
    if (modname == NULL)
        return DRMF_ERROR_INVALID_PARAMETER; /* don't support caching */
    if (symbol == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    if (!initialized)
        return DRMF_ERROR_NOT_INITIALIZED;
    dr_mutex_lock(symcache_lock);
    modcache = (mod_cache_t *) hashtable_lookup(&symcache_table, (void *)mod->full_path);
    if (modcache == NULL) {
        LOG(2, "%s: there is no cache for %s\n", __FUNCTION__, modname);
        dr_mutex_unlock(symcache_lock);
        return DRMF_ERROR_NOT_FOUND;
    }
    if (symcache_symbol_add(modname, &modcache->table, symbol, offs) &&
        modcache->from_file)
        modcache->appended = true;
    dr_mutex_unlock(symcache_lock);
    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
drsymcache_lookup(const module_data_t *mod, const char *symbol,
                  size_t **offs_array OUT, uint *num_entries OUT, size_t *offs_single OUT)
{
    offset_list_t *olist;
    offset_entry_t *e;
    mod_cache_t *modcache;
    uint i;
    const char *modname = dr_module_preferred_name(mod);
    if (modname == NULL)
        return DRMF_ERROR_INVALID_PARAMETER; /* don't support caching */
    if (!initialized)
        return DRMF_ERROR_NOT_INITIALIZED;
    if (symbol == NULL || offs_array == NULL || num_entries == NULL ||
        offs_single == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    dr_mutex_lock(symcache_lock);
    modcache = (mod_cache_t *) hashtable_lookup(&symcache_table, (void *)mod->full_path);
    if (modcache == NULL) {
        dr_mutex_unlock(symcache_lock);
        return DRMF_ERROR_NOT_FOUND;
    }
    olist = (offset_list_t *) hashtable_lookup(&modcache->table, (void *)symbol);
    if (olist == NULL) {
        dr_mutex_unlock(symcache_lock);
        return DRMF_ERROR_NOT_FOUND;
    }
    ASSERT(olist->num > 0, "empty list not allowed");
    if (olist->num == 1)
        *offs_array = offs_single;
    else {
        *offs_array = (size_t *) global_alloc(olist->num * sizeof(size_t),
                                              HEAPSTAT_HASHTABLE);
    }
    *num_entries = olist->num;
    for (e = olist->list, i = 0; e != NULL; i++, e = e->next) {
        ASSERT(i < olist->num, "symcache count is off");
        (*offs_array)[i] = e->offs;
        LOG(2, "sym lookup of %s in %s => symcache hit %d of %d == "PIFX"\n",
            symbol, mod->full_path, i, olist->num, e->offs);
    }
    dr_mutex_unlock(symcache_lock);
    return DRMF_SUCCESS;
}

DR_EXPORT
drmf_status_t
drsymcache_free_lookup(size_t *offs, uint num)
{
    if (num == 0 || offs == NULL)
        return DRMF_ERROR_INVALID_PARAMETER;
    if (num > 1) /* else we used the singleton passed to us */
        global_free(offs, num * sizeof(size_t), HEAPSTAT_HASHTABLE);
    return DRMF_SUCCESS;
}
