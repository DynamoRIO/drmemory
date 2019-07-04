/* ***************************************************************************
 * Copyright (c) 2013-2019 Google, Inc.  All rights reserved.
 * ***************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "drltrace.h"
#include <algorithm>
/****************************************************************************
 * Routines to support libcalls hashtable
 */

#define LIBCALLS_TABLE_HASH_BITS 6
/* We init the following hashtable to be able to get library call arguments when
 * it is required for printing.
 */
static hashtable_t libcalls_table;

static void
free_args_list(void *p)
{
    std::vector<drsys_arg_t *> *args_list = (std::vector<drsys_arg_t *> *) p;
    std::vector<drsys_arg_t *>::iterator it;
    for (it = args_list->begin(); it != args_list->end(); ++it)
        global_free(*it, sizeof(drsys_arg_t), HEAPSTAT_MISC);

    delete args_list;
}

static void
init_libcalls_hashtable()
{
    hashtable_init_ex(&libcalls_table, LIBCALLS_TABLE_HASH_BITS, HASH_STRING_NOCASE,
                      false/*!strdup*/, false, free_args_list, NULL, NULL);
}

void
libcalls_hashtable_delete()
{
    hashtable_delete(&libcalls_table);
}

std::vector<drsys_arg_t *> *
libcalls_search(const char *name)
{
    return (std::vector<drsys_arg_t *> *)hashtable_lookup(&libcalls_table, (void *)name);
}

static bool
libcalls_hashtable_insert(const char *name, std::vector<drsys_arg_t *> *args_list)
{
    return hashtable_add(&libcalls_table, (void *)name, (void *)args_list);
}

/****************************************************************************
 * Config file parsing routines
 */

static std::string
erase_token(std::string src_string, std::string pattern)
{
    std::string::size_type i = src_string.find(pattern);
    while (i != std::string::npos) {
        src_string.erase(i, pattern.length());
        i = src_string.find(pattern, i);
    }
    return src_string;
}

/* The function returns a new drsys_arg_t object allocated on the global heap
 * that the caller should free.
 */
static drsys_arg_t *
config_parse_type(std::string type_name, uint index)
{

    ASSERT(!type_name.empty(), "an empty type name was provided");

    drsys_arg_t *arg = (drsys_arg_t *)global_alloc(sizeof(drsys_arg_t), HEAPSTAT_MISC);

    /* init arg */
    arg->type = DRSYS_TYPE_UNKNOWN;
    arg->ordinal = index;
    arg->size = 0;
    arg->arg_name = NULL;
    arg->type_name = NULL;
    arg->pre = true;

    if (type_name.find("__inout") != std::string::npos)
        arg->mode = (drsys_param_mode_t)(DRSYS_PARAM_IN|DRSYS_PARAM_OUT);
    else if (type_name.find("__out") != std::string::npos)
        arg->mode = DRSYS_PARAM_OUT;
    else if (type_name.find("*") != std::string::npos)
        arg->mode = DRSYS_PARAM_IN;
    else
        arg->mode = DRSYS_PARAM_INLINED;

    /* we don't need special symbols __inout, __out or * further */
    type_name = erase_token(type_name, "*");
    type_name = erase_token(type_name, "__inout");
    type_name = erase_token(type_name, "__out");

    /* sanitize input type, we assume ASCII chars here */
    std::transform(type_name.begin(), type_name.end(), type_name.begin(), ::toupper);
    type_name.erase(std::remove(type_name.begin(), type_name.end(), ' '),
                    type_name.end());
    type_name.erase(std::remove(type_name.begin(), type_name.end(), '\r'),
                    type_name.end());
    type_name.erase(std::remove(type_name.begin(), type_name.end(), '\n'),
                    type_name.end());

    /* FIXME i#1948: Currently, we have only few cross-platform libcalls in the config
     * file which is possible to use both for Windows and Linux. However, we
     * need to separate them into two configs and fix CMAKE accordingly.
     * Moreover, we have to provide two different interfaces for type parsing
     * in Windows and Linux.
     */

    if (type_name.compare("VOID") == 0) {
        arg->type_name = "void";
        arg->type = DRSYS_TYPE_VOID;
    } else if (type_name.compare("INT") == 0) {
        arg->type_name = "int";
        arg->size = sizeof(int);
        arg->type = DRSYS_TYPE_SIGNED_INT;
    } else if (type_name.compare("LONG") == 0) {
        arg->type_name = "long";
        arg->size = sizeof(long);
        arg->type = DRSYS_TYPE_SIGNED_INT;
    } else if (type_name.compare("SIZE_T") == 0) {
        arg->type_name = "size_t";
        arg->size = sizeof(size_t);
        arg->type = DRSYS_TYPE_SIZE_T;
    }
#ifdef WINDOWS
    else if (type_name.compare("HANDLE") == 0) {
        arg->type_name = "HANDLE";
        arg->size = sizeof(HANDLE);
        arg->type = DRSYS_TYPE_HANDLE;
    } else if (type_name.compare("HKEY") == 0) {
        arg->type_name = "HKEY";
        arg->size = sizeof(HKEY);
        arg->type = DRSYS_TYPE_HANDLE;
    } else if (type_name.compare("HDC") == 0) {
        arg->type_name = "HDC";
        arg->size = sizeof(HDC);
        arg->type = DRSYS_TYPE_HANDLE;
    } else if (type_name.compare("HFILE") == 0) {
        arg->type_name = "HFILE";
        arg->size = sizeof(HFILE);
        arg->type = DRSYS_TYPE_HFILE;
    } else if (type_name.compare("HMODULE") == 0) {
        arg->type_name = "HMODULE";
        arg->size = sizeof(HFILE);
        arg->type = DRSYS_TYPE_HMODULE;
    } else if (type_name.compare("UINT") == 0) {
        arg->type_name = "uint";
        arg->size = sizeof(UINT);
        arg->type = DRSYS_TYPE_UNSIGNED_INT;
    } else if (type_name.compare("ULONG") == 0) {
        arg->type_name = "ULONG";
        arg->size = sizeof(ULONG);
        arg->type = DRSYS_TYPE_UNSIGNED_INT;
    } else if (type_name.compare("ULONGLONG") == 0) {
        arg->type_name = "ULONGLONG";
        arg->size = sizeof(ULONGLONG);
        arg->type = DRSYS_TYPE_UNSIGNED_INT;
    } else if (type_name.compare("DWORD") == 0) {
        arg->type_name = "DWORD";
        arg->size = sizeof(DWORD);
        arg->type = DRSYS_TYPE_UNSIGNED_INT;
    } else if (type_name.compare("WORD") == 0) {
        arg->type_name = "WORD";
        arg->size = sizeof(WORD);
        arg->type = DRSYS_TYPE_UNSIGNED_INT;
    } else if (type_name.compare("BYTE") == 0) {
        arg->type_name = "BYTE";
        arg->size = sizeof(BYTE);
        arg->type = DRSYS_TYPE_UNSIGNED_INT;
    } else if (type_name.compare("BOOL") == 0) {
        arg->type_name = "BOOL";
        arg->size = sizeof(BOOL);
        arg->type = DRSYS_TYPE_BOOL;
    } else if (type_name.compare("LCID") == 0) {
        arg->type_name = "LCID";
        arg->size = sizeof(LCID);
        arg->type = DRSYS_TYPE_LCID;
    } else if (type_name.compare("LPARAM") == 0) {
        arg->type_name = "LPARAM";
        arg->size = sizeof(LPARAM);
        arg->type = DRSYS_TYPE_LPARAM;
    }
#endif
    else if (type_name.compare("CHAR") == 0) {
        arg->type_name = "char";
        arg->type = DRSYS_TYPE_CSTRING;
    } else if (type_name.compare("WCHAR") == 0) {
        arg->type_name = "wchar_t";
        arg->type = DRSYS_TYPE_CWSTRING;
    } else {
        /* XXX i#1948: We have to extend a list of supported types here. */
        arg->type_name = "<unknown>";
        DO_ONCE(VNOTIFY(0, "<Found unknown types in the config file>" NL););
        VNOTIFY(2, "Found unknown type %s in the config file" NL, type_name.c_str());
    }

    return arg;
}

static int
split(const char *buf, const char delim, std::vector<std::string> *tokens_list)
{
    int count = 0;
    std::stringstream ss;
    std::string item;

    ss.str(buf);
    while (std::getline(ss, item, delim)) {
        tokens_list->push_back(item);
        count++;
    }
    return count;
}

static bool
parse_line(const char *line, int line_num)
{
    std::vector<std::string> tokens;
    drsys_arg_t *tmp_arg;
    const char *func_name = NULL;
    int elem_index = 0, tokens_count = 0;

    if (line == NULL)
        return false;

    if (line[0] == '#') /* just a comment */
        return true;

    if (strlen(line) <= 0 || line[0] == '\n' || line[0] == '\r')
        return true; /* just an empty line */

    tokens_count = split(line, '|', &tokens);

    if (tokens_count <= 0) {
        VNOTIFY(0, "unable to parse config file at line %d: %s" NL, line_num, line);
        return false;
    }

    std::vector<drsys_arg_t *> *args_vector = new std::vector<drsys_arg_t *>();
    std::vector<std::string>::iterator it;
    for (it = tokens.begin(); it != tokens.end(); ++it) {
        /* FIXME i#1948: Currently, we don't support ret value printing and
         * skipping it here.
         */
        if (elem_index >= 2) {
            tmp_arg = config_parse_type(*it, elem_index - 2);
            args_vector->push_back(tmp_arg);
        } else if (elem_index == 1)
            func_name = it->c_str();

        elem_index++;
    }

    if (func_name == NULL || args_vector->size() <= 0) {
        VNOTIFY(0, "unable to parse config file at line %d: %s" NL, line_num, line);
        return false;
    }

    VNOTIFY(2, "adding %s from config file with %d arguments in the hashtable" NL,
            func_name, args_vector->size());
    IF_DEBUG(bool ok =)
        libcalls_hashtable_insert(strdup(func_name), args_vector);
    ASSERT(ok, "failed to add libcall in the hashtable");

    return true;
}

void
parse_config(void)
{
    void *map = NULL;
    uint64 size_to_read = 0;
    size_t actual_size = 0;
    file_t file_desc = INVALID_FILE;
    int lines_count = 0, line_num = 1;
    bool res = false;
    std::vector<std::string> lines_list;

    if (!op_use_config.get_value())
        return;

    /* open and map config file */
    file_desc = dr_open_file(op_config_file.get_value().c_str(), DR_FILE_READ);
    if (file_desc != INVALID_FILE) {
        res = dr_file_size(file_desc, &size_to_read);
        if (res) {
            actual_size = (size_t)size_to_read;
            map = dr_map_file(file_desc, &actual_size, 0,
                              NULL, DR_MEMPROT_READ, 0);
        }
    }

    if (!res || map == NULL || actual_size < size_to_read) {
        if (map != NULL)
            dr_unmap_file(map, actual_size);
        if (file_desc != INVALID_FILE)
            dr_close_file(file_desc);
        VNOTIFY(0, "unable to open config file at %s, config is not used" NL,
                op_config_file.get_value().c_str());
        op_use_config.set_value(false);
        return;
    }

    lines_count = split((const char *)map, '\n', &lines_list); /* split buffer by lines */

    dr_unmap_file(map, actual_size);
    dr_close_file(file_desc);

    if (lines_count <= 0) {
        VNOTIFY(0, "An empty config file was specified, config is not used" NL);
                op_use_config.set_value(false);
        return;
    }

    init_libcalls_hashtable();

    std::vector<std::string>::iterator it;
    for (it = lines_list.begin(); it != lines_list.end(); it++) {
        /* XXX: we have to describe a format of the config file in the drltrace's
         * documentation as well as list supported types.
         */
        if (!parse_line(it->c_str(), line_num)) {
            VNOTIFY(0, "incorrect format for the line %d: %s in config file" NL,
                    line_num, it->c_str());
            op_use_config.set_value(false);
            libcalls_hashtable_delete();
            break;
        }
        line_num++;
    }
}
