#!/usr/bin/python

# **********************************************************
# Copyright (c) 2014 Google, Inc.  All rights reserved.
# **********************************************************

# Dr. Memory: the memory debugger
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation;
# version 2.1 of the License, and no later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Library General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# mkenumtable.py
#
# expecting enum constants like these, from Windows headers:
#
#
# #define STATUS_WAIT_0                    ((DWORD   )0x00000000L)
#
#
# Usage mkenumtable.py <header_name>
# The script doesn't generate final code.
# The output should be parsed manually.
#

import sys
import os
import re


pattern = '[{}()]'
forbidden_labels = ["sizeof", "extern", "EXTERN_C", ":", "DECLSPEC_ALIGN"]

def check_flag_name (str = None):
    '''
    The routine checks entry string for
    patterns and length.
    '''
    word_list = str.split()
    # The string should consist of 3 or more words.
    if len(word_list) >= 3:
    # First word should be "#define"
       if word_list[0].find("#define") != -1:
           # Second word should be a flag name without (){} symbol
           result = re.findall(pattern, word_list[1])
           if result==[]:
               return 1
    return 0

def delete_symbols (str = None):
    '''
    The routine removes additional spaces & comments.
    '''
    # remove comments
    index = str.find("//")
    if index > 0:
        str = str[:index]
    # remove additional & trailing spaces and \n
    str = str.replace("\n", "")
    pattern_spaces = re.compile(r'\s+')
    sentence = re.sub(pattern_spaces, ' ', str)
    sentence = sentence.strip()
    sentence = sentence.replace("( ", "(")
    sentence = sentence.replace(" )", ")")
    # remove additional space after DWORD & WORD
    index = sentence.find("(DWORD )")
    if index > 0:
        sentence = sentence.replace("WORD )", "WORD)")
    return sentence

def parse_file_buffer (buffer = None):
    '''
    The routine parses raw buffer from file
    and returns only enums.
    '''
    iterator = iter(buffer)
    all_strings = []
    for str in iterator:
       # #define should be in the string
       if str.find("#define") != -1:
            if check_flag_name(str) == 1:
                # additional check for \ symbol
                flag = None
                while (flag != 0):
                    # remove additional symbols
                    str = delete_symbols(str)
                    res = str.find("\\")
                    if res != -1:
                        # add next string/strings
                        str = str.replace("\\", "");
                        str = str + next(iterator)
                    else:
                        flag = 0
                all_strings.append(str)
    return all_strings

def check_output(entry):
    '''
    The routine makes comments when entry contains
    the same constant names or the same values.
    '''
    strings_list = []
    values_list = []
    for sub_entry in entry:
        sub_entry = sub_entry.split(" ")
        value_to_find = sub_entry[2]
        str_to_find = sub_entry[1]
        values_list.append(value_to_find)
        strings_list.append(str_to_find)
    for index,same in enumerate(strings_list):
        if strings_list.count(same) > 1:
            entry[index] = entry[index] + " FIXME:_the_same_names"
            print entry[index]
    for index,same in enumerate(values_list):
        if values_list.count(same) > 1:
            entry[index] = entry[index] + " FIXME:_the_same_values"
            print entry[index]
    return entry

def add_leading_zeros(str_value):
    '''
    The routine adds leading zeros
    in the given string with hex value.
    '''
    pattern = "0x[\dA-Fa-f]*"
    result = re.findall(pattern,str_value)
    if result:
        value = int(result[0],16)
        value = "0x%0.8x" % value
        str_value = str_value.replace(result[0],str(value))
    return str_value

def generate_table_entries (raw_table):
    '''
    The routine generates final output to write
    in a file.
    '''
    output_all = []
    output_array = "void *const_struct_array[] = {\n";
    for entry in raw_table:
        # get name of the 1th string in entry
        enum_name = entry[0].split(" ")[1]
        enum_name = enum_name.lower()
        # We should check entry before generate output.
        entry = check_output(entry)
        output = "static const_values_t " + enum_name + "[] = {\n"
        output_array = output_array + "    " + enum_name + ",\n"
        for sub_entry in entry:
            # generate output entry
            enum_name = sub_entry.split(" ")
            if ((len(enum_name) > 3) and ("FIXME:" in sub_entry)):
                enum_value = "".join(enum_name[2:3])
                enum_value = add_leading_zeros(enum_value)
                enum_comment = " ".join(enum_name[3:])
                enum_value = enum_value.replace("|", "|\n      ")
                output = output + "    {" + enum_value + ', "' \
                                          + enum_name[1] + '"}, ' \
                                          + "/* "+ enum_comment + " */\n"
            else:
                enum_value = "".join(enum_name[2:])
                enum_value = add_leading_zeros(enum_value)
                enum_value = enum_value.replace("|", "|\n      ")
                output = output + "    {" + enum_value + ', "' \
                                          + enum_name[1] + '"},\n'
        output = output + '    {0},\n};\n'
        output_all.append(output)
    output_all.append(output_array + "};")
    return output_all

def make_structure (strings):
    '''
    The routine tries to find basic types and groups
    to add them in to the separate structures.
    '''
    string_list_all = []
    output = []
    for string in strings:
        string_list = string.split(" ")
        string_list = string_list[1].split("_")
        string_list_all.append(string_list)
    # determine basic type
    index = 0
    while index < len(string_list_all):
        basic_type_number = 0
        for sub_index,str in enumerate(string_list_all[index]):
            # step-by-step compare first enum name with next enum name
            try:
                if (string_list_all[index][sub_index] ==
                    string_list_all[index+1][sub_index]):
                    basic_type_number = basic_type_number + 1
                else:
                    break
            except:
                break
        if basic_type_number > 0:
            basic_name_index = index
            # The names have basic type. Let's look next names.
            next_flag = True
            while next_flag != False:
                try:
                    if (string_list_all[basic_name_index][0:basic_type_number] ==
                       string_list_all[index+1][0:basic_type_number]):
                        next_flag = True
                        index = index + 1
                    else:
                        next_flag = False
                except:
                    break
            index = index + 1
            output.append(strings[basic_name_index:index])
        else:
            # it's single enum name
            output.append(strings[index:index+1])
            index = index + 1
    return output

def save (all_strings_list, filename):
    '''
    The routine saves strings in a file.
    '''
    try:
        # Open specified file for writing.
        header = open(filename, 'w')
        # Write strings in the file.
        for string in all_strings_list:
            header.write(string)
            header.write("\n")
    except:
        print "Couldn't open a file for write"

def parse (hfile = None):
    '''
    The routine parse header & write results in a file.
    '''
    if hfile == None:
        return 0
    try:
        # Read file in a buffer
        buffer = hfile.readlines()
    except:
        print "Couldn't read a file"
    print "Start file parsing"
    all_strings = parse_file_buffer(buffer)
    output = make_structure(all_strings)
    output_strings = generate_table_entries(output)
    return output_strings

if __name__ == "__main__":
    if len(sys.argv) == 2:
        header_name = sys.argv[1]
        try:
            # Open specified file for reading
            hfile = open(header_name,'r')
        except:
            print "Couldn't open a file for reading"
            sys.exit(1)
        # Parse given file
        output = parse(hfile)
        # Write results in output file
        filename = header_name.replace(".h", "") + "_header.out"
        save(output,filename)
        print "Parsing successfully done"
    else:
        print "Usage: mkenumtable.py <header_to_parse>"
        sys.exit(1)
    sys.exit(0)
