# **********************************************************
# Copyright (c) 2020 Google, Inc.  All rights reserved.
# **********************************************************
#
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
#
{
  "version": "2",
  "threads": [
    {
      "thread_id": "",
      "stack_frames": [
        {
          "program_counter": "",
          "frame_pointer": "",
          "function": "%ANY%!drmemory_dump_memory_layout"
        },
        {
          "program_counter": "",
          "frame_pointer": "",
          "function": "%ANY%!foo"
# Windows is having callstack troubles.
%if UNIX
        },
        {
          "program_counter": "",
          "frame_pointer": "",
          "function": "%ANY%!main"
%endif
        }
      ]
    }
  ],
  "heap objects": [
    {
      "address": "",
%if X32
      "size": "12",
%endif
%if X64
      "size": "24",
%endif
      "contents": [
        {
          "address": "",
          "value": "",
          "points-to-type": "heap",
          "points-to-base": "",
          "points-to-offset": ""
        },
# We just make sure we have a stack section.
  "thread stacks": [
