#!/usr/bin/perl
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
# 
# Usage:
# mksymguid.pl <dll or exe name to replace GUID>
# 
# Script replaces GUID in the given PE file to GUID valid for 
# Microsoft Wintypes.pdb. (PTAL i#1540 for detail information).

use Fcntl ':seek';

if (@ARGV < 1) {
    die 'Invalid argument. Please specify executable name\n'
}
my $filename = $ARGV[0];

open my $FH, '+<:raw', $filename or die "Cannot open '$filename' $!\n";

read $FH, my $data, -s $FH or die "Cannot read from '$filename' $!\n";

length $data == -s $FH or die "Could only read ", length $data,
                              " bytes from a ", -s $FH, " byte file.\n";

# This guid string came from original Wintypes.dll debug section.
# The string contains GUID to fetch wintypes.pdb from MS Symbol Server.
$guid = "\x01\xEF\x00\xBB\x60\x8D\x43\x44\xAE\x6F\xFF\xBC\x56\xCB\x76\xBD\x02\x00\x00\x00";

# Replace given GUID with Wintypes GUID
if ($data =~ s/(RSDS)(.{20})(symbol_fetch.pdb)/RSDS$guid\WinTypes.pdb/s) {
    seek $FH, 0, SEEK_SET or die "Cannot seek on '$filename' $!\n";
    print $FH $data;
    print 'all_done'
} else {
    die 'Can\'t match regular expression\n'
}
