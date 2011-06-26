#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2011 Google, Inc.  All rights reserved.
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

use strict;

my %name_map = (
    'NtUserControlMagnification' => 'NtUserMagControl',
    'NtUserGetMagnificationLensCtxInformation' => 'NtUserMagGetContextInformation',
    'NtUserSetMagnificationLensCtxInformation' => 'NtUserMagSetContextInformation',
    'NtUserCopyAcceleratorTableW' => 'NtUserCopyAcceleratorTable',
    'NtUserCreateAcceleratorTableW' => 'NtUserCreateAcceleratorTable',
    'NtUserGetUserObjectInformationW' => 'NtUserGetObjectInformation',
    'NtUserSetUserObjectInformationA' => 'NtUserSetObjectInformation',
    'NtUserSetUserObjectInformationW' => 'NtUserSetObjectInformation',
    'NtUserRealSetScrollInfo' => 'NtUserSetScrollInfo',
    'NtUserPrivateSetDbgTag' => 'NtUserSetDbgTag',
    'NtUserPrivateSetRipFlags' => 'NtUserSetRipFlags',
    'NtUserRealEnableScrollBar' => 'NtUserEnableScrollBar',
    'ImmDisableIme' => 'NtUserDisableThreadIme',
    'ImmDisableIME' => 'NtUserDisableThreadIme',

    'NtGdiDestroyPhysicalMonitorInternal' => 'NtGdiDestroyPhysicalMonitor',
    'NtGdiEnableEUDC' => 'NtGdiEnableEudc',
    'NtGdiGdiFullscreenControl' => 'NtGdiFullscreenControl',
    'NtGdiGdiGetSpoolMessage' => 'NtGdiGetSpoolMessage',
    'NtGdiGdiInitSpool' => 'NtGdiInitSpool',
    'NtGdiGdiQueryFonts' => 'NtGdiQueryFonts',
    'NtGdiGetClipBox' => 'NtGdiGetAppClipBox',
    'NtGdiGdiConsoleTextOut' => 'NtGdiConsoleTextOut',
    'NtGdiGetBitmapDimensionEx' => 'NtGdiGetBitmapDimension',
    'NtGdiEnableEUDC' => 'NtGdiEnableEudc',
    'NtGdiGdiFullscreenControl' => 'NtGdiFullscreenControl',
    'NtGdiGdiGetSpoolMessage' => 'NtGdiGetSpoolMessage',
    'NtGdiGdiInitSpool' => 'NtGdiInitSpool',
    'NtGdiGdiQueryFonts' => 'NtGdiQueryFonts',
    'NtGdiGdiConsoleTextOut' => 'NtGdiConsoleTextOut',
    'NtGdiEnableEUDC' => 'NtGdiEnableEudc',
    'NtGdiGdiFullscreenControl' => 'NtGdiFullscreenControl',
    'NtGdiGetBitmapDimensionEx' => 'NtGdiGetBitmapDimension',
    'NtGdiGdiGetSpoolMessage' => 'NtGdiGetSpoolMessage',
    'NtGdiGdiInitSpool' => 'NtGdiInitSpool',
    'NtGdiGdiQueryFonts' => 'NtGdiQueryFonts',
    'NtGdiSetBitmapDimensionEx' => 'NtGdiSetBitmapDimension',
    'NtGdiGdiConsoleTextOut' => 'NtGdiConsoleTextOut',
    'NtGdiEnableEUDC' => 'NtGdiEnableEudc',
    'NtGdiGdiFullscreenControl' => 'NtGdiFullscreenControl',
    'NtGdiGdiGetSpoolMessage' => 'NtGdiGetSpoolMessage',
    'NtGdiGdiInitSpool' => 'NtGdiInitSpool',
    'NtGdiGdiQueryFonts' => 'NtGdiQueryFonts',
    'NtGdiEngGradientFill' => 'NtGdiCheckAndGetBitmapBits',
    );

# These are bogus, not sure whose fault it is (winsyms or dbghelp?  windbg shows
# different address or can't find symbol), in 2K user32:
my %user32_delete = (
    'NtGdiSTROBJ_bGetAdvanceWidths' => 1,
    'NtUserDdeDisconnectList' => 1,
    'NtUserFreeDDElParam' => 1,
    'NtUserTestWindowProcess' => 1,
    );

my $os = 0;
my %nums;
my %sysnums;

if ($#ARGV < 0 || $ARGV[0] =~ /^-/) {
    die "Usage: $0 <prefix> files in platform order...\n";
}

my $prefix = $ARGV[0];
shift;
my $name_prefix = "";
if ($prefix =~ /USER32/) {
    $name_prefix = "NtUser";
} elsif ($prefix =~ /GDI32/) {
    $name_prefix = "NtGdi";
}
while ($#ARGV >= 0) {
    open(IN,"<$ARGV[0]") || die"Error opening $ARGV[0]\n";
    while (<IN>) {
        if (/(0x\w+) .*= (\w+)/) {
            my $sysnum = $1;

            # normalize the names
            my $name = $2;
            $name =~ s/^Zw/Nt/;
            if ($name !~ /^Nt/) {
                $name = $name_prefix . $name;
            }

            $name = $name_map{$name} if (defined($name_map{$name}));

            # skip the duplicate names:
            # * NtGdiDdEntryN maps to various non-numeric names, identically
            #   across plaforms
            # * NtGdiD3DKMT* maps to NtGdiDdDDI*
            next if ($name =~ /^NtGdiDdEntry/);
            next if ($name =~ /^NtGdiD3DKMT/);

            next if ($prefix =~ /USER32/ && defined($user32_delete{$name}));

            if (defined($sysnums{$os,$sysnum}) &&
                $sysnums{$os,$sysnum} ne $name) {
                print "WARNING: duplicate for $ARGV[0]: $sysnum == ".
                    "$sysnums{$os,$sysnum} vs $name\n";
            }
            $sysnums{$os,$sysnum} = $name;
            $nums{$name}[$os] = $sysnum;
        }
    }
    shift;
    $os++;
}

foreach my $n (sort (keys %nums)) { 
    printf "%s(%-45s", $prefix, $n;
    for (my $i = 0; $i < $os; $i++) {
        if (defined($nums{$n}[$i])) {
            printf ", %s", $nums{$n}[$i];
        } else {
            printf ",   NONE";
        }
    } 
    print ")\n";
}

