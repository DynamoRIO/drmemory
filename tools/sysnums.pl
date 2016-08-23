#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2011-2016 Google, Inc.  All rights reserved.
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

# This script formats system call numbers into columns for drsyscall/drsyscall_numx.h.
# The numbers are obtained from the output of DR's winsysnums tool on system dlls+pdbs.
# An example of usage:
# % tools/sysnums.pl NTDLL <path-to-drmemory>/drsyscall/drsyscall_numx.h ntdll.dll/10.0.10586.20-x86/syscalls ntdll.dll/10.0.10586.20-wow64/syscalls ntdll.dll/10.0.10586.20-x64/syscalls

use strict;

my %name_map = (
    # special case: "Desktoa" to precede "Desktop" :)
    'GetThreadDesktop' => 'NtUserGetThreadDesktoa-SPECIALCASED',

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

    'RtlGetCurrentProcessorNumber' => 'NtGetCurrentProcessorNumber',

    # win8
    'NtUserSkipPointerFrameMessages' => 'NtUserDiscardPointerFrameMessages',
    'NtUserSetCoalescableTimer' => 'NtUserSetTimer',
    'NtUserShutdownReasonDestroy' => 'NtUserShutdownBlockReasonDestroy',
    'NtUsergDispatchTableValues' => 'NtUserProcessConnect',

    # win8.1
    'NtUserPhysicalToLogicalPointForPerMonitorDPI' => 'NtUserPerMonitorDPIPhysicalToLogicalPoint',
    'NtUserLogicalToPhysicalPointForPerMonitorDPI' => 'NtUserLogicalToPerMonitorDPIPhysicalPoint',

    # win10
    "NtUserGetDpiSystemMetrics" => "NtUserGetDpiMetrics",

    # imm32
    'NtUserImmDisableIme' => 'NtUserDisableThreadIme',
    'NtUserImmDisableIME' => 'NtUserDisableThreadIme',

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
    # CheckAndGetBitmapBits shows up as a dup in a win2k pdb
    'NtGdiCheckAndGetBitmapBits' => 'NtGdiEngGradientFill',
    );

# These are bogus, not sure whose fault it is (winsyms or dbghelp?  windbg shows
# different address or can't find symbol), in 2K user32:
my %user32_delete = (
    'NtGdiSTROBJ_bGetAdvanceWidths' => 1,
    'NtUserDdeDisconnectList' => 1,
    'NtUserFreeDDElParam' => 1,
    'NtUserTestWindowProcess' => 1,
    );

# On Win10 this shows up in our syscalls files but it matches
# NtQuerySystemInformation for x64 but NtWow64GetNativeSystemInformation
# for wow64.  Best to just throw it out.
my %ntdll_delete = (
    "RtlGetNativeSystemInformation" => 1,
    );

my %imm32_only = (
    # These we list only under imm32 as on some platforms the wrapper is not
    # in user32:
    'NtUserAssociateInputContext' => 1,
    'NtUserBuildHimcList' => 1,
    'NtUserCreateInputContext' => 1,
    'NtUserDestroyInputContext' => 1,
    'NtUserGetAppImeLevel' => 1,
    'NtUserGetImeInfoEx' => 1,
    'NtUserQueryInputContext' => 1,
    'NtUserSetAppImeLevel' => 1,
    'NtUserSetImeInfoEx' => 1,
    'NtUserSetThreadLayoutHandles' => 1,
    );

my $os = 0;
my %nums;
my %sysnums;
my %skip;

if ($#ARGV < 0 || $ARGV[0] =~ /^-/) {
    die "Usage: $0 <prefix> <existing_table> files in platform order...\n";
}

my $prefix = $ARGV[0];
shift;
my $existing = $ARGV[0];
shift;

my $new_os = @ARGV;
my $old_os = 0;

my @maxlen;

open(IN,"<$existing") || die"Error opening $existing\n";
my $entire_existing = "";
while (<IN>) {
    $entire_existing .= $_;
    if (/^$prefix/) {
        chomp;
        s/, /,/g;
        s/\)//;
        s/^$prefix\((\w+)\s*,//;
        my $name = $1;
        my @matches = split ',', $_;
        $name = $name_map{$name} if (defined($name_map{$name}));
        if ($old_os == 0) {
            $old_os = @matches;
        } else {
            die "Count mismatch in table\n" unless ($old_os == @matches);
        }
        for (my $m = 0; $m < @matches; $m++) {
            # we append to the end, so old OS entries go first
            $nums{$name}[$m] = $matches[$m];
            $maxlen[$m] = length($matches[$m])
                unless (length($matches[$m]) < $maxlen[$m]);
        }
    }
}
close(IN);

my $name_prefix = "";
if ($prefix =~ /USER32/ || $prefix =~ /IMM32/) {
    $name_prefix = "NtUser";
} elsif ($prefix =~ /GDI32/) {
    $name_prefix = "NtGdi";
}
$os = $old_os;
while ($#ARGV >= 0) {
    open(IN,"<$ARGV[0]") || die"Error opening $ARGV[0]\n";
    $maxlen[$os] = 0;
    while (<IN>) {
        if (/(0x\w+) .*= (\w+)/) {
            my $sysnum = $1;
            my $name = $2;

            # only wow64 needs more than 4 digits, and only for later OS versions
            if (length($sysnum) > 6 && $sysnum !~ /^0x0000/) {
                die "non-wow64 has upper digits: $_" if ($ARGV[0] !~ /wow64/);
            }
            # We want all columns to be minimal length for max digits so we remove
            # leading zeroes here and re-add later to match max.
            $sysnum =~ s/0x0*/0x/;
            $maxlen[$os] = length($sysnum)
                unless (length($sysnum) < $maxlen[$os]);

            # normalize the names
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
            next if ($prefix =~ /NTDLL/ && defined($ntdll_delete{$name}));
            next if ($prefix =~ /USER32/ && defined($imm32_only{$name}));
            # XXX: there could be new imm32-only wrappers that we'll miss this way!
            next if ($prefix =~ /IMM32/ && !defined($imm32_only{$name}));

            # assume the gdi ones are also all in gdi32.dll, and ditto for reverse
            next if ($prefix =~ /USER32/ && $name =~ /^NtGdi/);
            next if ($prefix =~ /GDI32/ && $name !~ /^NtGdi/);

            if (!defined($nums{$name}[0])) {
                # New syscall.
                # For win10-1607, win32u has kernel32, user32, and gdi32 all combined,
                # so do not duplicate entries from one to another.
                if ($entire_existing =~ /\($name[\s,]/ ||
                    # For new syscalls, put them in the right place
                    ($prefix =~ /KERNEL32/ &&
                     ($name =~ /^NtUser/ ||
                      ($name !~ /^NtWow64Csr/ && $name !~ /Console/)))) {
                    $skip{$name} = 1;
                    next;
                }
            }

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
    # These end up in the keys somehow so we have to skip again.
    next if ($skip{$n});
    if ($n eq 'NtUserGetThreadDesktoa-SPECIALCASED') {
        # preserve the comment and extra entry
        $n = 'GetThreadDesktop';
        printf "/* i#487: this has a different sysnum on some platforms.  It must be before NtUserGetThreadDesktop (i#1418). */\n";
    }
    printf "%s(%-50s", $prefix, $n;
    for (my $i = 0; $i < $os; $i++) {
        if (defined($nums{$n}[$i])) {
            # Add leading zeroes to match max length of this column
            for (my $l = length($nums{$n}[$i]); $l < $maxlen[$i]; $l++) {
                $nums{$n}[$i] =~ s/0x/0x0/;
                $nums{$n}[$i] =~ s/NONE/ NONE/;
            }
            printf ",%s", $nums{$n}[$i];
        } else {
            # Start w/ max padding and remove to match max length for this column
            my $s = ",      NONE";
            for (my $l = 10; $l > $maxlen[$i]; $l--) {
                $s =~ s/, /,/;
            }
            printf "$s";
        }
    }
    print ")\n";
}

close(IN);
