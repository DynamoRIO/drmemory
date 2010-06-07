#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2008-2009 VMware, Inc.  All rights reserved.
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

# mksystable.pl
#
# expecting headers like this, currently from either Nebbett or Metasploit:
#   
# NTSYSAPI
# NTSTATUS
# NTAPI
# ZwQuerySystemInformation(
#     IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
#     OUT PVOID SystemInformation,
#     IN ULONG SystemInformationLength,
#     OUT PULONG ReturnLength OPTIONAL
#     );

while (<STDIN>) {
    # Nebbett has ^NTSYSAPI, Metasploit has .*NTSYSAPI
    next unless (/NTSYSAPI\s*$/);
    while (<STDIN>) {
        next if (/^NTSTATUS/ || /^NTAPI/ || /^ULONG/ || /^BOOLEAN/);
        last;
    }
    die "Parsing error $_" unless (/^((Zw)|(Nt))(\w+)\s*\(\s*$/);
    $name = "Nt" . $4;
    # not a real system call: just reads KUSER_SHARED_DATA
    next if ($name eq "NtGetTickCount");
    print "    {0,\"$name\", ";
    $argnum = 0;
    $toprint = "";
    while (<STDIN>) {
        last if (/^\s*\);/);
        if (/^\s*(VOID)\s*(,|\);|)\s*$/) {
            $inout = "";
            $type = $1;
        } else {
            die "Parsing error $_" unless
                (/^\s*((IN\s+OUT)|(IN)|(OUT))\s*((struct\s+)?[_\w]+)\s*(\*?\s*\w+)\s*(OPTIONAL)?\s*(,|\);|)\s*$/);
            print "\t$1-$2-$3-$4-$5-$6-$7\n" if ($verbose);
            $inout = $1;
            $type = $5;
            $var = $7;
            $optional = $8;
            $type .= '*' if ($var =~ /\*/);
            print "\t=> $inout $type\n" if ($verbose);

            # convert Nebbett types to Metasploit's updated types
            $type =~ s/PORT_SECTION_READ/REMOTE_PORT_VIEW/;
            $type =~ s/PORT_SECTION_WRITE/PORT_VIEW/;

            # convert enum to ULONG
            $type =~ s/HARDERROR_RESPONSE/ULONG/;
            $type =~ s/SAFEBOOT_MODE/ULONG/;
            $type =~ s/OPEN_SUB_KEY_INFORMATION/ULONG/;

            # convert VOID* to PVOID
            $type =~ s/VOID\*/PVOID/;
        }
        if ($name eq 'NtVdmControl' && $var eq 'ServiceData') {
            # FIXME: ServiceData arg to NtVdmControl in Metasploit is IN OUT
            # but we don't know size so we ignore its OUT and hope we
            # never see it
        } elsif (($type =~ /^P/ || $type =~ /^struct.*\*/) &&
            # IN PVOID is inlined
            ($type ne 'PVOID' || $inout =~ /OUT/) &&
            # list of inlined types that start with P
            $type !~ /_INFORMATION_CLASS/ && $type ne 'PROCESSINFOCLASS' &&
            $type ne 'POWER_ACTION' && $type ne 'POWER_INFORMATION_LEVEL' &&
            $type ne 'PKNORMAL_ROUTINE' && $type ne 'PIO_APC_ROUTINE' &&
            $type ne 'PTIMER_APC_ROUTINE') {
            $printarg++;
            if ($type eq 'PVOID' || $type eq 'PWSTR') {
                # assume next arg holds length
                $toprint .= sprintf("%d,-%d,", $argnum, $argnum+1);
            } else {
                $rtype = $type;
                $rtype =~ s/^P//;
                $rtype =~ s/\*$//;
                $toprint .= sprintf("%d,sizeof(%s),", $argnum, $rtype);
            }
            $toprint .= sprintf("%s, ", $inout =~ /OUT/ ?
                                ($rtype eq 'PORT_MESSAGE' ? "WP" : "W") : "R");
        } elsif ($inout eq 'IN' && $type eq 'BOOLEAN') {
            $toprint .= sprintf("%d,0,IB, ", $argnum);
        } else {
            die "OUT arg w/o P type" if ($inout =~ /OUT/);
        }
        $argnum++;
        last if (/\);/);
    }
    printf("%d, %s},\n", $argnum*4, $toprint);
}
