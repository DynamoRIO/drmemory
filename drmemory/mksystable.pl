#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2011 Google, Inc.  All rights reserved.
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

use Getopt::Long;

# list of non-pointer types that start with P
%ptypes = ('PROCESSINFOCLASS' => 1,
           'POWER_ACTION' => 1,
           'POWER_INFORMATION_LEVEL' => 1,
           'PKNORMAL_ROUTINE' => 1,
           'PIO_APC_ROUTINE' => 1,
           'PTIMER_APC_ROUTINE' => 1,
           'PALETTEENTRY' => 1,
           'PATHOBJ' => 1,
           'POINT' => 1,
           'POINTL' => 1,
           'POINTFIX' => 1,
           'POINTQF' => 1,
           'POLYTEXTW' => 1,
           'POLYPATBLT' => 1,
           'PERBANDINFO' => 1,
    );

$verbose = 0;
if (!GetOptions("v" => \$verbose)) {
    die "usage error\n";
}

while (<STDIN>) {
    # Nebbett has ^NTSYSAPI, Metasploit has .*NTSYSAPI
    next unless (/(NTSYSAPI\s*$)|(^__kernel_entry W32KAPI)/);
    $is_w32k = /W32KAPI/;
    while (<STDIN>) {
        next if (/^NTSTATUS/ || /^NTAPI/ || /^ULONG/ || /^BOOLEAN/);
        last;
    }
    next if (/^APIENTRY\s*$/); # sometimes on next line
    die "Parsing error $_" unless (/^((Zw)|(Nt))(\w+)\s*\(/);
    $name = "Nt" . $4;
    # not a real system call: just reads KUSER_SHARED_DATA
    next if ($name eq "NtGetTickCount");
    print "    {0,\"$name\", OK, ";
    print "\n" if ($verbose);
    my $argnum = 0;
    my $toprint = "";
    my $nameline = $_;
    while (<STDIN>) {
        last if (/^\s*\);/ || $nameline =~ /\(\s*\);/);
        s|//.*$||; # remove comments
        s|\s*const(\s*)|\1|; # remove const
        if (/^\s*(VOID)\s*(,|\);|)\s*$/) {
            $inout = "";
            $arg_type[$argnum] = $1;
        } else {
            if ($is_w32k) {
                # __-style param annotations in ntgdi.h
                # hack for missing var name (rather than relaxing pattern)
                s/SURFOBJ \*\s*$/SURFOBJ *varname/;
                die "Parsing error $_" unless (/^\s*(__[_a-z]+(\(.+\))?(\s*__typefix\(.*\))?)\s*((struct\s+)?[_\w]+)\s*(\**\s*\w+)\s*(,|\);|)\s*$/);
                print "\tann: $1, type: $3, var: $5\n" if ($verbose > 1);
                $ann = $1;
                $arg_type[$argnum] = $4;
                $arg_var[$argnum] = $6;
                $arg_bufsz[$argnum] = '';
                $arg_comment[$argnum] = '';
                # annotation components are split by underscores.
                # we also have parens that go with range(x,y) or
                # with [eb]count -- but for the latter there can be
                # other modifiers prior to the parens.
                # examples:
                #   __out_ecount_part_opt(cwc, *pcCh)
                #   __deref_out_range(0, MAX_PATH * 3) ULONG* pcwc,
                $ann =~ s/^__//;
                # deal w/ parens first, then we can use split on rest
                # we ignore range()
                $ann =~ s/range\([^\)]+\)//;
                # typefix seems to be separate by a space
                if ($ann =~ s/\s*__typefix\(([^\)]+)\)//) {
                    $arg_type[$argnum] = $1; # replace type
                }
                # we assume only one other set of parens: [eb]count
                if ($ann =~ s/\((.+)\)//) {
                    $arg_bufsz[$argnum] = $1;
                }
                foreach $a (split('_', $ann)) {
                    if ($a eq 'in' || $a eq 'out' || $a eq 'inout') {
                        $arg_inout[$argnum] = uc($a);
                    } elsif ($a eq 'opt' || # we don't care
                             $a eq 'part') { # we assume we'll see (size,length)
                        # ignore annotation
                    } elsif ($a =~ /^bcount/) {
                        $arg_ecount[$argnum] = 0;
                    } elsif ($a =~ /^ecount/) {
                        $arg_ecount[$argnum] = 1;
                    } elsif ($a =~ /^xcount/) {
                        # xcount requires additional handling done manually
                        # so far only seen in NtGdiExtTextOutW
                        $arg_ecount[$argnum] = 1;
                        $arg_comment[$argnum] .= '/*FIXME size can be larger*/';
                    } elsif ($a =~ /^post/) {
                        # the buffer size is unknown at pre time: supposed to
                        # call twice, first w/ NULL buffer to get required size.
                        $arg_comment[$argnum] .= '/*FIXME pre size from prior syscall ret*/';
                    } elsif ($a =~ /^deref/) {
                        # XXX: this one I don't quite get: it's used on things
                        # that look like regular OUT vars to me.
                        # is it just to say it can't be NULL (vs _deref_opt)?
                        # but what about all the OUT vars w/ no _dref?
                    } else {
                        die "Unknown annotation: $a\n";
                    }
                }
                # handle "bcount(var * sizeof(T)) __typefix(T) PVOID"
                if ($arg_bufsz[$argnum] =~ /^(\w+)\s*\*\s*sizeof\(([^\)]+)\)/) {
                    my $newsz = $1;
                    my $type = $2;
                    if ($arg_type[$argnum] =~ /^${type}\s*\*$/ ||
                        $arg_type[$argnum] =~ /^P${type}$/) {
                        $arg_bufsz[$argnum] = $newsz;
                        $arg_ecount[$argnum] = 1;
                    }
                }
            } else {
                # all-caps, separate-words param annotations
                die "Parsing error $_" unless
                    (/^\s*((IN\s+OUT)|(IN)|(OUT))\s*((struct\s+)?[_\w]+)\s*(\*?\s*\w+)\s*(OPTIONAL)?\s*(,|\);|)\s*$/);
                print "\t$1-$2-$3-$4-$5-$6-$7\n" if ($verbose);
                $arg_inout[$argnum] = $1;
                $arg_type[$argnum] = $5;
                $arg_var[$argnum] = $7;
                $optional = $8;
            }
            while ($arg_var[$argnum] =~ s/\*//) {
                $arg_type[$argnum] .= '*';
                $arg_var[$argnum] =~ s/^\s*//;
            }
            s/\r?\n$//;
            print "\t$argnum: $_ => $arg_inout[$argnum]:$arg_type[$argnum]:$arg_var[$argnum]\n"
                if ($verbose);

            if (!$is_w32k) {
                # convert Nebbett types to Metasploit's updated types
                $arg_type[$argnum] =~ s/PORT_SECTION_READ/REMOTE_PORT_VIEW/;
                $arg_type[$argnum] =~ s/PORT_SECTION_WRITE/PORT_VIEW/;

                # convert enum to ULONG
                $arg_type[$argnum] =~ s/HARDERROR_RESPONSE/ULONG/;
                $arg_type[$argnum] =~ s/SAFEBOOT_MODE/ULONG/;
                $arg_type[$argnum] =~ s/OPEN_SUB_KEY_INFORMATION/ULONG/;
            }

            # convert VOID* to PVOID
            $arg_type[$argnum] =~ s/^VOID\*/PVOID/;

            $arg_type[$argnum] =~ s/^LP/P/;
        }
        $arg_name_to_num{$arg_var[$argnum]} = $argnum;
        $argnum++;
        last if (/\);/);
    }

    # now print out the entry
    for ($i = 0; $i < $argnum; $i++) {
        my $inout = $arg_inout[$i];
        my $type = $arg_type[$i];
        if ($name eq 'NtVdmControl' && $arg_var[$i] eq 'ServiceData') {
            # FIXME: ServiceData arg to NtVdmControl in Metasploit is IN OUT
            # but we don't know size so we ignore its OUT and hope we
            # never see it
        } elsif (($type =~ /^P/ || $type =~ /\*/) &&
                 # IN PVOID is inlined
                 ($type ne 'PVOID' || $inout =~ /OUT/) &&
                 # list of inlined types that start with P
                 $type !~ /_INFORMATION_CLASS/ &&
                 !defined($ptypes{$type})) {
            my $rtype = $type;
            if ($type eq 'PWSTR' || $type eq 'PCWSTR') {
                $rtype = 'wchar_t';
            } elsif ($type eq 'PSTR') {
                $rtype = 'char';
            } else {
                if ($rtype =~ /\*/) {
                    $rtype =~ s/\s*\*$//;
                } elsif ($rtype =~ /^P/) {
                    $rtype =~ s/^P//;
                }
            }
            my $inout_string = $inout =~ /OUT/ ? ($inout =~ /IN/ ? "R|W" : "W") : "R";
            my $cap;
            my $wrote = '';
            $toprint .= "{";
            if ($arg_bufsz[$i] ne '') {
                if ($arg_bufsz[$i] =~ /([^,]+),\s+(.+)/) {
                    $cap = $1;
                    $wrote = $2;
                    die "Cannot have 2 sizes for IN param\n" unless ($inout =~ /OUT/);
                } else {
                    $cap = $arg_bufsz[$i];
                    $wrote = ''; # same as cap
                }
                if ($cap eq 'return') {
                    $cap = 0;
                    $arg_comment[$i] .= "/*FIXME size from retval so earlier call*/";
                }
                if ($cap =~ /^\*/) {
                    $cap =~ s/^\*//;
                    if ($inout_string eq 'W') {
                        $inout_string = 'WI';
                    } else {
                        $inout_string = 'R|SYSARG_LENGTH_INOUT';
                    }
                }
                if (defined($arg_name_to_num{$cap})) {
                    $toprint .= sprintf("%d,-%d,", $i, $arg_name_to_num{$cap});
                } else {
                    $toprint .= sprintf("%d,%s,", $i, $cap);
                }
            } elsif (!$is_w32k && ($type eq 'PVOID' || $type eq 'PWSTR')) {
                # when don't have length annotations: assume next arg holds length
                # XXX: pretty risky assumption: verify manually
                $toprint .= sprintf("%d,-%d,", $i, $i+1);
            } else {
                $toprint .= sprintf("%d,sizeof(%s),", $i, $rtype);
            }
            if ($rtype eq 'PORT_MESSAGE' && $inout_string =~ 'W') {
                die "PORT_MESSAGE with W*\n" if ($inout_string ne 'W');
                $inout_string = 'WP';
            }
            $toprint .= sprintf("%s", $inout_string);
            if ($arg_bufsz[$i] ne '' && $arg_ecount[$i]) {
                $toprint .= sprintf("|SYSARG_SIZE_IN_ELEMENTS,sizeof(%s)", $rtype);
            } else {
                $toprint .= ",";
            }
            $toprint .= $arg_comment[$i];
            $toprint .= "}, ";

            if ($wrote ne '') {
                # XXX: share code w/ above
                my $wrote_inout = 'W';
                if ($wrote =~ /^\*/) {
                    $wrote =~ s/^\*//;
                    $wrote_inout = 'WI';
                }
                if (defined($arg_name_to_num{$wrote})) {
                    $toprint .= sprintf("{%d,-%d,", $i, $arg_name_to_num{$wrote});
                } else {
                    $wrote = 'RET' if ($wrote eq 'return');
                    $toprint .= sprintf("{%d,%s,", $i, $wrote);
                }
                $toprint .= $wrote_inout;
                if ($arg_bufsz[$i] ne '' && $arg_ecount[$i]) {
                    $toprint .= sprintf("|SYSARG_SIZE_IN_ELEMENTS,sizeof(%s)", $rtype);
                } else {
                    $toprint .= ",";
                }
                $toprint .= "}, ";
            }
        } elsif ($inout eq 'IN' && $type eq 'BOOLEAN') {
            $toprint .= sprintf("%d,0,IB, ", $i);
        } else {
            die "OUT arg w/o P or * type" if ($inout =~ /OUT/);
        }
    }
    $toprint = '{' . $toprint . '}' if ($toprint ne '');
    printf("%d, %s},\n", $argnum*4, $toprint);
}
