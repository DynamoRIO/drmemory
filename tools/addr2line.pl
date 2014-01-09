#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2004-2009 VMware, Inc.  All rights reserved.
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

# **********************************************************
# Copyright (c) 2004-2006 VMware, Inc.  All rights reserved.
# **********************************************************

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice,
#   this list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of VMware, Inc. nor the names of its contributors may be
#   used to endorse or promote products derived from this software without
#   specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# DAMAGE.

### addr2line.pl
###
### launches a debugger and runs the "ln" command to get the nearest
###   symbol to each address in question
### obviously works best if you have symbols: pdb in same dir, _NT_SYMBOL_PATH
### sample usage:
###   addr2line.pl c:/foo.exe 7004e660 77f830e7
### it also accepts stdin or a file with -f <file>
###
### note about -i interactive use feature:
###   cdb within rxvt has some problems: interactive typing loses the last
###   char or more, so put spaces after everything.
###   for interactive should launch ntsd, or run cdb from within a cygwin-in-cmd shell

# $^O is either "linux", "cygwin", or "MSWin32"
$is_unix = ($^O eq "linux") ? 1 : 0;
$is_cygwin = ($^O eq "cygwin") ? 1 : 0;

# default debugger paths to try
# we first try cdb from Debugging Tools For Windows
#   (so we can get stdout and don't need a temp logfile)
# else we use the ntsd on everyone's machines and a logfile,
#   which we clobber every time
$sysroot = &win32path2unix($ENV{'SYSTEMROOT'});
$progroot = &win32path2unix($ENV{'PROGRAMFILES'});
# try to find installation of debugging tools for windows
# avoid issues w/ spaces in path by quoting
@debugtools = glob("\"$progroot\"/Debug*/cdb.exe");
@try_dbgs = ("$debugtools[0]", "$sysroot/system32/ntsd.exe");

# parameters
# FIXME: allow to specify exe args
# FIXME: non-const-dll-base, or non-statically-bound dlls: have option
# to load in that dll and compute offs from original base
$usage = "Usage: $0 [-raw] [-a] [-i] [-s] [-f <addrfile>] [-d <debuggerpath>]
<exepath> [<addr1> ... <addrN>]\n";

$debugger = "";
$verbose = 0;
$raw = 0;
$addrfile = "";
$exepath = "";
$havedll = 0;
$numaddrs = 0;
$interactive = 0;
$match_addr2line = 0;
$symbol2addr = 0;
while ($#ARGV >= 0) {
    if ($ARGV[0] eq '-f') {
        die $usage if ($#ARGV <= 0);
        shift;
        $addrfile = $ARGV[0];
        unless (-f "$addrfile") {
            die "$err No file $addrfile\n";
        }
    } elsif ($ARGV[0] eq '-d') {
        die $usage if ($#ARGV <= 0);
        shift;
        $debugger = $ARGV[0];
        # checked below for existence
    } elsif ($ARGV[0] eq '-raw') {
        $raw = 1;
    } elsif ($ARGV[0] eq '-i') {
        $interactive = 1;
    } elsif ($ARGV[0] eq '-a') {
        $match_addr2line = 1;
    } elsif ($ARGV[0] eq '-s') {
        $symbol2addr = 1;
    } elsif ($ARGV[0] =~ /^-/) {
        die $usage;
    } else {
        if (!$havedll) {
            $exepath = $ARGV[0];
            $havedll = 1;
        } else {
            # can't use both -f and cmdline params
            die $usage if ($addrfile ne "");
            $addrs[$numaddrs++] = $ARGV[0];
        }
    }
    shift;
}

if ($numaddrs == 0) { # no cmdline addrs
    if ($addrfile ne "") {
        open(ADDRS, "< $addrfile") || die "Couldn't open $addrfile\n";
    } else {
        open(ADDRS, "< -") || die "Couldn't open stdin\n";
    }
    while (<ADDRS>) {
        # remove \n, \r, spaces, etc.
        s|\s*||g;
        $addrs[$numaddrs++] = $_;
    }
    close(ADDRS);
}

die $usage if ($exepath eq "");
$exepathwin32 = &unixpath2win32($exepath);
# try both -- different perls like different paths
unless (-f "$exepath" || -f "$exepathwin32") {
    die "Cannot find exe at $exepath or $exepathwin32\n";
}

# see if user-specified debugger exists
if ($debugger ne "") {
    $debugger = &win32path2unix($debugger);
    print "Trying debugger at $debugger\n" if ($verbose);
    if (! -f "$debugger") { # -x seems to require o+x so we don't check
        die "Cannot find debugger at $debugger\n";
    }
} else {
    for ($i = 0; $i <= $#try_dbgs; $i++) {
        $debugger = &win32path2unix($try_dbgs[$i]);
        print "Trying debugger at $debugger\n" if ($verbose);
        last if (-f "$debugger");
    }
    die "Cannot find a debugger: @try_dbgs\n" if ($i > $#try_dbgs);
}
if ($debugger !~ /cdb/) {
    $use_logfile = 1;
    if ($symbol2addr) {
        # ntsd doesn't seem to support the "x" command
        print "-s not supported with ntsd" if ($verbose);
        exit 1;
    }
}

die $usage if ($numaddrs == 0);
$queries = "";
$marker = 'eeeeeeee';
for ($i=0; $i<=$#addrs; $i++) {
    # use a marker to indicate boundaries of output for each command
    # (some have empty output)
    if ($symbol2addr) {
        $queries .= "? $marker; x *!$addrs[$i]; ";
    } else {
        $queries .= "? $marker; ln $addrs[$i]; ";
    }
}
# put marker at the end too
$queries .= "? $marker;";

# FIXME: win2k ntsd does not load symbols by following loaded dll's path!
# setting _NT_SYMBOL_PATH ENV here or exporting in shell doesn't work,
# and -y not available on win2k ntsd, and .sympath takes all chars following
# (even \r, \n, ", ;!), no aS available to break cmd -- giving up

# enable line numbers (off by default in cdb)!
$cmd = ".lines -e; l+l; $queries";

if ($use_logfile) {
    # must go through logfile as debugger won't write to accessible stdout
    my $logdir = $ENV{'TMPDIR'} || $ENV{'TEMP'} || $ENV{'TMP'} || '/tmp';
    die "Cannot find temp directory $logdir" if (! -d $logdir);
    $logfile = "$logdir/address_query-$$.log";
    $logfile = &unixpath2win32($logfile);
    print "Log file is $logfile\n" if ($verbose);
    # start fresh -- no stale results
    unlink $logfile if (-f $logfile);
    $cmd = ".logopen $logfile; $cmd; .logclose;";
}

$cmd .= " q" unless ($interactive);

# put quotes around debugger to handle spaces
# FIXME: I used to use -g to skip initial breakpoint: why?!?
# it causes GUI apps' windows to pop up and does not seem to be
# necessary at all.
$cmdline = "\"$debugger\" -c \"$cmd\" $exepathwin32";
print $cmdline if ($verbose);
if ($interactive) {
    system("$cmdline") && die "Error: couldn't run $cmdline\n";
} elsif ($raw) {
    system("$cmdline") && die "Error: couldn't run $cmdline\n";
    if ($use_logfile) {
        open(LOG, "< $logfile") || die "Error: couldn't open $logfile\n";
        while (<LOG>) {
            print $_;
        }
        close(LOG);
    }
} else {
    # prefix each ln output with the query (debugger doesn't re-print -c cmds)
    $i = -1;
    $output = 0;
    if ($use_logfile) {
        system("$cmdline") && die "Error: couldn't run $cmdline\n";
        open(DBGOUT, "< $logfile") || die "Error: couldn't open $logfile\n";
    } else {
        open(DBGOUT, "$cmdline |") || die "Error: couldn't run $cmdline\n";
    }
    while (<DBGOUT>) {
        # look for our marker
        if (/= $marker/) {
            $i++;
            if ($i <= $#addrs) {
                if (!$match_addr2line && !$symbol2addr) {
                    print "\n$addrs[$i]:\n";
                }
                $output = 1;
            } else {
                $output = 0; # at end
            }
            if ($match_addr2line) {
                print "$func\n$line\n" if ($i > 0);
                $func = "<function not available>";
                $line = "<source line not available>";
            }
        } elsif ($output) {
            # example:
            #   *** WARNING: Unable to verify checksum for app2-undef.exe
            #   e:\derek\barb-hw\03_undo_array\main_solution.cpp(17)+0x8
            #   (00401ee0)   app2_undef!main+0x1b   |  (00401fd0)   app2_undef!SimpleTest
            if ($match_addr2line) {
                # look for absolute source file name and for function name
                if (/^[a-z]:/) {
                    $line = $_;
                    chomp $line;
                } elsif (/^\(\w+\)\s+([^\|]+)\|/) {
                    $func = $1;
                    $func =~ s/\s*$//;
                }
            } else {
                # for $symbol2addr we only show lines like:
                #   00401ee0 app2_undef!main (int, char**)
                # and suppres warnings/errors about symbols, etc.
                if (!$symbol2addr || /^\d/) {
                    print $_;
                }
            }
        }
        # I used to match the addresses printed but these debuggers sometimes
        # give weird output -- the right-hand is not always a larger address
        # than the left-hand!!!  FIXME: what's going on?
        # example:
        # w/ export symbols:
        #   0:001> ln 77f8d96b
        #   (77f8d02e)   ntdll!RtlNtStatusToDosError+0x93d   |  (77f8db68)   ntdll!aulldiv
        # w/ pdb:
        #   0:001> ln 77f8d96b
        #   (77f8d7c8)   ntdll!RtlpRunTable+0x1a3   |  (77f81ec1)   ntdll!RtlSetUserValueHeap
    }
    close(DBGOUT);
}

sub unixpath2win32($) {
    my ($p) = @_;
    # use cygpath if available, it will convert /home to c:\cygwin\home, etc.
    $cp = `cygpath -wi \"$p\"` if ($is_cygwin);
    chomp $cp;
    if ($cp eq "") {
        # do it by hand
        # add support for /x => x:
        $p =~ s|^/([a-z])/|\1:/|;
        # forward slash becomes backslash since going through another shell
        $p =~ s|/|\\|g;
    } else {
        $p = $cp;
    }
    # make single backslashes doubles
    $p =~ s|\\{1}|\\\\|g;
    return $p;
}

sub win32path2unix($) {
    my ($p) = @_;
    # avoid issues with spaces by using 8.3 names
    $cp = `cygpath -dmi \"$p\"` if ($is_cygwin);
    chomp $cp;
    if ($cp eq "") {
        # do it by hand
        $p =~ s|\\|/|g;
    } else {
        $p = $cp;
    }
    return $p;
}
