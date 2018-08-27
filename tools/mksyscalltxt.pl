#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2016-2018 Google, Inc.  All rights reserved.
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

# This script creates the syscall number text file for each platform that
# we can provide to users to support new Windows releases (i#1908).
# It generates syscalls_{x86,wow64,x64}.txt into the directory specified by
# its only parameter.
# We run it on Windows as part of the test suite.

use strict;
use File::Basename;
use Cwd qw(abs_path cwd);

my $header = 'DrSyscall Number File
1';
my $key = 'NtGetContextThread';
my $endmark = '=END';

my %outfile_names = (
    'x86' => 'syscalls_x86.txt',
    'wow64' => 'syscalls_wow64.txt',
    'x64' => 'syscalls_x64.txt');

my %outf;

# XXX: I would construct this dynamically, but being static makes callx2indices
# much simpler.
my %numx2index = (
    'w2k'    => 0,
    'xpx86'  => 1,
    'w2003'  => 2,
    'xpwow'  => 3,
    'xp64'   => 4,
    'vis86'  => 5,
    'viwow'  => 6,
    'vis64'  => 7,
    'w7x86'  => 8,
    'w7wow'  => 9,
    'w7x64'  => 10,
    'w8x86'  => 11,
    'w8wow'  => 12,
    'w8x64'  => 13,
    'w81x86' => 14,
    'w81wow' => 15,
    'w81x64' => 16,
    'w10x86' => 17,
    'w10wow' => 18,
    'w10x64' => 19,
    'w11x86' => 20,
    'w11wow' => 21,
    'w11x64' => 22,
    'w12x86' => 23,
    'w12wow' => 24,
    'w12x64' => 25,
    'w13x86' => 26,
    'w13wow' => 27,
    'w13x64' => 28,
    'w14x86' => 29,
    'w14wow' => 30,
    'w14x64' => 31,
    'w15x86' => 32,
    'w15wow' => 33,
    'w15x64' => 34,
    );

# Maps OS labels in drsyscall_callx.h to our array from drsyscall_usercallx.h
my %callx2indices = (
    'w2k'  => [$numx2index{'w2k'}],
    'xp'   => [$numx2index{'xpx86'}],
    '2003' => [$numx2index{'w2003'}, $numx2index{'xpwow'}, $numx2index{'xp64'}],
    'vistaSP01' => [], # We don't support Vista SPO0 or SP1 in syscall files
    'vistaSP2' => [$numx2index{'vis86'}, $numx2index{'viwow'}, $numx2index{'vis64'}],
    'w7'   => [$numx2index{'w7x86'}, $numx2index{'w7wow'}, $numx2index{'w7x64'}],
    'w8'   => [$numx2index{'w8x86'}, $numx2index{'w8wow'}, $numx2index{'w8x64'}],
    'w81'  => [$numx2index{'w81x86'}, $numx2index{'w81wow'}, $numx2index{'w81x64'}],
    'w10'  => [$numx2index{'w10x86'}, $numx2index{'w10wow'}, $numx2index{'w10x64'}],
    'w11'  => [$numx2index{'w11x86'}, $numx2index{'w11wow'}, $numx2index{'w11x64'}],
    'w12'  => [$numx2index{'w12x86'}, $numx2index{'w12wow'}, $numx2index{'w12x64'}],
    'w13'  => [$numx2index{'w13x86'}, $numx2index{'w13wow'}, $numx2index{'w13x64'}],
    'w14'  => [$numx2index{'w14x86'}, $numx2index{'w14wow'}, $numx2index{'w14x64'}],
    'w15'  => [$numx2index{'w15x86'}, $numx2index{'w15wow'}, $numx2index{'w15x64'}],
    );

my %os_numx2flavor_map = (
    'w2k'    => 'x86',
    'xpx86'  => 'x86',
    'w2003'  => 'x86',
    'xpwow'  => 'wow64',
    'xp64'   => 'x64',
    'vis86'  => 'x86',
    'viwow'  => 'wow64',
    'vis64'  => 'x64',
    'w7x86'  => 'x86',
    'w7wow'  => 'wow64',
    'w7x64'  => 'x64',
    'w8x86'  => 'x86',
    'w8wow'  => 'wow64',
    'w8x64'  => 'x64',
    'w81x86' => 'x86',
    'w81wow' => 'wow64',
    'w81x64' => 'x64',
    'w10x86' => 'x86',
    'w10wow' => 'wow64',
    'w10x64' => 'x64',
    'w11x86' => 'x86',
    'w11wow' => 'wow64',
    'w11x64' => 'x64',
    'w12x86' => 'x86',
    'w12wow' => 'wow64',
    'w12x64' => 'x64',
    'w13x86' => 'x86',
    'w13wow' => 'wow64',
    'w13x64' => 'x64',
    'w14x86' => 'x86',
    'w14wow' => 'wow64',
    'w14x64' => 'x64',
    'w15x86' => 'x86',
    'w15wow' => 'wow64',
    'w15x64' => 'x64',
    );

my ($scriptname,$scriptpath,$suffix) = fileparse($0);
$scriptpath = abs_path($scriptpath);

my $numx_file = "$scriptpath/../drsyscall/drsyscall_numx.h";
my $callx_file = "$scriptpath/../drsyscall/drsyscall_usercallx.h";

my %nums; # maps each syscall to an array of hex strings, one per OS
my @os_names;
my @callx_names;
my $callx_count;
my $found_os_names = 0;
my $os_count;

my $verbose = 0;

die "Usage: $0 <outdir>\n" unless ($#ARGV == 0);
my $outdir = $ARGV[0];

open(IN, "<$numx_file") || die "Error opening $numx_file\n";
while (<IN>) {
    if (/NTDLL\(name,\s*(.*)\)/) {
        my $names = $1;
        $names =~ s/\s//g;
        @os_names = split ',', $names;
        $found_os_names = 1;
        $os_count = @os_names;
        for (my $os = 0; $os < $os_count; $os++) {
            die "Index mismatch: $os_names[$os] is $os vs $numx2index{$os_names[$os]}\n"
                unless ($numx2index{$os_names[$os]} == $os);
        }
    }
    if (/^[A-Z0-9]+\((\w+)\s*,(.*)\)/) {
        die "Did not find name key\n" unless ($found_os_names);
        my $name = $1;
        my $hexstr = $2;
        $hexstr =~ s/\s//g;
        my @hexes = split ',', $hexstr;
        for (my $os = 0; $os < @hexes; $os++) {
            print "$name $os $os_names[$os] = $hexes[$os]\n" if ($verbose >= 1);
            $nums{$name}[$os] = $hexes[$os];
        }
    }
}
close(IN);

open(IN, "<$callx_file") || die "Error opening $callx_file\n";
while (<IN>) {
    if (/USERCALL\(type, name,\s*(.*)\)/) {
        my $names = $1;
        $names =~ s/\s//g;
        @callx_names = split ',', $names;
        $callx_count = @callx_names;
        for (my $c = 0; $c < $callx_count; $c++) {
            die "Bad callx os $c $callx_names[$c]\n"
                unless (defined($callx2indices{$callx_names[$c]}));
        }
    }
    if (/^USERCALL\((\w+),\s*(\w+)\s*,(.*)\)/) {
        my $primary = $1;
        my $secondary = $2;
        my $name = "$primary.$secondary";
        my $hexstr = $3;
        $hexstr =~ s/\s//g;
        my @hexes = split ',', $hexstr;
        for (my $c = 0; $c < @hexes; $c++) {
            foreach my $os (@{$callx2indices{$callx_names[$c]}}) {
                print "$name $c $os $os_names[$os] = $hexes[$c]\n" if ($verbose >= 1);
                $nums{$name}[$os] = $hexes[$c];
            }
        }
    }
}
close(IN);
die "Failed to parse $callx_file\n" unless ($callx_count > 0);

my $fh;
foreach my $flavor (keys %outfile_names) {
    local *OUTF;
    open(OUTF, "> $outdir/$outfile_names{$flavor}") ||
        die "Failed to write to $outdir/$outfile_names{$flavor}\n";
    $fh = *OUTF;
    $outf{$flavor} = $fh;
    my $str = "$header\n$key\n";
    print $fh $str;
    print "Printing to file: $str" if ($verbose);
}

# Now write to the files
for (my $os = 0; $os < $os_count; $os++) {
    my $flavor = $os_numx2flavor_map{$os_names[$os]};
    $fh = $outf{$flavor};
    printf $fh "START=%s\n", $nums{$key}[$os];
    foreach my $call (sort keys %nums) {
        if ($nums{$call}[$os] !~ /NONE/) {
            printf $fh "%s=%s\n", $call, $nums{$call}[$os];
        }
    }
    print $fh "$endmark\n";
}

foreach my $flavor (keys %outfile_names) {
    close($outf{$flavor});
}
