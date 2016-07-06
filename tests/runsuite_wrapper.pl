#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2016 Google, Inc.  All rights reserved.
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

# XXX: we should share this w/ DR.

# Build-and-test driver for Travis CI.
# Travis uses the exit code to check success, so we need a layer outside of
# ctest on runsuite.
# We stick with runsuite rather than creating a parallel scheme using
# a Travis matrix of builds.
# Travis only supports Linux and Mac, so we're ok relying on perl.

use strict;
use Cwd 'abs_path';
use File::Basename;
my $mydir = dirname(abs_path($0));

# Forward args to runsuite.cmake:
my $args = '';
for (my $i = 0; $i <= $#ARGV; $i++) {
    if ($i == 0) {
        $args .= ",$ARGV[$i]";
    } else {
        $args .= "\\;$ARGV[$i]";
    }
}

# We have no way to access the log files, so we use -VV to ensure
# we can diagnose failures.
# We tee to stdout to provide incremental output and avoid the 10-min
# no-output timeout on Travis.
my $res = '';
my $child = open(CHILD, '-|');
die "Failed to fork: $!" if (!defined($child));
if ($child) {
    # Parent
    my $output;
    while (<CHILD>) {
        print STDOUT $_;
        $res .= $_;
    }
    close(CHILD);
} else {
    system("ctest -VV -S ${mydir}/runsuite.cmake${args} 2>&1");
}

my @lines = split('\n', $res);
my $should_print = 0;
my $exit_code = 0;
foreach my $line (@lines) {
    $should_print = 1 if ($line =~ /^RESULTS/);
    if ($line =~ /^([-\w]+):.*\*\*/) {
        my $fail = 0;
        my $name = $1;
        if ($line =~ /build errors/ ||
            $line =~ /configure errors/ ||
            $line =~ /tests failed:/) {
            $fail = 1;
        } elsif ($line =~ /(\d+) tests failed, of which (\d+)/) {
            $fail = 1 if ($2 < $1);
        }
        if ($fail) {
            $exit_code++;
            print "\n====> FAILURE in $name <====\n";
        }
    }
    print "$line\n" if ($should_print);
}

exit $exit_code;
