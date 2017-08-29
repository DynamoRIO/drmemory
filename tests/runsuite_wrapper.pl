#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2016-2017 Google, Inc.  All rights reserved.
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
my $is_CI = 0;

# Forward args to runsuite.cmake:
my $args = '';
for (my $i = 0; $i <= $#ARGV; $i++) {
    $is_CI = 1 if ($ARGV[$i] eq 'travis');
    if ($i == 0) {
        $args .= ",$ARGV[$i]";
    } else {
        # We don't use a backslash to escape ; b/c we'll quote below, and
        # the backslash is problematically converted to / by Cygwin perl.
        $args .= ";$ARGV[$i]";
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
    if ($^O eq 'cygwin') {
        # CMake is native Windows so pass it a Windows path.
        # We use the full path to cygpath as git's cygpath is earlier on
        # the PATH for AppVeyor and it fails.
        $mydir = `/usr/bin/cygpath -wi \"$mydir\"`;
        chomp $mydir;
    }
    # To shrink the log sizes and make Travis and Appveyor error pages easier
    # to work with we omit a second V and instead use --output-on-failure.
    # We rely on runsuite_common_post.cmake extracting configure and build error
    # details from the xml files, as they don't show up with one V.
    system("ctest --output-on-failure -V -S \"${mydir}/runsuite.cmake${args}\" 2>&1");
    exit 0;
}

my @lines = split('\n', $res);
my $should_print = 0;
my $exit_code = 0;
for (my $i = 0; $i < $#lines; ++$i) {
    my $line = $lines[$i];
    my $fail = 0;
    my $name = '';
    $should_print = 1 if ($line =~ /^RESULTS/);
    if ($line =~ /^([-\w]+):.*\*\*/) {
        $name = $1;
        if ($line =~ /build errors/ ||
            $line =~ /configure errors/ ||
            $line =~ /tests failed:/) {
            $fail = 1;
        } elsif ($line =~ /(\d+) tests failed, of which (\d+)/) {
            $fail = 1 if ($2 < $1);
        }
    } elsif ($line =~ /^\s*ERROR: diff contains/) {
        $fail = 1;
        $should_print = 1;
        $name = "diff pre-commit checks";
    }
    if ($fail && $is_CI && $^O eq 'cygwin' && $line =~ /tests failed/) {
        # FIXME i#1938: ignoring certain AppVeyor test failures until
        # we get all tests passing.
        my $is_32 = $line =~ /-32/;
        my %ignore_failures_32 = ('procterm' => 1,
                                  'winthreads' => 1,
                                  'malloc_callstacks' => 1,
                                  'wrap_wincrt' => 1, # i#1741: flaky.
                                  'app_suite.pattern' => 1,
                                  'app_suite' => 1,
                                  'drstrace_unit_tests' => 1);
        my %ignore_failures_64 = ('handle' => 1,
                                  'app_suite' => 1,
                                  'app_suite.pattern' => 1,
                                  'drstrace_unit_tests' => 1);
        # Read ahead to examine the test failures:
        $fail = 0;
        my $num_ignore = 0;
        for (my $j = $i+1; $j < $#lines; ++$j) {
            my $test;
            if ($lines[$j] =~ /^\t(\S+)\s/) {
                $test = $1;
                if (($is_32 && $ignore_failures_32{$test}) ||
                    (!$is_32 && $ignore_failures_64{$test})) {
                    $lines[$j] = "\t(ignore: i#1938) " . $lines[$j];
                    $num_ignore++;
                } elsif ($test =~ /_FLAKY$/) {
                    # Don't count toward failure.
                } else {
                    $fail = 1;
                }
            } else {
                last if ($lines[$j] =~ /^\S/);
            }
        }
        $line =~ s/: \*/, but ignoring $num_ignore for i1938: */;
    }
    if ($fail) {
        $exit_code++;
        print "\n====> FAILURE in $name <====\n";
    }
    print "$line\n" if ($should_print);
}
if (!$should_print) {
    print "Error: RESULTS line not found\n";
    $exit_code++;
}

exit $exit_code;
