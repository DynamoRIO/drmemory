#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2016-2021 Google, Inc.  All rights reserved.
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

my $osdir = $mydir;
if ($^O eq 'cygwin') {
    # CMake is native Windows so pass it a Windows path.
    # We use the full path to cygpath as git's cygpath is earlier on
    # the PATH for AppVeyor and it fails.
    $osdir = `/usr/bin/cygpath -wi \"$mydir\"`;
    chomp $osdir;
}

# We have no way to access the log files, so we use -VV to ensure
# we can diagnose failures.
# We tee to stdout to provide incremental output and avoid the 10-min
# no-output timeout on Travis.
# If we're on UNIX or we have a Cygwin perl, we do this via a fork.
my $res = '';
my $child = 0;
my $outfile = '';
if ($^O ne 'MSWin32') {
    print "Forking child for stdout tee\n";
    $child = open(CHILD, '-|');
    die "Failed to fork: $!" if (!defined($child));
} else {
    $outfile = "runsuite_output.txt";
}
if ($child) {
    # Parent
    # i#4126: We include extra printing to help diagnose hangs on Travis.
    if ($^O ne 'cygwin') {
        print "Parent tee-ing child stdout...\n";
        local $SIG{ALRM} = sub {
            print "\nxxxxxxxxxx 30s elapsed xxxxxxxxxxx\n";
            alarm(30);
        };
        alarm(30);
        while (<CHILD>) {
            print STDOUT $_;
            $res .= $_;
        }
    } else {
        while (<CHILD>) {
            print STDOUT $_;
            $res .= $_;
        }
    }
    close(CHILD);
} elsif ($ENV{'CI_TARGET'} eq 'package') {
    # A package build.
    my $build = "0";
    if ($ENV{'VERSION_NUMBER'} =~ /-(\d+)$/) {
        $build = $1;
    }
    if ($args eq '') {
        $args = ",";
    } else {
        $args .= ";";
    }
    $args .= "drmem_only;build=${build}";
    if ($ENV{'DEPLOY_DOCS'} eq 'yes') {
        $args .= ";copy_docs";
    }
    if ($^O eq 'darwin' || $^O eq 'MacOS') {
        $args .= ";64_only";
    }
    if ($ENV{'VERSION_NUMBER'} =~ /^(\d+\.\d+\.\d+)/) {
        my $version = $1;
        $args .= ";version=${version}";
    }
    my $cmd = "ctest -VV -S \"${osdir}/../package.cmake${args}\"";
    print "Running ${cmd}\n";
    if ($^O eq 'MSWin32') {
        system("${cmd} 2>&1 | tee ${outfile}");
    } else {
        system("${cmd} 2>&1");
        exit 0;
    }
} else {
    # Despite creating larger log files, -VV makes it easier to diagnose issues.
    my $cmd = "ctest --output-on-failure -VV -S \"${osdir}/runsuite.cmake${args}\"";
    print "Running ${cmd}\n";
    if ($^O eq 'MSWin32') {
        system("${cmd} 2>&1 | tee ${outfile}");
        print "Finished running ${cmd}\n";
    } else {
        system("${cmd} 2>&1");
        print "Finished running ${cmd}\n";
        exit 0;
    }
}

if ($^O eq 'MSWin32') {
    open my $handle, '<', "$outfile" or die "Failed to open teed ${outfile}: $!";
    $res = do {
        local $/; <$handle>
    };
}
my @lines = split('\n', $res);
my $should_print = 0;
my $exit_code = 0;
for (my $i = 0; $i <= $#lines; ++$i) {
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
    } elsif ($line =~ /^FAILED: CMakeFiles\/package/) {
        $fail = 1;
        $should_print = 1;
        $name = "packaging step";
    }
    if ($fail && $is_CI  && $line =~ /tests failed/) {
        my $is_32 = $line =~ /-32/;
        my %ignore_failures_32 = ();
        my %ignore_failures_64 = ();
        if ($^O eq 'cygwin' ||
            $^O eq 'MSWin32') {
            # FIXME i#1938: ignoring certain Windows CI test failures until
            # we get all tests passing.
            %ignore_failures_32 = (
                'procterm' => 1,
                'winthreads' => 1,
                'malloc_callstacks' => 1,
                'app_suite.pattern' => 1,
                'app_suite' => 1,
                # TODO i#2180/i#2334: evaluate why failing on GA CI.
                'cs2bug' => 1,
                'reachable' => 1,
                'wincrt' => 1,
                'cs2bugMTdZI' => 1,
                'cs2bugMTd' => 1,
                'cs2bugMD' => 1,
                'cs2bugMDd' => 1,
                'gdi' => 1,
                'handle' => 1,
                'handle_only' => 1,
                'pcache-use' => 1,
                'drsyscall_test' => 1,
                'strace_test' => 1,
                'drstrace_unit_tests' => 1,
                'syscalls_win' => 1,
                'fuzz_threads' => 1,
                # TODO i#2342: These are hitting a DR encoding assert.  Maybe we
                # should just drop wrap_ support anyway.  Also xref i#1741.
                'wrap_malloc' => 1,
                'wrap_cs2bug' => 1,
                'wrap_operators' => 1,
                'wrap_wincrt' => 1,
                'wrap_wincrtdbg' => 1,
                'wrap_cs2bugMTd' => 1,
                'wrap_operatorsMDd' => 1,
                'leak_string' => 1,
                # TODO i#2375: Fix DR to avoid test failures.
                'umbra_client_faulty_redzone' => 1,
                );
            # FIXME i#2180: ignoring certain AppVeyor x64-full-mode failures until
            # we get all tests passing.
            %ignore_failures_64 = (
                'procterm' => 1,
                'badjmp' => 1,
                'cs2bug' => 1,
                'winthreads' => 1,
                'procterm.nativeparent' => 1,
                'malloc_callstacks' => 1,
                'reachable' => 1,
                'suppress' => 1, # i#2338
                'suppress-genoffs' => 1,
                'suppress-gensyms' => 1,
                'wincrt' => 1,
                'cs2bugMTd' => 1,
                'cs2bugMTdZI' => 1,
                'cs2bugMD' => 1,
                'cs2bugMDd' => 1,
                'operatorsMDd' => 1,
                'gdi' => 1,
                'syscalls_win' => 1,
                'handle_only' => 1,
                'nudge' => 1,
                'syscall_file_all' => 1,
                'syscall_file_gen' => 1,
                'handle' => 1,
                'drstrace_unit_tests' => 1,
                'app_suite.pattern' => 1,
                # TODO i#2180/i#2334: These have an extra invalid heap arg but it's
                # not printed out by the auto-print-results.txt: we need to get that
                # and suppress or fix.
                'fuzz_buffer.cpp' => 1,
                'fuzz_buffer.cpp.demangled' => 1,
                # TODO i#2180/i#2334: extra uninit but not printed out on CI!
                'nosyms' => 1,
                # TODO i#2180/i#2334: extra potential error but not printed out on CI!
                'allowlist_app' => 1,
                'allowlist_justlib' => 1,
                'allowlist_src' => 1,
                'allowlist_srclib' => 1,
                );
        } elsif ($^O eq 'darwin' || $^O eq 'MacOS') {
            %ignore_failures_32 = ('malloc' => 1); # i#2038
            %ignore_failures_64 = ('malloc' => 1);
        } else {
            %ignore_failures_32 = ('pcache-use' => 1, # i#2202
                                   'fuzz_threads' => 1, # i#2242
                                   # XXX: We should probably drop wrap_ support as we
                                   # do not have the resources to maintain it.
                                   'wrap_cs2bug' => 1,
                                   'wrap_operators' => 1,
                                   'app_suite.pattern' => 1,
                                   'app_suite' => 1);
            %ignore_failures_64 = ('pcache' => 1, # i#2243
                                   'app_suite.pattern' => 1);
        }
        # Read ahead to examine the test failures:
        $fail = 0;
        my $num_ignore = 0;
        for (my $j = $i+1; $j <= $#lines; ++$j) {
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
    if ($line =~ /Please check '([^']+)' for errors/) {
        my $log = $1;
        if ($^O eq 'cygwin') {
            $log = `/usr/bin/cygpath -u \"$log\"`;
        }
        chomp $log;
        if (open(LOG, "< $log")) {
            print "\n\n----------------- START $log -----------\n";
            while (<LOG>) {
                print $_;
            }
            print "\n----------------- END $log -----------\n\n";
        } else {
            print "Failed to open $log\n";
        }
        close(LOG);
    }
}
if (!$should_print) {
    print "Error: RESULTS line not found\n";
    $exit_code++;
}

exit $exit_code;
