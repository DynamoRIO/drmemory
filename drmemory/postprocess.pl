#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2010-2013 Google, Inc.  All rights reserved.
# Copyright (c) 2008-2010 VMware, Inc.  All rights reserved.
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

### postprocess.pl
###
### post-processes the output from Dr. Memory to add symbol and line # info
### If no -c command is passed in, assumes addr2line is on the path.

use Getopt::Long;
use File::Basename;
use File::Glob ':glob';
use FileHandle;
use IPC::Open3;
use Cwd qw(abs_path);
use Symbol; # for gensym
use IO::Select;

# $^O is either "linux", "cygwin", or "MSWin32"
$is_unix = ($^O eq "linux") ? 1 : 0;
$is_cygwin = ($^O eq "cygwin") ? 1 : 0;

# locate our module in same dir as script
use FindBin;
# RealBin doesn't work on cygwin
my $bindir = ($is_cygwin) ? "$FindBin::Bin" : "$FindBin::RealBin";
# we can't use var here since evaluated in first pass so we duplicate
use lib ($is_cygwin) ? "$FindBin::Bin/.." : "$FindBin::RealBin/..";

# do NOT use $0 as we need to support symlinks to this file
# RealBin resolves symlinks for us
($scriptname,$scriptpath,$suffix) = fileparse("$FindBin::RealBin/$FindBin::RealScript");

if ($is_unix) {
    $is_vmk = (`uname -s` =~ /VMkernel/) ? 1 : 0;
    # support post-processing on linux box vs vmk data
    $vs_vmk = (-e "$scriptpath/../frontend_vmk.pm");
} else {
    $is_vmk = 0;
    $vs_vmk = 0;
}

if ($is_vmk || $vs_vmk) {
    eval "use frontend_vmk qw(:All)";
    eval "use drmemory_vmk qw(:All)" if ($is_vmk);
    $vmk_grp = &vmk_drmem_group() if ($is_vmk);
}

# PR 453867: we need to store the original command line
@myargs = @ARGV;

$usage = "Usage: $0  -x <exe> [-p <prefix>] [-cygwin] [-no_sys_paths]".
    "[-f <srcfile filter>] -c <addr2line cmd> [-use_vmtree] ".
    "[-q] [-v] [-suppress <suppress_file>]* [-appid <app identifier>] ".
    "[-drmemdir <subdir>] [-l <logdir> | -aggregate <logdir list>] ".
    "[-nodefault_suppress] \n";
$default_prefix = "~~Dr.M~~ ";
$prefix = $default_prefix;
$winsyms_key = ";winsyms";
$addrcmd = "";
$exename = "";
$is_cygwin_exe = 0;
$logdir = "";
$srcfilter = "";
$use_vmtree = ($vs_vmk && &vmk_expect_vmtree());
$dr_home = "";
$quiet = 0;
$batch = 0;     # batch testing: no popups please
$verbose = 0;   # for debugging
$errnum = 0;    # error counter accounting for all logs
$errors_processed = 0;    # counter for all errors seen, including dups + suppressed
$appid = "";
$drmem_dir = "debug";
%logs = {};
%error = {};
%supp_syms_list = {};   # list of suppression regexps
@supp_syms_file = ();
%supp_used_count = {};  # times used
%addr_pipes = ();   # pipes to addr2line processes for each module; PR 454803.
$vmk_grp = "";  # vmkernel group for addr2line; PR 453395.
@dbg_sec_types = ("debug_info", # all DWARF 2 & 3 type info will have this
                  "debug_frame",# on Debian some libraries have only this
                  "debug ",     # for DWARF 1; the extra " " is to prevent
                                #   DWARF 2 matches
                  "stab");      # .stab is competing debug format to DWARF
$no_sys_paths = 0; # look in /lib, etc. for symbol files?
$aggregate = 0;
my $use_default_suppress = 1;
my $gen_suppress_offs = 1;
my $gen_suppress_syms = 1;
my $default_suppress_file = "$bindir/suppress-default.txt";
my $drmem_disabled = 0;
my $callstack_style = "0x101"; # should keep in sync, but normally passed even if default
my $warned_legacy_supp = 0;

# Use an error cache to prevent processing duplicates; indexed by error info
# excluding read/write message in the first line.  PR 420942.
#
%error_cache = {};

# Use a symbol and file cache to prevent duplicate invocations of addr2line;
# indexed by modoffs.  PR 420921.
#
%symfile_cache = {};

# Map the client's no-symbols version of the error number to our error string
@client_errnum_to_name = [];

# Part of PR 420942, to make users' life easy by showing potentially related
# errors.  Errors whose topmost frame has the same eip.  Can be extended to
# topmost frame having the same symbol too.
#
%similar_errors = {};

# Path to search libraries in
@libsearch = ();

# we want the keys in insertion order
# Tie::IxHash is not a standard module so we do it the hard way
@err_type_keys = ("UNADDRESSABLE ACCESS",
                  "UNINITIALIZED READ",
                  "INVALID HEAP ARGUMENT",
                  "WARNING",
                  "LEAK",
                  "POSSIBLE LEAK",
                  "REACHABLE LEAK");
%err_types = ("UNADDRESSABLE ACCESS" => "unaddressable access(es)",
              "UNINITIALIZED READ"   => "uninitialized access(es)",
              "INVALID HEAP ARGUMENT"=> "invalid heap argument(s)",
              "WARNING"              => "warning(s)",
              "LEAK"                 => "leak(s)",
              "POSSIBLE LEAK"        => "possible leak(s)",
              "REACHABLE LEAK"       => "still-reachable allocation(s)");

$nudge_count = 0;
# for PR 477013 to echo client summary lines
$client_leak_summary = "";
$no_leak_info = 0;
$no_possible_leak_info = 0;
$client_ignored = "";
# these are totals: unique not tracked separately
$client_suppressed_errors_default = 0;
$client_suppressed_errors_user = 0;
$client_suppressed_leaks_default = 0;
$client_suppressed_leaks_user = 0;
$post_suppressed_errors_default = 0;
$post_suppressed_errors_user = 0;
$post_suppressed_leaks_default = 0;
$post_suppressed_leaks_user = 0;
$leaks_only = 0; # right now this also means Dr. Heapstat
$replace_malloc = 0;

# what error types to report
$report_unaddr = 0;
$report_uninit = 0;
$report_invalid = 0;
$report_leaks = 0;

if (!GetOptions("p=s" => \$prefix,
                "x=s" => \$exename,
                "l=s" => \$logdir,
                "c=s" => \$addrcmd,
                "cygwin" => \$is_cygwin_exe,
                "f=s" => \$srcfilter,
                "q" => \$quiet,
                "batch" => \$batch,
                "v" => \$verbose,
                "use_vmtree" => \$use_vmtree,
                "appid=s" => \$appid,
                "suppress=s" => \@supp_syms_file,
                "default_suppress!" => \$use_default_suppress,
                "gen_suppress_offs!" => \$gen_suppress_offs,
                "gen_suppress_syms!" => \$gen_suppress_syms,
                "dr_home=s" => \$dr_home,
                "drmemdir=s" => \$drmem_dir,
                "no_sys_paths" => \$no_sys_paths,
                "aggregate" => \$aggregate,
                "callstack_style=s" => \$callstack_style,
                "replace_malloc" => \$replace_malloc,
                "leaks_only" => \$leaks_only)) {
    die $usage;
}

if ($aggregate) {
    $logdir = "." if ($logdir eq ''); # put results.txt in cur dir
}
die $usage unless ($logdir ne "");
die $usage unless ($exename ne "" || $aggregate);
if ($leaks_only) {
    $default_prefix = "~~Dr.H~~ ";
    # no summary in global log so we must add
    $report_leaks = 1;
}

$deprecated_supp_msg1 =
    "WARNING: Deprecated legacy limited Valgrind suppression format detected.\n";
$deprecated_supp_msg2 =
    "Use bin/valgrind2drmemory.pl to convert to more-powerful supported ".
    "Dr. Memory format.\n";

if ($callstack_style =~ /^0x(.*)/) {
    # GetOptions doesn't support hex so we parse a string
    $callstack_style = hex($1);
}

($module,$baselogdir,$suffix) = fileparse($logdir);

$outfile = "$logdir/results.txt";
$sumfile = "$logdir/results-summary.txt";
open(STDOUT, "> $outfile") || die "Can't redirect stdout to $outfile: $!";
open(SUMM_OUT, "> $sumfile") || die "Can't open $sumfile: $!";

if ($aggregate) {
    if (!$leaks_only) {
        if ($#ARGV == 0) {
            # this is likely to be -results so don't say "Aggregate"
            print "Dr. Memory results for @ARGV\n";
        } else {
            print "Dr. Memory aggregate results for @ARGV\n";
        }
    }
} else {
    # PR 426484: if app is killed, exit instead of spinning forever
    $pid = bsd_glob("$logdir/global.*.log"); # bsd_glob to not split on whitespace
    $pid =~ s|^.*/global.(\d+).log|$1|;
    print "Dr. Memory results for pid $pid, exe $exename, cmdline: \"$appid\"\n\n";
    if ($is_unix) {
        $is_vmk = (`uname -s` =~ /VMkernel/) ? 1 : 0;
        $ps_cmd = "ps -p $pid | grep $pid" if (!$is_vmk);
        $ps_cmd = "ps -C | grep $pid" if ($is_vmk);
        $newline = "\n";
    } else {
        $is_vmk = 0;
        $newline = "\r\n";
        eval "use Win32";
        if ($is_cygwin) {
            $ps_cmd = "ps -W -p $pid | grep $pid";
        } else {
            # tasklist is installed by default on xp+ but not on 2k, so
            # we ship with DRview
            $ps_cmd = "\"$dr_home/bin32/DRview.exe\" -pid $pid";
        }
    }
    $lastpass = 0;
    $global_done = 0;
}

print $prefix."Only showing errors matching $srcfilter\n" if ($srcfilter ne "");

print $prefix."Leaks are only listed if -check_leaks is on and app exited cleanly or a nudge was invoked.\n";

print "INFO: postprocess pid = $$\n" if ($verbose);

if ($use_default_suppress) {
    die "Error: cannot find $default_suppress_file\n"
        unless (-f $default_suppress_file);
    read_suppression_info($default_suppress_file, 1);
}

# Both <mod+offs> style and mod!func style callstacks are written to the same
# suppression file.
#
open(SUPP_OUT, "> $logdir/suppress.txt") ||
    die "Error creating $logdir/suppress.txt\n";
foreach $file (@supp_syms_file) {
    read_suppression_info($file, 0) if (-f $file);
}

$SIG{PIPE} = \&sigpipe_handler;
sub sigpipe_handler {
    # note that we try to catch SIGPIPE for writes below: this is our backup
    $SIG{INT} = \&sigpipe_handler;
    print "WARNING: received SIGPIPE when communicating with addr2line helpers\n";
}

init_libsearch_path($use_vmtree);
if ($aggregate) {
    my @dirs = @ARGV;
    if ($#dirs == 0 && $ARGV[0] !~ /DrMemory-/ && $ARGV[0] !~ /DrHeapstat-/) {
        # Workaround for shells/kernels with small limits on commandline
        # length: if a single dir is passed, aggregate all subdirs
        @dirs = bsd_glob("$ARGV[0]/DrMemory*");
    }

    foreach $dir (@dirs) {
        if (!$leaks_only) {
            if ($#dirs == 0) {
                # this is likely to be -results so don't say "Aggregating"
                print stderr "Producing results for $dir\n";
            } else {
                print stderr "Aggregating $dir\n";
            }
        }
        die "Aggregation error: $dir does not exist\n" unless (-e "$dir");
        # if passed in -x and only one dir we don't require results.txt.
        # note that we can't just turn off $aggregate when processing
        # a single dir b/c if we do we'll treat it as live and look for running
        # process, process fork.log, etc.
        if ($exename eq "" || $#dirs > 0) {
            die "Aggregation error: $dir not already processed individually\n"
                unless (-e "$dir/results.txt");
            $topline = `head -1 $dir/results.txt`;
            if ($topline =~ /for pid \d+, exe ([^,]+)/) {
                $exename = $1;
            } else {
                die "Cannot determine app path for $dir\n";
            }
        }

        # PR 536878: support Dr. Heapstat leak callstacks
        process_callstack_log("$dir/callstack.log") if (-e "$dir/callstack.log");

        @logfiles = bsd_glob("$dir/*.log"); # bsd_glob to not split on whitespace
        # We want leaks last so read thread.*.log before global.*.log
        @logfiles = reverse(sort(@logfiles));
        foreach $logfile (@logfiles) {
            next if ($logfile =~ /snapshot.log/ || $logfile =~ /callstack.log/);
            chomp $logfile;
            print stderr "  Processing $logfile\n" if ($verbose);
            process_all_errors($logfile);
        }
    }
} else {
    while (1) {
        # Do not pipe results to another command in the shell command, as that
        # makes it impossible for us to catch errors in ls and we then loop
        # forever.
        # For each iteration re-generate the file list to be safe from
        # missing logs for threads created in the last minute.
        #
        @logfiles = bsd_glob("$logdir/*.log"); # bsd_glob to not split on whitespace
        # We want leaks last so read thread.*.log before global.*.log
        @logfiles = reverse(sort(@logfiles));

        $done = 1;
        foreach $logfile (@logfiles) {
            chomp $logfile;
            $done = 0 if (process_all_errors($logfile) == 0);
        }

        if (%pending_forkexec) {
            check_new_logdirs();
        }

        # PR 453867: if waiting for children don't exit yet
        if (!%pending_fork && !%pending_forkexec) {
            last if ($lastpass);

            # If global log has LOG END and all logfiles have been processed, exit.
            last if ($done && $global_done);

            # PR 426484: if app is killed, exit instead of spinning forever.
            # But do one more pass to get any final logs.
            $lastpass = 1 if (`$ps_cmd` !~ /\b$pid\b/);
        } elsif (`$ps_cmd` !~ /\b$pid\b/) {
            # it's possible for app and children to be killed before children's
            # logdirs are created so make sure we don't wait forever
            last if ($iters++ > 40);
        }

        sleep 1 if (!$done);    # don't spin and consume cycles waiting for logs
    }
}

print "\n===========================================================================\nFINAL SUMMARY:\n";
print_final_summary();
close(SUMM_OUT);

close(SUPP_OUT);

if (!$is_unix && !$is_cygwin && !$batch) {
    # If running via Explorer or cmd, pop up notice pointing to results.
    # No easy way to tell whether in cmd window (SHELL env var not set for
    # some reason) but cmd not output-friendly anyway so we pop up
    # a window for cmd.
    if (!$quiet) {
        my $msg = "Results are in $outfile";
        system("notepad", "$outfile") &&
            Win32::MsgBox($msg, 0, "Dr. Memory");
    }
}

foreach $apipe (keys %addr_pipes) {        # reap all the addr2line processes
    # Append addr2line stderr.  While it might be nice printed
    # at the point of the error, I'm afraid it won't always have 2 lines
    # and so would mess up our bidirectional pipe, and it can look
    # ugly to have multi-line errors where a symbol should go in the
    # callstack, so I'm appending them all at the end.  Xref i#235.
    my $error = $addr_pipes{$apipe}{"error"};
    my $sel = IO::Select->new();
    $sel->add($error);
    while (my @ready = $sel->can_read(0.1)) {
        foreach my $handle (@ready) {
            my ($count, $data, $per_read);
            $per_read = 4096;
            $count = sysread($handle, $data, $per_read);
            if (defined($count) && $count > 0) {
                print "WARNING: error(s) processing symbols for $apipe: $data";
            } else {
                $sel->remove($handle);
            }
        }
    }

    if ($apipe eq $winsyms_key) {
        # winsyms.exe's fgets doesn't see an eof from our close so send
        # a special exit code
        my $write = $addr_pipes{$apipe}{"write"};
        print $write ";exit\n";
    }
    close $addr_pipes{$apipe}{"read"};
    close $addr_pipes{$apipe}{"write"};
    close $addr_pipes{$apipe}{"error"};
    # on windows closing our end doesn't send eof to addr2line
    # and perl's kill command doesn't seem to do the job
    kill 9, $addr_pipes{$apipe}{"pid"} if (!$is_unix && $apipe ne $winsyms_key);
    waitpid($addr_pipes{$apipe}{"pid"}, 0);
    print stderr "pid ".$addr_pipes{$apipe}{"pid"}." successfully waited on\n"
        if ($verbose);
}

exit 0;

#-------------------------------------------------------------------------------
# Parse errors from the logfile passed as argument.  Returns 0 if file ends
# before log ends; 1 if log has been completely processed.  If file ends
# before end of an error log, the position of the start of the last incomplete
# error is saved to be tried again later.  When end of log is reached, marks
# processing on logfile as done.
#
sub process_all_errors()
{
    my $logfile = shift(@_);
    my @lines = ();
    my $found_error_start = 0;
    my $found_duplicate_start = 0;
    my $found_suppressions_used = 0;
    my $found_summary_start = 0;
    my $found_ignored_start = 0;

    if (defined $logs{$logfile}) {
        # PR 453867: child may write to fork logfile after LOG END
        return 1 if ($logs{$logfile}{"done"} == 1 && !%pending_fork);
    } else {
        $logs{$logfile}{"done"} = 0;
        $logs{$logfile}{"bytes read"} = 0;
    }

    # If a log file can't be opened for read, it is highly unlikely it can be
    # done so again after a sleep, so just complain and mark the file as
    # processed.
    #
    if (!open($fh, $logfile)) {
        print "Error: couldn't open $logfile: $!\n";
        $logs{$logfile}{"done"} = 1;
        return 1;
    }

    # Perl doesn't always read successfully once eof has been reached, even if
    # that file was updated by another process later.  So saving position past
    # the last error log and closing file so that subsequent attempts can
    # reopen, seek past the last error log and continue reading.
    #
    seek($fh, $logs{$logfile}{"bytes read"}, 0) || die "seek on $logfile failed: $!\n";
    while (<$fh>) {
        # PR 453867: fork a new copy of this script
        if (!$aggregate && (/^FORK/ || /^EXEC/)) {
            if (/^FORK\s+child=(\d+)\s+logdir=(.*)/) {
                my $childpid = $1;
                delete $pending_fork{$childpid};
                # in case child's write comes first
                $handled_fork{$childpid} = 1;
                my $childdir = $2;
                my @cmd = @myargs;
                for ($i=0; $i<=$#cmd; $i++) {
                    $cmd[$i] =~ s|$logdir|$childdir|;
                }
                # FIXME PR 456501: handle Windows perl2exe
                @cmd = ("$^X", "$0", @cmd);
                print stderr $default_prefix."Forked child $childdir\n" if ($verbose);
                unless (fork()) {
                    exec(@cmd); # array to handle spaces in args
                    die "ERROR running $cmd\n";
                }
            } elsif (/^FORK\s+child=(\d+)$/) {
                # We should see a FORK msg w/ logdir once child starts up
                $pending_fork{$1} = 1 if (!$handled_fork{$1});
            } elsif (/^FORKEXEC\s+child=(\d+)\s+path=(.*)/) {
                # We need to watch for a logdir ourselves
                $pending_forkexec{$1}{"path"} = $2;
                $pending_forkexec{$1}{"is_exec"} = 0;
            } elsif (/^EXEC\s+path=(.*)/) {
                # We need to watch for a logdir ourselves
                $pending_forkexec{$pid}{"path"} = $1;
                $pending_forkexec{$pid}{"is_exec"} = 1;
            }
            $logs{$logfile}{"bytes read"} = tell $fh;   # tell shouldn't fail
            die "tell on $fh failed: $!\n" if ($logs{$logfile}{"bytes read"} == -1);
            next;
        }
        # PR 474554: mid-run summary/output on nudge (esp for daemon apps)
        elsif (!$aggregate && /^NUDGE/) {
            print "\n===========================================================================\nSUMMARY AFTER NUDGE #$nudge_count:\n";
            print_final_summary();
            $nudge_count++;
            $logs{$logfile}{"bytes read"} = tell $fh;   # tell shouldn't fail
            die "tell on $fh failed: $!\n" if ($logs{$logfile}{"bytes read"} == -1);
            next;
        }
        elsif (/^DISABLING MEMORY CHECKING/) {
            # PR 574018: Dr. Memory instrumentation disabled
            print "\n\n****************\nMEMORY CHECKS DISABLED FROM THIS POINT ON\n\n";
            $drmem_disabled = 1;
            $logs{$logfile}{"bytes read"} = tell $fh;   # tell shouldn't fail
            next;
        }
        elsif (/^Dr. Memory version/ || /ASSERT FAILURE/ || /FATAL ERROR/) {
           # propagate version string or errors into results file
           print "$_\n"; # extra \n is deliberate
            $logs{$logfile}{"bytes read"} = tell $fh;   # tell shouldn't fail
           next;
        }
        # PR 425858: skip non-error-related lines in logfile
        if (!$found_error_start && is_line_start_of_error($_)) {
            $found_error_start = 1;
            # summary might be missing
            # XXX: should DR give us an exit event on app crash?
            # b/c we'll not report error types we didn't see examples of
            # currently.
            $report_unaddr = 1 if (/UNADDR/);
            $report_uninit = 1 if (/UNINIT/);
            $report_leaks = 1 if (/LEAK/);
        }
        if ($found_error_start) {
            if (/^\s*callstack=(\d+)/) {
                foreach $l (split('\n', $cstack[$1])) {
                    push @lines, $l;
                }
            } else {
                push @lines, $_;
            }
            if (/\s+error end\r?$/) {
                process_one_error(\@lines);
                @lines = ();
                $found_error_start = 0;
                $logs{$logfile}{"bytes read"} = tell $fh;   # tell shouldn't fail
                die "tell on $fh failed: $!\n" if ($logs{$logfile}{"bytes read"} == -1);
            }
        }
        if (/^DUPLICATE ERROR COUNTS:/) {
            $found_duplicate_start = 1;
        } elsif ($found_duplicate_start) {
            if (/^\s*Error #\s*(\d+):\s*(\d+)/) {
                my $name = $client_errnum_to_name[$1];
                # subtract 1 b/c we've already added one instance
                my $dup_count = ($2 - 1);
                # subtract dups we've already accounted for, to avoid
                # accumulating when this data is printed multiple times on nudges
                $dup_count -= $error_cache{$name}{"dup_count_seen"};
                $error_cache{$name}{"dup_count_seen"} = $dup_count;
                if ($error_cache{$name}{"suppressed"}) {
                    my $is_default = $error_cache{$name}{"supp_is_default"};
                    # if we suppressed then DR's dup count should be added to
                    # suppression count not error count
                    if ($error_cache{$name}{"type"} =~ /LEAK/) {
                        if ($is_default) {
                            $post_suppressed_leaks_default += $dup_count;
                        } else {
                            $post_suppressed_leaks_user += $dup_count;
                        }
                    } else {
                        if ($is_default) {
                            $post_suppressed_errors_default += $dup_count;
                        } else {
                            $post_suppressed_errors_user += $dup_count;
                        }
                    }
                } else {
                    $error_cache{$name}{"dup_count_client"} += $dup_count;
                    $error_summary{$error_cache{$name}{"type"}}{"extra_client"} +=
                        $dup_count;
                    if ($error_cache{$name}{"type"} =~ /LEAK/) {
                        $error_summary{$error{"type"}}{"bytes"} +=
                            $error_cache{$name}{"numbytes"} * $dup_count;
                    }
                }
            } else {
                $found_duplicate_start = 0;
            }
        }

        if (/^SUPPRESSIONS USED:/) {
            $found_suppressions_used = 1;
        } elsif ($found_suppressions_used) {
            if (/^\s*(\d+)x:\s+\(leaked\s+(\d+)\s+bytes\):\s+(.*)$/) {
                $supp_used_count{$3} = $1;
                $supp_bytes_leaked{$3} = $2;
            } elsif (/^\s*(\d+)x:\s+(.*)$/) {
                $supp_used_count{$2} = $1;
            } else {
                $found_suppressions_used = 0;
            }
        }

        # PR 477013: provide proper summary: we need to extract info from
        # the client on what it ignored
        if (/^ERRORS FOUND:/ || /^NO ERRORS FOUND:/) {
            $found_summary_start = 1;
            $client_leak_summary = ""; # reset so we don't accumulate
        } elsif ($found_summary_start) {
            # don't summarize categories that were disabled
            $report_unaddr = 1 if (/total unaddr/);
            $report_uninit = 1 if (/total uninit/);
            $report_invalid = 1 if (/total invalid/);
            $report_leaks = 1 if (/of leak/);
            # If leaks are not separate errors we need to echo the client summary
            if (/^\s*(\d+) total.*leak/ || /^\s*\(re-run/) {
                $client_leak_summary .= $_;
                $no_leak_info = 1 if (/of leak/);
                $no_possible_leak_info = 1 if (/of possible leak/);
            } elsif (/of possible leak/) {
                # With -check_leaks but not -possible_leaks we do have
                # unique+total for possible but not separate errors
                my $tmp = $_;
                $_ = <$fh>; # ok since ERRORS IGNORED match is below
                if (/re-run.*possible_leak/) {
                    $client_leak_summary .= $tmp . $_;
                    $no_possible_leak_info = 1;
                }
            }
        }
        if (/^ERRORS IGNORED:/) {
            $found_summary_start = 0;
            $found_ignored_start = 1;
            $client_ignored = ""; # reset so we don't accumulate
        } elsif ($found_ignored_start) {
            if (/assumed-innocuous/) {
                # i#345: only show in logfile
            } elsif (/^\s*(\d+) (.+)$/) {
                if (/(\d+) user-suppressed, *(\d+) default-suppressed error/) {
                    $client_suppressed_errors_default = $2;
                    $client_suppressed_errors_user = $1;
                } elsif (/(\d+) user-suppressed, *(\d+) default-suppressed leak/) {
                    $client_suppressed_leaks_default = $2;
                    $client_suppressed_leaks_user = $1;
                } else {
                    $client_ignored .= $_;
                }
            } elsif (/^\S/) {
                $found_ignored_start = 0;
            } else {
                $client_ignored .= $_;
            }
        }
        if (/^LOG END/) {
            $logs{$logfile}{"done"} = 1;
            $global_done = 1 if ($logfile =~ /global.\d+.log$/);
            last;
        }
    }

    close $fh;
    return $logs{$logfile}{"done"};
}

#-------------------------------------------------------------------------------
# Parses the error in the input array, resolves symbols, does suppress checks
# and finally prints it.  Also records similarity info.
#
sub process_one_error($raw_error_lines_array_ref)
{
    my ($lines) = @_;
    my $first_line = ${$lines}[0];

    # Is the callstack identical to a previously seen one?  PR 420942.
    # Ignore the read/write info in the first line of an error - they change;
    # in fact, they are the reason that duplicates can't be identified by a
    # direct string comparison.  Also ignore the timestamp and thread id.
    $first_line =~ s/(reading|writing).*$//;
    my $err_str = $first_line.join("", @{$lines}[2..$#{$lines}]);

    if (!defined $error_cache{$err_str}{"dup_count"}) {     # not a duplicate
        # cache the error to catch dups.
        $error_cache{$err_str}{"dup_count"} = 0;
        $errnum++;
        my $supp = parse_error($lines, $err_str);
        $error_cache{$err_str}{"type"} = $error{"type"};
        $errnum-- if ($error{"type"} =~ /REACHABLE LEAK/);
        $error_cache{$err_str}{"numbytes"} = $error{"numbytes"};
        # first frame is a retaddr for invalid heap arg when wrapping malloc
        my $first_retaddr = ($error{"type"} =~ /INVALID HEAP/) && !$replace_malloc;
        my @symlines = lookup_addr(\%error, $first_retaddr);
        my ($err_str_ref, $err_cstack_ref) = generate_error_info(\%error, \@symlines);
        my $is_default;

        # If the error passes the source filter and doesn't match
        # call stack suppression specified then print it.
        if (($srcfilter eq "" || ${$err_str_ref} =~ /$srcfilter/) &&
            !suppress($error{"type"}, $err_cstack_ref, \$is_default, $supp,
                      $error{"numbytes"})) {
            print ${$err_str_ref};

            # If the first line excluding the read/write info was the same even
            # though the callstack was different, then there is a chance it is
            # the same memory error: but for errors that show up in common
            # functions like strcmp it may not be, so just record a hint.
            $similar_errors{$first_line} .= " $errnum";
            $error_cache{$err_str}{"errno"} = $errnum;
            $error_cache{$err_str}{"suppressed"} = 0;
            # PR 477013: keep counts per type
            $error_summary{$error{"type"}}{"unique"}++;
            $error_summary{$error{"type"}}{"total"}++;
            if ($error{"type"} =~ /LEAK/) {
                $error_summary{$error{"type"}}{"bytes"} += $error{"numbytes"};
            }
        } else {
            # If doesn't pass the source filter we count toward suppression stats
            # since not worth having separate set of counts.
            if ($error{"type"} =~ /LEAK/) {
                if ($is_default) {
                    $post_suppressed_leaks_default++;
                } else {
                    $post_suppressed_leaks_user++;
                }
            } else {
                if ($is_default) {
                    $post_suppressed_errors_default++;
                } else {
                    $post_suppressed_errors_user++;
                }
            }
            # If the error was suppressed then reclaim the error number,
            # otherwise error numbers won't be sequential in results.txt.
            $errnum--;
            $error_cache{$err_str}{"errno"} = 0;
            $error_cache{$err_str}{"suppressed"} = 1;
            $error_cache{$err_str}{"supp_is_default"} = $is_default;
        }
    } elsif ($first_line !~ /LEAK/) {
        # For leaks we do NOT increase dup or suppress counts b/c we assume dups
        # will only exist due to multiple nudges b/c the client will suppress
        # exact matches within one nudge and give us a dup count there.
        $error_cache{$err_str}{"dup_count"}++;
        if ($error_cache{$err_str}{"suppressed"}) {
            if ($error_cache{$err_str}{"type"} =~ /LEAK/) {
                if ($error_cache{$err_str}{"supp_is_default"}) {
                    $post_suppressed_leaks_default++;
                } else {
                    $post_suppressed_leaks_user++;
                }
            } else {
                if ($error_cache{$err_str}{"supp_is_default"}) {
                    $post_suppressed_errors_default++;
                } else {
                    $post_suppressed_errors_user++;
                }
            }
        } else {
            $error_summary{$error_cache{$err_str}{"type"}}{"total"}++;
        }
    }

    # PR 477344.  Print out error summary periodically.  After the
    # first 100, print out every 10 because the likelyhood of large
    # number of errors is high and because disk IO on ESXi can be slow.
    # We use a separate count that includes dups and suppressed to avoid
    # a very-stale summary of counts (xref PR 484191).
    $errors_processed++;
    print_summary(\*SUMM_OUT, 1, 0, $verbose)
        if ($errors_processed < 100 || $errors_processed % 10 == 0);
}

#-------------------------------------------------------------------------------
# PR 453867: watch for children created via forkexec/createprocess
#
sub check_new_logdirs()
{
  reiter:
    foreach my $child (keys %pending_forkexec) {
        # Could have any app name or instance count.  We could use
        # the path recorded at forkexec time but on vmkernel
        # "cmdline" will be used due to missing features.
        my @dirs = bsd_glob("$baselogdir/DrMemory-*.$child.*");
        foreach my $dir (@dirs) {
            # Skip if clearly already has script processing it
            next if (-e "$dir/results.txt");
            my $head = "";
            if (open(HEAD, "< $dir/global.$child.log")) {
                $head = <HEAD>;
                close(HEAD);
            }
            if ($head =~ /^process=$child, parent=$pid/ ||
                # for exec we just take 1st dir w/o .errors file. could
                # get wrong one if multiple rapid execs.  long-term
                # client should handle symbols and avoid all these
                # problems shadowing the app.
                $child eq $pid ||
                # on Windows we have no parent info so just take 1st dir
                $head =~ /^Dr\. Memory/) {
                # I'm assuming param for -c and -e have path after -e (addr2line,
                # or our own -e) or -a (addr2line.pl).
                # Not handling spaces in app right now.
                my $newapp = $pending_forkexec{$child}{"path"};
                my @cmd = @myargs;
                for ($i=0; $i<=$#cmd; $i++) {
                    $cmd[$i] =~ s|$logdir|$dir|;
                    if ($i > 0 && $cmd[$i-1] =~ /^\s*-x\s*/) {
                        $cmd[$i] =~ s|\S+|$newapp|g;
                    }
                }
                # FIXME PR 456501: handle Windows perl2exe
                @cmd = ("$^X", "$0", @cmd);
                if ($verbose) {
                    if ($pending_forkexec{$child}{"is_exec"}) {
                        print stderr $default_prefix."Exec child $dir\n";
                    } else {
                        print stderr $default_prefix."Fork+Exec child $dir\n";
                    }
                }
                unless (fork()) {
                    exec(@cmd); # array to handle spaces in args
                    die "ERROR running $cmd\n";
                }
                if ($pending_forkexec{$child}{"is_exec"}) {
                    # The forked script will handle this process in its new life.
                    # It will keep $pid so we won't know when to exit.
                    # Hard to avoid races w/ other threads vs the exec syscall
                    # going through but unlikely to have issues so we live w/ it.
                    $lastpass = 1;
                }
                delete $pending_forkexec{$child};
                # don't trust removing from hash in middle of iter
                goto reiter;
            }
        }
    }
}

#-------------------------------------------------------------------------------
# Parse the logs associated with one error report and set up the %error hash
# with details.  Also write <mod+offs> style suppresion data.  For example,
#
# UNADDRESSABLE ACCESS
# <test4-leak+0x510>
# <libc.so.6+0x510>
# <not in a module>
#
# Note: no leading white spaces.
#
sub parse_error($arr_ref, $err_str)
{
    my ($lines, $err_str) = @_;
    my $supp = "";
    $error{"aux_info"} = "";
    my $process_free_cstack = 0;
    foreach $line (@{$lines}) {
        # We ignore the error # since symbol-based suppressions can
        # eliminate errors from the middle, except for including
        # duplicate error counts.
        # We must include all the text after the error type to match
        # the client's output for online syms (xref PR 540913)
        if ($line =~ /^Error #\s*(\d+)+: (UN\w+\s+\w+)(:.*)$/ ||
            $line =~ /^Error #\s*(\d+)+: (INVALID HEAP ARGUMENT)(.*)$/ ||
            $line =~ /^Error #\s*(\d+)+: (REPORTED WARNING:.*)$/ ||
            $line =~ /^Error #\s*(\d+)+: (POSSIBLE LEAK)(\s+\d+.*)$/ ||
            $line =~ /^Error #\s*(\d+)+: (REACHABLE LEAK)(\s+\d+.*)$/ ||
            $line =~ /^Error #\s*(\d+)+: (LEAK)(\s+\d+.*)$/) {
            $client_errnum_to_name[$1] = $err_str;
            $error{"name"} = $2;
            $error{"type"} = $2;
            $error{"details"} = $3;
            $error{"addr"} = [];
            $error{"modoffs"} = [];
            $error{"is_module"} = [];
            $free{"addr"} = [];
            $free{"modoffs"} = [];
            $free{"is_module"} = [];
            $supp .= "$2\n";
            if ($line =~ /^Error #\s*\d+: UN\w+\s+\w+:/ ||
                $line =~ /^Error #\s*\d+: INVALID HEAP ARGUMENT/ ||
                $line =~ /^Error #\s*\d+: REPORTED WARNING:/) {
                if ($line =~ /^Error #\s*\d+: REPORTED WARNING:\s+(.*)$/) {
                    # strip the REPORTED from the msg
                    $error{"name"} = "WARNING: $1";
                    $error{"type"} = "WARNING";
                }
            } elsif ($line =~ /^Error #\s*\d+: LEAK/ ||
                     $line =~ /^Error #\s*\d+: POSSIBLE LEAK/) {
                if ($error{"details"} =~ /\s(\d+) direct.*\s(\d+) indirect/) {
                    $error{"numbytes"} = $1 + $2;
                } elsif ($error{"details"} =~ /\s(\d+) bytes/) {
                    $error{"numbytes"} = $1 + $2;
                } else {
                    die "Error: unknown leak detail text ".$error{"details"}."\n";
                }
            } elsif ($line =~ /^Error #\s*(\d+)+: (REACHABLE LEAK)(\s+\d+.*)$/) {
                # nothing special to do: no first-class support for reachable
                # leaks like we do w/ online syms.
            } else {
                die "Unrecognized error type: \"$line\"";
            }
        } elsif ($line =~ /^  info: @(\S+) in thread (\d+)/) {
            $error{"time"} = $1;
            $error{"thread"} = $2;
        } elsif ($line =~ /^  info: (.*)$/) {
            # additional info (PR 535568)
            my $info = $1;
            # a callstack for freed memory (i#205)
            if ($info =~ /^#\s*\d+\s+\S+!\?\s*\((\w+)\s+(<[^>]+>)\)/) {
                if ($1 ne "0x00000000") {
                    $process_free_cstack = 1;
                    push @{$free{"addr"}}, $1;
                    push @{$free{"modoffs"}}, $2;
                    push @{$free{"is_module"}}, 1;
                }
            } else {
                if ($process_free_cstack) {
                    # top frame is retaddr for free/malloc when wrapping malloc
                    my @symlines = lookup_addr(\%free, !$replace_malloc);
                    my ($err_str_ref, $err_cstack_ref) =
                        generate_callstack(\%free, \@symlines);
                    my $aux_cstack = ${$err_str_ref};
                    $aux_cstack =~ s/^/Note: /msg;
                    $error{"aux_info"} .= $aux_cstack;
                    $process_free_cstack = 0;
                }
                $error{"aux_info"} .= "Note: $info\n";
            }
        } elsif ($line =~ /^#\s*\d+\s+(system\s+call\s+.+)$/) {
            my $txt = $1;
            $txt =~ s/\s+$//; # remove trailing whitespace including \r
            push @{$error{"addr"}}, $txt;
            push @{$error{"modoffs"}}, "";
            push @{$error{"is_module"}}, 0;
            $supp .= "$txt\n";
        } elsif ($line =~ /^#\s*\d+\s+(<not in a module>)\s*\((\w+)\)/) {
            push @{$error{"addr"}}, $2;
            push @{$error{"modoffs"}}, $1;
            push @{$error{"is_module"}}, 0;
            $supp .= "$1\n";
        } elsif ($line =~ /^#\s*\d+\s+\S+!\?\s*\((\w+)\s+(<[^>]+>)\)/ ||
                 # Handle Dr. Heapstat w/ symbolized callstacks: for now
                 # we re-symbolize here for leaks, until we have i#926
                 # and this whole script goes away.
                 $line =~ /^#\s*\d+\s+\S+!.*\s*\((\w+)\s+(<[^>]+>)\)/) {
            if ($1 ne "0x00000000") {
                push @{$error{"addr"}}, $1;
                push @{$error{"modoffs"}}, $2;
                push @{$error{"is_module"}}, 1;
            }
            # PR 464809: must include 0 address to match generated callstack
            $supp .= "$2\n";
        }
    }
    if ($process_free_cstack) {
        # top frame is retaddr for free/malloc when wrapping malloc
        my @symlines = lookup_addr(\%free, !$replace_malloc);
        my ($err_str_ref, $err_cstack_ref) =
            generate_callstack(\%free, \@symlines);
        my $aux_cstack = ${$err_str_ref};
        $aux_cstack =~ s/^/Note: /msg;
        $error{"aux_info"} .= $aux_cstack;
        $process_free_cstack = 0;
    }
    $supp =~ s/REPORTED WARNING/WARNING/;
    return $supp;
}

#-------------------------------------------------------------------------------
# Looks up the addresses associated with one error
#
sub lookup_addr($error_ref, $first_retaddr)
{
    my ($error, $first_retaddr) = @_;
    my $module = "";
    my $off = 0;
    @symlines = ();
    my $num_frames = scalar @{${$error}{"addr"}};
    for ($a=0; $a<$num_frames; $a++) {
        my $modoffs = ${$error}{"modoffs"}[$a];
        my $symout = '';
        # PR 543863: subtract one from retaddrs in callstacks so the line#
        # is for the call and not for the next source code line, but only
        # for symbol lookup so we still display a valid instr addr.
        # We assume first frame is not a retaddr, unless invalid heap arg.
        my $addr_sym_disp = ($a == 0 && !$first_retaddr) ? 0 : -1;

        # Lookup symbol and file name cache.  PR 420921.
        if (defined $symfile_cache{$modoffs}) {
            push @symlines, $symfile_cache{$modoffs}{"symbol"};
            push @symlines, $symfile_cache{$modoffs}{"file"};
            next;
        }

        # To use offset with addr2line needs to be relative to section.
        if (${$error}{"modoffs"}[$a] =~ /<(.*)\+0x([a-f0-9]+)>/) {
            $module = $1;
            $offs = hex($2);
        } elsif (${$error}{"addr"}[$a] =~ /^system\s+call/) {
            push @symlines, ${$error}{"addr"}[$a];
            push @symlines, "<system call>";
            next;
        } else {
            if ($modoffs eq '<not in a module>') {
                push @symlines, $modoffs;
            } else {
                print "Invalid modoffs $modoffs\n";
                push @symlines, "<unknown symbol>";
            }
            push @symlines, "??:0";
            next;
        }

        # FIXME: we don't have executable on ESXi (PR 363063)
        if ($module eq "") {
            $module = fileparse($exename);
        }

        # FIXME: we don't have full paths to these modules
        # That's i#138 for DR and PR 401580 for ESXi
        if ($exename =~ /\Q$module\E/) {     # \Q...\E for PR 420898.
            if (mod_has_dbg_info($exename, @dbg_sec_types)) {
                $modpath{$module} = $exename;
                $has_dbg_info{$module} = 1;
            } else {
                get_mod_path($module, \%modpath);
            }
        } else {
            get_mod_path($module, \%modpath);
        }
        # Don't look at base if looking inside a .debug file;
        # addr2line doesn't work in that case.
        #
        # FIXME PR 460710: we need to do the same module base
        # adjustment for these debuglink modules as well, so need
        # the module search to return the path to the lib itself!
        if ($modpath{$module} =~ /debug$/) {
            $offs_str = sprintf("0x%x", $offs + $addr_sym_disp);
            $symout = lookup_symbol($modpath{$module}, $offs_str);
        } elsif ($modpath{$module} ne '') {
            # If the module has a non-0 default base we must add that base to
            # our offset from the module start.
            # An alternative is to find the section and use -j and an offset
            # from the section start, but older addr2line versions do not
            # support -j.
            # If we're not using addr2line we're using winsyms and want just the offset.
            if (&use_addr2line($modpath{$module}) && !defined($base{$module})) {
                open(SECLIST, "objdump -p \"$modpath{$module}\" |") ||
                    print "ERROR running objdump -p \"$modpath{$module}\"\n";
                while (<SECLIST>) {
                    if ($is_unix) {
                        next unless (/^\s+LOAD\s+off\s+\S+\s+vaddr\s+0x(\S+)\s+/);
                        $base{$module} = hex($1);
                    } else {
                        next unless (/^ImageBase\s+(\S+)/);
                        $base{$module} = hex($1);
                    }
                    last;
                }
                close(SECLIST);
            }

            $absaddr = sprintf("0x%x", $offs + $base{$module} + $addr_sym_disp);
            $symout = lookup_symbol($modpath{$module}, $absaddr);
        }

        $symout = "?\n??:0" if ($symout eq '');
        my $symprefix = "$module!";
        # PR 456175: indicate whether have symbols
        $symprefix = "$module<nosyms>!" if (!$has_dbg_info{$module});
        $symout = $symprefix . $symout;

        $symout =~ s/\r//g if (!$is_unix);
        ($symfile_cache{$modoffs}{"symbol"},
         $symfile_cache{$modoffs}{"file"}) = split('\n', $symout);

        push @symlines, $symfile_cache{$modoffs}{"symbol"};
        push @symlines, $symfile_cache{$modoffs}{"file"};
    }
    return @symlines;
}

#-------------------------------------------------------------------------------
# Compute error string and error callstack and return them as a string and an
# array references (both can be large, so no point in copying these around for
# hundreds of callstacks - references are efficient).
#
sub generate_error_info($error_ref, $symlines_ref)
{
    my ($error, $symlines) = @_;
    my $err_str = "";

    $err_str = "$prefix\n";
    # numbytes and aux_info are currently only for the 1st unique (PR 423750
    # covers providing such info for dups)
    $err_str .= $prefix;
    if (${$error}{"name"} !~ /REACHABLE LEAK/) {
        $err_str .= "Error \#$errnum: ";
    }
    $err_str .= ${$error}{"name"}.${$error}{"details"}."\n";

    my ($err_str_ref, $err_cstack_ref) = generate_callstack($error, $symlines);
    $err_str .= ${$err_str_ref};

    # When aggregating we'll just take the first timestamp + thread id
    $err_str .= $prefix."Note: elapsed time = ".${$error}{"time"}.
        " in thread ".${$error}{"thread"}."\n" if (defined(${$error}{"time"}));
    $err_str .= ${$error}{"aux_info"};

    return \$err_str, $err_cstack_ref;
}

sub generate_callstack($error_ref, $symlines_ref)
{
    my ($error, $symlines) = @_;
    my $err_str = "";
    my @err_cstack = ();

    # callstack style options.  this is duplicated from callstack.h.
    my $PRINT_FRAME_NUMBERS        = 0x0001;
    my $PRINT_ABS_ADDRESS          = 0x0002;
    my $PRINT_MODULE_OFFSETS       = 0x0004;
    my $PRINT_SYMBOL_OFFSETS       = 0x0008; # not supported since addrline doesn't have
    my $PRINT_LINE_OFFSETS         = 0x0010; # not supported since addrline doesn't have
    my $PRINT_SRCFILE_NEWLINE      = 0x0020;
    my $PRINT_SRCFILE_NO_COLON     = 0x0040;
    my $PRINT_SYMBOL_FIRST         = 0x0080;
    my $PRINT_ALIGN_COLUMNS        = 0x0100;
    my $PRINT_NOSYMS_OFFSETS       = 0x0200; # not implemented

    my $align_sym = 0;
    my $align_mod = 0;
    if ($callstack_style & $PRINT_ALIGN_COLUMNS) {
        $align_sym = 35;
        $align_mod = 15;
        # unlike drmem client we have module integrated
        $align_modsym = 47;
    }

    my $num_frames = scalar @{${$error}{"addr"}};
    if ($num_frames == 0) {
        $err_str .= $prefix."<no callstack available>\n";
    } else {
        for ($a=0; $a<$num_frames; $a++) {
            $err_str .= $prefix;
            if ($callstack_style & $PRINT_FRAME_NUMBERS) {
                $err_str .= sprintf("#%2d ", $a);
            }
            my $modfunc = "${$symlines}[$a*2]";
            my $fileline = ${$symlines}[$a*2+1];
            if (!${$error}{"is_module"}[$a]) {
                my $label = (${$error}{"addr"}[$a] =~ /^system\s+call/) ?
                    ${$error}{"addr"}[$a] : "<not in a module>";
                $err_str .= sprintf("%-*s", $align_modsym, $label);
                # $fileline already either "<system call>" or "?:0"
            } else {
                if ($callstack_style & $PRINT_SYMBOL_FIRST) {
                    my @mod_or_func = split('!', $modfunc);
                    $err_str .= sprintf("%-*s %-*s", $align_sym, $mod_or_func[1],
                                        $align_mod, $mod_or_func[0]);
                } else {
                    $err_str .= sprintf("%-*s", $align_modsym, $modfunc);
                }
                if ($callstack_style & $PRINT_SRCFILE_NO_COLON) {
                    $fileline =~ s/:/ @ /;
                }
                if (!($callstack_style & $PRINT_SRCFILE_NEWLINE)) {
                    if (${$symlines}[$a*2+1] ne '??:0') {
                        $err_str .= " ["."$fileline"."]";
                    }
                }
            }
            if ((${$error}{"addr"}[$a] !~ /^system\s+call/ &&
                 ($callstack_style & $PRINT_ABS_ADDRESS)) ||
                (${$error}{"is_module"}[$a] &&
                 ($callstack_style & $PRINT_MODULE_OFFSETS))) {
                $err_str .= " (";
                if (${$error}{"addr"}[$a] !~ /^system\s+call/ &&
                    ($callstack_style & $PRINT_ABS_ADDRESS)) {
                    $err_str .= ${$error}{"addr"}[$a];
                    if (${$error}{"is_module"}[$a] &&
                        ($callstack_style & $PRINT_MODULE_OFFSETS)) {
                        $err_str .= " ";
                    }
                }
                if (${$error}{"is_module"}[$a] &&
                    ($callstack_style & $PRINT_MODULE_OFFSETS)) {
                    $err_str .= ${$error}{"modoffs"}[$a];
                }
                $err_str .= ")";
            }
            if (${$error}{"addr"}[$a] =~ /^system\s+call/) {
                push @err_cstack, ${$error}{"addr"}[$a];
            } else {
                $modoffs = ${$error}{"modoffs"}[$a];
                $modoffs =~ s/<(.*)>/$1/;
                $func = ${$symlines}[$a*2];
                # for vmk mod+offs may not have mod but mod!func will (PR 363063)
                if ($modoffs =~ /^\+/ && $func =~ /^(.+)!/) {
                    $modoffs = $1.$modoffs;
                }
                $func =~ s/.*!(.*)\+0x\w+$/$1/;
                # linux doesn't have the trailing offs
                $func =~ s/.*!(.*)$/$1/;

                # turn modoffs and function name into
                # "mod+off!func" form to simplify suppression matching.
                $mod_off_func = "$modoffs!$func";
                push @err_cstack, $mod_off_func;
            }
            if ($callstack_style & $PRINT_SRCFILE_NEWLINE) {
                $err_str .= "\n" . $prefix . "    $fileline";
            }
            $err_str .= "\n";
        }
    }
    return \$err_str, \@err_cstack;
}

#-------------------------------------------------------------------------------
# Print summary either at end of run or at mid-run nudge
#
sub print_final_summary()
{
    # Print summary into results-summary.txt file at the end as summary may not
    # have been written to it when each error was reported due to throttling.  Both
    # summaries have to be consistent at the end, if possible.
    print_summary(\*SUMM_OUT, 1, 0, $verbose);   # to results-summary.txt
    print_summary(\*STDOUT, 0, 0, $verbose);     # to results.txt
    if (!$quiet) {
        # to stderr for user
        print_summary(\*STDERR, 0, 1, $verbose);
        print stderr $default_prefix."Details: $outfile\n";
    }
}

#-------------------------------------------------------------------------------
sub sort_supp_used($a, $b)
{
    # sort by count, but want leaks together
    if ($supp_bytes_leaked{$a} < $supp_bytes_leaked{$b}) {
        return -1;
    } elsif ($supp_bytes_leaked{$a} > $supp_bytes_leaked{$b}) {
        return 1;
    } else {
        return $supp_used_count{$a} <=> $supp_used_count{$b};
    }
}

#-------------------------------------------------------------------------------
# Print summary about errors, i.e., how many duplicates were there, which
# errors can be potentially related, etc.  Part of PR 420942. If $reset_in is
# set, then the output file handle ($where_in) will be reset to print summary
# at the start of the file.  If not, the summary will be appended.
# Note: For we want to dump summary at the end for results.txt and at the
# begining for results-summary.txt (i.e., overwrite old summary).
#
sub print_summary($fh, $reset, $summary_only, $print_default_supp)
{
    my ($fh, $reset, $summary_only, $print_default_supp) = @_;
    my $num_groups;
    my $err_str;
    my %duplicate_errors = ();
    my $pfx = ($fh == \*STDERR) ? $default_prefix : $prefix;

    seek $fh, 0, SEEK_SET if ($reset);      # Append summary or overwrite?

    if (!$summary_only) {
        print $fh "$pfx\n";
        print $fh $pfx."Grouping errors that may be the same or related:\n\n";

        foreach $group (keys %similar_errors) {
            $num_groups++;
            print $fh $pfx."Group $num_groups: $similar_errors{$group}\n";
        }

        print $fh "$pfx\n";
        print $fh $pfx."DUPLICATE ERROR COUNTS:\n\n";
        # Filter out duplicate information for unsuppressed errors to report.
        foreach $err_str (keys %error_cache) {
            my $errno = $error_cache{$err_str}{"errno"};
            my $suppressed = $error_cache{$err_str}{"suppressed"};
            my $dup_count = $error_cache{$err_str}{"dup_count"} +
                $error_cache{$err_str}{"dup_count_client"};
            $duplicate_errors{$errno} = $dup_count if (!$suppressed && $dup_count > 0);
        }
        # sort numerically, not the default alpha
        foreach $num (sort { $a <=> $b } (keys %duplicate_errors)) {
            # didn't increment until hit 1st dup so add 1
            printf $fh $pfx."Error \#%3d: %6d times\n",
                   $num, $duplicate_errors{$num} + 1;
        }
        print $fh "$pfx\n";

        printf $fh $pfx."SUPPRESSIONS USED:\n";
        foreach $name (sort sort_supp_used (keys %supp_used_count)) {
            if ($supp_used_count{$name} > 0 &&
                ($print_default_supp || !$supp_is_default{$name})) {
                printf $fh $pfx."\t%6dx", $supp_used_count{$name};
                if ($supp_bytes_leaked{$name} > 0) {
                    printf $fh " (leaked %8d bytes): ", $supp_bytes_leaked{$name};
                } else {
                    printf $fh ": ", $supp_bytes_leaked{$name};
                }
                printf $fh "%s\n", $name;
            }
        }
    }

    # PR 477013: print a full summary
    print $fh "$pfx\n";
    print $fh $pfx."MEMORY CHECKS WERE DISABLED FOR AT LEAST PART OF THIS RUN!\n"
        if ($drmem_disabled);
    my $total_reported_errors = 0;
    foreach $type (@err_type_keys) {
        $total_reported_errors += $error_summary{$type}{"unique"};
    }
    if ($total_reported_errors > 0) {
        print $fh $pfx."ERRORS FOUND:\n";
    } else {
        print $fh $pfx."NO ERRORS FOUND:\n";
    }
    foreach $type (@err_type_keys) {
        if ($type =~ /LEAK/) {
            if ($report_leaks) {
                if (($type ne 'LEAK' || !$no_leak_info) &&
                    ($type ne 'POSSIBLE LEAK' || !$no_possible_leak_info)) {
                    printf $fh "%s  %5d unique, %5d total, %6d byte(s) of %s\n",
                               $pfx, $error_summary{$type}{"unique"},
                               $error_summary{$type}{"total"} +
                               $error_summary{$type}{"extra_client"},
                               $error_summary{$type}{"bytes"}, $err_types{$type};
                }
            }
        } elsif (!$leaks_only &&
                 ($type !~ /UNADDR/ || $report_unaddr) &&
                 ($type !~ /UNINIT/ || $report_uninit) &&
                 ($type !~ /INVALID/ || $report_invalid)) {
            printf $fh "%s  %5d unique, %5d total %s\n",
                       $pfx, $error_summary{$type}{"unique"},
                       $error_summary{$type}{"total"} +
                       $error_summary{$type}{"extra_client"}, $err_types{$type};
        }
    }
    # If leaks weren't reported separately, echo client summary of leaks
    if ($client_leak_summary ne '') {
        my $tmp_lines = $client_leak_summary;
        $tmp_lines =~ s/^/$default_prefix/msg if ($fh == \*STDERR);
        print $fh $tmp_lines;
    }
    print $fh $pfx."ERRORS IGNORED:\n";
    if ($#supp_syms_file >= 0) {
        if (!$leaks_only) {
            printf $fh "%s  %5d user-suppressed, %5d default-suppressed error(s)\n",
            $pfx, $client_suppressed_errors_user + $post_suppressed_errors_user,
            $client_suppressed_errors_default + $post_suppressed_errors_default;
        }
        printf $fh "%s  %5d user-suppressed, %5d default-suppressed leak(s)\n",
        $pfx, $client_suppressed_leaks_user + $post_suppressed_leaks_user,
        $client_suppressed_leaks_default + $post_suppressed_leaks_default;
    }
    if ($client_ignored ne '') {
        $tmp_lines = $client_ignored;
        $tmp_lines =~ s/^/$default_prefix/msg if ($fh == \*STDERR);
        print $fh $tmp_lines;
    }
}

#-------------------------------------------------------------------------------
# Set up the module search path @libsearch
#
sub init_libsearch_path ($use_vmtree)
{
    my ($use_vmtree) = @_;

    if ($is_unix) {
        # Can also set colon-sep path in env var
        # Env var goes first to allow overriding system paths
        @libsearch = ( split(':', $ENV{"DRMEMORY_LIB_PATH"}) );

        &vmk_bora_paths(\@libsearch, $use_vmtree, $no_sys_paths, $is_vmk)
            if ($vs_vmk);

        # PR 485412: replaced libc routines show up inside drmem lib
        push @libsearch, "$scriptpath/$drmem_dir";

        # System paths go last to allow user specified paths to be searched first.
        if (!$no_sys_paths) {
            push @libsearch, (# standard debuginfo paths for linux
                              '/usr/lib/debug/lib32',
                              '/usr/lib/debug/lib',
                              '/usr/lib/debug/usr/lib32',
                              '/usr/lib/debug/usr/lib',
                              # system paths
                              '/lib',
                              '/usr/lib',
                              );
        }
    } else {
        # FIXME: we really need i#138 so we can find dlls not in these standard
        # system dirs
        $sysroot = &canonicalize_path($ENV{"SYSTEMROOT"});
        push @libsearch, ("$sysroot",
                          "$sysroot/system32",
                          "$sysroot/system32/wbem");
        @pathdirs = split(($is_cygwin) ? ':' : ';', $ENV{'PATH'});
        @pathdirs = map(&canonicalize_path($_), @pathdirs);
        push @libsearch, @pathdirs;
        # Example: C:\WINDOWS\WinSxS\x86_Microsoft.VC80.CRT_1fc8b3b9a1e18e3b_8.0.50727.762_x-ww_6B128700\
        push @libsearch, bsd_glob("$sysroot/WinSxS/x86*");
    }

    # PR 456175: include exe's path
    my ($module,$exepath,$suffix) = fileparse($exename);
    $exepath =~ s|[/\\]$||;
    if (join(' ', @libsearch) !~ m|$exepath|) {
        push @libsearch, $exepath;
    }

    print "INFO: libsearch is ".join("$newline\t", @libsearch)."\n\n"
        if ($verbose);
}

#-------------------------------------------------------------------------------
# Determines the path of $module using @libsearch & puts it in %modpath.  If
# $modpath{$module} has a debuglink section then the path of the debug file is
# put in %modpath.  As the .debug (this suffix is the default) file is also an
# ELF file and as objdump, readelf & addr2line treat it so, using that file
# path keeps debuglink chasing simple (otherwise we'd have to parse the
# .debug_link section to find the debug file - mostly it is libname.debug, so
# this is fine).  Also, %modpath isn't used for printing the error, so using
# the debug file name is fine.
#
# If $modpath{$module} doesn't have debug information or if $module can't be
# located a warning is printed.  In the latter case "" is stored in %modpath.
#
sub get_mod_path($module_name, $modpath_ref)
{
    my ($module, $modpath);
    ($module, $modpath) = @_;

    # Don't search for the file when it has been already searched for.
    return if (defined(${$modpath}{$module}));
    die "get_mod_path passed empty module name" if ($module eq '');

    my $modname = $module;
    my $fullpath = "";
    my $nondbg_fullpath = "";
    my $tryagain = 1;
    my $found = 0;

    while ($tryagain) {
        $tryagain = 0;
        foreach $path (@libsearch) {
            if (-f "$path/$modname") {
                $fullpath = "$path/$modname";
                $nondbg_fullpath = $fullpath if ($nondbg_fullpath eq "");
            } elsif ($path =~ "^/usr/lib/debug") {
                # Really we should read the debuglink section but for now we
                # just do this kind of mapping via glob:
                #   "libc.so.6" => "libc-2.11.1.so",
                #   "libm.so.6" => "libm-2.11.1.so",
                #   "ld-linux.so.2" => "ld-2.11.1.so",
                #   "libdl.so.2" => "libdl-2.11.1.so"
                if ($modname =~ /^ld-linux\.so\.\d+$/) {
                    $modnamebase = "ld";
                } else {
                    $modnamebase = $modname;
                    $modnamebase =~ s/\.so\.\d+$//;
                }
                $fullpath = bsd_glob("$path/$modnamebase-*");
                # "libstdc++.so.6" => "libstdc++.so.6.0.13"
                $fullpath = bsd_glob("$path/$modnamebase.so*") if ($fullpath eq '');
            } else {
                $fullpath = '';
            }
            if ($fullpath ne '') {
                # We are all set if the module was found and it had debug info.
                if (mod_has_dbg_info($fullpath, @dbg_sec_types)) {
                    $found = 1;
                    last;
                }

                # If module has debuglink, then locate the .debug file.
                if (mod_has_dbg_info($fullpath, "debuglink")) {
                    $tryagain = 1;
                    $modname .= ".debug";
                    last;
                }
                print "NO DBG INFO \"$path/$modname\"\n" if ($verbose);
            }
        }
    }

    my $set_path_msg = ($is_vmk) ?
        "set DRMEMORY_LIB_PATH and/or VMTREE env vars\n" :
        "set DRMEMORY_LIB_PATH env var\n";
    if ($nondbg_fullpath eq "") {
        print "WARNING: module $module not found: ".$set_path_msg;
    } elsif ($modname =~ /.debug$/ && !($fullpath =~ /.debug$/)) {
        print "WARNING: can't find .debug file for $module: ".$set_path_msg;
        $fullpath = $nondbg_fullpath;
    } elsif (!$found) {
        print "WARNING: can't find debug info for $module: ".$set_path_msg;
    } else {
        $has_dbg_info{$module} = 1;
    }

    # Observe that %modpath is indexed by $module, not $modname, so if a
    # .debug file is found, the index for %modpath will still be $module.
    #
    print "INFO: $module found at $fullpath\n" if ($verbose);
    ${$modpath}{$module} = $fullpath;
}

#-------------------------------------------------------------------------------
# Returns 1 if $module has at least one debug section as specified in
# @dbg_info_type.  Returns 0 otherwise.
#
sub mod_has_dbg_info($module, @dbg_info_type)
{
    my $module = shift @_;

    if ($is_unix) {
        my $dbg_sec_type;
        my $dbg_info = '';
        foreach $dbg_sec_type (@_) {
            my $key = "$module-$dbg_sec_type";
            if (defined($mod_dbg_info_cache{$key})) {
                return 1 if ($mod_dbg_info_cache{$key} > 0);
            } else {
                $dbg_info = `objdump -h \"$module\"` if ($dbg_info eq '');
                if ($dbg_info =~ /$dbg_sec_type/) {
                    $mod_dbg_info_cache{$key} = 1;
                    return 1;
                }
                $mod_dbg_info_cache{$key} = -1;
            }
        }
        return 0;
    } else {
        # NYI for Windows
        # FIXME: have winsyms take in a query and returns whether just has
        # export symbols?
        return 1;
    }
}

#-------------------------------------------------------------------------------
# Looks up the symbol name, file name and line number for $addr_to_lookup by
# invoking addr2line on $full_module_name.  $options are passed to addr2line if
# any are needed.
# Note: if options are changed during subsequent calls for the same module,
#       they are ignored.  This doesn't happen, so we are fine.
# Note: only for *nix systems; for windows we have our own addr2line.pl.
#
# To prevent repeated invocations of addr2line, a pipe is created, the first
# time, for each module for which addresses need to be looked up (for hostd
# alone it was a minimum of 30 secs in real time per lookup; see PR 454803).
# Subsequent lookups don't pay the cost of an addr2line process creation and
# its memory allocation to read the module.
#
sub lookup_symbol($modpath_in, $addr_in)
{
    my ($modpath, $addr, $pid, $read, $write, $error);
    ($modpath, $addr) = @_;
    return '' if ($modpath eq '');
    my $using_addr2line = 0;

    # If $addrcmd eq "", we're using addr2line for modules and
    # executable and we need to batch by module.
    # Else we're using winsyms.exe, which to avoid having a process
    # per dll on Windows, takes in a dll and address for each query.
    # In the winsyms case we will use addr2line for a cygwin .exe.
    # We split args up to avoid invoking through a shell, so we can get the
    # real pid and can actually kill it (for Windows where eof not sent).
    my ($pipekey, $cmdline);
    if (&use_addr2line($modpath)) {
        $using_addr2line = 1;
        $pipekey = $modpath;
        # PR 420927 - demangle c++ symbols via -C
        # FIXME: should we pass -i to addr2line?
        @cmdline = ("addr2line", "-C", "-f", "-e", "$modpath");
        splice @cmdline, 1, 0, "$vmk_grp" if ($vmk_grp ne '');
    } else {
        $pipekey = $winsyms_key;
        if ($addrcmd =~ /^(.*)\s+(-f)\s*/) {
            @cmdline = ($1, $2);
        } else {
            # What can we do but assume there are no spaces inside
            # components of cmdline?  Could split on -<param>.
            # Won't get here for winsysms, though, which will match the regexp
            @cmdline = split(' ', $addrcmd);
        }
    }
  reopen_pipe:
    if (!defined($addr_pipes{$pipekey}{"write"})) {
        if (-e $modpath) {
            my $pid;
            $error = gensym(); # initialize
            # open3 throws exception on failure so use eval to catch it
            eval { # try
                # capture stderr to avoid addr2line stderr messages from
                # polluting app's stderr (i#235)
                $pid = open3($write, $read, $error, @cmdline);
                1;
            } or do { # catch
                die "$@ running @cmdline: $!\n" if ($@ and $@ =~ /^open3:/);
            };
            print stderr "Running $pid = \"".join(' ', @cmdline)."\"\n" if ($verbose);
            print "INFO: Running $pid = \"".join(' ', @cmdline)."\"\n" if ($verbose);
            # we do not want coredumps when addr2line crashes (PR 558271)
            &vmk_disable_cores($pid) if ($is_vmk);
            $addr_pipes{$pipekey}{"pid"} = $pid;
            $addr_pipes{$pipekey}{"read"} = $read;
            $addr_pipes{$pipekey}{"write"} = $write;
            $addr_pipes{$pipekey}{"error"} = $error;
        } else {
            print "WARNING: can't find $modpath to do symbol lookup\n";
            return "?\n??:0";
        }
    } else {
        $read = $addr_pipes{$pipekey}{"read"};
        $write = $addr_pipes{$pipekey}{"write"};
        $error = $addr_pipes{$pipekey}{"error"};
    }
    if ($pipekey eq $winsyms_key) {
        print $write "$modpath;$addr\n";     # write modpath;addr to pipe
    } elsif ($using_addr2line) {
        # use local signal handler
        eval {
            $got_sigpipe = 0; # must be global
            local $SIG{PIPE} = sub { $got_sigpipe = 1; };
            print $write "$addr\n";     # write addr to pipe
        };
        if ($got_sigpipe) {
            # PR 526420: re-launch addr2line after one crash.
            # addr2line sometimes crashes on one address but works on
            # the others.  if it crashed on the last one the sigpipe won't
            # show up until this one, which may work.
            print "WARNING: SIGPIPE for $pipekey $addr => re-running cmd\n";
            close $addr_pipes{$pipekey}{"read"};
            close $addr_pipes{$pipekey}{"write"};
            close $addr_pipes{$pipekey}{"error"};
            undef $addr_pipes{$pipekey};
            goto reopen_pipe;
        }
    } else {
        # today we shouldn't get here since using addr2line if not winsyms
        print $write "$addr\n";     # write addr to pipe
    }
    # we do not need select() here b/c we know we'll get stdout.  we read stderr
    # only at the end when we reap the addr2line processes.
    my $out = <$read>;          # read symbol from pipe
    return $out .= <$read>;     # read file from pipe
}

#-------------------------------------------------------------------------------
# This routine reads in call stacks that are to be suppressed from reporting.
# It reads them from $file_in.  A sample format is:
#
# UNADDRESSABLE ACCESS
# test4-leak!main
# libc.so.6!__libc_start_main
# test4-leak!_start
# test4-leak!__libc_csu_init
# <not in a module>
#
# # comment line - there can also be a blank line, i.e., with just newline
#
# UNINITIALIZED READ
# libc.so.6!vfprintf
# libc.so.6!printf
# test4-leak!main
# libc.so.6!__libc_start_main
# test4-leak!_start
# test4-leak!__libc_csu_init
# <not in a module>
#
# Note: no leading white spaces and no paths in module names.
#
# The same suppression file is used for both drmemory client library and
# postprocess.pl.  Keeping just one file for suppression makes it easy for the
# user to specify their suppression details.
#
# Wildcards are also supported: a "*" can be used in a module name or
# a function name (PR 464821).
#
# Suppressions are by error type (PR 507837) so that suppressing a
# WARNING in function foo doesn't suppress all real errors in that
# function as well!
#
my $total_supp = 0;
sub read_suppression_info($file_in, $default_in)
{
    my ($file, $default) = @_;
    my $valid_frame = 0;    # to track valid frames followed by invalid ones
    my $callstack = "";
    my $name = sprintf("<no name %d>", $total_supp);
    my $type = "";
    my $new_type = "";
    my $num_supp = 0;
    my $brace_line = -1;

    # If suppression file can't be opened for reading, just ignore
    if (!open(SUPP_IN,$file)) {
        print "WARNING: Can't open suppression info file $file: $!\n".
              "         Disabling suppression.\n";
        return;
    }

    while (<SUPP_IN>) {
        next if (/^\s*$/ || /^\s*\#/);  # skip blank lines and ones starting with #
        s/\r//g if (!$is_unix);
        # is_line_start_of_*() can't match ^WARNING since client uses that
        # for other purposes so we add REPORTED in for the match (and then
        # remove when storing the suppression type)
        s/^WARNING/REPORTED WARNING/;
        if ($brace_line > -1) {
            if (!$warned_legacy_supp) {
                $warned_legacy_supp = 1;
                if (!$quiet) {
                    print stderr $default_prefix.$deprecated_supp_msg1;
                    print stderr $default_prefix.$deprecated_supp_msg2;
                    print $deprecated_supp_msg1.$deprecated_supp_msg2;
                }
            }
            $brace_line++;
            s/^\s*//;
            s/\s*$//;
            if ($brace_line == 1) {
                $name = $_;
            } elsif ($brace_line == 2) {
                if (($type = is_line_start_of_suppression($_))) {
                    # i#282: support mixed format
                } elsif (!/^Memcheck:/) {
                    # skip it
                    while (<SUPP_IN>) {
                        last if (/^\s*}/);
                    }
                    $num_supp--;
                    $total_supp--;
                    next;
                } elsif (/^Memcheck:Addr\d+$/ || /^Memcheck:Jump$/) {
                    # We ignore the {1,2,4,8,16} after Addr
                    $type = 'UNADDRESSABLE ACCESS';
                } elsif (/^Memcheck:Value\d+$/ || /^Memcheck:Cond$/ ||
                           # XXX: is Param used for unaddr syscall params?
                           /^Memcheck:Param/) {
                    # We ignore the {1,2,4,8,16} after Value
                    $type = 'UNINITIALIZED READ';
                } elsif (/^Memcheck:Leak$/) {
                    $type = 'LEAK';
                } elsif (/^Memcheck:Free$/) {
                    $type = 'INVALID HEAP ARGUMENT';
                } elsif (/^Memcheck:Overlap$/) {
                    # XXX i#156: NYI: stick in warning list for now
                    $type = 'WARNING';
                } else {
                    $callstack .= $_;   # need the malformed frame to print it out
                    die "ERROR: unknown type for Valgrind-style suppression:\n".
                        "$name\n$callstack\n";
                }
            } elsif (/^fun:(.*)$/) {
                # Valgrind format fun:sym => *!sym */
                # FIXME i#282: Valgrind C++ symbols are mangled!  NYI
                $callstack .= "*!$1\n";
            } elsif (/^obj:(.*)$/) {
                # Valgrind format obj:mod => mod!* */
                $callstack .= "$1!*\n";
            } elsif (/^\.\.\.$/ || /^\*$/) {
                $callstack .= $_;
            } elsif (/^}/) {
                $brace_line = -1;
            }
        } elsif (/^instruction=/) {
            # instruction suppression (i#498): we don't support here so ignore
        } elsif (/^name=(.*)$/) {
            $name = $1;
        } elsif ((/^.+!.+$/ && !/^</) || # mod!func, but no leading <
                 # support missing module for vmk (PR 363063)
                 (/^<.*\+.+>$/ && !/.*!.*/) || # <mod+off>, but no '!'
                 /<not in a module>/ || /^system call / || /^\.\.\.$/ || /^\*$/) {
            $valid_frame = 1;
            $callstack .= $_;
            $callstack =~ s/[ \t]*$//; # trim trailing whitespace (i#381)
        } elsif (($new_type = is_line_start_of_error($_)) ||
                 ($new_type = is_line_start_of_suppression($_)) ||
                 /^\s*{/) {
            $valid_frame = 0;
            $num_supp++ if ($callstack ne '');
            $total_supp++;
            add_suppress_callstack($type, $callstack, $default, $name)
                if ($callstack ne '');
            $callstack = "";
            $type = $new_type;
            $name = sprintf("<no name %d>", $total_supp);
            $brace_line = (/^{/) ? 0: -1;
        } else {
            $callstack .= $_;   # need the malformed frame to print it out
            die "ERROR: malformed suppression:\n".
                "$type\n$callstack\n".
                "The last frame is incorrect!\n\n".
                "Frames should be one of the following:\n".
                "\t module!function\n".
                "\t module!...\n".
                "\t <module+0xhexoffset>\n".
                "\t <not in a module>\n".
                "\t system call Name\n".
                "\t *\n".
                "\t ...\n";
        }
    }

    # The last one won't be recorded, so record it.
    add_suppress_callstack($type, $callstack, $default, $name)
        if ($callstack ne '');
    $num_supp++ if ($callstack ne '');

    close SUPP_IN;
    print $prefix."Loaded $num_supp suppressions from $file\n";
}

#-------------------------------------------------------------------------------
# Adds a callstack to the suppression regexp table.
#
sub add_suppress_callstack($type, $callstack, $default, $name)
{
    my ($type, $callstack, $default, $name) = @_;
    return if ($type eq '' || $callstack eq '');

    # support missing module name on vmk
    # we can't require suppress file to have the * b/c client doesn't support it
    $callstack =~ s/^<\+/<*+/gm;

    # make module name case-insensitive on windows
    if (!$is_unix) {
        $callstack =~ s/^([^!\+\n]+)([!\+])/\U\1\2/msg;
    }

    # Turn into a regex for wildcard matching.
    # We support two wildcards:
    # "?" matches any character, "*" matches zero or more characters
    #   in one frame. The matching characters don't include "!" in "mod!func"
    #   lines and "+" in "mod+off" lines.
    #   We turn these wildcards into the perl equivalent "." and ".*"
    #   respectively and escape anything else that perl considers non-literal.
    # "..." matches zero or more frames. Turn it into "(.*\n)*".
    # NB since we don't specify /s when matching, "." will not match newline.
    $callstack =~ s/\[/\\[/g;
    $callstack =~ s/\]/\\]/g;
    $callstack =~ s/\./\\./g;
    $callstack =~ s/\?/./g;
    $callstack =~ s/\*/.*/g;

    # generate_error_info formats stack frames as mod+off!func
    # so we need to modify the suppression frames as follows:
    #  a) mod!func  -> mod\+0x\w+!func
    #  b) <mod+off> -> mod\+off![^+]+
    # Suppression frames should not be mod+off!func
    # ensured by (read_suppression_info())
    $callstack =~ s/^(.+)!(.+)$/$1\\+0x\\w+!$2/gm;
    $callstack =~ s/^<(.+)\+(.+)>$/$1\\+$2![^+]+/gm;

    # do this after so our ^ above match
    $callstack =~ s/^(.+)!\\\.\\\.\\\.\n/($1!.*\\n)*/g;
    $callstack =~ s/\\\.\\\.\\\.\n/(.*\\n)*/g;

    # We want prefix matching but using /m so need \A not ^
    $callstack = "\\A" . $callstack;
    push @{ $supp_syms_list{$type} }, $callstack;
    if ($type eq "LEAK") {
        # POSSIBLE LEAK reports should also be checked against LEAK suppressions
        push @{ $supp_syms_list{"POSSIBLE LEAK"} }, $callstack;
        $supp_is_default{$callstack,"POSSIBLE LEAK"} = $default;
        $supp_name{$callstack,"POSSIBLE LEAK"} = $name;
    }
    print "adding suppression $name of type $type\n" if ($verbose);
    $supp_is_default{$callstack,$type} = $default;
    $supp_is_default{$name} = $default;
    $supp_name{$callstack,$type} = $name;
}

#-------------------------------------------------------------------------------
# Returns 1 if call stack pointed to by $callstack_ref_in is on the suppresion
# list; 0 otherwise and prints the call stack to the symbol-based suppression
# file.
#
sub suppress($errname, $callstack_ref, $default_ref, $supp_mod_offs, $bytes_leaked)
{
    my ($errname, $callstack_ref, $default_ref, $supp_mod_offs, $bytes_leaked) = @_;
    my $callstk_str = "";

    # Strip <nosym> and path from module name.
    foreach $frame (@{$callstack_ref}) {
        if ($frame =~ /<unknown symbol>/ ||
            $frame =~ /<not in a module>/) {
            $callstk_str .= "<not in a module>\n";
        } elsif ($frame =~ /^system call/) {
            $callstk_str .= "$frame\n";
        } else {
            $frame =~ s/<nosyms>//;     # strip <nosym>
            $frame =~ /(.+)!/;          # get module name
            # die is to handle potential problems - they always blow up here.
            die "potential symbol lookup bug\n" if ($1 eq "");
            my $sym = $';   # save $' as fileparse() can do a regex
            my $modname = fileparse($1);
            # make module name case-insensitive on windows
            if (!$is_unix) {
                $modname =~ s/^([^!\+]+)([!\+])/\U\1\2/;
            }
            $callstk_str .= $modname."!$sym\n";
        }
    }

    # PR 460923: match any prefix of callstack
    foreach $supp (@{ $supp_syms_list{$errname} }) {
        # Match using /m for multi-line but not /s to not have . match \n
        # FIXME: performance: check the #frames and skip this check if the
        # suppression has more frames than we've seen so far
        if ($callstk_str =~ /$supp/m) {
            my $name = $supp_name{$supp,$errname};
            print "suppression match $name $errname: \"$callstk_str\" vs \"$supp\"\n"
                if ($verbose);
            ${$default_ref} = $supp_is_default{$supp,$errname};
            $supp_used_count{$name}++;
            $supp_bytes_leaked{$name} += $bytes_leaked;
            return 1;
        }
    }

    # we need to wait until here to print this to avoid printing
    # when suppressed (i#525)
    print SUPP_OUT $supp_mod_offs if ($gen_suppress_offs);

    # Not matched.  If we reach this point then the <mod+offs> style call stack
    # has been written to the suppression info file, so let the user know that
    # this is another type of call stack, i.e., one with symbols.
    #
    print SUPP_OUT "\n";
    if ($gen_suppress_syms) {
        # remove the offsets
        $callstk_str =~ s/\+0x[^!]+!/!/g;
        print SUPP_OUT "# This call stack is the symbol based version of the ".
            "one above\n" if ($gen_suppress_offs);
        print SUPP_OUT "$errname\n$callstk_str\n";
    }
    return 0;
}

#-------------------------------------------------------------------------------
# Identifies whether a line is the start of a reported error
# FIXME: also parse rest of line and return the pieces to avoid
# duplication in parse_error()?
#
sub is_line_start_of_error($line)
{
    my ($line) = @_;
    if ($line =~ /^Error #\s*\d+: (UNADDRESSABLE ACCESS)/ ||
        $line =~ /^Error #\s*\d+: (UNINITIALIZED READ)/ ||
        $line =~ /^Error #\s*\d+: (INVALID HEAP ARGUMENT)/ ||
        $line =~ /^Error #\s*\d+: REPORTED (WARNING)/ ||
        $line =~ /^Error #\s*\d+: (LEAK)/ ||
        $line =~ /^Error #\s*\d+: (POSSIBLE LEAK)/ ||
        $line =~ /^Error #\s*\d+: (REACHABLE LEAK)/) {
        return $1;
    }
    return 0;
}

#-------------------------------------------------------------------------------
# Identifies whether a line is the start of an error in a suppression
# file
# FIXME: share code w/ is_line_start_of_error()
#
sub is_line_start_of_suppression($line)
{
    my ($line) = @_;
    foreach $type (@err_type_keys) {
        if ($line =~ /^($type)/ ||
            # support Windows-only errors
            $line =~ /^(GDI USAGE ERROR)/ ||
            $line =~ /^(HANDLE LEAK)/ ||
            # i#282: support Tool:Type
            $line =~ /^Dr.Memory:($type)/) {
            return $1;
        }
    }
    if ($line =~ /^REPORTED (WARNING)/) {
        return $1;
    }
    return 0;
}

#-------------------------------------------------------------------------------
# We want all paths to use forward slashes to avoid problems w/
# double-escaping through layers of interpretation (Windows
# handles forward just fine).  If on cygwin we want to support
# unix paths, so convert those to mixed (drive-letter + forward
# slashes).
sub canonicalize_path($p) {
    my ($p) = @_;
    return "" if ($p eq "");
    # Use cygpath if available, it will convert /home to c:\cygwin\home, etc.
    if ($is_cygwin) {
        $cp = `cygpath -mi \"$p\"`;
        chomp $cp;
        return $cp if ($cp ne "");
        # do drive letter conversion by hand: /x => x:
        $p =~ s|^/([a-z])/|\1:/|;
    } else {
        $p =~ s|\\|/|g;
        $p =~ s|//+|/|g; # clean up double slashes
    }
    return (-e "$p") ? abs_path("$p") : "$p"; # abs_path requires existence
}

#-------------------------------------------------------------------------------
# Whether we use addr2line (alternative is winsyms)
sub use_addr2line($modpath)
{
    my ($modpath) = @_;
    if ($addrcmd eq "" || ($is_cygwin_exe && $modpath =~ /\.exe$/i)) {
        return 1;
    }
    return 0;
}

#-------------------------------------------------------------------------------
# Reads callstacks from a callstack log into memory.
#
sub process_callstack_log($log_file_in)
{
    my ($log_file) = @_;
    my $id = -1;
    open LOG, $log_file or die "can't open $log_file: $!\n";
    while (<LOG>) {
        if (/^CALLSTACK\s*(\d+)/) {
            $id = $1;
            $cstack[$id] = '';
        } elsif ($id > -1 && /^\#\s*\d+/) {
            $cstack[$id] .= $_;
        } elsif (/^\s*error end/) {
            $id = -1;
        }
    }
    close LOG;
}

