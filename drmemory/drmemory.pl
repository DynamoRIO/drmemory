#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2010-2014 Google, Inc.  All rights reserved.
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

### drmemory.pl
###
### Wrapper script for Dr. Memory.
###
### Requirements:
### - DynamoRIO version 1.4.1: bundled with release package
### On Linux:
### - perl, binutils (addr2line, objdump)
### On Windows:
### - for cygwin apps: objdump, nm, addr2line
###     => packages needed: perl, binutils
### - for non-cygwin apps: not used: replaced by drmemory.exe

use Getopt::Long;
use File::Temp qw(tempfile);
use File::Basename;
use File::Glob ':glob';
use File::stat; # plain stat doesn't work on cygwin perl
use IPC::Open3;
use Cwd qw(abs_path cwd);
# locate our module in same dir as script
# RealBin resolves symlinks for us
use FindBin;
use lib "$FindBin::RealBin";

# do NOT use $0 as we need to support symlinks to this file
# RealBin resolves symlinks for us
($scriptname,$scriptpath,$suffix) = fileparse("$FindBin::RealBin/$FindBin::RealScript");

$use_drsyms = 1;

# $^O is either "linux", "cygwin", "MSWin32", or "darwin"
$is_unix = ($^O eq "linux" || $^O eq "darwin") ? 1 : 0;
if ($is_unix) {
    $is_mac = ($^O eq "darwin") ? 1 : 0;
    $is_vmk = (`uname -s` =~ /VMkernel/) ? 1 : 0;
    # support post-processing on linux box vs vmk data
    $vs_vmk = (-e "$scriptpath/frontend_vmk.pm");
} else {
    $is_vmk = 0;
    $vs_vmk = 0;
}
# we support running from a cygwin perl
$is_cygwin_perl = ($^O eq "cygwin") ? 1 : 0;
# we also support using windows perl or perl->.exe to run cygwin apps
$is_cygwin_avail =
    (!$is_unix &&
     ($ENV{'PATH'} =~ m|[\\/]cygwin[\\/]| || $ENV{'PATH'} =~ m!(^|:)/usr!)) ? 1 : 0;

if ($is_vmk || $vs_vmk) {
    # we could have drmemory_aux and copy in drmemory_{vmk,win32,linux}
    # but until we have other os-specific code we do runtime "use".
    # note that DEFAULT => have to qualify, for some reason, so we use All.
    eval "use frontend_vmk qw(:All)";
    eval "use drmemory_vmk qw(:All)" if ($is_vmk);
    &vmk_init() if ($is_vmk);
}

# We include client option usage here and pass them through (PR 478146)
$options_usage = "";
# Since we compile this script on Windows simpler to use a dynamic include rather
# than statically generating a separate script.
do 'options-perl.pl';
for ($i=0; $i<=$#script_ops; $i++) {
    $options_usage .= sprintf("  %-30s [%8s]  %s\n", $script_ops[$i*3],
                              $script_ops[$i*3+1], $script_ops[$i*3+2]);
}
$usage = "usage: $0 [options] -- <executable> [args ...]\noptions:\n$options_usage";

$verbose = 0;
$version = 0;
$drmemory_home = "";
$dr_home = "";
$use_vmtree = ($vs_vmk && &vmk_expect_vmtree());
$use_debug = 0;
$use_debug_force = 0;
$use_dr_debug = 0;
$logdir = "";
$persist_code = 0;
$persist_dir = "";
$perturb_only = 0;
$perturb = 0;
$batch = 0; # batch mode: no popups please
# -shared_slowpath requires -disable_traces
#   (actually it doesn't anymore: new trace event rebuilds trace from IR so
#   if we re-insert in for_trace bbs it will work.)
# to save space we use -bb_single_restore_prefix
# PR 415155: our code expansion causes us to exceed max bb size sometimes
# XXX: for pattern mode, we should be able to use traces for better performance.
# i#1263: on larger apps our shadow memory routinely exceeds DR's
#   default 128MB reservation.  DR is more efficient when all its
#   allocations are inside its reservation.
# DRi#1081: we disable reset until the DR bug is fixed.
$def_dr_ops = "-disable_traces -bb_single_restore_prefix -max_bb_instrs 256 -vm_size 256M -no_enable_reset";
$user_ops = "";
$nudge_pid = "";
$pid_file = "";
$external_pid_file = 0;
# XXX: we ignore -prefix_style for now.  This perl script will go away soon anyway.
my $prefix = "~~Dr.M~~";
my $aggregate = 0;
my $use_default_suppress = 1;
my $gen_suppress_offs = 1;
my $gen_suppress_syms = 1;
my $skip_postprocess = 0;
my $just_postprocess = 0;
my $postprocess_apppath = "";
my $follow_children = 1;
my $callstack_style = $default_op_vals{"callstack_style"};
my $replace_malloc = 0;
my @suppfiles = ();

# PR 527650: perl GetOptions negation prefix is -no or -no-
# We add support for -no_ so that prefix can be used for both perl and client
for ($i = 0; $i <= $#ARGV; $i++) {
    # not using map() b/c want to stop at --
    last if ($ARGV[$i] =~ /^--$/);
    next if ($i > 0 && $ARGV[$i - 1] =~ /^-dr_ops$/);
    # record whether we changed it, since when restoring we don't want to change
    # an option like -node or sthg
    if ($ARGV[$i] =~ s/^-no_/-no/) {
        # we can't mirror @ARGV since GetOptions will mutate it, so we use
        # a hash and assume we never have -nooption and -option!
        $changed_negation{$ARGV[$i]} = 1;
    }
}
# I'd use "require_order" to make it optional to use "--" to split app
#  ops from tool ops, but w/ PR 478146 we do need --
# pass_through: instead of complaining about unknown options, leave in ARGV
#  so we can pass to client
Getopt::Long::Configure("pass_through");
if (!GetOptions("dr=s" => \$dr_home,
                "drmemory=s" => \$drmemory_home,
                "srcfilter=s" => \$srcfilter,
                "ops=s" => \$user_ops, # for backward compat only
                "dr_ops=s" => \$dr_ops,
                "debug" => \$use_debug,
                "release" => sub { $use_debug = 0 },
                "dr_debug" => \$use_dr_debug,
                "follow_children!" => \$follow_children,
                "v" => \$verbose,
                "version" => \$version,
                "batch" => \$batch,
                "nudge=s" => \$nudge_pid,
                "pid_file=s" => \$pid_file,
                "use_vmtree!" => \$use_vmtree,
                "aggregate" => \$aggregate,
                "skip_postprocess|skip_results" => \$skip_postprocess,
                "results" => \$just_postprocess,
                "results_app=s" => \$postprocess_apppath,
                # client options that we process first here:
                "suppress=s" => \@suppfiles,
                "default_suppress!" => \$use_default_suppress,
                "gen_suppress_offs!" => \$gen_suppress_offs,
                "gen_suppress_syms!" => \$gen_suppress_syms,
                "logdir=s" => \$logdir,
                "persist_code" => \$persist_code,
                "persist_dir=s" => \$persist_dir,
                "perturb_only" => \$perturb_only,
                "callstack_style=s" => \$callstack_style,
                "replace_malloc" => \$replace_malloc,
                # required so perl option parser won't interpret as -perturb_only
                "perturb" => \$perturb)) {
    die $usage;
}

if ($version) {
    print "Dr. Memory version @TOOL_VERSION_NUMBER@ -- build @TOOL_BUILD_NUMBER@\n";
    exit 0;
}
# Restore negation prefixes
for ($i = 0; $i <= $#ARGV; $i++) {
    last if ($ARGV[$i] =~ /^--$/);
    $ARGV[$i] =~ s/^-no/-no_/ if ($changed_negation{$ARGV[$i]});
}
if ($#ARGV >= 0 && $ARGV[0] =~ /^-/) {
    while ($#ARGV >= 0 && $ARGV[0] !~ /^--$/) {
        $user_ops .= " $ARGV[0]";
        shift;
    }
    shift if ($#ARGV >= 0 && $ARGV[0] =~ /^--$/);
}
die "$usage\n" unless ($#ARGV >= 0 || $nudge_pid ne "");

die "$usage\n" if ($skip_postprocess && $just_postprocess); # mut exclusive
die "$usage\n" if ($postprocess_apppath ne '' && !$just_postprocess);

die "Not supported with drsyms"
    if ($use_drsyms && ($aggregate || $skip_postprocess || $just_postprocess));

# Now that we know the app to run, get its arch
$lib_arch = "lib32";
$bin_arch = "bin32";
$bindir = "bin";

if (`uname -m` =~ /x86_64/) {
    # experimental support for 64-bit
    $progpath = &canonicalize_path($ARGV[0]);
    $progpath = &find_on_path($progpath) if (! -e $progpath);
    if (`file $progpath 2>&1` =~ /64-bit/) {
        $bin_arch = "bin64";
        $lib_arch = "lib64";
        $bindir = "bin64";
    }
}

$perl2exe = (-e "$scriptpath/postprocess.exe") ? 1 : 0;
$default_home = "$scriptpath/..";
$default_home = abs_path($default_home);
$default_home = &canonicalize_path($default_home);

$drlibname = $is_unix ? ($is_mac ? "libdynamorio.dylib" : "libdynamorio.so")
    : "dynamorio.dll";
$drmemlibname = $is_unix ? ($is_mac ? "libdrmemory.dylib" : "libdrmemory.so")
    : "drmemory.dll";

$drmemory_home = $default_home if ($drmemory_home eq '');
# normally we're packaged with a DR release laid out in "dynamorio":
if ($dr_home eq '') {
    $dr_home = "$default_home/dynamorio";
}

$dr_home = &canonicalize_path($dr_home);
$drmemory_home = &canonicalize_path($drmemory_home);
for ($i = 0; $i <= $#suppfiles; $i++) {
    $suppfiles[$i] = &canonicalize_path($suppfiles[$i]);
}
$logdir = &canonicalize_path($logdir);

if (!$use_debug && ! -e "$drmemory_home/$bindir/release/$drmemlibname") {
    $use_debug = 1;
    # set var for warning after 64-bit check
    $use_debug_force = 1;
}
$libdir = ($use_debug) ? "debug" : "release";
if (! -e "$drmemory_home/$bindir/$libdir/$drmemlibname") {
    if ($bin_arch eq 'bin64') {
        die "$prefix This Dr. Memory release does not support 64-bit applications.\n".
            "$prefix Please recompile with -m32.\n";
    }
}
if ($use_debug_force) {
    # try to avoid warning for devs running from build dir
    print "$prefix WARNING: using debug Dr. Memory since release not found\n"
        unless ($user_ops =~ /-quiet/ || -e "$drmemory_home/CMakeCache.txt");
}

if (!$use_dr_debug && ! -e "$dr_home/$lib_arch/release/$drlibname") {
    $use_dr_debug = 1;
    print "$prefix WARNING: using debug DynamoRIO since release not found\n"
        unless ($user_ops =~ /-quiet/ ||
                # don't warn when DR is built with drmem
                -d "$drmemory_home/dynamorio");
}
$dr_debug = ($use_dr_debug) ? "-debug" : "";
$dr_libdir = ($use_dr_debug) ? "debug" : "release";

if ($use_vmtree && !$skip_postprocess) {
    if (!defined($ENV{"VMTREE"})) {
        # don't die: just a warning (PR 573991)
        print stderr "WARNING: VMTREE environment variable is not set!\n".
            "Symbols may not be found.  To correct set VMTREE and/or ".
            "DRMEMORY_LIB_PATH.  Disable this warning via -no_use_vmtree.\n";
    } else {
        die "VMTREE $ENV{'VMTREE'} not found\n$usage\n" if (! -e $ENV{'VMTREE'});
    }
}

if (!($aggregate || $just_postprocess)) {
    die "$drlibname not found in $dr_home/$lib_arch/$dr_libdir\n$usage\n"
        if (! -e "$dr_home/$lib_arch/$dr_libdir/$drlibname");
}
# even for post-run symbols, need drmem lib for replaced routine symbols
die "$drmemlibname not found in $drmemory_home/$bindir/$libdir\n$usage\n"
    if (! -e "$drmemory_home/$bindir/$libdir/$drmemlibname");

nudge($nudge_pid) if ($nudge_pid ne "");

$skip_postprocess = 1 if ($perturb_only);

$suppress_drmem = "";
for ($i = 0; $i <= $#suppfiles; $i++) {
    die "suppression file $suppfiles[$i] not found\n$usage\n"
        if (! -e $suppfiles[$i]);
    $suppress_drmem .= "-suppress `$suppfiles[$i]` ";
}
chomp $suppress_drmem;

@orig_argv = @ARGV;

if ($aggregate) {
    # rest of args are directory names
} elsif ($just_postprocess) {
    # should be a single arg containing a directory name
    die "A single directory expected\n$usage\n" unless
        ($#ARGV == 0 && -d $ARGV[0]);
} else {
    $apppath = &canonicalize_path($ARGV[0]);
    $apppath = &find_on_path($apppath) if (! -e $apppath);
    $app = fileparse($apppath);
    shift;

    # we need to store the rest of the original command line for passing args to the app,
    # including shell redirection.
    @appcmdline = ("$apppath");
    # PR 459374: support running shell built-ins and scripts
    #   $apppath = $ENV{'SHELL'} if (! -e $apppath);
    #   $appcmdline = "$apppath $appcmdline" if (! -e $apppath);
    # FIXME: not so sure we should support that: we'd have to run
    # with -c "cmdline" for some shells, which might conflict w/ quoting
    # in the app args: seems reasonable to require user to pass us a
    # real executable, so must prefix scripts with shell or perl.
    die "application $apppath not found\n$usage\n" unless (-e $apppath);
    # warn if 64-bit (i#33); swallow stderr if file cmd doesn't exist on Cygwin
    if ($user_ops !~ /-quiet/ && $use_debug && `file $apppath 2>&1` =~ /64-bit/) {
        print "64-bit application experimental support\n"
    }
    push @appcmdline, &vmk_app_pre_args(\@ARGV) if ($is_vmk);
    push @appcmdline, @ARGV;
}

if (!logdir_ok($logdir)) {
    print "$prefix Specified logdir $logdir is invalid\n" if ($logdir ne '');
    # default log dir is the "logs" dir from install package
    if (! -e "$default_home/drmemory/logs") {
        $logdir = "$default_home/logs";
    } else {
        $logdir = "$default_home/drmemory/logs";
    }
    if ($is_vmk) {
        # . may not have much space so try /scratch first
        # FIXME: create drmemory subdir
        $logdir = "/scratch" unless (logdir_ok($logdir));
    }
    # last choice is cur dir.  canonicalize in case running w/ cygwin perl.
    $logdir = &canonicalize_path(&cwd()) unless (logdir_ok($logdir));
}
# Default dir is created at install/config time but if user specifies
# a new base logdir we need to create the subdir.
mkdir "$logdir/dynamorio" if (! -d "$logdir/dynamorio");

if ($is_unix) {
    $app_is_win32 = 0;
} elsif ($is_cygwin_avail) {
    # is app cygwin or native windows?
    $app_is_win32 = (&system_filter_stderr("(not found)|(not recognized)",
                                           ("objdump -h \"$apppath\" | grep -q '\.stab'"))
                     == 0) ? 0 : 1;
} else {
    $app_is_win32 = 1;
}

my $win32_a2l = "$drmemory_home/$bindir/winsyms.exe";

# it's difficult to get " or ' past drrun so we use `
$ops = "-logdir `$logdir` $suppress_drmem $user_ops";
$ops .= " -no_default_suppress" unless ($use_default_suppress);
$ops .= " -no_gen_suppress_offs" unless ($gen_suppress_offs);
$ops .= " -no_gen_suppress_syms" unless ($gen_suppress_syms);
$ops .= " -perturb_only" if ($perturb_only);
$ops .= " -perturb" if ($perturb);
$ops .= " -replace_malloc" if ($replace_malloc);
$ops .= " -callstack_style $callstack_style"
    if ($callstack_style ne $default_op_vals{"callstack_style"});

$dr_ops .= ' -no_follow_children' unless ($follow_children);

if ($persist_code) {
    if ($persist_dir eq '') {
        $persist_dir = "$logdir/codecache"; # default
    } else {
        $persist_dir = &canonicalize_path($persist_dir);
    }
    die "-persist_dir $persist_dir is invalid\n" unless (logdir_ok($persist_dir));
    $dr_ops = "-persist -persist_dir `$persist_dir` " . $dr_ops;
    $ops .= " -persist_code";
}

if ($aggregate || $just_postprocess) {
    # nothing to deploy
} elsif ($is_unix) {
    my $drrun = "$dr_home/$bin_arch/drrun";
    if ($is_vmk) {
        $ops = &vmk_tool_ops($apppath, $ops);
        $def_dr_ops = &vmk_dr_ops($apppath, $def_dr_ops);
    }
    if ($ENV{'SHELL'} =~ /\/ash/) {
        # PR 470752: ash forks on exec!  so we bypass drrun and set env vars below
    } else {
        @appcmdline = ("$drrun", "-quiet", "-dr_home", "$dr_home",
                       "-client", "$drmemory_home/$bindir/$libdir/$drmemlibname",
                       "0", "$ops",
                       # put DR logs inside drmem logdir (i#874)
                       "-logdir", "$logdir/dynamorio",
                       "-ops", "$def_dr_ops $dr_ops",
                       @appcmdline);
        splice @appcmdline, 1, 0, "$dr_debug" if ($dr_debug ne '');
    }
} else {
    $drrun = "$dr_home/$bin_arch/drrun.exe";

    # PR 485412: pass in addresses of statically-included libc routines for
    # replacement.  We only support this for native Windows since we'd need
    # to add nm or another tool to do reverse lookup for cygwin or linux;
    # plus, cygwin/linux apps are less likely to have static libc.
    if ($app_is_win32) {
        # Since Windows-only we can quote the path and don't need open2
        my $addrs = `"$win32_a2l" -e "$apppath" -s memset memcpy memchr strchr strrchr strlen strcmp strncmp strcpy strncpy strcat strncat memmove`;
        $addrs =~ s/\r?\n/,/g;
        # save option string space
        $addrs =~ s/,\?\?/,?/g;
        $addrs =~ s/0x//g;
        # Only if we get all 13 should we pass it in since order matters
        if ($addrs =~ /([^,]+,){13,13}/) {
            $ops .= " -libc_addrs $addrs";
        }
    }

    # PR 459481: we can get the app's pid from drinject via a file
    if ($pid_file eq "") {
        ($fh, $pid_file) = tempfile();
        die "temp file $pid_file not empty!\n"
            unless (&get_file_size($pid_file) == 0);
        close($fh); # let drinject write to it
    } else {
        $external_pid_file = 1;
    }
    $pid_file = &canonicalize_path($pid_file);
    print "temp file for pid is $pid_file\n" if ($verbose);

    # With new config file scheme (PR 212034) AppInit is not set for
    # normal registration and so we no longer have to suppress it here.
    # We can also configure and run in one step using a one-time config file
    # that requires no unregistration.

    # use array to support paths with spaces (system() splits single arg on spaces)
    @deploycmdline = ("$drrun", "-pidfile", "$pid_file", "-quiet", "-root", "$dr_home",
                   "-client", "$drmemory_home/$bindir/$libdir/$drmemlibname",
                   "0", "$ops", "-ops", "$def_dr_ops $dr_ops");
    push @deploycmdline, ("$dr_debug") if ($dr_debug ne "");
    @appcmdline = (@deploycmdline, @appcmdline);
}

# i#1045: avoid glibc malloc checks aborting the app and confusing the user
$ENV{'MALLOC_CHECK_'} = "0";

$procid = $$;

if ($aggregate || $just_postprocess) {
    # not running app
    &post_process();
    exit 0;
}

# PR 425335: we must run the app in the foreground (in case takes stdin)
# so we run the rest of our script sideline
if (!$use_drsyms && !$is_unix && !$is_cygwin_perl) {
    # pp-produced .exe crashes on exit from child of fork
    $using_threads = 1;
    eval "use threads ()";
    $child = threads->create(\&post_process);
} elsif (!$use_drsyms) {
    $using_threads = 0;
    unless (fork()) {
        # PR 511242: Ctrl-C on an app launched with drmemory.pl should only
        # terminate the app, not postprocess.pl, to avoid an incomplete results
        # file.  By default the shell terminates all processes in the app's
        # group, so we move postprocess to its own group.  If we want headless
        # support we can change this to setsid.
        setpgrp(0,0) or die "Unable to setpgrp\n";
        &post_process();
        exit 0;
    }
}

print "running app: \"".join(' ',@appcmdline)."\"\n" if ($verbose);

if ($is_unix) {
    # use exec to keep the same pid (PR 459481)
    if ($ENV{'SHELL'} =~ /\/ash/) {
        # PR 470752: ash forks on exec!  so we bypass the drrun script
        $ENV{'LD_LIBRARY_PATH'} = "$dr_home/$lib_arch/$dr_libdir:$ENV{'LD_LIBRARY_PATH'}";
        $ENV{'LD_PRELOAD'} = "libdynamorio.so libdrpreload.so";
        $ENV{'DYNAMORIO_LOGDIR'} = (-d "$drmemory_home/logs") ?
            "$drmemory_home/logs" : $ENV{'PWD'};
        $ENV{'DYNAMORIO_OPTIONS'} = "-code_api -client_lib ".
            "\"$drmemory_home/$libdir/$drmemlibname;0;$ops\" $def_dr_ops $dr_ops";
        $ENV{'DYNAMORIO_RUNUNDER'} = "1";
    }
    exec(@appcmdline); # array to handle spaces in paths
    die "Failed to exec ".join(' ',@appcmdline)."\n";
} else {
    system(@appcmdline); # array to handle spaces in paths
    my $status = $?;
    $child->join() if ($using_threads);
    exit $status;
}

#-------------------------------------------------------------------------------

sub post_process()
{
    my $logsubdir = "";
    if (!($aggregate || $just_postprocess)) {
        if (!$is_unix) {
            # Retrieve pid.  Avoid opening file until drinject has written to it,
            # to avoid blocking the write.
            while (&get_file_size($pid_file) <= 0) {
                sleep 1;
            }
            open(PIDF, "< $pid_file") || die "Can't open $pid_file: $!\n";
            $procid = <PIDF>;
            chomp $procid;
            $procid =~ s/\r//;
            close(PIDF);
            unlink $pid_file if (!$external_pid_file);
            die "Malformed $pid_file: \"$procid\"\n" unless ($procid =~ /^\d+$/);
        }

        print "app has pid $procid\n" if ($verbose);

        # With PR 408644, the client creates the log dir, to better handle
        # fork+exec -- but that means our post-processing has to go find
        # the logdir.
        my $iters = 0;
        print "looking for $logdir/DrMemory-*.$procid.*\n" if ($verbose);
        while ($logsubdir eq "") {
            # get the latest dir matching our pid
            # we do not match app name to avoid assumptions there
            # FIXME: on an exec we may get the wrong dir if it happens too fast
            # use bsd_glob to not split on whitespace
            @dirs = bsd_glob("$logdir/DrMemory-*.$procid.*");
            @dirs = sort(sort_by_time @dirs);

            $logsubdir = $dirs[0];
            # On unix/cygwin we could use "ps" to see if app is around
            die "Giving up on finding logdir: assuming process $procid died\n"
                if ($iters++ > 180);

            # it may be a while before the logfile appears
            sleep 1 if ($logsubdir eq "");
        }
        print "found app logdir $logsubdir\n" if ($verbose);
        $iters = 0;
        if ($skip_postprocess) {
            open(RESFILE, "> $logsubdir/results.txt") ||
                die "Can't create $logsubdir/results.txt: $!";
            # work around lack of full path so that -results knows
            # path to executable (xref PR 401580.  i#138/PR 307636 are now
            # implemented and used on windows but not on *nix).
            print RESFILE "Results for \"$apppath\" are not available because ".
                "-skip_results was specified!\n";
            print RESFILE "To fill in this file, run with \"-results $logsubdir\".\n";
            close(RESFILE);
            print STDERR "$prefix To obtain results, run with: -results $logsubdir\n";
            return 0;
        }
        # wait for log file to be created before invoking postprocess script
        while (! -e "$logsubdir/global.$procid.log") {
            sleep 1;
            # On unix/cygwin we could use "ps" to see if app is around
            die "Giving up on finding logdir: assuming process $procid died\n"
                if ($iters++ > 60);
        }
    }

    if ($just_postprocess) {
        # support running on another machine that doesn't have same path
        $logsubdir = $ARGV[0];
        if ($postprocess_apppath ne '') {
            $apppath = $postprocess_apppath;
        } else {
            # retrieve app name from results.txt file
            open(RESFILE, "< $logsubdir/results.txt") ||
                die "Can't open $logsubdir/results.txt: $!";
            $_ = <RESFILE>;
            if (/Results for "(.*)" are not/) {
                $apppath = $1;
            } else {
                die "Malformed $logsubdir/results.txt: not from a -skip_results run!\n";
            }
        }
    }

    # Post-process to get line numbers and create suppression file.
    # FIXME: have option to send to stderr to see point of occurrence?
    # I do have -pause_at_*.  Would want online symbol queries.
    my $exeop = "";
    if (!$is_unix) {
        $libcmd = "$win32_a2l -f";
        $exeop = "-cygwin" if (!$app_is_win32);
    } else {
        # postprocess.pl itself massages a call to addr2line
        $libcmd = "";
    }

    &vmk_pre_script_setup() if ($is_vmk);

    $extraargs = ($user_ops =~ /-quiet/) ? "-q" : "";

    # we don't need the prefix since sending to a file instead of stdout
    my @postcmd;
    if ($perl2exe) {
        @postcmd = ("$drmemory_home/$bindir/postprocess.exe");
    } else {
        @postcmd = ("$^X", "$drmemory_home/$bindir/postprocess.pl");
    }
    push @postcmd, "-v" if ($verbose);
    push @postcmd, ("-p", "", "-c", "$libcmd");
    push @postcmd, ("-f", "$srcfilter") if ($srcfilter ne '');
    push @postcmd, "$exeop" if ($exeop ne '');
    push @postcmd, ("-dr_home", "$dr_home") if (!$is_unix && !$is_cygwin_perl);
    push @postcmd, "-use_vmtree" if ($use_vmtree);
    push @postcmd, "$extraargs" if ($extraargs ne '');
    # Don't use suppress_drmem as perl option parsing doesn't like ``
    for ($i = 0; $i <= $#suppfiles; $i++) {
        push @postcmd, ("-suppress", "$suppfiles[$i]");
    }
    push @postcmd, ("-nodefault_suppress") unless ($use_default_suppress);
    push @postcmd, ("-nogen_suppress_offs") unless ($gen_suppress_offs);
    push @postcmd, ("-nogen_suppress_syms") unless ($gen_suppress_syms);
    # Include app cmdline in results file (PR 470920)
    push @postcmd, ("-appid", join(' ', @orig_argv));
    push @postcmd, "-batch" if ($batch);
    push @postcmd, ("-drmemdir", "$libdir");
    push @postcmd, ("-callstack_style", "$callstack_style");
    push @postcmd, ("-replace_malloc") if ($replace_malloc);
    if ($aggregate || $just_postprocess) {
        push @postcmd, ("-aggregate", @ARGV);
    }
    if (!$aggregate) {
        # We need to pass in path to executable to work around PR 401580 via -x
        push @postcmd, ("-x",  "$apppath");
        push @postcmd, ("-l", "$logsubdir");
    }
    print "postcmd is \"".join(' ', @postcmd)."\"\n" if ($verbose);
    if ($using_threads) {
        system(@postcmd); # array to handle spaces in paths
    } else {
        exec(@postcmd); # array to handle spaces in paths
    }
    return 0;
}

#-------------------------------------------------------------------------------
# utility subroutines

sub get_file_size($f) {
    my ($f) = @_;
    my $sa = stat($f);
    return ($sa) ? $sa->size : -1;
}

# note: no args, as $a and $b are globals
sub sort_by_time {
    my $sa1 = stat($a);
    my $sa2 = stat($b);
    return 0 if (!$sa1 || !$sa2); # just avoid bad deref
    # larger numbers are later and we want most recent first
    return $sa2->ctime <=> $sa1->ctime;
}

sub system_filter_stderr($filter, @cmd) {
    my ($filter, @cmd) = @_;
    my ($in, $out, $err);
    my $pid;
    # open3 throws exception on failure so use eval to catch it
    eval { # try
        $pid = open3($in, $out, $err, @cmd);
        1;
    } or do { # catch
        if ($@ and $@ =~ /^open3:/) {
            print "$@ running @cmdline: $!\n" if ($verbose);
            return -1;
        }
    };
    waitpid($pid, 0);
    my $res = $?;
    while (<$err>) {
        print stderr $_ unless (/$filter/);
    }
    while (<$out>) {
        print $_ unless (/$filter/);
    }
    close($in);
    close($out);
    close($err);
    return $res;
}

# We want all paths to use forward slashes to avoid problems w/
# double-escaping through layers of interpretation (Windows
# handles forward just fine).  If on cygwin we want to support
# unix paths, so convert those to mixed (drive-letter + forward
# slashes).
sub canonicalize_path($p) {
    my ($p) = @_;
    return "" if ($p eq "");
    # Use cygpath if available, it will convert /home to c:\cygwin\home, etc.
    if ($is_cygwin_avail) {
        $cp = `cygpath -mai \"$p\"`;
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

# This routine does not return
sub nudge($p) {
    my ($pid) = @_;
    # PR 428709/PR 474554: user tells us when daemon app is "finished"
    # and we nudge it to get end-of-run data like leaks and stats.
    # We do not try to kill the app, so this can be used repeatedly.
    if ($is_vmk) {
        &vmk_nudge_cmd($pid);
    } else {
        my @cmd;
        # XXX: read drmemory.h to get NUDGE_LEAK_SCAN which we assume here is 0
        if ($is_unix) {
            push @cmd, ("$dr_home/$bin_arch/nudgeunix", "-client", "0", "0");
        } else {
            push @cmd, ("$dr_home/$bin_arch/DRcontrol.exe", "-client_nudge", "0");
        }
        push @cmd, ("-pid", "$pid");
        exec(@cmd); # array to handle spaces in paths
        die "Failed to exec ".join(' ',@cmd)."\n";
    }
    die "Failed to run -nudge command\n";
}

sub logdir_ok($l) {
    my ($logdir) = @_;
    return 0 if ($logdir eq "" || ! -d $logdir || ! -w $logdir);
    # -w fails to detect read-only mounts
    my $touch = "$logdir/_drmem_test_" . $$;
    die "Tmp file $touch exists!\n" if (-e $touch);
    if (mkdir $touch) {
        rmdir $touch || die "Unable to remove temp dir $touch\n";
        return 1;
    }
    return 0;
}

# XXX: share w/ frontend_vmk.pm: but we want on both plaforms
sub find_on_path($exe)
{
    my ($exe) = @_;
    # File::Which isn't standard enough
    my @PATH = split(":", $ENV{"PATH"});
    my @which = grep -x "$_/$exe", @PATH;
    return "$which[0]/$exe";
}

