#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
# Copyright (c) 2009-2010 VMware, Inc.  All rights reserved.
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

### drheapstat.pl
###
### Wrapper script for Dr. Heapstat front-end (data collection).
###
### Requirements:
### - DynamoRIO version 1.4.1: bundled with release package
### On Linux:
### - perl, binutils (addr2line, objdump)
### On Windows:
### - for cygwin apps: objdump, nm, addr2line
###     => packages needed: perl, binutils
### - for non-cygwin apps: nothing

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

# $^O is either "linux", "cygwin", or "MSWin32"
$is_unix = ($^O eq "linux") ? 1 : 0;
if ($is_unix) {
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
    # we could have drheapstat_aux and copy in drheapstat_{vmk,win32,linux}
    # but until we have other os-specific code we do runtime "use".
    # note that DEFAULT => have to qualify, for some reason, so we use All.
    eval "use frontend_vmk qw(:All)";
    eval "use drheapstat_vmk qw(:All)" if ($is_vmk);
    &vmk_init() if ($is_vmk);
}

# when using perl->exe, or if we set scripts up in bin/, we have a bin subdir
$perl2exe = (-e "$scriptpath/drheapstat.exe") ? 1 : 0;
$drmem_bin_subdir = ($scriptpath =~ m|/drheapstat/bin/?$|);
# handle the top-level bin symlink being dereferenced (PR 527580)
$symlink_deref = !$drmem_bin_subdir && (! -e "$scriptpath/bin32");
$default_home = $symlink_deref ? "$scriptpath/../drheapstat" : "$scriptpath/../";
$default_home = abs_path($default_home);
$default_home = &canonicalize_path($default_home);
$bindir = "bin/bin32";

$drlibname = $is_unix ? "libdynamorio.so" : "dynamorio.dll";
$drmemlibname = $is_unix ? "libdrheapstat.so" : "drheapstat.dll";

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
$drheapstat_home = $default_home;
# normally we're packaged with a DR release laid out in "dynamorio":
$dr_home = ($drmem_bin_subdir || $symlink_deref) ?
    "$default_home/../dynamorio" : "$default_home/dynamorio";
$use_debug = 0;
$use_dr_debug = 0;
$user_ops = "";
$logdir = "";
# -shared_slowpath requires -disable_traces
#   to save space we use -bb_single_restore_prefix
# PR 415155: our code expansion causes us to exceed max bb size sometimes
$def_dr_ops = "-disable_traces -bb_single_restore_prefix -max_bb_instrs 256";
$nudge_pid = "";
$pid_file = "";
$external_pid_file = 0;
$visualize = "";
$view_leaks = "";
$use_vmtree = ($vs_vmk && &vmk_expect_vmtree());  # only for -visualize
$group_by_files = 0;       # only for -visualize - PR 584617
$exename = "";      # only for -visualize
$profdir = "";      # only for -visualize
$from_nudge = -1;   # only for -visualize
$to_nudge = -1;     # only for -visualize
$view_nudge = -1;   # only for -visualize
$stale_since = -1;  # only for -visualize
$stale_for = -1;    # only for -visualize
$suppfile = "";
my $follow_children = 1;
my $callstack_style = $default_op_vals{"callstack_style"};

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
                "drheapstat=s" => \$drheapstat_home,
                "nudge=s" => \$nudge_pid,
                "ops=s" => \$user_ops, # for backward compat only
                "dr_ops=s" => \$dr_ops,
                "logdir=s" => \$logdir,
                "debug" => \$use_debug,
                "release" => sub { $use_debug = 0 },
                "dr_debug" => \$use_dr_debug,
                "follow_children!" => \$follow_children,
                "visualize" => \$visualize,
                "from_nudge=i" => \$from_nudge,
                "to_nudge=i" => \$to_nudge,
                "view_nudge=i" => \$view_nudge,
                "stale_since=i" => \$stale_since,
                "stale_for=i" => \$stale_for,
                "view_leaks" => \$view_leaks,
                "suppress=s" => \$suppfile,
                "x=s" => \$exename,
                "profdir=s" => \$profdir,
                "pid_file=s" => \$pid_file,
                "group_by_files" => \$group_by_files,
                "use_vmtree" => \$use_vmtree,
                "callstack_style=s" => \$callstack_style,
                "v" => \$verbose,
                "version" => \$version)) {
    die $usage;
}
if ($version) {
    print "Dr. Heapstat version @VERSION_NUMBER@ -- build @BUILD_NUMBER@\n";
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
die "$usage\n" unless ($#ARGV >= 0 || $nudge_pid ne "" || $visualize || $view_leaks);

$dr_home = &canonicalize_path($dr_home);
$drheapstat_home = &canonicalize_path($drheapstat_home);
$logdir = &canonicalize_path($logdir);
$exename = &canonicalize_path($exename);
$profdir = &canonicalize_path($profdir);

my $win32_a2l = "$drheapstat_home/$bindir/winsyms.exe";

launch_vistool() if ($visualize);
show_leaks() if ($view_leaks);

if (!$use_debug && ! -e "$drheapstat_home/$bindir/release/$drmemlibname") {
    $use_debug = 1;
    # try to avoid warning for devs running from build dir
    print "$prefix WARNING: using debug Dr. Heapstat since release not found\n"
        unless ($user_ops =~ /-quiet/ || -e "$drmemory_home/CMakeCache.txt");
}
$libdir = ($use_debug) ? "debug" : "release";

$dr_debug = ($use_dr_debug) ? "-debug" : "";
$dr_libdir = ($use_dr_debug) ? "debug" : "release";

die "$drlibname not found in $dr_home/lib32/$dr_libdir\n$usage\n"
    if (! -e "$dr_home/lib32/$dr_libdir/$drlibname");

die "$drmemlibname not found in $drheapstat_home/$bindir/$libdir\n$usage\n"
    if (! -e "$drheapstat_home/$bindir/$libdir/$drmemlibname");

nudge($nudge_pid) if ($nudge_pid ne "");

$apppath = &canonicalize_path($ARGV[0]);
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
push @appcmdline, &vmk_app_pre_args(\@ARGV) if ($is_vmk);
push @appcmdline, @ARGV;

if (!logdir_ok($logdir)) {
    print "$prefix Specified logdir $logdir is invalid\n" if ($logdir ne '');
    # default log dir is the "logs" dir from install package
    $logdir = ($drmem_bin_subdir || ! -e "$default_home/drheapstat") ?
        "$default_home/logs" : "$default_home/drheapstat/logs";
    if ($is_vmk) {
        # . may not have much space so try /scratch first
        # FIXME: create drheapstat subdir
        $logdir = "/scratch" unless (logdir_ok($logdir));
    }
    # last choice is cur dir.  canonicalize in case running w/ cygwin perl.
    $logdir = &canonicalize_path(&cwd()) unless (logdir_ok($logdir));
}

$app_is_win32 = &is_app_win32($apppath);

# it's difficult to get " or ' past drrun so we use `
$ops = "-logdir `$logdir` $user_ops";

$dr_ops .= ' -no_follow_children' unless ($follow_children);

if ($is_unix) {
    my $drrun = "$dr_home/bin32/drrun";
    if ($is_vmk) {
        $ops = &vmk_tool_ops($apppath, $ops);
        $def_dr_ops = &vmk_dr_ops($apppath, $def_dr_ops);
    }
    if ($ENV{'SHELL'} =~ /\/ash/) {
        # PR 470752: ash forks on exec!  so we bypass drrun and set env vars below
    } else {
        @appcmdline = ("$drrun", "-dr_home", "$dr_home",
                       "-client", "$drheapstat_home/$bindir/$libdir/$drmemlibname",
                       "0", "$ops", "-ops", "$def_dr_ops $dr_ops",
                       @appcmdline);
        splice @appcmdline, 1, 0, "$dr_debug" if ($dr_debug ne '');
    }
} else {
    $drrun = "$dr_home/bin32/drrun.exe";

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
                   "-client", "$drheapstat_home/$bindir/$libdir/$drmemlibname",
                   "0", "$ops", "-ops", "$def_dr_ops $dr_ops");
    push @deploycmdline, ("$dr_debug") if ($dr_debug ne "");
    @appcmdline = (@deploycmdline, @appcmdline);
}

$procid = $$;

# PR 425335: we must run the app in the foreground (in case takes stdin)
# so we run the rest of our script sideline
if (!$is_unix && !$is_cygwin_perl) {
    # pp-produced .exe crashes on exit from child of fork
    $using_threads = 1;
    eval "use threads ()";
    $child = threads->create(\&post_process);
} else {
    $using_threads = 0;
    unless (fork()) {
        &post_process();
        exit 0;
    }
}

print "running app: \"".join(' ',@appcmdline)."\"\n" if ($verbose);

if ($is_unix) {
    # use exec to keep the same pid (PR 459481)
    if ($ENV{'SHELL'} =~ /\/ash/) {
        # PR 470752: ash forks on exec!  so we bypass the drrun script
        $ENV{'LD_LIBRARY_PATH'} = "$dr_home/lib32/$dr_libdir:$ENV{'LD_LIBRARY_PATH'}";
        $ENV{'LD_PRELOAD'} = "libdynamorio.so libdrpreload.so";
        $ENV{'DYNAMORIO_LOGDIR'} = (-d "$drheapstat_home/logs") ?
            "$drheapstat_home/logs" : $ENV{'PWD'};
        $ENV{'DYNAMORIO_OPTIONS'} = "-code_api -client_lib ".
            "\"$drheapstat_home/$bindir/$libdir/$drmemlibname;0;$ops\" $def_dr_ops $dr_ops";
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

    my $prefix = "~~Dr.H~~";

    # With PR 408644, the client creates the log dir, to better handle
    # fork+exec -- but that means our post-processing has to go find
    # the logdir.
    my $logsubdir = "";
    my $iters = 0;
    print "looking for $logdir/DrHeapstat-*.$procid.*\n" if ($verbose);
    while ($logsubdir eq "") {
        # get the latest dir matching our pid
        # we do not match app name to avoid assumptions there
        # FIXME: on an exec we may get the wrong dir if it happens too fast
        # use bsd_glob to not split on whitespace
        @dirs = bsd_glob("$logdir/DrHeapstat-*.$procid.*");
        @dirs = sort(sort_by_time @dirs);

        $logsubdir = $dirs[0];
        # On unix/cygwin we could use "ps" to see if app is around
        die "Giving up on finding logdir: assuming process $procid died\n"
            if ($iters++ > 60);

        # it may be a while before the logfile appears
        sleep 1 if ($logsubdir eq "");
    }
    print "found app logdir $logsubdir\n" if ($verbose);
    $iters = 0;
    # wait for log file to be created before invoking postprocess script
    while (! -e "$logsubdir/global.$procid.log") {
        sleep 1;
        # On unix/cygwin we could use "ps" to see if app is around
        die "Giving up on finding logdir: assuming process $procid died\n"
            if ($iters++ > 60);
    }

    # Visualization tool launched by user separately, just point at dir
    print "$prefix Data is in $logsubdir/\n" if ($user_ops !~ /-quiet/);

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

sub is_app_win32($) {
    my ($apppath) = @_;
    if ($is_unix) {
        return 0;
    } elsif ($is_cygwin_avail) {
        # is app cygwin or native windows?
        # should cache this for perf if ever called more than once
        return (&system_filter_stderr("(not found)|(not recognized)",
                                      ("objdump -h \"$apppath\" | grep -q '\.stab'"))
                == 0) ? 0 : 1;
    } else {
        return 1;
    }
}

sub system_filter_stderr($filter, @cmd) {
    my ($filter, @cmd) = @_;
    my ($in, $out, $err);
    $pid = open3($in, $out, $err, @cmd) || return -1;
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
    # PR 476043: use nudge to output snapshots for daemon app
    if ($is_vmk) {
        &vmk_nudge_cmd($pid);
    } else {
        my @cmd;
        if ($is_unix) {
            push @cmd, ("$dr_home/bin32/nudgeunix", "-client", "0", "0");
        } else {
            push @cmd, ("$dr_home/bin32/DRcontrol.exe", "-client_nudge", "0");
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

sub launch_vistool() {
    die "Must use -x with -visualize.\n$usage" if ($exename eq "");
    die "Must use -profdir with -visualize.\n$usage" if ($profdir eq "");

    my $pp = "$drheapstat_home/$bindir/postprocess.pl";
    my @cmd = ($pp, "-x", $exename, "-profdir", $profdir);
    push @cmd, "-v" if ($verbose);
    push @cmd, "-use_vmtree" if ($use_vmtree);
    push @cmd, "-from_nudge", $from_nudge if ($from_nudge > -1);
    push @cmd, "-to_nudge", $to_nudge if ($to_nudge > -1);
    push @cmd, "-view_nudge", $view_nudge if ($view_nudge > -1);
    push @cmd, "-stale_since", $stale_since if ($stale_since > -1);
    push @cmd, "-stale_for", $stale_for if ($stale_for > -1);
    push @cmd, "-group_by_files" if ($group_by_files);
    exec @cmd;
    die "can't launch $pp: $!\n";
}

sub show_leaks() {
    die "Must use -x with -view_leaks.\n$usage" if ($exename eq "");
    die "Must use -profdir with -view_leaks.\n$usage" if ($profdir eq "");

    # For now we have not integreated with the vistool and we simply
    # run Dr. Memory's postprocess.pl, which is copied as postleaks.pl
    # Xref PR 536878.
    my $pp = "$drheapstat_home/$bindir/postleaks.pl";
    my @cmd = ("$^X", $pp, "-x", $exename, "-leaks_only",
               "-p", "", "-batch", "-l", $profdir);
    push @cmd, "-v" if ($verbose);
    push @cmd, ("-c", "$win32_a2l -f") if (&is_app_win32($exename));
    push @cmd, "-use_vmtree" if ($use_vmtree);
    push @cmd, ("-suppress", $suppfile) if ($suppfile ne '');
    push @cmd, ("-aggregate", $profdir);
    push @cmd, ("-callstack_style", "$callstack_style");
    print stderr "running ".join(' ', @cmd)."\n" if ($verbose);
    system(@cmd);
    die "Error $? processing data\n" if ($? != 0);
    exit 0;
}
