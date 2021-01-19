#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
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

# Things to do:
#
# TODO: PR 502467 - create common/symbol.pm
# TODO: PR 502465 - not tested on windows
# TODO: PR 502472 - server shouldn't hang on abnormal vistool exit
#                   (applies to postprocess.pl & vistool)
# TODO: PR 502473 - snapshot table not user sortable
#                   (applies to postprocess.pl & vistool)
# TODO: all index and summary files created will collide when multiple vistools
#       are supported - resolve them

#-------------------------------------------------------------------------------
use File::Glob ':glob';     # FIXME: remove with symbol.pm fix
use File::Basename;         # FIXME: remove with symbol.pm fix
use IPC::Open2;             # FIXME: remove with symbol.pm fix
use Getopt::Long;
use IO::Socket;
use FindBin qw($RealBin);
use File::Path;
use lib "$FindBin::RealBin/..";
use Cwd qw(abs_path);

# Must be as early as possible.
$SIG{__DIE__} = sub {
    # We delete the flash trust file on any abnormal exit so as to not annoy
    # the user with a message to delete it manually.
    unlink $flash_trust_file if (-e $flash_trust_file);
};

my $xaxis_label = "";   # can be one of: allocs, ticks, bytes or mallocs
my $fsize_idx = 7;  # index number for file size in the array returned by stat
my $use_vmtree = 0;
my $group_by_files = 0; # PR 584617
my $exename = "";
my $logdir = "";
my $verbose = 0;
my $total_ss = 0;       # total number of snapshots in the log file
my @sorted_ss = ();     # used to hold all snapshots sorted by x-axis value
my @snapshot_idx = ();
my @staleness_idx = ();
my @cstack_idx = ();
my $vistool = "$RealBin/drheapstat.swf";
my $visualize = 0;
my $from_nudge = -1;    # Which nudge to start reading data from.  PR 502468.
my $to_nudge = -1;      # Up to which nudge.
# Specifies which nudge to view - used only for constant number of snapshots;
# internally $view_nudge is built on top of $from_nudge and $to_nudge.
my $view_nudge = -1;

# This contains the nudge index, i.e., the file positions in snapshot and
# staleness logs for each nudge.  It also has 2 special entries, one for the
# start and one for the end for each of the two files.  This way all all reads
# from log files are normalized irrespective of whether there were any nudges
# or not.
my @nudge = ();

# User specified time to use as threshold for computing staleness graph.
my $stale_since = -1;   # "show me all memory that has been stale since x ticks"
my $stale_for = -1;     # "show me all memory that has been stale for x ticks"

# Directory to place the exception for drheapstat.swf.  Note, this isn't my
# because that will prevent it from being accessible in the 'die' handler.
$flash_trust_file = "";
#-------------------------------------------------------------------------------
# FIXME: the code below upto the next line is also common so move it into
# symbol.pm.  Note: make all these globals 'my' when in a module

# Use a symbol and file cache to prevent duplicate invocations of addr2line;
# indexed by modoffs.  PR 420921.
#
%symfile_cache = {};
%mod_dbg_info_cache = {};   # FIXME: new var; add to symbol.pm before deleting
@libsearch = ();    # Path to search libraries in
%addr_pipes = ();   # pipes to addr2line processes for each module; PR 454803.
$vmk_grp = "";      # vmkernel group for addr2line; PR 453395.
@dbg_sec_types = ("debug_info", # all DWARF 2 & 3 type info will have this
                  "debug ",     # for DWARF 1; the extra " " is to prevent
                                #   DWARF 2 matches
                  "stab");      # .stab is competing debug format to DWARF
$no_sys_paths = 0; # look in /lib, etc. for symbol files?

# do NOT use $0 as we need to support symlinks to this file
# RealBin resolves symlinks for us
($scriptname,$scriptpath,$suffix) = fileparse("$FindBin::RealBin/$FindBin::RealScript");

#-------------------------------------------------------------------------------
# FIXME: this OS identification part is common too can it be moved into
# frontend_vmk()
#
# $^O is either "linux", "cygwin", or "MSWin32"
$is_unix = ($^O eq "linux") ? 1 : 0;
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
    $use_vmtree = &vmk_expect_vmtree();
}

init_flash();   # Init flash before doing any work.

if (!GetOptions("x=s" => \$exename,
                "profdir=s" => \$logdir,
                "v" => \$verbose,
                "from_nudge=i" => \$from_nudge,
                "to_nudge=i" => \$to_nudge,
                "view_nudge=i" => \$view_nudge,
                "stale_since=i" => \$stale_since,
                "stale_for=i" => \$stale_for,
                "group_by_files" => \$group_by_files,
                "use_vmtree" => \$use_vmtree)) {
    die "Incorrect options passed - not meant to be invoked directly; ".
        "use drheapstat.pl.";
}

die "can't find directory: $logdir\n" if (! -e $logdir);
die "can't find executable: $exename\n" if (! -e $exename);

die "Visualization won't work on ESXi, use Linux or Windows.\n" if ($is_vmk);

init_libsearch_path($use_vmtree);

my $cstack_logfile = $logdir."/callstack.log";
my $snapshot_logfile = $logdir."/snapshot.log";
my $staleness_logfile = $logdir."/staleness.log";
my $nudge_idxfile = $logdir."/nudge.idx";

my $have_stale = ($stale_since != -1 || $stale_for != -1);
die "Can't specify -stale_since and -stale_for together.\n"
    if ($stale_since != -1 && $stale_for != -1);

# Do the basic file existence checks so that assumptions about file existence
# don't break later.
die "can't find $cstack_logfile: $!\n" if (!-e $cstack_logfile);
die "can't find $snapshot_logfile: $!\n" if (!-e $snapshot_logfile);
die "can't find $nudge_idxfile: $!\n" if (!-e $nudge_idxfile);
if (!-e $staleness_logfile) {
    die "can't find $staleness_logfile: $!\n" if ($have_stale);
} elsif (!$have_stale) {
    print "Memory staleness data is available.\n".
          "Use -stale_since or -stale_for with -visualize option to view it.\n";
}

process_all_logs();
collaborate_with_vistool();

unlink $flash_trust_file or
    die "Can't delete Flash player trust file: $flash_trust_file: $!.\n".
        "Delete it manually or future runs of drheapstat.pl -visualize won't ".
        "work.\n";

#-------------------------------------------------------------------------------
# FIXME: the code below upto exit() is also common so move it into symbol.pm.

foreach $apipe (keys %addr_pipes) {        # reap all the addr2line processes
    if ($apipe eq $winsyms_key) {
        # winsyms.exe's fgets doesn't see an eof from our close so send
        # a special exit code
        my $write = $addr_pipes{$apipe}{"write"};
        print $write ";exit\n";
    }
    close $addr_pipes{$apipe}{"read"};
    close $addr_pipes{$apipe}{"write"};
    # on windows closing our end doesn't send eof to addr2line
    # and perl's kill command doesn't seem to do the job
    kill 9, $addr_pipes{$apipe}{"pid"} if (!$is_unix && $apipe ne $winsyms_key);
    waitpid($addr_pipes{$apipe}{"pid"}, 0);
    print stderr "pid ".$addr_pipes{$apipe}{"pid"}." successfully waited on\n"
        if ($verbose);
}

exit 0;

#-------------------------------------------------------------------------------
# Set up flash player related details.
#
# TODO: try auto detecting flash player or browser if env. var not defined?
sub init_flash()
{
    # TODO: try using an option for flash player so as to not have the info
    # hidden in an env. var, but also make it easy to use so that the user
    # doen't have to specify it each time (like what using an env. var does) -
    # may be use both?
    # Note: can't use a default path for flash player as there isn't one esp.
    # on linux where it can be (and usually is) installed anywhere.
    die "Environment variable FLASH_PLAYER not defined.  ".
        "Define it to point to a flash player executable or a browser with ".
        "flash plugin installed.\n"
        if (!defined($ENV{"FLASH_PLAYER"}));
    die $ENV{"FLASH_PLAYER"}." doesn't exist\n" if (! -e $ENV{"FLASH_PLAYER"});

    die "Enviroment variable HOME isn't defined.\n" if (!defined($ENV{"HOME"}));
    my $flash_trust_dir = $ENV{"HOME"}.
                       "/.macromedia/Flash_Player/#Security/FlashPlayerTrust";

    if (! -e $flash_trust_dir) {
        my $res = mkpath($flash_trust_dir);
        die "Can't create Flash player trust directory: $flash_trust_dir"
            if (! -e $flash_trust_dir || $res < 1)
    }

    # Setup trust/exception for the visualization swf file so that it can get
    # data from a local unix domain socket.
    $flash_trust_file = "$flash_trust_dir/drheapstat.cfg";
    die "Flash player trust file: $flash_trust_file exists.\n".
        "Another drheapstat.pl -visualize is running: exit it\n".
        "Or the last run didn't exit cleanly: delete $flash_trust_file\n"
        if (-e $flash_trust_file);

    open FLASH_TRUST, ">$flash_trust_file" or
        die "can't open $flash_trust_file for writing: $!\n";

    print FLASH_TRUST "file://$vistool\n";
    close FLASH_TRUST;
}

#-------------------------------------------------------------------------------
# Sets up a socket, launches vistool in a browser and waits for the vistool
# client to connect.  Once connected, it services requests from the vistool
# client till it terminates or requests termination of communication.
#
# Note: server to vistool is a one-to-one communication.  If there are multiple
# vistools running, things won't work.
#
sub collaborate_with_vistool()
{
    my $server;
    my $client;
    my $res;

    # TODO: Share the port number with drheapstat.mxml instead of hard coding
    # in both locations - no easy way to do it.  Statically, can have an
    # include file and do build time processing (messy).  Dynamically, can pass
    # it as an option (if it exists for a flash app in a browser).
    my $port = 23456;

    # Server is set up on port 23456 so that a client, i.e., vistool can
    # connect; vistool MUST use the same port number.  Also, there is a
    # one-to-one relationship between the server and vistool.  This means only
    # one visualization of heap profile data can be done at a time.
    $server = IO::Socket::INET->new(Proto     => 'tcp',
                                    LocalPort => $port,
                                    Listen    => 1,     # only on vistool
                                    Reuse     => 1) ||
        die "can't create socket: $!\n";
    print "server started\n" if ($verbose);

    # Launch the vistool (client for this server) in the background.
    # Make sure to quote the path to handle spaces.
    my $player = $ENV{"FLASH_PLAYER"};
    $vistool = canonicalize_path($vistool);
    if (!$is_unix) {
        # canonicalize_path will leave as unix path (which we want for everything
        # else when using cygwin perl), so we do drive letter conversion here:
        $vistool =~ s|^/([a-z])/|\1:/|;
    }
    my $cmd = "\"$player\" $vistool &";
    system $cmd;
    print "launched vistool: $cmd\n" if ($verbose);

    $client = $server->accept();        # now wait for vistool to connect
    print "client connected\n" if ($verbose);
    $client->autoflush(1);
    while (<$client>) {     # wait for message for client
        print "message from client: $_\n" if ($verbose);
        chomp;
        $res = "";
        if (/callstack:(\d+)/) {
            # Client requested a callstack.
            $res = get_using_idx($cstack_logfile, \@cstack_idx, $1);
            $res = create_callstack_xml($res);
        } elsif (/snapshot:(\d+):(\d+)-(\d+)/){
            # Client requested a snapshot.
            my ($from, $to) = ($2, $3); # save; calls below might clobber them
            my $staleness_data = "";
            if ($have_stale) {
                $staleness_data = get_using_idx($staleness_logfile,
                                                \@staleness_idx, $1);
            }
            $res = get_using_idx($snapshot_logfile, \@snapshot_idx, $1);
            $res = create_snapshot_xml($res, $staleness_data, $from, $to);
        } elsif (/summary:(\d+)-(\d+)/){
            # Client requested snapshot summary for a specific range.
            $res = create_snapshot_summary_xml($1, $2);
        } elsif (/finished/){
            # Client notifies of exit.
            last;
        } elsif (/<policy-file-request\/>/) {
            # Attempt to satisfy Flash 9's policy file requirement to open
            # a socket connection.  However, this doesn't seem to work for me:
            # I need to instead listen on port 843 with a real policy file.
            # FIXME: have this code listen on 843.
            $res = "<?xml version=\"1.0\"?><cross-domain-policy><allow-access-from domain=\"*\" to-ports=\"*\"/></cross-domain-policy>\0";
        } else {
            print "unknown message from client\n" if ($verbose);
        }

        # Send out a reply if there is any.
        if ($res ne "") {
            print "message sent: $res\n" if ($verbose);
            print "sent ", length($res), " bytes to client\n" if ($verbose);
            my $size = pack "N", length($res);  # force 4 bytes;
            print $client $size;
            print $client $res;
        }
    }
    close $client;
}

#-------------------------------------------------------------------------------
# Checks nudge options, reads the nudge index file and sets up from and to
# points to read snapshot and staleness log files.  PR 502468.
#
sub process_nudges()
{
    my ($const_snapshots, $nudge_count) = process_nudge_index($nudge_idxfile);
    if ($nudge_count > 0) {
        my $ref_count = $nudge_count;
        my $log_has_end = has_log_end($snapshot_logfile);
        $ref_count++ if (!$const_snapshots);
        $ref_count++ if ($log_has_end);

        # If nudge reference points are available, let the user know.
        print $const_snapshots ? "Constant " : "Variable";
        print " number of snapshots detected.\n";
        print "$ref_count reference points available: \n";
        print "\t0: start point\n" if (!$const_snapshots);
        print "\t1 to $nudge_count: nudge points\n\t";
        if ($log_has_end) {
            print $const_snapshots ? $ref_count : $ref_count - 1;
            print ": end point\n";
        }

        die "Only -view_nudge or [-from_nudge and -to_nudge] can be ".
            "specified, not both.\n"
             if ($view_nudge != -1 && ($from_nudge != -1 || $to_nudge != -1));

        if ($const_snapshots) {
            die "Can't use -from_nudge and -to_nudge for visualizing constant ".
                "number of snapshots.\nUse -view_nudge instead.\n"
                if ($from_nudge != -1 || $to_nudge != -1);

            if ($view_nudge == -1) {
                # User didn't specify the nudge to visualize, so ask them to.
                die "Specify which reference point to visualize using ".
                    "-view_nudge\n";
            } elsif ($view_nudge < 1 || $view_nudge > $ref_count) {
                die "-view_nudge value of $view_nudge out of range of ".
                    "reference points available.\n";
            } else {
                # Just map the -view_nudge value into one set of snapshots
                # between two nudges.
                $from_nudge = $view_nudge - 1;
                $to_nudge = $view_nudge;
            }
        } else {    # Variable number of snapshots.
            die "Can't use -view_nudge for visualizing variable number of ".
                "snapshots.\nUse -from_nudge and -to_nudge instead.\n"
                if ($view_nudge != -1);

            # If the user didn't specify the nudge to visualize, ask them to.
            die "Specify which reference points to visualize between ".
                "using -from_nudge and -to_nudge\n"
                if ($from_nudge == -1 || $to_nudge == -1);
            die "-from_nudge value of $from_nudge can't be than 0.\n"
                if ($from_nudge < 0);
            die "-from_nudge value of $from_nudge should be less than ".
                "-to_nudge value of $to_nudge.\n"
                if ($from_nudge >= $to_nudge);
            die "-to_nudge value of $to_nudge exceeds maximum reference ".
                "points available\n"
                if ($to_nudge > ($log_has_end ? $ref_count - 1: $nudge_count));
        }
    } else {
        print "Ignoring -view_nudge as there are no nudges in the log files.\n"
            if ($view_nudge != -1);
        print "Ignoring -from_nudge and -to_nudge as there are no nudges ".
              "in the log files.\n"
            if ($from_nudge != -1 || $to_nudge != -1);

        # No nudges were seen and -{view,from,to}_nudge options weren't used.
        # So show all because there are only two entries in @nudge.
        $from_nudge = 0;
        $to_nudge = 1;
    }
}

#-------------------------------------------------------------------------------
# Read the nudge index file and get the location of new data succeeding each
# nudge in the snapshot and staleness log files.  Returns the number of nudges
# processed.
#
# Note, by using the start and end of file as the first and last elements in
# the nudge index, we can use the same scheme to read files without nudges too.
# Keeps code simpler.  PR 502468.
#
sub process_nudge_index($idx_file_in)
{
    my ($idx_file) = @_;
    my $count = 0;
    my $const_snapshots = 0;    # Does snapshot.log have const no. of sanpshots?

    $nudge[$count]{"snapshot"} = 0;
    $nudge[$count]{"staleness"} = 0 if ($have_stale);
    $count++;

    open NUDGE_IDX, $idx_file or die "can't open $idx_file: $!\n";
    my $snapshot_type = <NUDGE_IDX>;   # Constant or variable no. of snapshots?
    $const_snapshots = 1 if ($snapshot_type =~ /^constant snapshots/);
    while (<NUDGE_IDX>) {
        chomp;
        my ($nudge_num, $ss_log_pos, $st_log_pos) = split /,/;

        # Some error checking: nudge numbers should be sequential and log
        # file positions should be positive.
        #
        die "malformed nudge idx file: $nudge_num isn't $count\n"
            if ($nudge_num != $count);
        die "malformed nudge idx file: invalid snapshot log index ".
            "$ss_log_pos for nudge $nudge_num\n" if ($ss_log_pos <= 0);
        die "malformed nudge idx file: invalid staleness log index ".
            "$st_log_pos for nudge $nudge_num\n"
            if ($have_stale && $st_log_pos <= 0);

        # The index file stores the file position marking the end of data
        # dumped for each nudge, i.e., the file position of the begining of new
        # data post nudge.
        $nudge[$count]{"snapshot"} = $ss_log_pos;
        $nudge[$count]{"staleness"} = $st_log_pos if ($have_stale);
        $count++;
    }
    close NUDGE_IDX;

    $nudge[$count]{"snapshot"} = (stat($snapshot_logfile))[$fsize_idx];
    $nudge[$count]{"staleness"} = (stat($staleness_logfile))[$fsize_idx]
        if ($have_stale);

    return ($const_snapshots, $count - 1);
}

#-------------------------------------------------------------------------------
# Processes all the log files created by Dr. HeapStat client, viz., nudge.idx,
# snapshot.log, staleness.log (optionally) and callstack.log in that order.
#
# If $verbose is set, indices for {snapshot,staleness,callstack}.log and the
# snapshot summary are written to files (callstack index is actually created by
# process_callstack_log() which is invoked in this routine).  Indices contain
# snapshot IDs and their corresponding file locations and sizes in the
# respective log files.
#
# FIXME: Use indices like nudge.idx to avoid a pass through big
# {snapshot,staleness,callstack}.log files.  Startup time suffers with each
# additional log processed and users can easily be put off for large apps.
#
# CAUTION: Don't change the order in which logs are processed in this routine.
#
sub process_all_logs()
{
    # Nudge index should read in first as that is what is used to determine
    # where and how much to read from other log files.
    process_nudges();

    # Process snapshot and staleness logs before sorting and handling peak
    # snapshots.  Note: there is a 1-to-1 correspondence between snapshots
    # in both logs, so their data is kept together in @snapshots().
    # Processing of staleness assumes that snapshot log file was read first.
    # Don't change order.
    my @snapshots = ();
    process_log($snapshot_logfile, "snapshot", \@snapshots);
    process_log($staleness_logfile, "staleness", \@snapshots) if ($have_stale);

    # Snapshots in the log file are numbered sequentially but aren't sorted by
    # the x-axis value, so sort them and re-number them.  This way the user
    # will see snapshots in the order they were taken and with an increasing
    # snapshot number.  PR 544598.
    #
    @sorted_ss = sort {$a->{x_axis_val} <=> $b->{x_axis_val}} @snapshots;

    process_peak_snapshots(\@sorted_ss);

    if ($verbose) {     # Create index files for debugging.
        my $ss_idx_file = $logdir."/snapshot.idx";
        open SS_IDX, ">$ss_idx_file" or die "can't open $ss_idx_file: $!\n";
        if ($have_stale) {
            my $stale_idx_file = $logdir."/staleness.idx";
            open STALE_IDX, ">$stale_idx_file" or
                die "can't open $stale_idx_file: $!\n";
        }
    }

    # Re-number the sorted snapshots in the snapshot array and indices.
    my $i = 0;
    foreach my $snapshot (@sorted_ss) {
        ${$snapshot}{"id"} = $i;    # explicitly re-number the snapshot
        $snapshot_idx[$i]{"pos"} = ${$snapshot}{"snapshot_pos"};
        $snapshot_idx[$i]{"size"} = ${$snapshot}{"snapshot_size"};
        if ($have_stale) {
            $staleness_idx[$i]{"pos"} = ${$snapshot}{"staleness_pos"};
            $staleness_idx[$i]{"size"} = ${$snapshot}{"staleness_size"};
        }
        if ($verbose) {
            print SS_IDX $snapshot_idx[$i]{"pos"}." ".
                         $snapshot_idx[$i]{"size"}."\n";
            print STALE_IDX $staleness_idx[$i]{"pos"}." ".
                            $stalenes_idx[$i]{"size"}."\n" if ($have_stale);
        }
        $i++;
    }
    $total_ss = $i;

    if ($verbose) {
        close SS_IDX;
        close STALE_IDX if ($have_stale);
    }

    # Processing the callstack log goes last.
    process_callstack_log($cstack_logfile, $logdir."/callstack.idx");
}

#-------------------------------------------------------------------------------
# Creates an index for a callstack log.  Index contains callstack IDs, their
# corresponding file location and size in the callstack log.  If $verbose is
# set, the index is written to files.
#
# FIXME: Use indices like nudge.idx to avoid a pass through big
# {snapshot,staleness,callstack}.log files.  Startup time suffers with each
# additional log processed and users can easily be put off for large apps.
#
sub process_callstack_log($log_file_in, $idx_file_in)
{
    my ($log_file, $idx_file) = @_;
    my $i = 0;

    open LOG, $log_file or die "can't open $log_file: $!\n";
    open IDX, ">$idx_file" or die "can't open $idx_file: $!\n" if ($verbose);
    while (<LOG>) {
        if (/^CALLSTACK\s*(\d+)/) {
            $i++;
            die "Call stack numbers in $log_file aren't sequential from 1.  ".
                "Possible bug in heap profile collection.\n" if ($i != $1);

            my $pos = file_pos_before_read(tell LOG, length, $log_file);
            $cstack_idx[$i]{"pos"} = $pos;

            # Only when reading the next callstack can the size of the previous
            # one in the log file be computed.
            if ($i > 0) {
                # Unlike the snapshot log, callstack log doesn't have to be
                # sorted, so the size of the callstack entry isn't needed.  We
                # still store it so that a common get_using_index() can be used
                # for both snapshot and callstack logs.
                $cstack_idx[$i-1]{"size"} = $pos - $cstack_idx[$i-1]{"pos"};
                print IDX $cstack_idx[$i-1]{"pos"}." ".
                          $cstack_idx[$i-1]{"size"}."\n" if ($verbose);
            }
        } elsif (/^LOG END/) {
            # Compute the last callstack's size.
            my $pos = file_pos_before_read(tell LOG, length, $log_file);
            if ($i >= 0) {
                $cstack_idx[$i]{"size"} = $pos - $cstack_idx[$i1]{"pos"};
                print IDX $cstack_idx[$i]{"pos"}." ".
                          $cstack_idx[$i]{"size"}."\n" if ($verbose);
            }
            last;       # No point in trying to read the log file again.
        }
    }
    close LOG;
    close IDX if ($verbose);
}

#-------------------------------------------------------------------------------
# Creates a XML string containing the summary of 50 snapshots within the range
# of snapshots specified from $from_ss to $to_ss.  If the range is more than 50
# snapshots, 50 are sampled at uniform distances, else all the snapshots in the
# range are returned.  When the vistool makes the first request, it doesn't
# know the total number of snapshots available, so will make its range 0 to 0 -
# that is handled by this routine.  PR 581809.
#
# NOTE: summary file will be overwritten for each snapshot request - ok, since
# it is only for debugging - appending can cause a lot of disk space to be used
# quickly.
#
sub create_snapshot_summary_xml($from_ss, $to_ss)
{
    my ($from_ss, $to_ss) = @_;
    my $snapshots_shown = 50;   # show 50 data points in the graph; conservative
    my ($delta, $i);

    if ($verbose) {     # Create xml file for debugging
        my $sum_file = $logdir."/snapshot_summary.xml";
        open SUM, ">$sum_file" or die "can't open $sum_file: $!\n";
    }

    my $snapshot_summary_xml = "<snapshot_summary ".
                                   "totSnapshots=\"$total_ss\" ".
                                   "xAxisLabel=\"$xaxis_label\" ".
                                   "hasStale=\"";
    if ($have_stale) {
        if ($stale_since > -1) {
            $snapshot_summary_xml .= "yes\" staleType=\"since\" ".
                                     "staleTime=\"$stale_since\">\n";
        } else {
            $snapshot_summary_xml .= "yes\" staleType=\"for\" ".
                                     "staleTime=\"$stale_for\">\n";
        }
    } else {
        $snapshot_summary_xml .= "no\">\n";
    }

    die "invalid summary request: from $from_ss to $to_ss - possible bug\n"
        if ($from_ss < 0 || $to_ss < 0);

    # When the vistool makes the first summary request, it doesn't know the
    # number snapshots in the log, so sends zero.
    $to_ss = $total_ss if ($to_ss == 0);
    if (($to_ss - $from_ss + 1) > $snapshots_shown) {
        $delta = ($to_ss - $from_ss + 1) / $snapshots_shown;
    } else {
        # Note: be careful to not include the same snapshot twice!  If the
        # value of $delta is less than 1, then it can happen.  If the total
        # number of snapshots is less than $snapshots_shown then just show all
        # snapshots.
        $delta = 1;
        $snapshots_shown = $to_ss - $from_ss + 1;
    }
    my $prev_ss_num = -1;
    for ($i = 0; $i <= $snapshots_shown; $i++) {
        my $ss_num = int($from_ss + ($i * $delta));
        my $snapshot = $sorted_ss[$ss_num];
        die "snapshot sampling chose the same snapshot twice: $ss_num ".
            "for range $from_ss to $to_ss\n" if ($ss_num == $prev_ss_num);
        $prev_ss_num = $ss_num;

        $snapshot_summary_xml .= "\t<snapshot id=\"".${$snapshot}{"id"}."\"".
                                 " totMemReq=\"".${$snapshot}{"totMemReq"}."\"".
                                 " totMemPad=\"".${$snapshot}{"totMemPad"}."\"".
                                 " totMemTot=\"".${$snapshot}{"totMemTot"}."\"";
        $snapshot_summary_xml .= " totMemStale=\"".${$snapshot}{"totMemStale"}."\""
            if ($have_stale);
        $snapshot_summary_xml .= "/>\n";
    }
    $snapshot_summary_xml .= "</snapshot_summary>";

    if ($verbose) {
        print SUM $snapshot_summary_xml, "\n";
        close SUM;
    }

    return $snapshot_summary_xml;
}

#-------------------------------------------------------------------------------
# Converts a snapshot string into XML, sorts it and sends ($to-$from) callstack
# info in the snapshot starting at $from (after sort).
# FIXME: Sorting done only on memTot, not parameterized based on client request
#
sub create_snapshot_xml($snapshot_str, $staleness_str, $from, $to)
{
    my ($snapshot_str, $staleness_str, $from, $to) = @_;
    my $xml = "";
    my %snapshot_details = ();
    my @sorted_cstack_ids = ();
    my ($snapshot_id, $xaxis);
    my $num_cstacks = 0;

    # Parse the snapshot string (it contains the whole snapshot).
    foreach my $str (split /\n/, $snapshot_str) {
        if ($str =~ /^SNAPSHOT\s*#\s*(\d+)\s*@\s*(\d+)/) {
            $snapshot_id = $1;
            $xaxis = $2;
        } elsif ($str =~ /^(\d+),(\d+),(\d+),(\d+),(\d+)/) {
            $snapshot_details{$1}{"num"} = $2;
            $snapshot_details{$1}{"memReq"} = $3;
            # data from libdrheapstat.so is just delta for the next two, so add
            # them up
            $snapshot_details{$1}{"memPad"} = $3 + $4;
            $snapshot_details{$1}{"memTot"} = $3 + $4 + $5;
            $snapshot_details{$1}{"memStale"} = 0 if ($have_stale);
            $num_cstacks++;
        }
    }

    # If it exists, parse the staleness string (it contains the whole staleness
    # snapshot).
    if ($have_stale) {
        my $ss_time = 0;    # Time at which snapshot was taken.
        foreach my $str (split /\n/, $staleness_str) {
            if ($str =~ /^SNAPSHOT\s*#\s*(\d+)\s+@\s+(\d+)\s+(\w+)/) {
                $ss_time = $2;      # Used for computing -stale_for graph data.
            } elsif ($str =~ /^(\d+),(\d+),(\d+)/) {
                $snapshot_details{$1}{"memStale"} += $2
                    if (is_stale($ss_time, $3));
            } elsif ($str =~ /^LOG END/ || $str =~ /^NUDGE/) {
                # Ignore these lines.
            } else {
                die "Invalid format for staleness data:\n$staleness_str";
            }
        }
    }

    # FIXME: when sorting is parameterized, this has to change - probably can
    # get sort key name in a var from client and use that instead of the
    # hardcoded "memTot".
    # Note: sorting based on the 3-frame header is going to be super expensive
    # as all 30k entries would have to have their callstacks parsed before
    # doing so - so might want to limit it to the 50 displayed in the snapshot
    # window.
    @sorted_cstack_ids =  sort {
        # We want it descending so that we can pick the top $from-$to elements.
        $snapshot_details{$b}{"memTot"} <=> $snapshot_details{$a}{"memTot"}
    } keys %snapshot_details;

    $xml .= "<snapshot id=\"$snapshot_id\" xaxis=\"$xaxis\" ".
            "numCallstacks=\"$num_cstacks\">\n";

    # If more callstacks than available are requested adjust accordingly.  This
    # happens when fewer callstacks are available than the default request of
    # 50 from the vistool.
    if ($to > $num_cstacks) {
        my $num_cstacks_req = $to - $from;
        $to = $num_cstacks;
        $from = $to - $num_cstacks_req;
        $from = 1 if ($from < 1);
    }

    # Client will ask for, say, first 50 callstacks in a snapshot, like 1-50 -
    # internally here it is an array, so array elements are 0 to 49, i.e., must
    # subract one.
    $from--;
    $to--;
    foreach my $cstack_id (@sorted_cstack_ids[$from .. $to]) {
        # FIXME: this can be optimized - prevent multiple log file reads - can
        #        slow down - may be a cache in get_using_idx instead of
        #        %callstack_cache would be a better idea
        my $cstack_str = get_using_idx($cstack_logfile,
                                       \@cstack_idx, $cstack_id);
        my $cstack_hdr = create_callstack_header($cstack_str);
        $xml .= "\t<callstack id=\"$cstack_id\" ".
                "hdr=\"".$cstack_hdr."\" ".
                "num=\"".$snapshot_details{$cstack_id}{"num"}."\" ".
                "memReq=\"".$snapshot_details{$cstack_id}{"memReq"}."\" ".
                "memPad=\"".$snapshot_details{$cstack_id}{"memPad"}."\" ".
                "memTot=\"".$snapshot_details{$cstack_id}{"memTot"}."\"";
        $xml .= " memStale=\"".$snapshot_details{$cstack_id}{"memStale"}."\""
            if ($have_stale);
        $xml .= "/>\n";
    }

    $xml .= create_file_list_xml(\%snapshot_details) if ($group_by_files);

    $xml .= "</snapshot>";
    return $xml;
}

#-------------------------------------------------------------------------------
# For a given snapshot, this routine breaks down memory usage by source files.
# It returns the file list as XML.  It computes file-wise memory usage by
# looking for the first frame whose module isn't a system library and uses the
# source file corresponding to that symbol as the file to account against.
# PR 584617.
#
# Note: this may be really slow for hostd as it has 30k callstacks per
# snapshot.  That is part of the reason why I am grouping by the first
# non-system library frame I see in the callstack, i.e., I reduce the symbol
# lookups need for each callstack to just one.
#
# Note: Limiting the number of source files displayed to 50 for now as hostd
# can easily utilize thousands of files in a snapshot and that would bring the
# vistool down.  If users want we can add "previous" and "next" buttons similar
# to callstack table in the gui.
#
sub create_file_list_xml()
{
    my ($snapshot) = @_;
    my %src_files = ();

    # FIXME: provide ENV var for a user to specify more system libraries.  Keep
    # the default to a minimum to avoid performance problems.
    my @syslibs = ("libc.so", "libstdc++.so", "libpthreads.so",
                   "ld-linux.so", "libdl.so", "libcrypto.so",
                   "libpam.so", "libssl.so", "libcurl.so", "libz.so");
    my $xml = "";

    foreach my $cstack_id (keys %$snapshot) {
        my $fr_count = -1;      # PR 543863: to show actual line in source file
        my $cstack_str = get_using_idx($cstack_logfile, \@cstack_idx, $cstack_id);
        foreach my $frame (split /\n/, $cstack_str) {
            $fr_count++;
            # Grouping is done by the first non system library frame seen in the
            # callstack.
            if ($frame =~ /\s+<(.*)\+(.*)>/) {
                my ($module, $offset) = ($1, $2);
                # \Q...\E for PR 420898.  Else libstdc++'s + will be used as a
                # meta character.  Match all versions of the system libraries
                # by matching a .# at the end.  Keeps the list small.
                # Note: keep only the library name inside \Q & \E, else meta
                # characters will be matched literally!
                my $matched = grep {$module =~ /^\Q$_\E(\.\d)+/} @syslibs;
                next if ($matched);     # skip system libraries

                my ($symbol, $file_and_line) = lookup_addr("<$module+$offset>",
                                                           $fr_count ? 0 : -1);

                # Note: we don't use the line number here, but in future we may
                # want to show all the lines in each file that were consuming
                # memory.
                my ($file) = split /:/, $file_and_line;

                # If file name isn't available then add it to an unknown group.
                $file = "unknown" if ($file_and_line eq "??:0");

                $src_files{$file}{"memReq"} += $$snapshot{$cstack_id}{"memReq"};
                $src_files{$file}{"memPad"} += $$snapshot{$cstack_id}{"memPad"};
                $src_files{$file}{"memTot"} += $$snapshot{$cstack_id}{"memTot"};
                $src_files{$file}{"memStale"} += $$snapshot{$cstack_id}{"memStale"};

                # Done with this callstack after the first non-system library
                # with srcfile is found.
                last;
            }
        }
    }

    # Sort src_files by memTot.  Note, for hash sorting, only the keys are
    # returned, which we still have to use to get the actual memory consumption
    # data.
    my @sorted_src_files = sort {
        # We want it descending so that we can pick the top 50 files.
        $src_files{$b}{"memTot"} <=> $src_files{$a}{"memTot"}
    } keys %src_files;
    my $file_count = 0;
    foreach my $src_file (@sorted_src_files) {
        # add to file_grouping_xml
        $xml .= "\t<srcFile name=\"$src_file\" ".
                "memReq=\"".$src_files{$src_file}{"memReq"}."\" ".
                "memPad=\"".$src_files{$src_file}{"memPad"}."\" ".
                "memTot=\"".$src_files{$src_file}{"memTot"}."\"";
        $xml .= " memStale=\"".$src_files{$src_file}{"memStale"}."\""
            if ($have_stale);
        $xml .= "/>\n";

        last if (++$file_count == 50);  # limit to 50 files in the list
    }
    return $xml;
}

#-------------------------------------------------------------------------------
# Converts a call stack string into XML.
#
sub create_callstack_xml($cstack_str_in)
{
    my ($cstack_str) = @_;
    my $symbol;
    my $src_file;
    my $xml = "";
    # PR 543863: subtract one from retaddrs in callstacks so the line#
    # is for the call and not for the next source code line, but only
    # for symbol lookup so we still display a valid instr addr.
    # We assume first frame is not a retaddr.
    my $addr_sym_disp = 0;

    foreach my $str (split /\n/, $cstack_str) {
        if ($str =~ /^CALLSTACK\s*(\d+)/) {
            $xml .= "<callstack id=\"$1\">\n";
        } elsif ($str =~ /\s+<(.*)>/) {
            ($symbol, $src_file) = lookup_addr("<$1>", $addr_sym_disp);
            # Can't use < or > in xml file, but templates have them.
            $symbol =~ s/</&lt;/g;
            $symbol =~ s/>/&gt;/g;
            $xml .= "\t<frame>\n";
            $xml .= "\t\t<symbol>$symbol</symbol>\n";
            $xml .= "\t\t<file>$src_file</file>\n";
            $xml .= "\t</frame>\n";
        } else {
            print stderr "unknown callstack line $str\n" if ($verbose);
        }
        $addr_sym_disp = -1; # now past 1st frame
    }
    $xml .= "</callstack>";
    return $xml;
}

#-------------------------------------------------------------------------------
# Converts a call stack string into a 3-frame header string with the top 3
# frames.  This is to be shown in the snapshot summary table.
# FIXME: can be merged with create_callstack_xml & along with a %callstack_cache
#        for better performance
#
sub create_callstack_header($cstack_str_in)
{
    my ($cstack_str) = @_;
    my $symbol;
    my $src_file;
    my $xml = "";
    my $header = "";
    my $num_fr = 0;
    # PR 543863: subtract one from retaddrs in callstacks so the line#
    # is for the call and not for the next source code line, but only
    # for symbol lookup so we still display a valid instr addr.
    # We assume first frame is not a retaddr.
    my $addr_sym_disp = 0;

    foreach my $str (split /\n/, $cstack_str) {
        if ($str =~ /^CALLSTACK\s*(\d+)/) {
            $xml .= "<callstack id=\"$1\">\n";
            # callstack #1 is a special case
            return "Allocations before Dr. HeapStat got control" if ($1 == 1);
        } elsif ($str =~ /\s+<(.*)>/) {
            ($symbol, $src_file) = lookup_addr("<$1>", $addr_sym_disp);

            # Don't have to worry about <> in a symbol because we rip out
            # libnames (which can have <nosyms>) and use only function names in
            # templated symbols.
            $symbol = $1 if ($symbol =~ /.*!(.*)/);     # discard library name
            # get only func name for templated symbols
            $symbol = $1 if ($symbol =~ /.*::([^:]+)\(/);
            $symbol = $1 if ($symbol =~ /(.*)<.*>/);    # remove template info
            $header .= " &lt;-- " if ($num_fr > 0);     # use escape for <
            $header .= $symbol;
            $num_fr++;
            last if ($num_fr == 3);     # PR 544640 - empty call stack headers
        } else {
            print stderr "unknown callstack line $str\n" if ($verbose);
        }
        $addr_sym_disp = -1; # now past 1st frame
    }
    return $header;
}

#-------------------------------------------------------------------------------
# Retrieves record $num_in from $file_in using $idx_ref_in and returns a string.
#
sub get_using_idx($file_in, $idx_ref_in, $num_in)
{
    my ($file, $idx_ref, $num) = @_;
    my $str;

    die "no entry index for $num\n" if (!defined(${$idx_ref}[$num]));
    open INPUT, $file or die "can't open $file: $!\n";
    my $pos = ${$idx_ref}[$num]{"pos"};
    my $size = ${$idx_ref}[$num]{"size"};
    seek INPUT, $pos, SEEK_SET || die "can't seek to $pos in $file: $!\n";
    read INPUT, $str, $size || die "can't read $size bytes at $pos in $file: $!\n";
    close INPUT;
    return $str;
}

#-------------------------------------------------------------------------------
# Helper routine to avoid some repeated code.
#
sub file_pos_before_read()
{
    my ($cur_pos, $bytes_read, $file) = @_;
    die "tell failed on $file: $!\n" if ($cur_pos == -1);
    return $cur_pos - $bytes_read;
}

#-------------------------------------------------------------------------------
# Returns 1 if the $file_in ends with "LOG END", 0 otherwise.
#
sub has_log_end($file_in)
{
    my ($file) = @_;
    my $marker = "LOG END\n";
    my $fpos = (stat($file))[$fsize_idx] - length($marker);

    open LOG_END, $file or die "Can't open file for LOG END check: $!\n";
    seek LOG_END, $fpos, SEEK_SET;
    $line = <LOG_END>;
    return $line =~ /$marker/ ? 1 : 0;
    close LOG_END;
}

#-------------------------------------------------------------------------------
# PR 476018 - Peak snapshots can have the same x-axis value as another
# snapshot.  This routine uses the snapshot representing higher memory usage
# and discards the other one.  For a constant number of snapshots there will be
# just one overlap at maximum as there is only one peak snapshot.  However, for
# a variable number of snapshots when nudge is used there can be many as peak
# snapshots get reset on nudge, i.e., one peak snapshot per nudge  Thus, we
# must loop through the whole array even if one overlapping snapshot was
# handled.
#
# The argument $ss_aref is a reference to the snapshots array.  This
# routine assumes that it is sorted by the x_axis_val field.
#
# Note: This routine will also eliminate non-peak snapshots (regular ones) that
# are duplicates, i.e., ones that have the same x-axis value.  It will do so by
# selecting the one which represents higher memory use (instead of the most
# recent; it's better to err on side of showing higher memory usage, when it
# isn't clear whether older or newer is better).  Such duplicates happen
# because the client dumps the last active snapshot at process exit even if
# there was no allocation/deallocation activity since the last snapshot dumped;
# this is for all time units, but mostly seen in -time_{allocs,bytes}.
#
sub process_peak_snapshots($ss_aref)
{
    my ($ss_aref) = @_;
    my $prev = 0;
    my $i;

    for ($i = 1; $i < scalar(@{$ss_aref}); $i++) {
        if ($$ss_aref[$prev]{"x_axis_val"} == $$ss_aref[$i]{"x_axis_val"}) {
            # Overlapping snapshots detected.
            print "In $snapshot_logfile snapshots ", $$ss_aref[$prev]{"id"},
                  " and ", $$ss_aref[$i]{"id"}, " overlap.\n" if ($verbose);

            # If the current snapshot represents more memory usage than the
            # previous one, then update the previous one with the current one
            # and delete the current one.
            if ($$ss_aref[$prev]{"totMemReq"} < $$ss_aref[$i]{"totMemReq"}) {
                $$ss_aref[$prev] = $$ss_aref[$i]
            } else {
                undef %{$ss_aref[$i]};  # Delete unused hash.
            }
            splice(@{$ss_aref}, $i, 1);

            # We just deleted the current element, so next element has been
            # pulled up, which means $i now points to the next element.  Loop
            # increment will make us skip it if we don't fix it here.
            $i--;
        } elsif ($$ss_aref[$prev]{"x_axis_val"} > $$ss_aref[$i]{"x_axis_val"}) {
            # Assert that the array is sorted.
            die "Snapshot array isn't sorted by x_axis_val\n";
        } else {

            # If no match was found then the current snapshot becomes the
            # previous.  If a match was found the current snapshot gets
            # deleted, so previous remains the same.
            $prev = $i;
        }
    }
}

#-------------------------------------------------------------------------------
# Processes all the snapshots in {snapshot,staleness}.log depending upon the
# $log_type specified and stores all snapshots in the LoH reference ($ss_aref)
# passed.
#
# FIXME: use index file just like nudge.idx, avoids a pass through a big logfile
#
sub process_log($log_file, $log_type, $ss_aref)
{
    my ($log_file, $log_type, $ss_aref) = @_;

    my ($is_snapshot_log, $is_staleness_log) = (0, 0);
    if ($log_type eq "snapshot") {
        $is_snapshot_log = 1;
    } elsif ($log_type eq "staleness") {
        $is_staleness_log = 1;
    } else {
        die "unknown log type: $log_type\n"
    }

    open LOG, $log_file or die "can't open $log_file: $!\n";

    # Decide which location to start reading snapshot info from.  PR 502468.
    my $bytes_read = 0;
    if ($from_nudge > 0) {
        # Offset begins with 0, so bytes read and new offset will be the same.
        $bytes_read = $nudge[$from_nudge]{$log_type};
        seek LOG, $nudge[$from_nudge]{$log_type}, SEEK_SET;
    }
    my $i = -1;
    my $ss_time = 0;    # Time at which snapshot was taken.
    while (<LOG>) {
        # Store length of line read for later use, $_ can be overwritten.
        my $line_len = length ($_);
        $bytes_read += $line_len;
        if (/^SNAPSHOT\s*#\s*(\d+)\s+@\s+(\d+)\s+(\w+)/) {
            $i++;
            if ($is_snapshot_log) {     # snapshot log specific code
                $$ss_aref[$i]{"id"} = $1;
                $$ss_aref[$i]{"x_axis_val"} = $2;
                $xaxis_label = $3;
            } elsif ($is_staleness_log) {       # staleness log specific
                # We assume that staleness.log was read first, hence this check.
                if ($$ss_aref[$i]{"id"} != $1 ||
                    $$ss_aref[$i]{"x_axis_val"} != $2 ||
                    $xaxis_label != $3) {
                    die "$log_file doesn't correspond to $snapshot_logfile.\n";
                }
                # Initialize staleness count to zero here because there can be
                # (and were) snapshots in the staleness log that have no
                # entries.  Otherwise the graph gets messed up.
                $$ss_aref[$i]{"totMemStale"} = 0;
                $ss_time = $2;      # Used for computing -stale_for graph data.
            }
            my $pos = &file_pos_before_read(tell LOG, $line_len, $log_file);
            $$ss_aref[$i]{$log_type."_pos"} = $pos;

            # Only when reading the next snapshot can the size of the previous
            # one in the log file be computed.  As snapshot log isn't sorted,
            # the size of each snapshot entry has to be stored, can't just
            # subtract from next entry as we are sorting them below.
            $$ss_aref[$i-1]{$log_type."_size"} = $pos - $$ss_aref[$i-1]{$log_type."_pos"}
                if ($i > 0);
        } elsif (/^total:\s*(\d+),(\d+),(\d+),(\d+)/) {
            if ($is_snapshot_log) {     # snapshot log specific code
                # $1 - the number of mallocs is ignored for now, not currently
                # displayed in vistool - a FIXME?

                $$ss_aref[$i]{"totMemReq"} = $2;
                $$ss_aref[$i]{"totMemPad"} = $3;
                $$ss_aref[$i]{"totMemTot"} = $4;
            }
        } elsif (/^(\d+),(\d+),(\d+)$/) {
            if ($is_staleness_log) {        # staleness log specific
                # $1 is the call stack id and $2 is the bytes requested for a
                # particular malloc and $3 is the absolute time (relative to
                # start of process) since last access.

                die "$logfile doesn't have a valid snapshot time for snapshot ".
                    "at $bytes_read.\n" if ($ss_time <= 0 );

                $$ss_aref[$i]{"totMemStale"} += $2 if (is_stale($ss_time, $3));
            }
        } elsif (/^LOG END/ || /^NUDGE/) {
            # Compute the size of the last snapshot before a nudge or log end.
            my $pos = &file_pos_before_read(tell LOG, length, $log_file);
            $$ss_aref[$i]{$log_type."_size"} = $pos - $$ss_aref[$i]{$log_type."_pos"}
                if ($i >= 0);
        }
        last if ($bytes_read >= $nudge[$to_nudge]{$log_type});
    }
    close LOG;
}

#-------------------------------------------------------------------------------
# Returns 1 if the last access time of a malloc was earlier than what the user
# specified (either via -stale_since or -stale_for), 0 otherwise.
#
sub is_stale($snapshot_time, $last_access_time)
{
    my ($snapshot_time, $last_access_time) = @_;

    if ($stale_since > -1) {
        # If the last access time for a malloc was less than what the user
        # specified, then that malloc is stale.
        return 1 if ($last_access_time < $stale_since);
    } elsif ($stale_for > -1) {
        # If the last access time for a malloc was less than the current
        # snapshot time by the time specified by the user, then that malloc is
        # stale.
        return 1 if ($last_access_time <= ($snapshot_time - $stale_for));
    } else {
        die "invalid -stale_since ($stale_since) or ".
            "invalid -stale_for ($stale_for) values\n";
    }
    return 0;
}

#-------------------------------------------------------------------------------
# CAUTION: All code below are duplicates of drmemory/postprocess.pl except,
# 1. lookup_addr() has been modified to work on a single modoffs,
# 2. mod_has_dbg_info() has been modified to cache results
# 3. init_libsearch_path() uses $ENV{"DRHEAPSTAT_LIB_PATH"} instead of DRMEMORY*
#       and the corresponding strings
#
sub lookup_addr($modoffs_in, $addr_sym_disp)
{
    my ($modoffs, $addr_sym_disp) = @_;
    my $module = "";
    my $off = 0;
    my $symout = '';

    # Lookup symbol and file name cache.  PR 420921.
    if (defined $symfile_cache{$modoffs}) {
        return $symfile_cache{$modoffs}{"symbol"},
               $symfile_cache{$modoffs}{"file"};
    }

    # To use offset with addr2line needs to be relative to section.
    if ($modoffs =~ /<(.*)\+0x([a-f0-9]+)>/) {
        $module = $1;
        $offs = hex($2);
    } else {
        print "Invalid modoffs $modoffs\n" if ($modoffs ne '<not in a module>');
        return "<unknown symbol>", "??:0";
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

    return $symfile_cache{$modoffs}{"symbol"}, $symfile_cache{$modoffs}{"file"};
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
        @libsearch = ( split(':', $ENV{"DRHEAPSTAT_LIB_PATH"}) );

        &vmk_bora_paths(\@libsearch, $use_vmtree, $no_sys_paths, $is_vmk)
            if ($vs_vmk);

        # PR 485412: replaced libc routines show up inside drmem lib
        push @libsearch, "$scriptpath/$drmem_dir";

        # System paths go last to allow user specified paths to be searched first.
        if (!$no_sys_paths) {
            push @libsearch, ('/lib',
                              '/usr/lib',
                              '/usr/lib/vmware',
                              '/usr/lib/vmware/vmacore',
                              # standard debuginfo paths for linux
                              '/usr/lib/debug/lib',
                              '/usr/lib/debug/usr/lib');
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
        if ($verbose_verbose); # huge list so not printing
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
    my $tryagain = 1;
    my $found = 0;

    while ($tryagain) {
        $tryagain = 0;
        foreach $path (@libsearch) {
            if (-f "$path/$modname") {
                $fullpath = "$path/$modname";

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
            }
        }
    }

    my $set_path_msg = ($is_vmk) ?
        "set DRHEAPSTAT_LIB_PATH and/or VMTREE env vars\n" :
        "set DRHEAPSTAT_LIB_PATH env var\n";
    if ($fullpath eq "") {
        print "WARNING: module $module not found: ".$set_path_msg;
    } elsif ($modname =~ /.debug$/ && !($fullpath =~ /.debug$/)) {
        print "WARNING: can't find .debug file for $module: ".$set_path_msg;
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
    my ($modpath, $addr, $pid, $read, $write);
    ($modpath, $addr) = @_;
    return '' if ($modpath eq '');

    # If $addrcmd eq "", we're using addr2line for modules and
    # executable and we need to batch by module.
    # Else we're using winsyms.exe, which to avoid having a process
    # per dll on Windows, takes in a dll and address for each query.
    # In the winsyms case we will use addr2line for a cygwin .exe.
    # We split args up to avoid invoking through a shell, so we can get the
    # real pid and can actually kill it (for Windows where eof not sent).
    my ($pipekey, $cmdline);
    if (&use_addr2line($modpath)) {
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
    if (!defined($addr_pipes{$pipekey}{"write"})) {
        if (-e $modpath) {
            my $pid;
            # open2 throws exception on failure so use eval to catch it
            eval { # try
                $pid = open2($read, $write, @cmdline);
                1;
            } or do { # catch
                die "$@ running @cmdline: $!\n" if ($@ and $@ =~ /^open2:/);
            };
            print stderr "Running $pid = \"".join(' ', @cmdline)."\"\n" if ($verbose);
            # we do not want coredumps when addr2line crashes (PR 558271)
            &vmk_disable_cores($pid) if ($is_vmk);
            $addr_pipes{$pipekey}{"pid"} = $pid;
            $addr_pipes{$pipekey}{"read"} = $read;
            $addr_pipes{$pipekey}{"write"} = $write;
        } else {
            print "WARNING: can't find $modpath to do symbol lookup\n";
            return "?\n??:0";
        }
    } else {
        $read = $addr_pipes{$pipekey}{"read"};
        $write = $addr_pipes{$pipekey}{"write"};
    }
    if ($pipekey eq $winsyms_key) {
        print $write "$modpath;$addr\n";     # write modpath;addr to pipe
    } else {
        print $write "$addr\n";     # write addr to pipe
    }
    my $out = <$read>;          # read symbol from pipe
    return $out .= <$read>;     # read file from pipe
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
