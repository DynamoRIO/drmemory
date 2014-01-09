#!/usr/bin/perl

# **********************************************************
# Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
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

# valgrind2drmemory.pl
#
# Converts legacy Valgrind suppression files into Dr. Memory's format
# Relies on "c++filt" being on the local system.
#
# This uses heuristics and is relatively fragile wrt complex types.
# Note that can't distinguish * in func param types from wildcard: not a big deal.

use Getopt::Long;

# symlinks are ok so just use $0
$usage = "Converts a legacy Valgrind Memcheck suppression file into a Dr. Memory suppression file\nUsage: $0 [-v] <valgrind-format-file> <output-file>\n";

my $verbose = 0;
if (!GetOptions("v" => \$verbose)) {
    die $usage;
}
die $usage unless ($#ARGV == 1);

my $fh_in;
my $fh_out;
my $supp_count = 0;
my $prob_count = 0;

my $infile = $ARGV[0];
my $outfile = $ARGV[1];
open($fh_in, "< $infile") || die "Unable to read $infile\n";
open($fh_out, "> $outfile") || die "Unable to write $outfile\n";

%type2drmem = ( "Memcheck:Addr" => "UNADDRESSABLE ACCESS",
                "Memcheck:Jump" => "UNADDRESSABLE ACCESS",
                "Memcheck:Value" => "UNINITIALIZED READ",
                "Memcheck:Cond" => "UNINITIALIZED READ",
                "Memcheck:Param" => "UNINITIALIZED READ", # XXX: could be unaddr!
                "Memcheck:Leak" => "LEAK",
                "Memcheck:Free" => "INVALID HEAP ARGUMENT",
                "Memcheck:Overlap" => "WARNING", # XXX i#156: NYI
                # Custom types added at Google
                "Memcheck:Uninitialized" => "UNINITIALIZED READ",
                "Memcheck:Unaddressable" => "UNADDRESSABLE ACCESS",
    );

while (next_line($fh_in, $fh_out, 1)) {
    if (/^{$/) {
        my $name = next_line($fh_in, $fh_out, 0);
        my $type = next_line($fh_in, $fh_out, 0);
        my $drmtype = $type;
        if ($type !~ /^Memcheck:/) {
            print "Ignoring unknown type $type\n";
            while (<$fh_in>) {
                last if (/^\s*}\s*$/);
            }
            next;
        }
        # we ignore the {1,2,4,8,16} after Addr or Value
        $drmtype =~ s/\d+$//;
        die "Unknown type $type\n" unless (defined($type2drmem{$drmtype}));
        $drmtype = $type2drmem{$drmtype};
        $supp_count++;
        print $fh_out "$drmtype\n";
        print $fh_out "name=$name\n";
        if ($type eq 'Memcheck:Param') {
            my $call = next_line($fh_in, $fh_out, 0);
            if (/([^\(]+)\(/) {
                s/socketcall\.//;
                print $fh_out "system call $1*\n";
            } elsif (/^(\.\.\.)$/) {
                print $fh_out "$1\n";
            } else {
                die "Unknown system call frame $_";
            }
        }
        while (next_line($fh_in, $fh_out, 0)) {
            last if (/^}$/);
            if (/^(\.\.\.)$/) {
                print $fh_out "$1\n";
            } elsif (/^obj:(.*)$/) {
                # remove path
                $mod = $1;
                $mod =~ s|^/.*/||;
                print $fh_out "$mod!*\n";
            } elsif (/^fun:(.*)$/) {
                my $fun = convert_fun($1);
                print $fh_out "*!$fun\n";
            } else {
                die "Unknown frame $_";
            }
        }
        print $fh_out "\n";
    }
}

close($fh_in);
close($fh_out);

print "Converted $supp_count suppressions\n";
print "Had problems with $prob_count frames\n";

sub next_line($fh_in, $fh_out, $fh_out, $eof_ok) {
    my ($fh_in, $fh_out, $eof_ok) = @_;
    while (<$fh_in>) {
        # throw out leading and trailing whitespace
        s/^\s*//;
        s/\s*$//;
        # skip but preserve comments and blank lines
        if (/^\s*\#/ || /^\s*$/) {
            print $fh_out "$_\n";
            next;
        }
        return $_;
    }
    die "File ended unexpectedly\n" if (!$eof_ok);
}

sub convert_fun($f) {
    my ($f) = @_;
    # We do our best but it's not always possible b/c of ambiguities in what
    # could match a wildcard.  But it's better to convert up front so
    # user can then edit in the proper format, rather than a perf hit
    # and complexities in client to match mangled (i#282).
    # Although this script is pretty hacky!
    my $ans = '';
    my $ignore_rest = 0;
    if ($f !~ /^_Z/ && $f !~ /^\*/) {
        $ans = $f;
        print "=> \"$ans\"\n" if ($verbose);
        return $ans;
    }
    if ($f =~ /\*/ || $f =~ /\?/) {
        # C++ mangled name with wildcards
        # Strategy: split by wildcard, try to translate each piece,
        # and put them back together
        @fsubs = split(/(\*|\?)/, $f); # keep splitters as entries
        foreach $fsub (@fsubs) {
            print "for $f processing \"$fsub\"\n" if ($verbose);
            if ($fsub eq '' || $fsub eq '*' || $fsub eq '?') {
                $ans .= $fsub;
                next;
            } elsif ($fsub =~ /^_Z[NL]?$/) {
                next;
            }
            last if ($ignore_rest); # we do include wildcards
            my $lookup = '';
            if ($fsub !~ /^_Z/) {
                $lookup = '_Z';
                if ($fsub =~ /^[0-9]/ ||
                    # We assume an E near the end means C++: we could
                    # be wrong but we have to make some assumptions
                    $fsub =~ /E[^0-9]*$/) {
                    # Nested scope
                    $lookup .= "N";
                }
                if ($fsub !~ /^[0-9]/) {
                    # Add length
                    my $end;
                    if ($fsub =~ /([CD][0-3])E/) {
                        $end = $`;
                    } else {
                        $end = index($fsub, 'E');
                    }
                    if ($end > 0) {
                        $lookup .= $end;
                    }
                }
                $lookup .= $fsub;
            } elsif ($fsub =~ /^_ZN/) {
                # walk the names to fix up length of final name (if ends in *)
                my $idx = 3; # skip _ZN
                while (substr($fsub, $idx) =~ /^(\d+)/) {
                    my $prev_idx = $idx;
                    print " idx=$idx\n" if ($verbose);
                    $idx += length($1) + $1;
                    print "  idx=$idx vs ".length($fsub)." and ".
                        substr($fsub, $prev_idx)."\n" if ($verbose);
                    if ($idx > length($fsub) &&
                        substr($fsub, $prev_idx) =~ /^(\d+)(.*)$/) {
                        my $wronglen = $1;
                        my $rest = $2;
                        my $reallen = length($rest);
                        print " replacing with $reallen and $rest\n" if ($verbose);
                        $fsub =~ s/$wronglen$rest/$reallen$rest/;
                    } elsif (substr($fsub, $idx) =~ /[CD]$/) {
                        # matching constructor/destructor
                        # oh boy: not easy to support: try for just C1
                        $fsub .= "1";
                        $ignore_rest = 1; # take wildcard but nothing else
                    }
                }
                $lookup .= $fsub;
            } else {
                $lookup = $fsub;
            }
            print "\trunning on \"$lookup\"\n" if ($verbose);
            my $filt = `c++filt $lookup`;
            # we don't bother to try and parse the whole thing and
            # find template I..E, etc.: just simple heuristics
            my $iter = 0;
            my $wild_template_end = 0;
            while ($iter++ < 6 && $filt =~ /^_Z/) {
                # try again w/ another end delim
                if ($fsub !~ /^_ZN/ && $lookup =~ /^_ZN/) {
                    # try _ZL
                    $lookup =~ s/^_ZN/_ZL/;
                } elsif ($lookup =~ /EM/) {
                    # remove the pointer-to-member altogether since
                    # if we add a type we'll want to wildcard it anyway:
                    # too complex.
                    $lookup =~ s/EM.*/E/;
                    # a hack: usually these are template params and we
                    # just removed one so we have to remove the ">"
                    $wild_template_end = 1 if ($lookup =~ /I/);
                } elsif ($lookup =~ /S[0-9]$/) {
                    $lookup .= "_";
                } elsif ($lookup =~ /EL/ && $lookup !~ /0E*$/) {
                    # L..0 == pointer to NULL or sthg:
                    # > c++filt _ZN5IDMapIN3IPC7Channel8ListenerEL23IDMapOwnershipSemantics0EE6RemoveEi
                    # IDMap<IPC::Channel::Listener, (IDMapOwnershipSemantics)0>::Remove(int)
                    $lookup .= "0";
                } else {
                    $lookup .= "E";
                }
                print "\ttrying again \"$lookup\"\n" if ($verbose);
                $filt = `c++filt $lookup`;
            }
            chomp $filt;
            if ($filt =~ /^_Z/) {
                # remove E's that we tried to add
                $filt =~ s/E+$//;
            }
            if ($wild_template_end) {
                $filt =~ s/>$//;
            }
            $ans .= $filt;
            print "\t=> \"$filt\"\n" if ($verbose);
        }
    } else {
        $ans = `c++filt $f`;
        chomp $ans;
    }
    if ($ans =~ /^_Z/) {
        $prob_count++;
        print stderr "WARNING: unable to de-mangle $f\n";
        # go with any function match: usually in middle of stack.
        # we warned the user on stderr already.
        # or would it be better to force mismatch since false pos is better
        # than false neg?
        $ans = "* # WARNING: failed on $ans";
    }
    # Remove parameter types, which DrMemory won't match against.
    # Seems like a very small risk of over-matching a different overload.
    $ans =~ s/\([^)]+\)//;
    print "=> \"$ans\"\n" if ($verbose);
    return $ans;
}
