#!/bin/bash

# **********************************************************
# Copyright (c) 2014 Google, Inc.    All rights reserved.
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

# This is the pre-commit git hook, which is run when a developer attempts
# to commit locally.

# Prevent committing to master
# The --short option is too recent to rely on so we use a bash expansion
# to remove refs/heads/.
branch=`git symbolic-ref -q HEAD`
if [ "${branch##*/}" == "master" ]; then
    exec 1>&2
    cat <<\EOF
Error: it looks like you're committing on master.
Use a topic branch instead.
Aborting commit.
EOF
    exit 1
fi

# Prevent mistaken submodule commits by checking whether committing
# submodule + other stuff and if so bail if the submodule version is older.
# We want to allow a submodule-only rollback.
# Prevent mistaken submodule commits by checking whether committing
# submodule + other stuff and if so bail if the submodule version is older.
# We want to allow a submodule-only rollback.
# XXX: this relies on several unix utilities which we assume are available
# on Windows.
dr_diff=`git diff --cached dynamorio`
if ! test -z "$dr_diff" ; then
    # dynamorio submodule is changed in the diff
    others=`git diff --cached --name-only | grep -v dynamorio`
    if ! test -z "$dr_diff" ; then
        # There's at least one other change.  Let's run git log on
        # oldhash..newhash to see which is newer.
        range=`git diff --cached dynamorio | grep Subproject | awk '{print $NF}' | xargs | sed 's/ /../'`
        between=`cd dynamorio && git log --pretty=oneline $range`
        if test -z "$between" ; then
            exec 1>&2
            cat <<\EOF
Error: the dynamorio submodule is being rolled back.
This is likely a mistake: did you pull but not run git submodule update?
Aborting commit.
EOF
            exit 1
        fi
    fi
fi

# XXX: move code style checks here from runsuite.cmake?
