#!/bin/sh

# **********************************************************
# Copyright (c) 2014-2017 Google, Inc.    All rights reserved.
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

# Developers should run this script once in each repository
# immediately after cloning.

# Set up submodules
git submodule update --init

# Convert CRLF to LF on commit but not checkout:
git config core.autocrlf input

# Highlight tabs at start of line and check in pre-commit:
git config core.whitespace blank-at-eol,tab-in-indent

# Pull should always rebase:
git config branch.autosetuprebase always

# Aliases for our workflow:
git config alias.newbranch "!sh -c \"git checkout --track -b \$1 origin/master\""
git config alias.split "!sh -c \"git checkout -b \$1 \$2 && git branch --set-upstream-to=origin/master \$1\""
# Shell aliases always run from the root dir.  Use "$@" to preserve quoting.
git config alias.review "!myf() { make/git/git_review.sh \"\$@\"; }; myf"
git config alias.pullall "!myf() { make/git/git_pullall.sh \"\$@\"; }; myf"

# Commit template
git config commit.template make/git/commit-template.txt

# Set up hooks
cp make/git/hook-pre-commit-launch.sh .git/hooks/pre-commit
cp make/git/hook-commit-msg-launch.sh .git/hooks/commit-msg

# Author name and email
# XXX: we could try to read in the info here
echo "Initial setup is complete."
echo Please ensure your author name is correct: \"$(git config user.name)\"
echo "  Run \"git config user.name New Name\" to update"
echo Please ensure your author email is correct: \"$(git config user.email)\"
echo "  Run \"git config user.email New Email\" to update"
