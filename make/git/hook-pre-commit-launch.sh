#!/bin/sh

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

# This is what we copy into .git/hooks/.  We separate it from the real
# work so we can conveniently keep the meat of the hook under version
# control.

# XXX: some of these hooks are identical to DR's so perhaps we should make
# a separate repo to share them, or else drop support for separately-built DR.

# Run our own hooks:
make/git/hook-pre-commit.sh || exit 1

# We want the sample as well for the leading tab check:
.git/hooks/pre-commit.sample || exit 1
