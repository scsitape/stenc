# SPDX-FileCopyrightText: 2022 stenc authors
#
# SPDX-License-Identifier: GPL-2.0-or-later

AM_CPPFLAGS=-std=c++17 -I${top_srcdir}/src
TESTS=scsi output
check_PROGRAMS=scsi output
scsi_SOURCES=catch.hpp scsi.cpp ${top_srcdir}/src/scsiencrypt.cpp
output_SOURCES=catch.hpp output.cpp ${top_srcdir}/src/scsiencrypt.cpp
