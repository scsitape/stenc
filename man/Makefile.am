# SPDX-FileCopyrightText: 2022 stenc authors
#
# SPDX-License-Identifier: GPL-2.0-or-later

man1_MANS = stenc.1

EXTRA_DIST = stenc.rst

all: stenc.1

stenc.1: stenc.rst
	pandoc --standalone --to man $? -o $@

clean:
	rm -f stenc.1

distclean: clean
	rm -f Makefile

