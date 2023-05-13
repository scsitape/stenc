# SPDX-FileCopyrightText: 2022 stenc authors
#
# SPDX-License-Identifier: CC0-1.0

man1_MANS = stenc.1

EXTRA_DIST = stenc.rst

all: stenc.1

stenc.1: stenc.rst
	pandoc --standalone --to man $? -o $@

clean:
	rm -f stenc.1

distclean: clean
	rm -f Makefile

