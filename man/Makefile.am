EXTRA_DIST = stenc.rst

all: stenc.1

stenc.1: stenc.rst
	pandoc --standalone --to man $< -o $@

clean:
	rm -f stenc.1
