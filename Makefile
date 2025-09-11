CC ?= gcc
override CFLAGS += -std=c99 -Wall
.DEFAULT_GOAL := all

SRCDIR = $(CURDIR)
TESTDIR ?= /tmp/path-mapping
TESTTOOLS = $(notdir $(basename $(wildcard $(SRCDIR)/test/testtool-*.c)))
UNIT_TESTS = test-pathmatching test-common

path-mapping.so: path-mapping.c
	$(CC) $(CFLAGS) -shared -fPIC -Os -g0 -s path-mapping.c -o $@ -ldl

all: path-mapping.so pathmap

clean:
	rm -f *.so pathmap pathmap-static*
	rm -rf $(TESTDIR)

test: all unit_tests testtools
	for f in $(UNIT_TESTS); do $(TESTDIR)/$$f; done
	TESTDIR="$(TESTDIR)" test/integration-tests.sh

unit_tests: $(addprefix $(TESTDIR)/, $(UNIT_TESTS))

testtools: $(addprefix $(TESTDIR)/, $(TESTTOOLS))

$(TESTDIR)/test-%: $(SRCDIR)/test/test-%.c $(SRCDIR)/path-mapping.c
	mkdir -p $(TESTDIR)
	cd $(TESTDIR); $(CC) $(CFLAGS) -I"$(SRCDIR)" $< "$(SRCDIR)/path-mapping.c" -ldl -o $@

$(TESTDIR)/testtool-%: $(SRCDIR)/test/testtool-%.c
	mkdir -p $(TESTDIR)
	cd $(TESTDIR); $(CC) $(CFLAGS) $^ -o $@

pathmap: pathmap.c
	$(CC) $(CFLAGS) -Os -g0 -s pathmap.c -o $@

# Statically linked tracer (glibc or musl depending on CC)
pathmap-static: pathmap.c
	$(CC) $(CFLAGS) -static -Os -g0 -s pathmap.c -o $@

# Static PIE tracer (requires toolchain support, e.g. GCC >= 8)
pathmap-static-pie: pathmap.c
	$(CC) $(CFLAGS) -static-pie -fPIE -Os -g0 -s pathmap.c -o $@

.PHONY: all libs clean test unit_tests testtools check

check: test
