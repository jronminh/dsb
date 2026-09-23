#!/bin/sh
# Build the dsb client and daemon into out/ (C99 + POSIX/Linux headers only;
# no libraries).
set -eu
cd "$(dirname "$0")"
mkdir -p out
CC="${CC:-cc}"
CFLAGS="${CFLAGS:--O2 -Wall -Wextra -D_FORTIFY_SOURCE=2 -fstack-protector-strong}"
$CC $CFLAGS -o out/dsb src/dsb.c
$CC $CFLAGS -o out/dsbd src/dsbd.c src/dsb-conf.c
echo "built: $(pwd)/out/dsb $(pwd)/out/dsbd"
