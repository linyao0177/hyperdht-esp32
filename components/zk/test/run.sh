#!/bin/bash
# Builds and runs test.c on this machine, with the component's mcl settings.
set -e
cd "$(dirname "$0")"
T=$(pwd)
Z=$T/..
M=$Z/mcl
B=$(mktemp -d)
trap 'rm -rf "$B"' EXIT
DEFS="-DMCL_STANDALONE -DMCL_SIZEOF_UNIT=4 -DMCL_FP_BIT=256 -DMCL_FR_BIT=256 -DMCL_BINT_ASM=0 -DMCL_DONT_USE_XBYAK -DNDEBUG"
python3 gen_vectors.py data/event_v2_vkey.json data/events.jsonl data/root.hex > "$B/vectors.h"
c++ -std=c++17 -O2 -fno-exceptions -fno-rtti -fno-threadsafe-statics $DEFS -I$M/include -I$M/src -c $M/src/fp.cpp -o "$B/fp.o"
(cd "$B" && cc -std=c11 -O2 -Wall -Wextra $DEFS -I$Z/include -I$Z -I$M/include -I"$B" -c $Z/g16.c $Z/g16_poseidon.c $Z/zk_event.c $T/test.c)
c++ "$B"/*.o -o "$B/test"
"$B/test"
