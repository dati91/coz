#!/bin/bash
# Builds the sim_test app used to verify Coz's dlopen()/dlmopen() support.
# Run from anywhere; always builds in-place in this directory.
#
# ENABLE_EXPERIMENTAL=1 ./build.sh rebuilds block_compute.cpp with
# -DENABLE_EXPERIMENTAL_PATH, switching it to a different #ifdef'd branch -
# see the comment at the top of block_compute.cpp for what this demonstrates
# about --fixed-line/--fixed-symbol and conditionally-compiled code.
set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

EXPERIMENTAL_FLAGS=""
if [ -n "$ENABLE_EXPERIMENTAL" ]; then
  EXPERIMENTAL_FLAGS="-DENABLE_EXPERIMENTAL_PATH"
  echo "Building block_compute.cpp with ENABLE_EXPERIMENTAL_PATH defined."
fi

# Driver: no -g, no coz knowledge, stripped afterward.
gcc -O2 -o driver driver.c -ldl
strip --strip-all driver

# Coz wrapper: the only place that touches coz.h. Built first since app.cpp
# and block_pool.cpp link directly against it.
g++ -g -O2 -std=c++11 -shared -fPIC -o libcozwrap.so cozwrap.cpp -ldl \
  -I ../include

# App logic: dlopen's the blocks, links libcozwrap directly.
g++ -g -O2 -std=c++11 -shared -fPIC -o libapp.so app.cpp -ldl \
  -L. -lcozwrap -Wl,-rpath,'$ORIGIN'

# Blocks. Only the pool block links against libcozwrap (the others don't
# talk to coz at all).
g++ -g -O2 -std=c++11 -shared -fPIC $EXPERIMENTAL_FLAGS \
  -o libblock_compute.so block_compute.cpp
g++ -g -O2 -std=c++11 -shared -fPIC -o libblock_io.so block_io.cpp
g++ -g -O2 -std=c++11 -shared -fPIC -o libblock_pool.so block_pool.cpp -lpthread \
  -L. -lcozwrap -Wl,-rpath,'$ORIGIN'
g++ -g -O2 -std=c++11 -shared -fPIC -o libblock_shapes.so block_shapes.cpp
g++ -g -O2 -std=c++11 -shared -fPIC -o libblock_mathutil.so block_mathutil.cpp

echo "Build complete."
