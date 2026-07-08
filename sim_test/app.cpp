/*
 * The actual "application logic" - dlopen'd by the debug-symbol-free
 * driver. Runs a simulator loop for a number of cycles; each cycle runs
 * three independently dlopen'd "block" plugins, then reports progress via
 * the coz wrapper library. Unlike the blocks, libcozwrap is a normal link
 * dependency of this library (not dlopen'd) - app.cpp only ever needs the
 * per-cycle progress point, never the work begin/end latency hooks, which
 * are block_pool's concern alone.
 */
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>

#include "cozwrap.h"

typedef void (*block_fn)();

static void* must_dlopen(const char* path) {
  void* h = dlopen(path, RTLD_NOW);
  if (!h) {
    fprintf(stderr, "libapp: dlopen(%s) failed: %s\n", path, dlerror());
    exit(1);
  }
  return h;
}

template <typename T>
static T must_dlsym(void* handle, const char* name) {
  void* sym = dlsym(handle, name);
  if (!sym) {
    fprintf(stderr, "libapp: dlsym(%s) failed: %s\n", name, dlerror());
    exit(1);
  }
  return reinterpret_cast<T>(sym);
}

extern "C" void run_simulation(int cycles) {
  void* block_a = must_dlopen("./libblock_compute.so");
  void* block_b = must_dlopen("./libblock_io.so");
  void* block_c = must_dlopen("./libblock_pool.so");
  void* block_d = must_dlopen("./libblock_shapes.so");
  void* block_e = must_dlopen("./libblock_mathutil.so");

  block_fn run_compute  = must_dlsym<block_fn>(block_a, "run_block");
  block_fn run_io       = must_dlsym<block_fn>(block_b, "run_block");
  block_fn run_pool     = must_dlsym<block_fn>(block_c, "run_block");
  block_fn run_shapes   = must_dlsym<block_fn>(block_d, "run_block");
  block_fn run_mathutil = must_dlsym<block_fn>(block_e, "run_block");

  fprintf(stderr, "libapp: running simulation for %d cycles\n", cycles);

  for (int i = 0; i < cycles; i++) {
    run_compute();
    run_io();
    run_pool();
    run_shapes();
    run_mathutil();
    coz_progress_cycles();
  }

  fprintf(stderr, "libapp: simulation complete\n");
}
