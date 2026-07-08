/*
 * The driver. Deliberately built with no debug info and no knowledge of
 * Coz, coz.h, or what the loaded library actually does: it just dlopen()s
 * a shared object by relative path and calls its entry point.
 */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

typedef void (*run_simulation_fn)(int);

int main(int argc, char** argv) {
  int cycles = (argc > 1) ? atoi(argv[1]) : 300;

  void* handle = dlopen("./libapp.so", RTLD_NOW);
  if (!handle) {
    fprintf(stderr, "driver: dlopen(libapp.so) failed: %s\n", dlerror());
    return 1;
  }

  run_simulation_fn run_simulation = (run_simulation_fn)dlsym(handle, "run_simulation");
  if (!run_simulation) {
    fprintf(stderr, "driver: dlsym(run_simulation) failed: %s\n", dlerror());
    return 1;
  }

  run_simulation(cycles);
  return 0;
}
