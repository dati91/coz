/* Simulated "compute" block: pure CPU-bound work, single-threaded.
 *
 * ENABLE_EXPERIMENTAL_PATH demonstrates how --fixed-line/--fixed-symbol
 * behave around #ifdef'd code: the line numbers below are always the same
 * in this file regardless of which branch got compiled, but the DWARF line
 * table (and therefore what Coz can find) only ever contains entries for
 * whichever branch THIS build actually took. Build normally (macro
 * undefined) and a --fixed-line/--fixed-symbol target inside the
 * experimental branch just never resolves - not an error, it stays pending
 * forever, identical to naming a line that doesn't exist. Rebuild with
 * ENABLE_EXPERIMENTAL_PATH defined (see build.sh) and that same target
 * resolves immediately, because now the compiler actually emitted code -
 * and debug info - for it in this translation unit. */

#ifdef ENABLE_EXPERIMENTAL_PATH
#include <cmath>

static double experimental_step(int i) {
  return std::sqrt(static_cast<double>(i)) * 1.0001;
}
#endif

extern "C" void run_block()
{
#ifdef ENABLE_EXPERIMENTAL_PATH
  volatile double acc = 0;
  for (int i = 0; i < 3000; i++)
  {
    acc += experimental_step(i);
  }
#else
  volatile long acc = 0;
  for (int i = 0; i < 3000; i++)
  {
    acc += (i * i) ^ (i << 1);
  }
#endif
}
