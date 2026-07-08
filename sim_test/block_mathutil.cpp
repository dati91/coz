/* Simulated "mathutil" block: overloaded functions and a template function
 * instantiated for two types, to exercise --fixed-symbol against names that
 * collide within a single binary (not just across binaries like run_block).
 *
 * noinline is deliberate here, not decorative: at -O2, GCC fully inlines
 * every call site of these small functions and keeps no out-of-line copy at
 * all - confirmed with `nm -C libblock_mathutil.so`, which shows no
 * `square`/`clamp` symbols whatsoever without this attribute. A fully
 * inlined function has no address of its own for a symbol lookup to find,
 * DWARF or otherwise - the same limitation gdb's `break` hits on inlined
 * code. If a real function you want to target with --fixed-symbol seems to
 * never resolve, this - not a bug in symbol lookup - is the first thing to
 * rule out. */

namespace mathutil {

__attribute__((noinline)) int square(int x) {
  return x * x;
}

__attribute__((noinline)) double square(double x) {
  return x * x;
}

template <typename T>
__attribute__((noinline)) T clamp(T value, T lo, T hi) {
  if (value < lo) return lo;
  if (value > hi) return hi;
  return value;
}

// Default argument - the compiler bakes the default into every unannotated
// call site, so it doesn't show up as a distinct "argument value" in DWARF,
// just as a normal two-arg call at the resolved value.
int scaled(int base, int multiplier = 3) {
  volatile int acc = 0;
  for (int i = 0; i < 40000; i++) {
    acc += square(base) * multiplier - clamp(i, 0, 1000);
  }
  return acc;
}

} // namespace mathutil

extern "C" void run_block() {
  volatile double acc = 0;
  for (int i = 0; i < 5; i++) {
    acc += mathutil::square(1.5 + i);
    acc += mathutil::scaled(i);
    acc += mathutil::clamp(3.5 + i, 0.0, 10.0);
  }
}
