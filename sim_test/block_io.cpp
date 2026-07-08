/* Simulated "io" block: stands in for I/O-shaped work (buffer churn),
 * single-threaded, no real syscalls. */
#include <cstring>

extern "C" void run_block()
{
  char buf[4096];
  for (int i = 0; i < 6000; i++)
  {
    memset(buf, i & 0xff, sizeof(buf));
    buf[0] = buf[sizeof(buf) - 1];
  }
}
