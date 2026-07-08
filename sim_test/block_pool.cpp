/* Simulated "pool" block: spins up a small thread pool each cycle and does
 * a chunk of work on each thread, wrapping each individual unit of work in
 * the coz_work_begin()/coz_work_end() latency hooks. This is the only
 * block that talks to the coz wrapper - app.cpp never sees begin/end. */
#include <thread>
#include <vector>

#include "cozwrap.h"

static const int kWorkerCount = 4;

static void worker(int id)
{
  volatile long acc = 0;
  for (int i = 0; i < 60000; i++)
  {
    acc += (i * i) ^ (i << 1);
  }
}

extern "C" void run_block()
{
  std::vector<std::thread> pool;
  pool.reserve(kWorkerCount);
  coz_work_begin();

  for (int t = 0; t < kWorkerCount; t++)
  {
    pool.emplace_back(worker, t);
  }
  for (auto &th : pool)
  {
    th.join();
  }
  coz_work_end();
}
