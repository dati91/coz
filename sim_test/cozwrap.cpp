/*
 * Standalone wrapper around the three Coz macros used by this test app.
 * Every other library talks to Coz only through these three functions -
 * they never include coz.h themselves.
 */
#include "cozwrap.h"
#include "coz.h"

extern "C" void coz_progress_cycles() {
  COZ_PROGRESS_NAMED("cycle");
}

extern "C" void coz_work_begin() {
  COZ_BEGIN("work");
}

extern "C" void coz_work_end() {
  COZ_END("work");
}
