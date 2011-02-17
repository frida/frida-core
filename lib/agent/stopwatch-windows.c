#include "zed-agent.h"

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

#define GUM_NSEC_PER_SEC (G_GUINT64_CONSTANT (1000000000))

void
zed_agent_stopwatch_start (ZedAgentStopwatch * self)
{
  LARGE_INTEGER freq, stamp;
  BOOL success;

  success = QueryPerformanceFrequency (&freq);
  g_assert (success);
  self->freq = freq.QuadPart;

  success = QueryPerformanceCounter (&stamp);
  g_assert (success);
  self->start_stamp = stamp.QuadPart;
}

guint64
zed_agent_stopwatch_elapsed (ZedAgentStopwatch * self)
{
  LARGE_INTEGER now;
  BOOL success;
  double elapsed_seconds;

  success = QueryPerformanceCounter (&now);
  g_assert (success);

  elapsed_seconds = ((double) (now.QuadPart - self->start_stamp)) / (double) self->freq;

  return elapsed_seconds * GUM_NSEC_PER_SEC;
}