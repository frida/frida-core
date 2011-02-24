#include "zed-agent.h"

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

#define ZED_NSEC_PER_SEC (G_GUINT64_CONSTANT (1000000000))

void
zed_agent_stopwatch_initialize (ZedAgentStopwatch * self)
{
  LARGE_INTEGER freq;
  BOOL success;

  success = QueryPerformanceFrequency (&freq);
  g_assert (success);
  self->freq = freq.QuadPart;
}

void
zed_agent_stopwatch_restart (ZedAgentStopwatch * self)
{
  LARGE_INTEGER stamp;
  BOOL success;

  success = QueryPerformanceCounter (&stamp);
  g_assert (success);
  self->start_stamp = stamp.QuadPart;
}

gdouble
zed_agent_stopwatch_elapsed (ZedAgentStopwatch * self)
{
  LARGE_INTEGER now;
  BOOL success;

  success = QueryPerformanceCounter (&now);
  g_assert (success);

  return ((double) (now.QuadPart - self->start_stamp)) / (double) self->freq;
}

guint64
zed_agent_stopwatch_elapsed_nanoseconds (ZedAgentStopwatch * self)
{
  return zed_agent_stopwatch_elapsed (self) * ZED_NSEC_PER_SEC;
}
