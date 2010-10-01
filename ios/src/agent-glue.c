#define DEBUG_HEAP_LEAKS 0

#include "zed-agent.h"

#include <gio/gio.h>
#include <gum/gum.h>

#ifdef G_OS_WIN32
#include <crtdbg.h>
#endif

void
zed_agent_environment_init (void)
{
#if defined (G_OS_WIN32) && DEBUG_HEAP_LEAKS
  int tmp_flag;

  /*_CrtSetBreakAlloc (1337);*/

  _CrtSetReportMode (_CRT_ERROR, _CRTDBG_MODE_FILE);
  _CrtSetReportFile (_CRT_ERROR, _CRTDBG_FILE_STDERR);

  tmp_flag = _CrtSetDbgFlag (_CRTDBG_REPORT_FLAG);

  tmp_flag |= _CRTDBG_ALLOC_MEM_DF;
  tmp_flag |= _CRTDBG_LEAK_CHECK_DF;
  tmp_flag &= ~_CRTDBG_CHECK_CRT_DF;

  _CrtSetDbgFlag (tmp_flag);
#endif

  g_setenv ("G_DEBUG", "fatal-warnings:fatal-criticals", TRUE);
#if DEBUG_HEAP_LEAKS
  g_setenv ("G_SLICE", "always-malloc", TRUE);
#endif
#ifdef _DEBUG
  g_thread_init_with_errorcheck_mutexes (NULL);
#else
  g_thread_init (NULL);
#endif
  g_type_init ();
  gum_init_with_features ((GumFeatureFlags)
      (GUM_FEATURE_ALL & ~GUM_FEATURE_SYMBOL_LOOKUP));
}

void
zed_agent_environment_deinit (void)
{
  g_io_deinit ();

  gum_deinit ();
  g_type_deinit ();
  g_thread_deinit ();
  g_mem_deinit ();
}
