#define DEBUG_HEAP_LEAKS 0

#include "zed-tests.h"

#include <gio/gio.h>
#include <gum/gum.h>
#include <clutter/clutter.h>

#ifdef G_OS_WIN32
#include <windows.h>
#include <conio.h>
#include <crtdbg.h>
#include <stdio.h>
#endif

void
zed_test_environment_init (int * args_length1, char *** args)
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
  g_thread_init (NULL);
  g_type_init ();
  g_test_init (args_length1, args, NULL);
  gum_init ();
  clutter_init (args_length1, args);
}

void
zed_test_environment_deinit (void)
{
  g_io_deinit ();

  gum_deinit ();
  g_test_deinit ();
  g_type_deinit ();
  g_thread_deinit ();
  g_mem_deinit ();

#if defined (G_OS_WIN32) && !DEBUG_HEAP_LEAKS
  if (IsDebuggerPresent ())
  {
    printf ("\nPress a key to exit.\n");
    _getch ();
  }
#endif
}
