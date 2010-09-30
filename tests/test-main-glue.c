#define DEBUG_HEAP_LEAKS 0

#include "zed-tests.h"

#ifdef G_OS_WIN32
#include <windows.h>
#include <conio.h>
#include <crtdbg.h>
#endif

void
zed_test_environment_init (void)
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
}

void
zed_test_environment_deinit (void)
{
#if defined (G_OS_WIN32) && !DEBUG_HEAP_LEAKS
  if (IsDebuggerPresent ())
  {
    g_print ("\nPress a key to exit.\n");
    _getch ();
  }
#endif
}
