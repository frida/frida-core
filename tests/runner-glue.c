#define DEBUG_HEAP_LEAKS 0

#include "frida-tests.h"

#include <gio/gio.h>
#include <gum/gum.h>

#ifdef G_OS_WIN32
#include <windows.h>
#include <conio.h>
#include <crtdbg.h>
#include <stdio.h>
#endif

void
frida_test_environment_init (int * args_length1, char *** args)
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
#if GLIB_CHECK_VERSION (2, 46, 0)
  glib_init ();
  gio_init ();
#endif
  g_test_init (args_length1, args, NULL);
  gum_init ();
  frida_error_quark (); /* Initialize early so GDBus will pick it up */
}

void
frida_test_environment_deinit (void)
{
#if DEBUG_HEAP_LEAKS
  gum_deinit ();
# if GLIB_CHECK_VERSION (2, 46, 0)
  gio_deinit ();
  glib_deinit ();
# endif
#endif

#if defined (G_OS_WIN32) && !DEBUG_HEAP_LEAKS
  if (IsDebuggerPresent ())
  {
    printf ("\nPress a key to exit.\n");
    _getch ();
  }
#endif
}

FridaTestOS
frida_test_os (void)
{
#if defined (G_OS_WIN32)
  return FRIDA_TEST_OS_WINDOWS;
#elif defined (HAVE_MAC)
  return FRIDA_TEST_OS_MAC;
#elif defined (HAVE_IOS)
  return FRIDA_TEST_OS_IOS;
#elif defined (HAVE_ANDROID)
  return FRIDA_TEST_OS_ANDROID;
#elif defined (HAVE_LINUX)
  return FRIDA_TEST_OS_LINUX;
#elif defined (HAVE_QNX)
  return FRIDA_TEST_OS_QNX;
#endif
}

FridaTestCPU
frida_test_cpu (void)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  return FRIDA_TEST_CPU_X86_32;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  return FRIDA_TEST_CPU_X86_64;
#elif defined (HAVE_ARM)
  return FRIDA_TEST_CPU_ARM_32;
#elif defined (HAVE_ARM64)
  return FRIDA_TEST_CPU_ARM_64;
#endif
}
