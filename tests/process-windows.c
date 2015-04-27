#include "frida-tests.h"

#include <windows.h>
#include <psapi.h>

char *
frida_test_process_backend_filename_of (void * handle)
{
  WCHAR filename_utf16[MAX_PATH + 1];

  GetModuleFileNameExW (handle, NULL, filename_utf16, sizeof (filename_utf16));

  return g_utf16_to_utf8 (filename_utf16, -1, NULL, NULL, NULL);
}

void *
frida_test_process_backend_self_handle (void)
{
  return GetCurrentProcess ();
}

guint
frida_test_process_backend_self_id (void)
{
  return GetCurrentProcessId ();
}

void
frida_test_process_backend_do_start (const char * path, gchar ** argv,
    int argv_length, gchar ** envp, int envp_length, FridaTestArch arch,
    void ** handle, guint * id, GError ** error)
{
  LPWSTR path_utf16;
  STARTUPINFOW startup_info = { 0, };
  PROCESS_INFORMATION process_info = { 0, };
  BOOL success;

  /* TODO: implement these when needed */
  (void) argv;
  (void) argv_length;
  (void) envp;
  (void) envp_length;
  (void) arch;

  path_utf16 = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);

  startup_info.cb = sizeof (startup_info);

  success = CreateProcessW (path_utf16, NULL, NULL, NULL, FALSE, 0, NULL, NULL,
      &startup_info, &process_info);

  if (success)
  {
    CloseHandle (process_info.hThread);

    *handle = process_info.hProcess;
    *id = process_info.dwProcessId;
  }
  else
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to spawn executable at “%s”: 0x%08x\n",
        path, GetLastError ());
  }

  g_free (path_utf16);
}

int
frida_test_process_backend_do_join (void * handle, guint timeout_msec,
    GError ** error)
{
  DWORD exit_code;

  if (WaitForSingleObject (handle,
      (timeout_msec != 0) ? timeout_msec : INFINITE) == WAIT_TIMEOUT)
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_TIMED_OUT,
        "Timed out while waiting for process to exit");
    return -1;
  }

  GetExitCodeProcess (handle, &exit_code);
  CloseHandle (handle);

  return exit_code;
}
