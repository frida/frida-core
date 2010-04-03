#include <glib.h>
#include <windows.h>
#include <psapi.h>

char *
zed_platform_process_backend_filename_of (void * handle)
{
  WCHAR filename_utf16[MAX_PATH + 1];

  GetModuleFileNameExW (handle, NULL, filename_utf16, sizeof (filename_utf16));

  return g_utf16_to_utf8 (filename_utf16, -1, NULL, NULL, NULL);
}

void *
zed_platform_process_backend_self_handle (void)
{
  return GetCurrentProcess ();
}

glong
zed_platform_process_backend_self_id (void)
{
  return GetCurrentProcessId ();
}

gboolean
zed_platform_process_backend_do_start (const char * filename,
    void ** handle, glong * id)
{
  LPWSTR filename_utf16;
  STARTUPINFOW startup_info = { 0, };
  PROCESS_INFORMATION process_info = { 0, };
  BOOL success;

  filename_utf16 =
      g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);

  startup_info.cb = sizeof (startup_info);

  success = CreateProcessW (filename_utf16, NULL, NULL, NULL, FALSE, 0, NULL,
      NULL, &startup_info, &process_info);

  if (success)
  {
    CloseHandle (process_info.hThread);

    *handle = process_info.hProcess;
    *id = process_info.dwProcessId;
  }

  g_free (filename_utf16);

  return success;
}

glong
zed_platform_process_backend_do_join (void * handle)
{
  DWORD exit_code;

  WaitForSingleObject (handle, INFINITE);

  GetExitCodeProcess (handle, &exit_code);
  CloseHandle (handle);

  return exit_code;
}
