#include "frida-core.h"

#define VC_EXTRALEAN
#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include <strsafe.h>

gboolean
frida_winjector_helper_instance_is_process_still_running (void * handle)
{
  DWORD exit_code;

  if (!GetExitCodeProcess (handle, &exit_code))
    return FALSE;

  return exit_code == STILL_ACTIVE;
}

void
frida_winjector_helper_instance_close_process_handle (void * handle)
{
  g_assert (handle != NULL);
  CloseHandle (handle);
}

void *
frida_winjector_helper_factory_spawn (const gchar * path, const gchar * parameters, FridaPrivilegeLevel level, GError ** error)
{
  HANDLE process_handle;
  SHELLEXECUTEINFOW ei = { 0, };
  gchar * file;
  WCHAR * file_utf16;
  WCHAR * parameters_utf16;

  CoInitializeEx (NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

  ei.cbSize = sizeof (ei);

  ei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI
      | SEE_MASK_UNICODE | SEE_MASK_WAITFORINPUTIDLE;
  if (level == FRIDA_WINJECTOR_PRIVILEGE_LEVEL_ELEVATED)
    ei.lpVerb = L"runas";
  else
    ei.lpVerb = L"open";

  file = g_file_get_path (self->file);
  file_utf16 = (WCHAR *) g_utf8_to_utf16 (file, -1, NULL, NULL, NULL);
  ei.lpFile = file_utf16;
  g_free (file);

  parameters_utf16 =
      (WCHAR *) g_utf8_to_utf16 (parameters, -1, NULL, NULL, NULL);
  ei.lpParameters = parameters_utf16;

  ei.nShow = SW_HIDE;

  if (ShellExecuteExW (&ei))
  {
    process_handle = ei.hProcess;
  }
  else
  {
    process_handle = NULL;

    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "ShellExecuteExW failed: %d", GetLastError ());
  }

  g_free (parameters_utf16);
  g_free (file_utf16);

  CoUninitialize ();

  return process_handle;
}
