#include "zed-core.h"

#define VC_EXTRALEAN
#include <windows.h>
#include <strsafe.h>

gboolean
zed_service_winjector_helper_is_process_still_running (void * handle)
{
  DWORD exit_code;

  if (!GetExitCodeProcess (handle, &exit_code))
    return FALSE;

  return exit_code == STILL_ACTIVE;
}

void
zed_service_winjector_helper_close_process_handle (void * handle)
{
  g_assert (handle != NULL);
  CloseHandle (handle);
}

char *
zed_service_winjector_temporary_directory_create_tempdir (void)
{
  const guint max_chars = MAX_PATH;
  WCHAR * name;
  GUID id;
  gsize len;
  gchar * name_utf8;

  name = g_new0 (WCHAR, max_chars);
  if (GetTempPathW (max_chars, name) == 0)
    goto error;
  if (CoCreateGuid (&id) != S_OK)
    goto error;
  StringCchCatW (name, max_chars, L"zed");
  len = wcslen (name);
  StringFromGUID2 (&id, name + len, max_chars - len - 1);
  name[len] = L'-';
  name[wcslen (name) - 1] = L'\\';

  if (!CreateDirectoryW (name, NULL))
    goto error;

  name_utf8 = g_utf16_to_utf8 (name, -1, NULL, NULL, NULL);
  g_free (name);
  return name_utf8;

error:
  g_free (name);
  return NULL;
}

void
zed_service_winjector_temporary_directory_destroy_tempdir (const char * path)
{
  WCHAR * path_utf16;

  path_utf16 = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  RemoveDirectoryW (path_utf16);
  g_free (path_utf16);
}

void *
zed_service_winjector_temporary_file_execute (
    ZedServiceWinjectorTemporaryFile * self, const char * parameters,
    ZedServiceWinjectorPrivilegeLevel level, GError ** error)
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
  if (level == ZED_SERVICE_WINJECTOR_PRIVILEGE_LEVEL_ELEVATED)
    ei.lpVerb = L"runas";
  else
    ei.lpVerb = L"open";

  file = g_file_get_path (self->file);
  file_utf16 = g_utf8_to_utf16 (file, -1, NULL, NULL, NULL);
  ei.lpFile = file_utf16;
  g_free (file);

  parameters_utf16 = g_utf8_to_utf16 (parameters, -1, NULL, NULL, NULL);
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
        ZED_SERVICE_WINJECTOR_ERROR,
        ZED_SERVICE_WINJECTOR_ERROR_EXECUTE_FAILED,
        "ShellExecuteExW failed: %d", GetLastError ());
  }

  g_free (parameters_utf16);
  g_free (file_utf16);

  CoUninitialize ();

  return process_handle;
}
