#include "frida-core.h"

#include "access-helpers.h"

#define VC_EXTRALEAN
#include <aclapi.h>
#include <objbase.h>
#include <sddl.h>
#include <shellapi.h>
#include <strsafe.h>
#include <windows.h>

#define CHECK_WINAPI_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto winapi_failure; \
  }

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
frida_winjector_helper_factory_spawn (const gchar * path, const gchar * parameters, FridaWinjectorPrivilegeLevel level, GError ** error)
{
  HANDLE process_handle;
  SHELLEXECUTEINFOW ei = { 0, };
  WCHAR * path_utf16;
  WCHAR * parameters_utf16;

  CoInitializeEx (NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

  ei.cbSize = sizeof (ei);

  ei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI
      | SEE_MASK_UNICODE | SEE_MASK_WAITFORINPUTIDLE;
  if (level == FRIDA_WINJECTOR_PRIVILEGE_LEVEL_ELEVATED)
    ei.lpVerb = L"runas";
  else
    ei.lpVerb = L"open";

  path_utf16 = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  ei.lpFile = path_utf16;

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
        FRIDA_ERROR,
        FRIDA_ERROR_PERMISSION_DENIED,
        "Unable to spawn helper executable at '%s': 0x%08lx",
        path, GetLastError ());
  }

  g_free (parameters_utf16);
  g_free (path_utf16);

  CoUninitialize ();

  return process_handle;
}

void
frida_winjector_resource_store_set_acls_as_needed (const gchar * path, GError ** error)
{
  const gchar * failed_operation;
  LPWSTR path_utf16;
  LPCWSTR sddl;
  SECURITY_DESCRIPTOR * sd = NULL;
  BOOL dacl_present;
  BOOL dacl_defaulted;
  PACL dacl;

  path_utf16 = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  sddl = frida_access_get_sddl_string_for_temp_directory ();

  if (sddl != NULL)
  {
    DWORD success = ConvertStringSecurityDescriptorToSecurityDescriptor (sddl, SDDL_REVISION_1, &sd, NULL);
    CHECK_WINAPI_RESULT (success, !=, FALSE, "ConvertStringSecurityDescriptorToSecurityDescriptor");

    dacl_present = FALSE;
    dacl_defaulted = FALSE;
    success = GetSecurityDescriptorDacl (sd, &dacl_present, &dacl, &dacl_defaulted);
    CHECK_WINAPI_RESULT (success, !=, FALSE, "GetSecurityDescriptorDacl");

    success = SetNamedSecurityInfo (path_utf16, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL);
    CHECK_WINAPI_RESULT (success, ==, ERROR_SUCCESS, "SetNamedSecurityInfo");
  }

  goto beach;

winapi_failure:
  {
    DWORD last_error = GetLastError ();
    g_set_error (error,
        G_IO_ERROR,
        g_io_error_from_win32_error (last_error),
        "Error setting ACLs (%s returned 0x%08lx)",
        failed_operation, last_error);
    goto beach;
  }

beach:
  {
    if (sd != NULL)
      LocalFree (sd);

    g_free (path_utf16);
  }
}
