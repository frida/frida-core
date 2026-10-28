#include "frida-core.h"

#include "access-helpers.h"

#define VC_EXTRALEAN
#include <aclapi.h>
#include <sddl.h>
#include <windows.h>

#define CHECK_WINAPI_RESULT(n1, cmp, n2, op) \
  if (!(n1 cmp n2)) \
  { \
    failed_operation = op; \
    goto winapi_failure; \
  }

void
frida_winjector_set_acls_as_needed (const gchar * path, GError ** error)
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
    DWORD success = ConvertStringSecurityDescriptorToSecurityDescriptorW (sddl, SDDL_REVISION_1, (PSECURITY_DESCRIPTOR *) &sd, NULL);
    CHECK_WINAPI_RESULT (success, !=, FALSE, "ConvertStringSecurityDescriptorToSecurityDescriptor");

    dacl_present = FALSE;
    dacl_defaulted = FALSE;
    success = GetSecurityDescriptorDacl (sd, &dacl_present, &dacl, &dacl_defaulted);
    CHECK_WINAPI_RESULT (success, !=, FALSE, "GetSecurityDescriptorDacl");

    success = SetNamedSecurityInfoW (path_utf16, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, dacl, NULL);
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

void *
frida_agent_resource_create_section (GBytes * blob, GError ** error)
{
  gsize size;
  gconstpointer data;
  HANDLE section;
  gpointer view;

  data = g_bytes_get_data (blob, &size);

  section = CreateFileMappingW (INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, (DWORD) ((guint64) size >> 32), (DWORD) size,
      NULL);
  if (section == NULL)
    goto failure;

  view = MapViewOfFile (section, FILE_MAP_WRITE, 0, 0, size);
  if (view == NULL)
    goto failure;
  memcpy (view, data, size);
  UnmapViewOfFile (view);

  return section;

failure:
  {
    DWORD last_error = GetLastError ();

    if (section != NULL)
      CloseHandle (section);

    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unable to create section (0x%08lx)",
        last_error);
    return NULL;
  }
}

void
frida_agent_resource_close_section (void * section)
{
  CloseHandle (section);
}
