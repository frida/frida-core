#include "zed-core.h"

#ifdef G_OS_WIN32
#define VC_EXTRALEAN
#include <windows.h>
#endif

char *
zed_service_storage_backend_get_data_directory (void)
{
  gchar * result;

#ifdef G_OS_WIN32
  WCHAR filename_utf16[MAX_PATH] = { 0, };
  gchar * filename;

  GetModuleFileNameW (NULL, filename_utf16, MAX_PATH);
  filename = g_utf16_to_utf8 ((gunichar2 *) filename_utf16, -1, NULL, NULL,
      NULL);
  result = g_path_get_dirname (filename);
  g_free (filename);
#else
  result = g_strdup ("/tmp"); /* FIXME */
#endif

  return result;
}
