#define COBJMACROS 1

#include "frida-core.h"

#include "icon-helpers.h"

#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shobjidl.h>
#include <unknwn.h>

#define PARSE_STRING_MAX_LENGTH   (40 + 1)

typedef struct _FridaSpawnInstance FridaSpawnInstance;

struct _FridaSpawnInstance
{
  FridaWindowsHostSession * host_session;
  PROCESS_INFORMATION process_info;
};

static FridaSpawnInstance * frida_spawn_instance_new (FridaWindowsHostSession * host_session);
static void frida_spawn_instance_free (FridaSpawnInstance * instance);
static void frida_spawn_instance_resume (FridaSpawnInstance * self);

static WCHAR * command_line_from_argv (const gchar ** argv, gint argv_length);
static WCHAR * environment_block_from_envp (const gchar ** envp, gint envp_length);

static void append_n_backslashes (GString * str, guint n);

FridaImageData *
_frida_windows_host_session_provider_extract_icon (GError ** error)
{
  FridaImageData * result = NULL;
  OLECHAR my_computer_parse_string[PARSE_STRING_MAX_LENGTH];
  IShellFolder * desktop_folder = NULL;
  IEnumIDList * children = NULL;
  ITEMIDLIST * child;

  (void) error;

  wcscpy_s (my_computer_parse_string, PARSE_STRING_MAX_LENGTH, L"::");
  StringFromGUID2 (&CLSID_MyComputer, my_computer_parse_string + 2, PARSE_STRING_MAX_LENGTH - 2);

  if (SHGetDesktopFolder (&desktop_folder) != S_OK)
    goto beach;

  if (IShellFolder_EnumObjects (desktop_folder, NULL, SHCONTF_FOLDERS, &children) != S_OK)
    goto beach;

  while (result == NULL && IEnumIDList_Next (children, 1, &child, NULL) == S_OK)
  {
    STRRET display_name_value;
    WCHAR display_name[MAX_PATH];
    SHFILEINFOW file_info = { 0, };

    if (IShellFolder_GetDisplayNameOf (desktop_folder, child, SHGDN_FORPARSING, &display_name_value) != S_OK)
      goto next_child;
    StrRetToBufW (&display_name_value, child, display_name, MAX_PATH);

    if (_wcsicmp (display_name, my_computer_parse_string) != 0)
      goto next_child;

    if (SHGetFileInfoW ((LPCWSTR) child, 0, &file_info, sizeof (file_info), SHGFI_PIDL | SHGFI_ICON | SHGFI_SMALLICON | SHGFI_ADDOVERLAYS) == 0)
      goto next_child;

    result = _frida_image_data_from_native_icon_handle (file_info.hIcon, FRIDA_ICON_SMALL);

    DestroyIcon (file_info.hIcon);

next_child:
    CoTaskMemFree (child);
  }

beach:
  if (children != NULL)
    IUnknown_Release (children);
  if (desktop_folder != NULL)
    IUnknown_Release (desktop_folder);

  return result;
}

guint
_frida_windows_host_session_do_spawn (FridaWindowsHostSession * self, const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, GError ** error)
{
  FridaSpawnInstance * instance = NULL;
  WCHAR * application_name, * command_line, * environment;
  STARTUPINFO startup_info;

  if (!g_file_test (path, G_FILE_TEST_EXISTS))
    goto handle_path_error;

  instance = frida_spawn_instance_new (self);

  application_name = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  command_line = command_line_from_argv (argv, argv_length);
  environment = environment_block_from_envp (envp, envp_length);

  ZeroMemory (&startup_info, sizeof (startup_info));
  startup_info.cb = sizeof (startup_info);

  if (!CreateProcessW (application_name, command_line, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS, environment, NULL, &startup_info, &instance->process_info))
    goto handle_create_error;
  DebugActiveProcessStop (instance->process_info.dwProcessId);

  gee_abstract_map_set (GEE_ABSTRACT_MAP (self->instance_by_pid), GUINT_TO_POINTER (instance->process_info.dwProcessId), instance);

  g_free (environment);
  g_free (command_line);
  g_free (application_name);

  return instance->process_info.dwProcessId;

handle_path_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_EXECUTABLE_NOT_FOUND,
        "Unable to find executable at '%s'",
        path);
    goto error_epilogue;
  }
handle_create_error:
  {
    DWORD last_error = GetLastError ();
    if (last_error == ERROR_BAD_EXE_FORMAT)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_EXECUTABLE_NOT_SUPPORTED,
          "Unable to spawn executable at '%s': unsupported file format",
          path);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_NOT_SUPPORTED,
          "Unable to spawn executable at '%s': 0x%08lx",
          path, GetLastError ());
    }
    goto error_epilogue;
  }
error_epilogue:
  {
    if (instance != NULL)
      frida_spawn_instance_free (instance);
    return 0;
  }
}

void
_frida_windows_host_session_resume_instance (FridaWindowsHostSession * self, void * instance)
{
  (void) self;

  frida_spawn_instance_resume (instance);
}

void
_frida_windows_host_session_free_instance (FridaWindowsHostSession * self, void * instance)
{
  (void) self;

  frida_spawn_instance_free (instance);
}

static FridaSpawnInstance *
frida_spawn_instance_new (FridaWindowsHostSession * host_session)
{
  FridaSpawnInstance * instance;

  instance = g_slice_new0 (FridaSpawnInstance);
  instance->host_session = g_object_ref (host_session);

  return instance;
}

static void
frida_spawn_instance_free (FridaSpawnInstance * instance)
{
  PROCESS_INFORMATION * info = &instance->process_info;
  if (info->hProcess != NULL)
  {
    CloseHandle (info->hProcess);
    CloseHandle (info->hThread);
  }

  g_object_unref (instance->host_session);

  g_slice_free (FridaSpawnInstance, instance);
}

static void
frida_spawn_instance_resume (FridaSpawnInstance * self)
{
  ResumeThread (self->process_info.hThread);
}

static WCHAR *
command_line_from_argv (const gchar ** argv, gint argv_length)
{
  GString * line;
  WCHAR * line_utf16;
  gint i;

  line = g_string_new ("");

  for (i = 0; i != argv_length; i++)
  {
    const gchar * arg = argv[i];
    gboolean no_quotes_needed;

    if (i > 0)
      g_string_append_c (line, ' ');

    no_quotes_needed = arg[0] != '\0' &&
        g_utf8_strchr (arg, -1, ' ') == NULL &&
        g_utf8_strchr (arg, -1, '\t') == NULL &&
        g_utf8_strchr (arg, -1, '\n') == NULL &&
        g_utf8_strchr (arg, -1, '\v') == NULL &&
        g_utf8_strchr (arg, -1, '"') == NULL;
    if (no_quotes_needed)
    {
      g_string_append (line, arg);
    }
    else
    {
      const gchar * c;

      g_string_append_c (line, '"');

      for (c = arg; *c != '\0'; c = g_utf8_next_char (c))
      {
        guint num_backslashes = 0;

        while (*c != '\0' && *c == '\\')
        {
          num_backslashes++;
          c++;
        }

        if (*c == '\0')
        {
          append_n_backslashes (line, num_backslashes * 2);
          break;
        }
        else if (*c == '"')
        {
          append_n_backslashes (line, (num_backslashes * 2) + 1);
          g_string_append_c (line, *c);
        }
        else
        {
          append_n_backslashes (line, num_backslashes);
          g_string_append_unichar (line, g_utf8_get_char (c));
        }
      }

      g_string_append_c (line, '"');
    }
  }

  line_utf16 = (WCHAR *) g_utf8_to_utf16 (line->str, -1, NULL, NULL, NULL);

  g_string_free (line, TRUE);

  return line_utf16;
}

static WCHAR *
environment_block_from_envp (const gchar ** envp, gint envp_length)
{
  GString * block;
  gint i;

  block = g_string_new ("");

  if (envp_length > 0)
  {
    for (i = 0; i != envp_length; i++)
    {
      gunichar2 * var;
      glong items_written;

      var = g_utf8_to_utf16 (envp[i], -1, NULL, &items_written, NULL);
      g_string_append_len (block, (gchar *) var, (items_written + 1) * sizeof (gunichar2));
      g_free (var);
    }
  }
  else
  {
    g_string_append_c (block, '\0');
    g_string_append_c (block, '\0');
  }
  g_string_append_c (block, '\0');

  return (WCHAR *) g_string_free (block, FALSE);
}

static void
append_n_backslashes (GString * str, guint n)
{
  guint i;

  for (i = 0; i != n; i++)
    g_string_append_c (str, '\\');
}
