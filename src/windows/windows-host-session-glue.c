#define COBJMACROS 1

#include "frida-core.h"

#include "icon-helpers.h"

#include <gio/gwin32inputstream.h>
#include <gio/gwin32outputstream.h>
#include <shellapi.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <shobjidl.h>
#include <unknwn.h>

#define PARSE_STRING_MAX_LENGTH   (40 + 1)

static void frida_child_process_on_death (GPid pid, gint status, gpointer user_data);

static WCHAR * command_line_from_argv (const gchar ** argv, gint argv_length);
static WCHAR * environment_block_from_envp (const gchar ** envp, gint envp_length);

static void append_n_backslashes (GString * str, guint n);

static void frida_make_pipe (HANDLE * read, HANDLE * write);
static void frida_ensure_not_inherited (HANDLE handle);

FridaImageData *
_frida_windows_host_session_provider_try_extract_icon (void)
{
  FridaImageData * result = NULL;
  OLECHAR my_computer_parse_string[PARSE_STRING_MAX_LENGTH];
  IShellFolder * desktop_folder = NULL;
  IEnumIDList * children = NULL;
  ITEMIDLIST * child;

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

FridaChildProcess *
_frida_windows_host_session_do_spawn (FridaWindowsHostSession * self, const gchar * path, FridaHostSpawnOptions * options, GError ** error)
{
  WCHAR * application_name, * command_line, * environment, * current_directory;
  const gchar * cwd;
  STARTUPINFO startup_info;
  FridaStdio stdio;
  HANDLE stdin_read = NULL, stdin_write = NULL;
  HANDLE stdout_read = NULL, stdout_write = NULL;
  HANDLE stderr_read = NULL, stderr_write = NULL;
  PROCESS_INFORMATION process_info;
  FridaStdioPipes * pipes;
  FridaChildProcess * process;
  guint watch_id;
  GSource * watch;

  if (!g_file_test (path, G_FILE_TEST_EXISTS))
    goto handle_path_error;

  if (frida_host_spawn_options_get_aslr (options) == FRIDA_ASLR_DISABLED)
    goto handle_aslr_error;

  application_name = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);

  if (frida_host_spawn_options_get_has_argv (options))
  {
    gchar ** argv;
    gint argv_length;

    argv = frida_host_spawn_options_get_argv (options, &argv_length);
    command_line = command_line_from_argv (argv, argv_length);
  }
  else
  {
    command_line = NULL;
  }

  if (frida_host_spawn_options_get_has_envp (options))
  {
    gchar ** envp;
    gint envp_length;

    envp = frida_host_spawn_options_get_envp (options, &envp_length);
    environment = environment_block_from_envp (envp, envp_length);
  }
  else
  {
    environment = NULL;
  }

  cwd = frida_host_spawn_options_get_cwd (options);
  if (*cwd != '\0')
    current_directory = (WCHAR *) g_utf8_to_utf16 (cwd, -1, NULL, NULL, NULL);
  else
    current_directory = NULL;

  ZeroMemory (&startup_info, sizeof (startup_info));
  startup_info.cb = sizeof (startup_info);

  stdio = frida_host_spawn_options_get_stdio (options);
  switch (stdio)
  {
    case FRIDA_STDIO_INHERIT:
      startup_info.hStdInput = GetStdHandle (STD_INPUT_HANDLE);
      startup_info.hStdOutput = GetStdHandle (STD_OUTPUT_HANDLE);
      startup_info.hStdError = GetStdHandle (STD_ERROR_HANDLE);
      startup_info.dwFlags = STARTF_USESTDHANDLES;

      break;

    case FRIDA_STDIO_PIPE:
      frida_make_pipe (&stdin_read, &stdin_write);
      frida_make_pipe (&stdout_read, &stdout_write);
      frida_make_pipe (&stderr_read, &stderr_write);

      frida_ensure_not_inherited (stdin_write);
      frida_ensure_not_inherited (stdout_read);
      frida_ensure_not_inherited (stderr_read);

      startup_info.hStdInput = stdin_read;
      startup_info.hStdOutput = stdout_write;
      startup_info.hStdError = stderr_write;
      startup_info.dwFlags = STARTF_USESTDHANDLES;

      break;

    default:
      g_assert_not_reached ();
  }

  if (!CreateProcessW (
      application_name,
      command_line,
      NULL,
      NULL,
      TRUE,
      CREATE_SUSPENDED |
      CREATE_UNICODE_ENVIRONMENT |
      CREATE_NEW_PROCESS_GROUP |
      DEBUG_PROCESS |
      DEBUG_ONLY_THIS_PROCESS,
      environment,
      current_directory,
      &startup_info,
      &process_info))
  {
    goto handle_create_error;
  }

  DebugActiveProcessStop (process_info.dwProcessId);

  g_free (current_directory);
  g_free (environment);
  g_free (command_line);
  g_free (application_name);

  if (stdio == FRIDA_STDIO_PIPE)
  {
    CloseHandle (stdin_read);
    CloseHandle (stdout_write);
    CloseHandle (stderr_write);

    pipes = frida_stdio_pipes_new (
        g_win32_output_stream_new (stdin_write, TRUE),
        g_win32_input_stream_new (stdout_read, TRUE),
        g_win32_input_stream_new (stderr_read, TRUE));
  }
  else
  {
    pipes = NULL;
  }

  process = frida_child_process_new (
      G_OBJECT (self),
      process_info.dwProcessId,
      process_info.hProcess,
      process_info.hThread,
      pipes);

  watch_id = g_child_watch_add_full (
      G_PRIORITY_DEFAULT,
      process_info.hProcess,
      frida_child_process_on_death,
      g_object_ref (process),
      g_object_unref);
  watch = g_main_context_find_source_by_id (g_main_context_get_thread_default (), watch_id);
  g_assert (watch != NULL);
  frida_child_process_set_watch (process, watch);

  return process;

handle_path_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_EXECUTABLE_NOT_FOUND,
        "Unable to find executable at '%s'",
        path);
    return NULL;
  }
handle_aslr_error:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Disabling ASLR is not supported on this OS");
    return NULL;
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

    if (stdio == FRIDA_STDIO_PIPE)
    {
      CloseHandle (stdin_read);
      CloseHandle (stdin_write);

      CloseHandle (stdout_read);
      CloseHandle (stdout_write);

      CloseHandle (stderr_read);
      CloseHandle (stderr_write);
    }

    g_free (current_directory);
    g_free (environment);
    g_free (command_line);
    g_free (application_name);

    return NULL;
  }
}

gboolean
_frida_windows_host_session_process_is_alive (guint pid)
{
  HANDLE process;
  DWORD res;

  process = OpenProcess (SYNCHRONIZE, FALSE, pid);
  if (process == NULL)
    return GetLastError () == ERROR_ACCESS_DENIED;

  res = WaitForSingleObject (process, 0);

  CloseHandle (process);

  return res == WAIT_TIMEOUT;
}

void
frida_child_process_close (FridaChildProcess * self)
{
  GSource * watch;

  if (self->closed)
    return;

  watch = frida_child_process_get_watch (self);
  if (watch != NULL)
    g_source_destroy (watch);

  CloseHandle (frida_child_process_get_handle (self));
  CloseHandle (frida_child_process_get_main_thread (self));

  self->closed = TRUE;
}

void
frida_child_process_resume (FridaChildProcess * self, GError ** error)
{
  if (self->resumed)
    goto already_resumed;

  ResumeThread (frida_child_process_get_main_thread (self));

  self->resumed = TRUE;
  return;

already_resumed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_INVALID_OPERATION,
        "Already resumed");
  }
}

static void
frida_child_process_on_death (GPid pid, gint status, gpointer user_data)
{
  FridaChildProcess * self = user_data;

  (void) pid;

  _frida_windows_host_session_on_child_dead (
      FRIDA_WINDOWS_HOST_SESSION (frida_child_process_get_parent (self)),
      self,
      status);
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

  block = g_string_new ("");

  if (envp_length > 0)
  {
    gint i;

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

static void
frida_make_pipe (HANDLE * read, HANDLE * write)
{
  SECURITY_ATTRIBUTES attributes;
  DWORD default_buffer_size = 0;
  BOOL pipe_created;

  attributes.nLength = sizeof (attributes);
  attributes.bInheritHandle = TRUE;
  attributes.lpSecurityDescriptor = NULL;

  pipe_created = CreatePipe (read, write, &attributes, default_buffer_size);
  g_assert (pipe_created);
}

static void
frida_ensure_not_inherited (HANDLE handle)
{
  BOOL inherit_flag_updated;

  inherit_flag_updated = SetHandleInformation (handle, HANDLE_FLAG_INHERIT, 0);
  g_assert (inherit_flag_updated);
}
