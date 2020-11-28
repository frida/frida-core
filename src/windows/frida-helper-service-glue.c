#include "frida-helper-service-glue.h"

#include <windows.h>

#if GLIB_SIZEOF_VOID_P == 8
# define FRIDA_HELPER_SERVICE_ARCH "64"
#else
# define FRIDA_HELPER_SERVICE_ARCH "32"
#endif

#define STANDALONE_JOIN_TIMEOUT_MSEC (5 * 1000)

typedef struct _FridaServiceContext FridaServiceContext;

struct _FridaServiceContext
{
  gchar * service_basename;

  SC_HANDLE scm;
  SC_HANDLE service32;
  SC_HANDLE service64;

  HANDLE standalone32;
  HANDLE standalone64;
};

static void WINAPI frida_managed_helper_service_main (DWORD argc, WCHAR ** argv);
static DWORD WINAPI frida_managed_helper_service_handle_control_code (DWORD control, DWORD event_type, void * event_data, void * context);
static void frida_managed_helper_service_report_status (DWORD current_state, DWORD exit_code, DWORD wait_hint);

static gboolean frida_register_and_start_services (FridaServiceContext * self);
static void frida_stop_and_unregister_services (FridaServiceContext * self);
static gboolean frida_spawn_standalone_services (FridaServiceContext * self);
static gboolean frida_join_standalone_services (FridaServiceContext * self);
static void frida_kill_standalone_services (FridaServiceContext * self);
static void frida_release_standalone_services (FridaServiceContext * self);

static gboolean frida_register_services (FridaServiceContext * self);
static gboolean frida_unregister_services (FridaServiceContext * self);
static gboolean frida_start_services (FridaServiceContext * self);
static gboolean frida_stop_services (FridaServiceContext * self);

static SC_HANDLE frida_register_service (FridaServiceContext * self, const gchar * suffix);
static gboolean frida_unregister_service (FridaServiceContext * self, SC_HANDLE handle);
static gboolean frida_start_service (FridaServiceContext * self, SC_HANDLE handle);
static gboolean frida_stop_service (FridaServiceContext * self, SC_HANDLE handle);

static HANDLE frida_spawn_standalone_service (FridaServiceContext * self, const gchar * suffix);
static gboolean frida_join_standalone_service (FridaServiceContext * self, HANDLE handle);
static void frida_kill_standalone_service (FridaServiceContext * self, HANDLE handle);

static FridaServiceContext * frida_service_context_new (const gchar * service_basename);
static void frida_service_context_free (FridaServiceContext * self);

static WCHAR * frida_managed_helper_service_name = NULL;
static SERVICE_STATUS_HANDLE frida_managed_helper_service_status_handle = NULL;

void *
frida_helper_manager_start_services (const char * service_basename, FridaPrivilegeLevel level)
{
  FridaServiceContext * self;

  self = frida_service_context_new (service_basename);

  self->scm = (level == FRIDA_PRIVILEGE_LEVEL_ELEVATED)
      ? OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS)
      : NULL;
  if (self->scm != NULL)
  {
    if (!frida_register_and_start_services (self))
    {
      CloseServiceHandle (self->scm);
      self->scm = NULL;
    }
  }

  if (self->scm == NULL)
  {
    if (!frida_spawn_standalone_services (self))
    {
      frida_service_context_free (self);
      self = NULL;
    }
  }

  return self;
}

void
frida_helper_manager_stop_services (void * context)
{
  FridaServiceContext * self = context;

  if (self->scm != NULL)
  {
    frida_stop_and_unregister_services (self);
  }
  else
  {
    if (!frida_join_standalone_services (self))
      frida_kill_standalone_services (self);
  }

  frida_service_context_free (self);
}

char *
frida_helper_service_derive_basename (void)
{
  WCHAR filename_utf16[MAX_PATH + 1] = { 0, };
  gchar * name, * tmp;

  GetModuleFileNameW (NULL, filename_utf16, MAX_PATH);

  name = g_utf16_to_utf8 (filename_utf16, -1, NULL, NULL, NULL);

  tmp = g_path_get_dirname (name);
  g_free (name);
  name = tmp;

  tmp = g_path_get_basename (name);
  g_free (name);
  name = tmp;

  tmp = g_strconcat (name, "-", NULL);
  g_free (name);
  name = tmp;

  return name;
}

char *
frida_helper_service_derive_filename_for_suffix (const char * suffix)
{
  WCHAR filename_utf16[MAX_PATH + 1] = { 0, };
  gchar * name, * tmp;
  glong len;

  GetModuleFileNameW (NULL, filename_utf16, MAX_PATH);

  name = g_utf16_to_utf8 (filename_utf16, -1, NULL, &len, NULL);
  if (g_str_has_suffix (name, "-32.exe") || g_str_has_suffix (name, "-64.exe"))
  {
    name[len - 6] = '\0';
    tmp = g_strconcat (name, suffix, ".exe", NULL);
    g_free (name);
    name = tmp;
  }
  else
  {
    g_critical ("Unexpected filename: %s", name);
  }

  return name;
}

char *
frida_helper_service_derive_svcname_for_self (void)
{
  gchar * basename, * name;

  basename = frida_helper_service_derive_basename ();
  name = g_strconcat (basename, FRIDA_HELPER_SERVICE_ARCH, NULL);
  g_free (basename);

  return name;
}

char *
frida_helper_service_derive_svcname_for_suffix (const char * suffix)
{
  gchar * basename, * name;

  basename = frida_helper_service_derive_basename ();
  name = g_strconcat (basename, suffix, NULL);
  g_free (basename);

  return name;
}

void
frida_managed_helper_service_enter_dispatcher_and_main_loop (void)
{
  SERVICE_TABLE_ENTRYW dispatch_table[2] = { 0, };
  gchar * name;

  name = frida_helper_service_derive_svcname_for_self ();
  frida_managed_helper_service_name = g_utf8_to_utf16 (name, -1, NULL, NULL, NULL);
  g_free (name);

  dispatch_table[0].lpServiceName = frida_managed_helper_service_name;
  dispatch_table[0].lpServiceProc = frida_managed_helper_service_main;

  StartServiceCtrlDispatcherW (dispatch_table);

  frida_managed_helper_service_status_handle = NULL;

  g_free (frida_managed_helper_service_name);
  frida_managed_helper_service_name = NULL;
}

static void WINAPI
frida_managed_helper_service_main (DWORD argc, WCHAR ** argv)
{
  GMainLoop * loop;

  (void) argc;
  (void) argv;

  loop = g_main_loop_new (NULL, FALSE);

  frida_managed_helper_service_status_handle = RegisterServiceCtrlHandlerExW (
      frida_managed_helper_service_name,
      frida_managed_helper_service_handle_control_code,
      loop);

  frida_managed_helper_service_report_status (SERVICE_START_PENDING, NO_ERROR, 0);

  frida_managed_helper_service_report_status (SERVICE_RUNNING, NO_ERROR, 0);
  g_main_loop_run (loop);
  frida_managed_helper_service_report_status (SERVICE_STOPPED, NO_ERROR, 0);

  g_main_loop_unref (loop);
}

static gboolean
frida_managed_helper_service_stop (gpointer data)
{
  GMainLoop * loop = data;

  g_main_loop_quit (loop);

  return FALSE;
}

static DWORD WINAPI
frida_managed_helper_service_handle_control_code (DWORD control, DWORD event_type, void * event_data, void * context)
{
  GMainLoop * loop = context;

  (void) event_type;
  (void) event_data;

  switch (control)
  {
    case SERVICE_CONTROL_STOP:
      frida_managed_helper_service_report_status (SERVICE_STOP_PENDING, NO_ERROR, 0);
      g_idle_add (frida_managed_helper_service_stop, loop);
      return NO_ERROR;

    case SERVICE_CONTROL_INTERROGATE:
      return NO_ERROR;

    default:
      return ERROR_CALL_NOT_IMPLEMENTED;
  }
}

static void
frida_managed_helper_service_report_status (DWORD current_state, DWORD exit_code, DWORD wait_hint)
{
  SERVICE_STATUS status;
  static DWORD checkpoint = 1;

  status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  status.dwCurrentState = current_state;

  if (current_state == SERVICE_START_PENDING)
    status.dwControlsAccepted = 0;
  else
    status.dwControlsAccepted = SERVICE_ACCEPT_STOP;

  status.dwWin32ExitCode = exit_code;
  status.dwServiceSpecificExitCode = 0;

  if (current_state == SERVICE_RUNNING || current_state == SERVICE_STOPPED)
  {
    status.dwCheckPoint = 0;
  }
  else
  {
    status.dwCheckPoint = checkpoint++;
  }

  status.dwWaitHint = wait_hint;

  SetServiceStatus (frida_managed_helper_service_status_handle, &status);
}

static gboolean
frida_register_and_start_services (FridaServiceContext * self)
{
  if (!frida_register_services (self))
    return FALSE;

  if (!frida_start_services (self))
  {
    frida_unregister_services (self);
    return FALSE;
  }

  return TRUE;
}

static void
frida_stop_and_unregister_services (FridaServiceContext * self)
{
  frida_stop_services (self);
  frida_unregister_services (self);
}

static gboolean
frida_spawn_standalone_services (FridaServiceContext * self)
{
  HANDLE standalone32, standalone64;

  standalone32 = frida_spawn_standalone_service (self, "32");
  if (standalone32 == NULL)
    return FALSE;

  if (frida_windows_system_is_x64 ())
  {
    standalone64 = frida_spawn_standalone_service (self, "64");
    if (standalone64 == NULL)
    {
      frida_kill_standalone_service (self, standalone32);
      CloseHandle (standalone32);
      return FALSE;
    }
  }
  else
  {
    standalone64 = NULL;
  }

  self->standalone32 = standalone32;
  self->standalone64 = standalone64;

  return TRUE;
}

static gboolean
frida_join_standalone_services (FridaServiceContext * self)
{
  gboolean success = TRUE;

  if (frida_windows_system_is_x64 ())
    success &= frida_join_standalone_service (self, self->standalone64);

  success &= frida_join_standalone_service (self, self->standalone32);

  if (success)
    frida_release_standalone_services (self);

  return success;
}

static void
frida_kill_standalone_services (FridaServiceContext * self)
{
  if (frida_windows_system_is_x64 ())
    frida_kill_standalone_service (self, self->standalone64);

  frida_kill_standalone_service (self, self->standalone32);

  frida_release_standalone_services (self);
}

static void
frida_release_standalone_services (FridaServiceContext * self)
{
  if (frida_windows_system_is_x64 ())
  {
    g_assert (self->standalone64 != NULL);
    CloseHandle (self->standalone64);
    self->standalone64 = NULL;
  }

  g_assert (self->standalone32 != NULL);
  CloseHandle (self->standalone32);
  self->standalone32 = NULL;
}

static gboolean
frida_register_services (FridaServiceContext * self)
{
  SC_HANDLE service32, service64;

  service32 = frida_register_service (self, "32");
  if (service32 == NULL)
    return FALSE;

  if (frida_windows_system_is_x64 ())
  {
    service64 = frida_register_service (self, "64");
    if (service64 == NULL)
    {
      frida_unregister_service (self, service32);
      CloseServiceHandle (service32);
      return FALSE;
    }
  }
  else
  {
    service64 = NULL;
  }

  self->service32 = service32;
  self->service64 = service64;

  return TRUE;
}

static gboolean
frida_unregister_services (FridaServiceContext * self)
{
  gboolean success = TRUE;

  if (frida_windows_system_is_x64 ())
  {
    success &= frida_unregister_service (self, self->service64);
    CloseServiceHandle (self->service64);
    self->service64 = NULL;
  }

  success &= frida_unregister_service (self, self->service32);
  CloseServiceHandle (self->service32);
  self->service32 = NULL;

  return success;
}

static gboolean
frida_start_services (FridaServiceContext * self)
{
  if (!frida_start_service (self, self->service32))
    return FALSE;

  if (frida_windows_system_is_x64 ())
  {
    if (!frida_start_service (self, self->service64))
    {
      frida_stop_service (self, self->service32);
      return FALSE;
    }
  }

  return TRUE;
}

static gboolean
frida_stop_services (FridaServiceContext * self)
{
  gboolean success = TRUE;

  if (frida_windows_system_is_x64 ())
    success &= frida_stop_service (self, self->service64);

  success &= frida_stop_service (self, self->service32);

  return success;
}

static SC_HANDLE
frida_register_service (FridaServiceContext * self, const gchar * suffix)
{
  SC_HANDLE handle;
  gchar * servicename_utf8;
  WCHAR * servicename;
  gchar * displayname_utf8;
  WCHAR * displayname;
  gchar * filename_utf8;
  WCHAR * filename;

  servicename_utf8 = g_strconcat (self->service_basename, suffix, NULL);
  servicename = g_utf8_to_utf16 (servicename_utf8, -1, NULL, NULL, NULL);

  displayname_utf8 = g_strdup_printf ("Frida %s-bit helper (%s)", suffix, servicename_utf8);
  displayname = g_utf8_to_utf16 (displayname_utf8, -1, NULL, NULL, NULL);

  filename_utf8 = frida_helper_service_derive_filename_for_suffix (suffix);
  filename = g_utf8_to_utf16 (filename_utf8, -1, NULL, NULL, NULL);

  handle = CreateServiceW (self->scm,
      servicename,
      displayname,
      SERVICE_ALL_ACCESS,
      SERVICE_WIN32_OWN_PROCESS,
      SERVICE_DEMAND_START,
      SERVICE_ERROR_NORMAL,
      filename,
      NULL,
      NULL,
      NULL,
      NULL,
      NULL);

  g_free (filename);
  g_free (filename_utf8);

  g_free (displayname);
  g_free (displayname_utf8);

  g_free (servicename);
  g_free (servicename_utf8);

  return handle;
}

static gboolean
frida_unregister_service (FridaServiceContext * self, SC_HANDLE handle)
{
  (void) self;

  return DeleteService (handle);
}

static gboolean
frida_start_service (FridaServiceContext * self, SC_HANDLE handle)
{
  (void) self;

  return StartService (handle, 0, NULL);
}

static gboolean
frida_stop_service (FridaServiceContext * self, SC_HANDLE handle)
{
  SERVICE_STATUS status = { 0, };

  (void) self;

  return ControlService (handle, SERVICE_CONTROL_STOP, &status);
}

static HANDLE
frida_spawn_standalone_service (FridaServiceContext * self, const gchar * suffix)
{
  HANDLE handle = NULL;
  gchar * appname_utf8;
  WCHAR * appname;
  gchar * cmdline_utf8;
  WCHAR * cmdline;
  STARTUPINFOW si = { 0, };
  PROCESS_INFORMATION pi = { 0, };

  (void) self;

  appname_utf8 = frida_helper_service_derive_filename_for_suffix (suffix);
  appname = (WCHAR *) g_utf8_to_utf16 (appname_utf8, -1, NULL, NULL, NULL);

  cmdline_utf8 = g_strconcat ("\"", appname_utf8, "\" STANDALONE", NULL);
  cmdline = (WCHAR *) g_utf8_to_utf16 (cmdline_utf8, -1, NULL, NULL, NULL);

  si.cb = sizeof (si);

  if (CreateProcessW (appname, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
  {
    handle = pi.hProcess;
    CloseHandle (pi.hThread);
  }

  g_free (cmdline);
  g_free (cmdline_utf8);

  g_free (appname);
  g_free (appname_utf8);

  return handle;
}

static gboolean
frida_join_standalone_service (FridaServiceContext * self, HANDLE handle)
{
  (void) self;

  return WaitForSingleObject (handle,
      STANDALONE_JOIN_TIMEOUT_MSEC) == WAIT_OBJECT_0;
}

static void
frida_kill_standalone_service (FridaServiceContext * self, HANDLE handle)
{
  (void) self;

  TerminateProcess (handle, 1);
}

static FridaServiceContext *
frida_service_context_new (const gchar * service_basename)
{
  FridaServiceContext * self;

  self = g_slice_new0 (FridaServiceContext);
  self->service_basename = g_strdup (service_basename);

  return self;
}

static void
frida_service_context_free (FridaServiceContext * self)
{
  g_assert (self->standalone64 == NULL);
  g_assert (self->standalone32 == NULL);

  g_assert (self->service64 == NULL);
  g_assert (self->service32 == NULL);

  if (self->scm != NULL)
    CloseServiceHandle (self->scm);

  g_free (self->service_basename);

  g_slice_free (FridaServiceContext, self);
}
