#include <glib.h>
#include <windows.h>

typedef struct _WinjectorServiceContext WinjectorServiceContext;

struct _WinjectorServiceContext
{
  gboolean system_is_x64;
  gchar * service_basename;

  SC_HANDLE scm;
  SC_HANDLE service32;
  SC_HANDLE service64;
};

static gboolean register_and_start_services (WinjectorServiceContext * self);
static void stop_and_unregister_services (WinjectorServiceContext * self);
static gboolean spawn_standalone_services (WinjectorServiceContext * self);
static void join_standalone_services (WinjectorServiceContext * self);

static gboolean register_services (WinjectorServiceContext * self);
static gboolean unregister_services (WinjectorServiceContext * self);
static gboolean start_services (WinjectorServiceContext * self);
static gboolean stop_services (WinjectorServiceContext * self);

static SC_HANDLE register_service (WinjectorServiceContext * self,
    const gchar * suffix);
static gboolean unregister_service (WinjectorServiceContext * self,
    SC_HANDLE handle);
static gboolean start_service (WinjectorServiceContext * self,
    SC_HANDLE handle);
static gboolean stop_service (WinjectorServiceContext * self,
    SC_HANDLE handle);

static WinjectorServiceContext * winjector_service_context_new (
    const gchar * service_basename);
static void winjector_service_context_free (WinjectorServiceContext * self);

void *
winjector_manager_start_services (const char * service_basename)
{
  WinjectorServiceContext * self;

  self = winjector_service_context_new (service_basename);

  self->scm = OpenSCManager (NULL, NULL, SC_MANAGER_ALL_ACCESS);
  if (self->scm != NULL)
  {
    if (!register_and_start_services (self))
    {
      CloseServiceHandle (self->scm);
      self->scm = NULL;
    }
  }

  if (self->scm == NULL)
  {
    if (!spawn_standalone_services (self))
    {
      winjector_service_context_free (self);
      self = NULL;
    }
  }

  return self;
}

void
winjector_manager_stop_services (void * context)
{
  WinjectorServiceContext * self = context;

  if (self->scm != NULL)
    stop_and_unregister_services (self);
  else
    join_standalone_services (self);

  winjector_service_context_free (self);
}

char *
winjector_service_derive_basename (void)
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
winjector_service_derive_filename (const char * suffix)
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

static gboolean
register_and_start_services (WinjectorServiceContext * self)
{
  if (!register_services (self))
    return FALSE;

  if (!start_services (self))
  {
    unregister_services (self);
    return FALSE;
  }

  return TRUE;
}

static void
stop_and_unregister_services (WinjectorServiceContext * self)
{
  stop_services (self);
  unregister_services (self);
}

static gboolean
spawn_standalone_services (WinjectorServiceContext * self)
{
  g_assert_not_reached ();
  return FALSE;
}

static void
join_standalone_services (WinjectorServiceContext * self)
{
  g_assert_not_reached ();
}

static gboolean
register_services (WinjectorServiceContext * self)
{
  SC_HANDLE service32, service64;

  service32 = register_service (self, "32");
  if (service32 == NULL)
    return FALSE;

  if (self->system_is_x64)
  {
    service64 = register_service (self, "64");
    if (service64 == NULL)
    {
      unregister_service (self, service32);
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
unregister_services (WinjectorServiceContext * self)
{
  gboolean success = TRUE;

  if (self->system_is_x64)
  {
    success &= unregister_service (self, self->service64);
    CloseServiceHandle (self->service64);
    self->service64 = NULL;
  }

  success &= unregister_service (self, self->service32);
  CloseServiceHandle (self->service32);
  self->service32 = NULL;

  return success;
}

static gboolean
start_services (WinjectorServiceContext * self)
{
  if (!start_service (self, self->service32))
    return FALSE;

  if (self->system_is_x64)
  {
    if (!start_service (self, self->service64))
    {
      stop_service (self, self->service32);
      return FALSE;
    }
  }

  return TRUE;
}

static gboolean
stop_services (WinjectorServiceContext * self)
{
  gboolean success = TRUE;

  if (self->system_is_x64)
    success &= stop_service (self, self->service64);

  success &= stop_service (self, self->service32);

  return success;
}

static SC_HANDLE
register_service (WinjectorServiceContext * self, const gchar * suffix)
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

  displayname_utf8 = g_strdup_printf ("Zed Winjector %s-bit helper (%s)",
      suffix, servicename_utf8);
  displayname = g_utf8_to_utf16 (displayname_utf8, -1, NULL, NULL, NULL);

  filename_utf8 = winjector_service_derive_filename (suffix);
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
unregister_service (WinjectorServiceContext * self, SC_HANDLE handle)
{
  return DeleteService (handle);
}

static gboolean
start_service (WinjectorServiceContext * self, SC_HANDLE handle)
{
  return StartService (handle, 0, NULL);
}

static gboolean
stop_service (WinjectorServiceContext * self, SC_HANDLE handle)
{
  SERVICE_STATUS status = { 0, };
  return ControlService (handle, SERVICE_CONTROL_STOP, &status);
}

static WinjectorServiceContext *
winjector_service_context_new (const gchar * service_basename)
{
  WinjectorServiceContext * self;
  SYSTEM_INFO si;

  self = g_new0 (WinjectorServiceContext, 1);

  GetNativeSystemInfo (&si);
  self->system_is_x64 = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;

  self->service_basename = g_strdup (service_basename);

  return self;
}

static void
winjector_service_context_free (WinjectorServiceContext * self)
{
  g_assert (self->service64 == NULL);
  g_assert (self->service32 == NULL);

  if (self->scm != NULL)
    CloseServiceHandle (self->scm);

  g_free (self->service_basename);

  g_free (self);
}
