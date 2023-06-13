#include "frida-core.h"

#include "icon-helpers.h"

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sysctl.h>

#ifdef HAVE_MACOS
# include <libproc.h>
# import <AppKit/AppKit.h>
# if __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_12
#  define NSBitmapImageFileTypePNG NSPNGFileType
# endif
#endif

#if defined (HAVE_IOS) || defined (HAVE_TVOS)
# import "springboard.h"
#endif

#if defined (HAVE_WATCHOS) || defined (HAVE_TVOS)
# import <Foundation/Foundation.h>
#endif

#ifndef PROC_PIDPATHINFO_MAXSIZE
# define PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN)
#endif

typedef struct _FridaEnumerateApplicationsOperation FridaEnumerateApplicationsOperation;
typedef struct _FridaEnumerateProcessesOperation FridaEnumerateProcessesOperation;

struct _FridaEnumerateApplicationsOperation
{
  FridaScope scope;
  GHashTable * process_by_identifier;
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
  FridaSpringboardApi * api;
#endif

  GArray * result;
};

struct _FridaEnumerateProcessesOperation
{
  FridaScope scope;
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
  FridaSpringboardApi * api;
#endif

  GArray * result;
};

#if defined (HAVE_IOS) || defined (HAVE_TVOS)
static void frida_collect_application_info_from_id_cstring (const gchar * identifier, FridaEnumerateApplicationsOperation * op);
static void frida_collect_application_info_from_id_nsstring (NSString * identifier, FridaEnumerateApplicationsOperation * op);
#endif

static void frida_collect_process_info_from_pid (guint pid, FridaEnumerateProcessesOperation * op);
static void frida_collect_process_info_from_kinfo (struct kinfo_proc * process, FridaEnumerateProcessesOperation * op);

#if defined (HAVE_MACOS) || defined (HAVE_IOS) || defined (HAVE_TVOS)
static void frida_add_app_id (GHashTable * parameters, NSString * identifier);
#endif

#if defined (HAVE_MACOS)
static void frida_add_app_icons (GHashTable * parameters, NSImage * image);
#elif defined (HAVE_IOS) || defined (HAVE_TVOS)
static void frida_add_app_metadata (GHashTable * parameters, NSString * identifier, FridaSpringboardApi * api);
static void frida_add_app_state (GHashTable * parameters, guint pid, FridaSpringboardApi * api);
static void frida_add_app_icons (GHashTable * parameters, NSString * identifier);
#endif

#ifndef HAVE_MACOS
extern int proc_pidpath (int pid, void * buffer, uint32_t buffer_size);
#endif

static void frida_add_process_metadata (GHashTable * parameters, const struct kinfo_proc * process);

static struct kinfo_proc * frida_system_query_kinfo_procs (guint * count);
static GVariant * frida_uid_to_name (uid_t uid);

#if defined (HAVE_MACOS)

void
frida_system_get_frontmost_application (FridaFrontmostQueryOptions * options, FridaHostApplicationInfo * result, GError ** error)
{
  g_set_error (error,
      FRIDA_ERROR,
      FRIDA_ERROR_NOT_SUPPORTED,
      "Not implemented");
}

FridaHostApplicationInfo *
frida_system_enumerate_applications (FridaApplicationQueryOptions * options, int * result_length)
{
  *result_length = 0;

  return NULL;
}

#elif defined (HAVE_IOS) || defined (HAVE_TVOS)

void
frida_system_get_frontmost_application (FridaFrontmostQueryOptions * options, FridaHostApplicationInfo * result, GError ** error)
{
  NSAutoreleasePool * pool;
  FridaSpringboardApi * api;
  NSString * identifier = nil;
  NSString * name = nil;
  FridaScope scope;
  struct kinfo_proc * processes = NULL;
  guint count, i;

  pool = [[NSAutoreleasePool alloc] init];

  api = _frida_get_springboard_api ();

  identifier = api->SBSCopyFrontmostApplicationDisplayIdentifier ();
  if (identifier == nil || identifier.length <= 1)
    goto no_frontmost_app;

  name = api->SBSCopyLocalizedApplicationNameForDisplayIdentifier (identifier);
  if (name == nil)
    goto no_frontmost_app;

  result->identifier = g_strdup ([identifier UTF8String]);
  result->name = g_strdup ([name UTF8String]);
  result->parameters = frida_make_parameters_dict ();
  result->pid = 0;

  scope = frida_frontmost_query_options_get_scope (options);

  processes = frida_system_query_kinfo_procs (&count);

  for (i = 0; i != count && result->pid == 0; i++)
  {
    struct kinfo_proc * process = &processes[i];
    guint pid;
    NSString * cur_identifier;

    pid = process->kp_proc.p_pid;

    cur_identifier = api->SBSCopyDisplayIdentifierForProcessID (pid);
    if (cur_identifier != nil)
    {
      if ([cur_identifier isEqualToString:identifier])
      {
        result->pid = pid;

        if (scope != FRIDA_SCOPE_MINIMAL)
          frida_add_process_metadata (result->parameters, process);
      }

      [cur_identifier release];
    }
  }

  if (scope != FRIDA_SCOPE_MINIMAL)
    frida_add_app_metadata (result->parameters, identifier, api);

  if (scope == FRIDA_SCOPE_FULL)
    frida_add_app_icons (result->parameters, identifier);

  goto beach;

no_frontmost_app:
  {
    frida_host_application_info_init_empty (result);
    goto beach;
  }
beach:
  {
    g_free (processes);

    [name release];
    [identifier release];

    [pool release];
  }
}

FridaHostApplicationInfo *
frida_system_enumerate_applications (FridaApplicationQueryOptions * options, int * result_length)
{
  FridaEnumerateApplicationsOperation op;
  NSAutoreleasePool * pool;
  struct kinfo_proc * processes;
  guint count, i;

  op.scope = frida_application_query_options_get_scope (options);
  op.process_by_identifier = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);
  op.api = _frida_get_springboard_api ();

  op.result = g_array_new (FALSE, FALSE, sizeof (FridaHostApplicationInfo));

  pool = [[NSAutoreleasePool alloc] init];

  processes = frida_system_query_kinfo_procs (&count);
  for (i = 0; i != count; i++)
  {
    struct kinfo_proc * process = &processes[i];
    NSString * identifier;

    identifier = op.api->SBSCopyDisplayIdentifierForProcessID (process->kp_proc.p_pid);
    if (identifier != nil)
    {
      g_hash_table_insert (op.process_by_identifier, (gpointer) [identifier UTF8String], process);
      [identifier autorelease];
    }
  }

  if (frida_application_query_options_has_selected_identifiers (options))
  {
    frida_application_query_options_enumerate_selected_identifiers (options, (GFunc) frida_collect_application_info_from_id_cstring, &op);
  }
  else
  {
    NSArray * identifiers = op.api->SBSCopyApplicationDisplayIdentifiers (NO, NO);

    if (identifiers == nil)
      identifiers = [[[[op.api->LSApplicationWorkspace defaultWorkspace] allApplications] valueForKey:@"applicationIdentifier"] retain];

    count = [identifiers count];
    for (i = 0; i != count; i++)
      frida_collect_application_info_from_id_nsstring ([identifiers objectAtIndex:i], &op);

    [identifiers release];
  }

  g_free (processes);
  g_hash_table_unref (op.process_by_identifier);

  [pool release];

  *result_length = op.result->len;

  return (FridaHostApplicationInfo *) g_array_free (op.result, FALSE);
}

static void
frida_collect_application_info_from_id_cstring (const gchar * identifier, FridaEnumerateApplicationsOperation * op)
{
  frida_collect_application_info_from_id_nsstring ([NSString stringWithUTF8String:identifier], op);
}

static void
frida_collect_application_info_from_id_nsstring (NSString * identifier, FridaEnumerateApplicationsOperation * op)
{
  FridaHostApplicationInfo info = { 0, };
  FridaScope scope = op->scope;
  FridaSpringboardApi * api = op->api;
  NSString * name;
  struct kinfo_proc * process;

  name = api->SBSCopyLocalizedApplicationNameForDisplayIdentifier (identifier);
  if (name == nil)
  {
    LSApplicationProxy * app = [api->LSApplicationProxy applicationProxyForIdentifier:identifier];
    name = [[app localizedNameWithPreferredLocalizations:nil useShortNameOnly:YES] retain];
  }

  info.identifier = g_strdup (identifier.UTF8String);
  info.name = g_strdup ((name != nil) ? name.UTF8String : "");
  info.parameters = frida_make_parameters_dict ();

  process = g_hash_table_lookup (op->process_by_identifier, info.identifier);
  if (process != NULL)
  {
    info.pid = process->kp_proc.p_pid;
  }
  else if (api->FBSSystemService != nil)
  {
    gint pid = [[api->FBSSystemService sharedService] pidForApplication:identifier];
    if (pid > 0)
      info.pid = pid;
  }

  if (scope != FRIDA_SCOPE_MINIMAL)
  {
    frida_add_app_metadata (info.parameters, identifier, api);

    if (process != NULL)
    {
      frida_add_app_state (info.parameters, process->kp_proc.p_pid, api);

      frida_add_process_metadata (info.parameters, process);
    }
  }

  if (scope == FRIDA_SCOPE_FULL)
    frida_add_app_icons (info.parameters, identifier);

  [name release];

  g_array_append_val (op->result, info);
}

#endif

FridaHostProcessInfo *
frida_system_enumerate_processes (FridaProcessQueryOptions * options, int * result_length)
{
  FridaEnumerateProcessesOperation op;
  NSAutoreleasePool * pool;

  op.scope = frida_process_query_options_get_scope (options);
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
  op.api = _frida_get_springboard_api ();
#endif

  op.result = g_array_new (FALSE, FALSE, sizeof (FridaHostProcessInfo));

  pool = [[NSAutoreleasePool alloc] init];

  if (frida_process_query_options_has_selected_pids (options))
  {
    frida_process_query_options_enumerate_selected_pids (options, (GFunc) frida_collect_process_info_from_pid, &op);
  }
  else
  {
    struct kinfo_proc * processes;
    guint count, i;

    processes = frida_system_query_kinfo_procs (&count);

    for (i = 0; i != count; i++)
      frida_collect_process_info_from_kinfo (&processes[i], &op);

    g_free (processes);
  }

  [pool release];

  *result_length = op.result->len;

  return (FridaHostProcessInfo *) g_array_free (op.result, FALSE);
}

static void
frida_collect_process_info_from_pid (guint pid, FridaEnumerateProcessesOperation * op)
{
  struct kinfo_proc process;
  size_t size;
  int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
  gint err;

  size = sizeof (process);

  err = sysctl (mib, G_N_ELEMENTS (mib), &process, &size, NULL, 0);
  g_assert (err != -1);

  if (size == 0)
    return;

  frida_collect_process_info_from_kinfo (&process, op);
}

static void
frida_collect_process_info_from_kinfo (struct kinfo_proc * process, FridaEnumerateProcessesOperation * op)
{
  FridaHostProcessInfo info = { 0, };
  FridaScope scope = op->scope;
  gboolean still_alive;
  gchar path[PROC_PIDPATHINFO_MAXSIZE];

  info.pid = process->kp_proc.p_pid;

  info.parameters = frida_make_parameters_dict ();

  if (scope != FRIDA_SCOPE_MINIMAL)
    frida_add_process_metadata (info.parameters, process);

#if defined (HAVE_MACOS)
  {
    NSRunningApplication * app = [NSRunningApplication runningApplicationWithProcessIdentifier:info.pid];
    if (app.icon != nil)
    {
      NSString * name = app.localizedName;
      if (name.length > 0)
        info.name = g_strdup (name.UTF8String);

      if (scope != FRIDA_SCOPE_MINIMAL)
      {
        NSString * identifier = app.bundleIdentifier;
        if (identifier != nil)
          frida_add_app_id (info.parameters, identifier);

        if (app.active)
          g_hash_table_insert (info.parameters, g_strdup ("frontmost"), g_variant_ref_sink (g_variant_new_boolean (TRUE)));
      }

      if (scope == FRIDA_SCOPE_FULL)
        frida_add_app_icons (info.parameters, app.icon);
    }
  }
#elif defined (HAVE_IOS) || defined (HAVE_TVOS)
  {
    FridaSpringboardApi * api = op->api;
    NSString * identifier;

    identifier = api->SBSCopyDisplayIdentifierForProcessID (info.pid);
    if (identifier != nil)
    {
      NSString * app_name;

      app_name = api->SBSCopyLocalizedApplicationNameForDisplayIdentifier (identifier);
      info.name = g_strdup ([app_name UTF8String]);
      [app_name release];

      if (scope != FRIDA_SCOPE_MINIMAL)
      {
        frida_add_app_id (info.parameters, identifier);

        frida_add_app_state (info.parameters, info.pid, api);
      }

      if (scope == FRIDA_SCOPE_FULL)
        frida_add_app_icons (info.parameters, identifier);

      [identifier release];
    }
  }
#endif

  still_alive = proc_pidpath (info.pid, path, sizeof (path)) > 0;
  if (still_alive)
  {
    if (info.name == NULL)
      info.name = g_path_get_basename (path);

    if (scope != FRIDA_SCOPE_MINIMAL)
      g_hash_table_insert (info.parameters, g_strdup ("path"), g_variant_ref_sink (g_variant_new_string (path)));
  }

  if (still_alive)
    g_array_append_val (op->result, info);
  else
    frida_host_process_info_destroy (&info);
}

void
frida_system_kill (guint pid)
{
  kill (pid, SIGKILL);
}

gchar *
frida_temporary_directory_get_system_tmp (void)
{
  if (geteuid () == 0)
  {
#ifdef HAVE_MACOS
    /* Sandboxed system daemons are likely able to read from this location */
    return g_strdup ("/private/var/root");
#else
    return g_strdup ("/Library/Caches");
#endif
  }
  else
  {
#ifdef HAVE_MACOS
    /* Mac App Store apps are sandboxed but able to read ~/.Trash/ */
    return g_build_filename (g_get_home_dir (), ".Trash", ".frida", NULL);
#else
    return g_strdup (g_get_tmp_dir ());
#endif
  }
}

#if defined (HAVE_MACOS) || defined (HAVE_IOS) || defined (HAVE_TVOS)

static void
frida_add_app_id (GHashTable * parameters, NSString * identifier)
{
  GVariantBuilder builder;

  g_variant_builder_init (&builder, G_VARIANT_TYPE_STRING_ARRAY);
  g_variant_builder_add_value (&builder, g_variant_new_string (identifier.UTF8String));
  g_hash_table_insert (parameters, g_strdup ("applications"), g_variant_ref_sink (g_variant_builder_end (&builder)));
}

#endif

#if defined (HAVE_MACOS)

static void
frida_add_app_icons (GHashTable * parameters, NSImage * image)
{
  GVariantBuilder builder;
  const guint sizes[] = { 16, 32 };
  guint i;

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

  for (i = 0; i != G_N_ELEMENTS (sizes); i++)
  {
    guint size = sizes[i];
    NSBitmapImageRep * rep;
    NSGraphicsContext * context;
    NSData * png;

    rep = [[NSBitmapImageRep alloc]
        initWithBitmapDataPlanes:nil
                      pixelsWide:size
                      pixelsHigh:size
                   bitsPerSample:8
                 samplesPerPixel:4
                        hasAlpha:YES
                        isPlanar:NO
                  colorSpaceName:NSCalibratedRGBColorSpace
                    bitmapFormat:0
                     bytesPerRow:size * 4
                    bitsPerPixel:32];

    context = [NSGraphicsContext graphicsContextWithBitmapImageRep:rep];

    [NSGraphicsContext saveGraphicsState];
    [NSGraphicsContext setCurrentContext:context];
    [image drawInRect:NSMakeRect (0, 0, size, size)
             fromRect:NSZeroRect
            operation:NSCompositingOperationCopy
             fraction:1.0];
    [context flushGraphics];
    [NSGraphicsContext restoreGraphicsState];

    png = [rep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];

    g_variant_builder_open (&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add (&builder, "{sv}", "format", g_variant_new_string ("png"));
    g_variant_builder_add (&builder, "{sv}", "width", g_variant_new_int64 (size));
    g_variant_builder_add (&builder, "{sv}", "height", g_variant_new_int64 (size));
    g_variant_builder_add (&builder, "{sv}", "image",
        g_variant_new_from_data (G_VARIANT_TYPE ("ay"), png.bytes, png.length, TRUE, (GDestroyNotify) CFRelease, [png retain]));
    g_variant_builder_close (&builder);

    [rep release];
  }

  g_hash_table_insert (parameters, g_strdup ("icons"), g_variant_ref_sink (g_variant_builder_end (&builder)));
}

#elif defined (HAVE_IOS) || defined (HAVE_TVOS)

static void
frida_add_app_metadata (GHashTable * parameters, NSString * identifier, FridaSpringboardApi * api)
{
  LSApplicationProxy * app;
  const char * version, * build, * data_path;
  NSDictionary<NSString *, NSURL *> * container_urls;
  NSNumber * get_task_allow;

  app = [api->LSApplicationProxy applicationProxyForIdentifier:identifier];
  if (app == nil)
    return;

  version = app.shortVersionString.UTF8String;
  if (version != NULL)
    g_hash_table_insert (parameters, g_strdup ("version"), g_variant_ref_sink (g_variant_new_string (version)));

  build = app.bundleVersion.UTF8String;
  if (build != NULL)
    g_hash_table_insert (parameters, g_strdup ("build"), g_variant_ref_sink (g_variant_new_string (build)));

  g_hash_table_insert (parameters, g_strdup ("path"), g_variant_ref_sink (g_variant_new_string (app.bundleURL.path.UTF8String)));

  data_path = app.dataContainerURL.path.UTF8String;
  container_urls = app.groupContainerURLs;
  if (data_path != NULL || container_urls.count > 0)
  {
    GVariantBuilder containers;

    g_variant_builder_init (&containers, G_VARIANT_TYPE_VARDICT);

    if (data_path != NULL)
      g_variant_builder_add (&containers, "{sv}", "data", g_variant_new_string (data_path));

    for (NSString * group in container_urls)
      g_variant_builder_add (&containers, "{sv}", group.UTF8String, g_variant_new_string (container_urls[group].path.UTF8String));

    g_hash_table_insert (parameters, g_strdup ("containers"), g_variant_ref_sink (g_variant_builder_end (&containers)));
  }

  get_task_allow = [app entitlementValueForKey:@"get-task-allow" ofClass:NSNumber.class];
  if (get_task_allow.boolValue)
    g_hash_table_insert (parameters, g_strdup ("debuggable"), g_variant_ref_sink (g_variant_new_boolean (TRUE)));
}

static void
frida_add_app_state (GHashTable * parameters, guint pid, FridaSpringboardApi * api)
{
  NSDictionary * info;
  NSNumber * is_frontmost;

  info = api->SBSCopyInfoForApplicationWithProcessID (pid);

  is_frontmost = info[@"BKSApplicationStateAppIsFrontmost"];
  if (is_frontmost.boolValue)
    g_hash_table_insert (parameters, g_strdup ("frontmost"), g_variant_ref_sink (g_variant_new_boolean (TRUE)));

  [info release];
}

static void
frida_add_app_icons (GHashTable * parameters, NSString * identifier)
{
  NSData * png;
  GVariantBuilder builder;

  png = _frida_get_springboard_api ()->SBSCopyIconImagePNGDataForDisplayIdentifier (identifier);
  if (png == nil)
    return;

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));

  g_variant_builder_open (&builder, G_VARIANT_TYPE_VARDICT);
  g_variant_builder_add (&builder, "{sv}", "format", g_variant_new_string ("png"));
  g_variant_builder_add (&builder, "{sv}", "image",
      g_variant_new_from_data (G_VARIANT_TYPE ("ay"), png.bytes, png.length, TRUE, (GDestroyNotify) CFRelease, png));
  g_variant_builder_close (&builder);

  g_hash_table_insert (parameters, g_strdup ("icons"), g_variant_ref_sink (g_variant_builder_end (&builder)));
}

#endif /* HAVE_IOS */

static void
frida_add_process_metadata (GHashTable * parameters, const struct kinfo_proc * process)
{
  const struct timeval * started = &process->kp_proc.p_un.__p_starttime;
  GDateTime * t0, * t1;

  g_hash_table_insert (parameters, g_strdup ("user"), frida_uid_to_name (process->kp_eproc.e_ucred.cr_uid));

  g_hash_table_insert (parameters, g_strdup ("ppid"), g_variant_ref_sink (g_variant_new_int64 (process->kp_eproc.e_ppid)));

  t0 = g_date_time_new_from_unix_utc (started->tv_sec);
  t1 = g_date_time_add (t0, started->tv_usec);
  g_hash_table_insert (parameters, g_strdup ("started"), g_variant_ref_sink (g_variant_new_take_string (g_date_time_format_iso8601 (t1))));
  g_date_time_unref (t1);
  g_date_time_unref (t0);
}

static struct kinfo_proc *
frida_system_query_kinfo_procs (guint * count)
{
  struct kinfo_proc * processes = NULL;
  int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
  size_t size;

  if (sysctl (mib, G_N_ELEMENTS (mib), NULL, &size, NULL, 0) != 0)
    goto sysctl_failed;

  while (TRUE)
  {
    size_t previous_size;
    gboolean still_too_small;

    processes = g_realloc (processes, size);

    previous_size = size;
    if (sysctl (mib, G_N_ELEMENTS (mib), processes, &size, NULL, 0) == 0)
      break;

    still_too_small = errno == ENOMEM;
    if (!still_too_small)
      goto sysctl_failed;

    size = previous_size * 11 / 10;
  }

  *count = size / sizeof (struct kinfo_proc);

  return processes;

sysctl_failed:
  {
    g_free (processes);

    *count = 0;

    return NULL;
  }
}

static GVariant *
frida_uid_to_name (uid_t uid)
{
  GVariant * name;
  static size_t buffer_size = 0;
  char * buffer;
  struct passwd pwd, * entry;

  if (buffer_size == 0)
    buffer_size = sysconf (_SC_GETPW_R_SIZE_MAX);

  buffer = g_malloc (buffer_size);

  entry = NULL;
  getpwuid_r (uid, &pwd, buffer, buffer_size, &entry);

  if (entry != NULL)
    name = g_variant_new_string (entry->pw_name);
  else
    name = g_variant_new_take_string (g_strdup_printf ("%u", uid));
  name = g_variant_ref_sink (name);

  g_free (buffer);

  return name;
}
