#include "frida-core.h"

#include "icon-helpers.h"

#include <signal.h>
#include <unistd.h>
#include <sys/sysctl.h>

static struct kinfo_proc * frida_system_query_kinfo_procs (guint * count);

#ifdef HAVE_MACOS

# include <libproc.h>
# import <AppKit/AppKit.h>

static void extract_icons_from_image (NSImage * image, FridaImageData * small_icon, FridaImageData * large_icon);

#endif

#ifdef HAVE_IOS

# import "springboard.h"

static void extract_icons_from_identifier (NSString * identifier, FridaImageData * small_icon, FridaImageData * large_icon);

extern int proc_pidpath (int pid, void * buffer, uint32_t buffer_size);

#endif

#ifndef PROC_PIDPATHINFO_MAXSIZE
# define PROC_PIDPATHINFO_MAXSIZE (4 * MAXPATHLEN)
#endif

typedef struct _FridaIconPair FridaIconPair;

struct _FridaIconPair
{
  FridaImageData small_icon;
  FridaImageData large_icon;
};

static void frida_icon_pair_free (FridaIconPair * pair);

static GHashTable * icon_pair_by_identifier = NULL;

static void
frida_system_init (void)
{
  if (icon_pair_by_identifier == NULL)
  {
    icon_pair_by_identifier = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) frida_icon_pair_free);
  }
}

void
frida_system_get_frontmost_application (FridaHostApplicationInfo * result, GError ** error)
{
#ifdef HAVE_IOS
  NSAutoreleasePool * pool;
  FridaSpringboardApi * api;
  NSString * identifier;

  frida_system_init ();

  pool = [[NSAutoreleasePool alloc] init];

  api = _frida_get_springboard_api ();

  identifier = api->SBSCopyFrontmostApplicationDisplayIdentifier ();
  if (identifier != nil && [identifier length] > 1)
  {
    NSString * name;
    struct kinfo_proc * entries;
    guint count, i;

    name = api->SBSCopyLocalizedApplicationNameForDisplayIdentifier (identifier);
    if (name != nil)
    {
      result->_identifier = g_strdup ([identifier UTF8String]);
      result->_name = g_strdup ([name UTF8String]);
      [name release];

      entries = frida_system_query_kinfo_procs (&count);
      for (result->_pid = 0, i = 0; result->_pid == 0 && i != count; i++)
      {
        guint pid = entries[i].kp_proc.p_pid;
        NSString * cur_identifier;

        cur_identifier = api->SBSCopyDisplayIdentifierForProcessID (pid);
        if (cur_identifier != nil)
        {
          if ([cur_identifier isEqualToString:identifier])
            result->_pid = pid;
          [cur_identifier release];
        }
      }
      g_free (entries);

      extract_icons_from_identifier (identifier, &result->_small_icon, &result->_large_icon);
    }
    else
    {
      frida_host_application_info_init_empty (result);
    }
  }
  else
  {
    frida_host_application_info_init_empty (result);
  }

  [identifier release];
  [pool release];
#else
  g_set_error (error,
      FRIDA_ERROR,
      FRIDA_ERROR_NOT_SUPPORTED,
      "Not implemented");
#endif
}

FridaHostApplicationInfo *
frida_system_enumerate_applications (int * result_length)
{
#ifdef HAVE_IOS
  NSAutoreleasePool * pool;
  FridaSpringboardApi * api;
  GHashTable * pid_by_identifier;
  struct kinfo_proc * entries;
  NSArray * identifiers;
  guint count, i;
  FridaHostApplicationInfo * result;

  frida_system_init ();

  pool = [[NSAutoreleasePool alloc] init];

  api = _frida_get_springboard_api ();

  pid_by_identifier = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  entries = frida_system_query_kinfo_procs (&count);

  for (i = 0; i != count; i++)
  {
    struct kinfo_proc * e = &entries[i];
    guint pid = e->kp_proc.p_pid;
    NSString * identifier;

    identifier = api->SBSCopyDisplayIdentifierForProcessID (pid);
    if (identifier != nil)
    {
      g_hash_table_insert (pid_by_identifier, g_strdup ([identifier UTF8String]), GUINT_TO_POINTER (pid));
      [identifier release];
    }
  }

  g_free (entries);

  identifiers = api->SBSCopyApplicationDisplayIdentifiers (NO, NO);

  count = [identifiers count];
  result = g_new0 (FridaHostApplicationInfo, count);
  *result_length = count;

  for (i = 0; i != count; i++)
  {
    NSString * identifier, * name;
    FridaHostApplicationInfo * info = &result[i];

    identifier = [identifiers objectAtIndex:i];
    name = api->SBSCopyLocalizedApplicationNameForDisplayIdentifier (identifier);
    info->_identifier = g_strdup ([identifier UTF8String]);
    info->_name = g_strdup ([name UTF8String]);
    info->_pid = GPOINTER_TO_UINT (g_hash_table_lookup (pid_by_identifier, info->_identifier));
    [name release];

    extract_icons_from_identifier (identifier, &info->_small_icon, &info->_large_icon);
  }

  [identifiers release];

  g_hash_table_unref (pid_by_identifier);

  [pool release];

  return result;
#else
  *result_length = 0;

  return NULL;
#endif
}

FridaHostProcessInfo *
frida_system_enumerate_processes (int * result_length)
{
  GArray * result;
  NSAutoreleasePool * pool;
  struct kinfo_proc * entries;
  guint count, i;

  frida_system_init ();

  pool = [[NSAutoreleasePool alloc] init];

  entries = frida_system_query_kinfo_procs (&count);

  result = g_array_sized_new (FALSE, TRUE, sizeof (FridaHostProcessInfo), count);

#ifdef HAVE_IOS
  FridaSpringboardApi * api = _frida_get_springboard_api ();
#endif

  for (i = 0; i != count; i++)
  {
    struct kinfo_proc * e = &entries[i];
    FridaHostProcessInfo info = { 0, };
    gboolean still_alive = TRUE;

    info._pid = e->kp_proc.p_pid;

#ifdef HAVE_IOS
    NSString * identifier = api->SBSCopyDisplayIdentifierForProcessID (info._pid);
    if (identifier != nil)
    {
      NSString * app_name;

      app_name = api->SBSCopyLocalizedApplicationNameForDisplayIdentifier (identifier);
      info._name = g_strdup ([app_name UTF8String]);
      [app_name release];

      extract_icons_from_identifier (identifier, &info._small_icon, &info._large_icon);

      [identifier release];
    }
    else
#endif
    {
#ifdef HAVE_MACOS
      NSRunningApplication * app = [NSRunningApplication runningApplicationWithProcessIdentifier:info._pid];
      if (app.icon != nil)
      {
        info._name = g_strdup ([app.localizedName UTF8String]);

        extract_icons_from_image (app.icon, &info._small_icon, &info._large_icon);
      }
      else
#endif
      {
        gchar path[PROC_PIDPATHINFO_MAXSIZE];

        still_alive = proc_pidpath (info._pid, path, sizeof (path)) > 0;
        if (still_alive)
        {
          info._name = g_path_get_basename (path);
        }

        frida_image_data_init_empty (&info._small_icon);
        frida_image_data_init_empty (&info._large_icon);
      }
    }

    if (still_alive)
      g_array_append_val (result, info);
    else
      frida_host_process_info_destroy (&info);
  }

  g_free (entries);

  [pool release];

  *result_length = result->len;

  return (FridaHostProcessInfo *) g_array_free (result, FALSE);
}

static struct kinfo_proc *
frida_system_query_kinfo_procs (guint * count)
{
  struct kinfo_proc * entries;
  int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
  size_t size;
  gint err;

  err = sysctl (name, G_N_ELEMENTS (name) - 1, NULL, &size, NULL, 0);
  g_assert (err != -1);

  entries = g_malloc0 (size);

  err = sysctl (name, G_N_ELEMENTS (name) - 1, entries, &size, NULL, 0);
  g_assert (err != -1);

  *count = size / sizeof (struct kinfo_proc);

  return entries;
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

#ifdef HAVE_MACOS

static void
extract_icons_from_image (NSImage * image, FridaImageData * small_icon, FridaImageData * large_icon)
{
  _frida_image_data_init_from_native_image_scaled_to (small_icon, image, 16, 16);
  _frida_image_data_init_from_native_image_scaled_to (large_icon, image, 32, 32);
}

#endif

#ifdef HAVE_IOS

static void
extract_icons_from_identifier (NSString * identifier, FridaImageData * small_icon, FridaImageData * large_icon)
{
  FridaIconPair * pair;

  pair = g_hash_table_lookup (icon_pair_by_identifier, [identifier UTF8String]);
  if (pair == NULL)
  {
    NSData * png_data;
    UIImage * image;

    png_data = _frida_get_springboard_api ()->SBSCopyIconImagePNGDataForDisplayIdentifier (identifier);

    pair = g_new (FridaIconPair, 1);
    image = [UIImage imageWithData:png_data];
    _frida_image_data_init_from_native_image_scaled_to (&pair->small_icon, image, 16, 16);
    _frida_image_data_init_from_native_image_scaled_to (&pair->large_icon, image, 32, 32);
    g_hash_table_insert (icon_pair_by_identifier, g_strdup ([identifier UTF8String]), pair);

    [png_data release];
  }

  frida_image_data_copy (&pair->small_icon, small_icon);
  frida_image_data_copy (&pair->large_icon, large_icon);
}

#endif /* HAVE_IOS */

static void
frida_icon_pair_free (FridaIconPair * pair)
{
  frida_image_data_destroy (&pair->small_icon);
  frida_image_data_destroy (&pair->large_icon);
  g_free (pair);
}
