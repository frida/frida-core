#include "frida-core.h"

#include "icon-helpers.h"

#include <signal.h>
#include <unistd.h>
#include <sys/sysctl.h>

#ifdef HAVE_MAC

# include <libproc.h>
# import <AppKit/AppKit.h>

static void extract_icons_from_image (NSImage * image, FridaImageData * small_icon, FridaImageData * large_icon);

#endif

#ifdef HAVE_IOS

# import "springboard.h"

static void extract_icons_from_identifier (NSString * identifier, FridaImageData * small_icon, FridaImageData * large_icon);

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

FridaHostApplicationInfo *
frida_system_enumerate_applications (int * result_length)
{
#ifdef HAVE_IOS
  NSAutoreleasePool * pool;
  FridaSpringboardApi * api;
  GHashTable * pid_by_identifier;
  int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
  size_t length;
  gint err;
  struct kinfo_proc * entries;
  NSArray * identifiers;
  NSUInteger count, i;
  FridaHostApplicationInfo * result;

  frida_system_init ();

  pool = [[NSAutoreleasePool alloc] init];

  api = _frida_get_springboard_api ();

  pid_by_identifier = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  err = sysctl (name, G_N_ELEMENTS (name) - 1, NULL, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);

  entries = g_malloc0 (length);

  err = sysctl (name, G_N_ELEMENTS (name) - 1, entries, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);
  count = length / sizeof (struct kinfo_proc);

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
  NSAutoreleasePool * pool;
  int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
  struct kinfo_proc * entries;
  size_t length;
  gint err;
  guint count, i;
  FridaHostProcessInfo * result;

  frida_system_init ();

  pool = [[NSAutoreleasePool alloc] init];

  err = sysctl (name, G_N_ELEMENTS (name) - 1, NULL, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);

  entries = g_malloc0 (length);

  err = sysctl (name, G_N_ELEMENTS (name) - 1, entries, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);
  count = length / sizeof (struct kinfo_proc);

  result = g_new0 (FridaHostProcessInfo, count);
  *result_length = count;

#ifdef HAVE_IOS
  FridaSpringboardApi * api = _frida_get_springboard_api ();
#endif

  for (i = 0; i != count; i++)
  {
    struct kinfo_proc * e = &entries[i];
    FridaHostProcessInfo * info = &result[i];

    info->_pid = e->kp_proc.p_pid;

#ifdef HAVE_IOS
    NSString * identifier = api->SBSCopyDisplayIdentifierForProcessID (info->_pid);
    if (identifier != nil)
    {
      NSString * app_name;

      app_name = api->SBSCopyLocalizedApplicationNameForDisplayIdentifier (identifier);
      info->_name = g_strdup ([app_name UTF8String]);
      [app_name release];

      extract_icons_from_identifier (identifier, &info->_small_icon, &info->_large_icon);

      [identifier release];
    }
    else
#endif
    {
#ifdef HAVE_MAC
      NSRunningApplication * app = [NSRunningApplication runningApplicationWithProcessIdentifier:info->_pid];
      if (app.icon != nil)
      {
        info->_name = g_strdup ([app.localizedName UTF8String]);

        extract_icons_from_image (app.icon, &info->_small_icon, &info->_large_icon);
      }
      else
#endif
      {
#ifdef HAVE_MAC
        gchar path[PROC_PIDPATHINFO_MAXSIZE];

        proc_pidpath (info->_pid, path, sizeof (path));
        info->_name = g_path_get_basename (path);
#else
        info->_name = g_strdup (e->kp_proc.p_comm);
#endif

        frida_image_data_init (&info->_small_icon, 0, 0, 0, "");
        frida_image_data_init (&info->_large_icon, 0, 0, 0, "");
      }
    }
  }

  g_free (entries);

  [pool release];

  return result;
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
    /* Sandboxed system daemons are likely able to read from this location */
    return g_strdup ("/private/var/root");
  }
  else
  {
#ifdef HAVE_MAC
    /* Mac App Store apps are sandboxed but able to read ~/.Trash/ */
    return g_build_filename (g_get_home_dir (), ".Trash", NULL);
#else
    return g_strdup (g_get_tmp_dir ());
#endif
  }
}

#ifdef HAVE_MAC

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
