#include "frida-core.h"

#include "icon-helpers.h"

#include <sys/sysctl.h>

#ifdef HAVE_MAC

typedef struct _FridaMacModel FridaMacModel;

struct _FridaMacModel
{
  const gchar * name;
  const gchar * icon;
};

static const FridaMacModel mac_models[] =
{
  { NULL,         "com.apple.led-cinema-display-27" },
  { "MacBookAir", "com.apple.macbookair-11-unibody" },
  { "MacBookPro", "com.apple.macbookpro-13-unibody" },
  { "MacBook",    "com.apple.macbook-unibody" },
  { "iMac",       "com.apple.imac-unibody-21" },
  { "Macmini",    "com.apple.macmini-unibody" },
  { "MacPro",     "com.apple.macpro" }
};

#endif

FridaImageData *
_frida_darwin_host_session_provider_extract_icon (void)
{
#ifdef HAVE_MAC
  size_t size;
  gchar * model_name;
  const FridaMacModel * model;
  guint i;
  gchar * filename;
  FridaImageData * icon;

  size = 0;
  sysctlbyname ("hw.model", NULL, &size, NULL, 0);
  model_name = g_malloc (size);
  sysctlbyname ("hw.model", model_name, &size, NULL, 0);

  for (model = NULL, i = 1; i != G_N_ELEMENTS (mac_models) && model == NULL; i++)
  {
    if (g_str_has_prefix (model_name, mac_models[i].name))
      model = &mac_models[i];
  }
  if (model == NULL)
    model = &mac_models[0];

  filename = g_strconcat ("/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/", model->icon, ".icns", NULL);
  icon = _frida_image_data_from_file (filename, 16, 16);
  g_free (filename);

  g_free (model_name);

  return icon;
#else
  return NULL;
#endif
}

gboolean
_frida_darwin_host_session_is_running_on_ios (void)
{
#ifdef HAVE_IOS
  return TRUE;
#else
  return FALSE;
#endif
}

#ifdef HAVE_IOS

#import "springboard.h"

void
frida_fruit_launcher_kill (const gchar * identifier)
{
  NSAutoreleasePool * pool;
  int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
  struct kinfo_proc * entries;
  size_t length;
  gint err;
  FridaSpringboardApi * api;
  gboolean found;
  guint count, i;

  pool = [[NSAutoreleasePool alloc] init];

  err = sysctl (name, G_N_ELEMENTS (name) - 1, NULL, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);

  entries = g_malloc0 (length);

  err = sysctl (name, G_N_ELEMENTS (name) - 1, entries, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);
  count = length / sizeof (struct kinfo_proc);

  api = _frida_get_springboard_api ();

  for (i = 0, found = FALSE; i != count && !found; i++)
  {
    struct kinfo_proc * e = &entries[i];
    UInt32 pid = e->kp_proc.p_pid;
    NSString * cur;

    cur = api->SBSCopyDisplayIdentifierForProcessID (pid);
    if (cur != nil)
    {
      if (strcmp ([cur UTF8String], identifier) == 0)
      {
        kill (pid, SIGKILL);
        found = TRUE;
      }

      [cur release];
    }
  }

  g_free (entries);

  [pool release];
}

#else

void
frida_fruit_launcher_kill (const gchar * identifier)
{
}

#endif
