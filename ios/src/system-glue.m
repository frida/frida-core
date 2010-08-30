#include "zid-core.h"

#import <UIKit/UIKit.h>

#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sysctl.h>

typedef NSString * (* SBSCopyDisplayIdentifierForProcessIDFunc) (UInt32 pid);
typedef NSData * (* SBSCopyIconImagePNGDataForDisplayIdentifierFunc) (NSString * identifier);

static SBSCopyDisplayIdentifierForProcessIDFunc SBSCopyDisplayIdentifierForProcessIDImpl = NULL;
static SBSCopyIconImagePNGDataForDisplayIdentifierFunc SBSCopyIconImagePNGDataForDisplayIdentifierImpl = NULL;

gboolean extract_icon_from_pid (guint pid, ZedHostProcessIcon * icon);

ZedHostProcessInfo *
zid_system_enumerate_processes (int * result_length1)
{
  int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
  struct kinfo_proc * entries;
  size_t length;
  gint err;
  guint count, i;
  ZedHostProcessInfo * result;
  ZedHostProcessIcon no_icon;

  err = sysctl (name, G_N_ELEMENTS (name) - 1, NULL, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);

  entries = g_malloc0 (length);

  err = sysctl (name, G_N_ELEMENTS (name) - 1, entries, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);
  count = length / sizeof (struct kinfo_proc);

  result = g_new (ZedHostProcessInfo, count);
  *result_length1 = count;

  zed_host_process_icon_init (&no_icon, 0, 0, 0, "");

  for (i = 0; i != count; i++)
  {
    struct kinfo_proc * e = &entries[i];
    guint pid = e->kp_proc.p_pid;
    ZedHostProcessIcon extracted_icon, * small_icon, * large_icon;
    gboolean has_icon;

    small_icon = &no_icon;
    has_icon = extract_icon_from_pid (pid, &extracted_icon);
    if (has_icon)
      large_icon = &extracted_icon;
    else
      large_icon = &no_icon;

    zed_host_process_info_init (&result[i], e->kp_proc.p_pid, e->kp_proc.p_comm, small_icon, large_icon);

    if (has_icon)
      zed_host_process_icon_destroy (&extracted_icon);
  }

  zed_host_process_icon_destroy (&no_icon);

  g_free (entries);

  return result;
}

void
zid_system_kill (guint pid)
{
  killpg (getpgid (pid), SIGTERM);
}

gboolean
extract_icon_from_pid (guint pid, ZedHostProcessIcon * icon)
{
  NSAutoreleasePool * pool;
  NSString * identifier;

  pool = [[NSAutoreleasePool alloc] init];

  if (SBSCopyDisplayIdentifierForProcessIDImpl == NULL)
  {
    void * sblib;

    sblib = dlopen ("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_LAZY | RTLD_GLOBAL);
    g_assert (sblib != NULL);

    SBSCopyDisplayIdentifierForProcessIDImpl = dlsym (sblib, "SBSCopyDisplayIdentifierForProcessID");
    g_assert (SBSCopyDisplayIdentifierForProcessIDImpl != NULL);

    SBSCopyIconImagePNGDataForDisplayIdentifierImpl = dlsym (sblib, "SBSCopyIconImagePNGDataForDisplayIdentifier");
    g_assert (SBSCopyIconImagePNGDataForDisplayIdentifierImpl != NULL);
  }

  identifier = SBSCopyDisplayIdentifierForProcessIDImpl (pid);
  if (identifier != nil)
  {
    NSData * png_data;

    png_data = SBSCopyIconImagePNGDataForDisplayIdentifierImpl (identifier);
    if (png_data != nil)
    {
      UIImage * image;
      CGSize size;
      CGFloat scale;
      guint width, height;

      image = [UIImage imageWithData: png_data];
      size = [image size];
      scale = [image scale];
      width = size.width * scale;
      height = size.height * scale;

      NSLog (@"%@ image of %ux%u (%fx%f, scale=%f)", identifier, width, height, size.width, size.height, scale);
    }

    [png_data release];
  }
  [identifier release];

  [pool release];

  return FALSE;
}

