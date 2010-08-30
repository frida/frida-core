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

gboolean extract_icons_from_pid (guint pid, ZedHostProcessIcon * small_icon, ZedHostProcessIcon * large_icon);
static void init_icon_from_ui_image_scaled_to (ZedHostProcessIcon * icon, UIImage * image, guint target_width, guint target_height);

ZedHostProcessInfo *
zid_system_enumerate_processes (int * result_length1)
{
  int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
  struct kinfo_proc * entries;
  size_t length;
  gint err;
  guint count, i;
  ZedHostProcessInfo * result;
  ZedHostProcessIcon empty_icon = { 0, };

  err = sysctl (name, G_N_ELEMENTS (name) - 1, NULL, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);

  entries = g_malloc0 (length);

  err = sysctl (name, G_N_ELEMENTS (name) - 1, entries, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);
  count = length / sizeof (struct kinfo_proc);

  result = g_new (ZedHostProcessInfo, count);
  *result_length1 = count;

  for (i = 0; i != count; i++)
  {
    struct kinfo_proc * e = &entries[i];
    ZedHostProcessInfo * info = &result[i];
    guint pid = e->kp_proc.p_pid;
    gboolean has_icons;

    zed_host_process_info_init (info, pid, e->kp_proc.p_comm, &empty_icon, &empty_icon);

    has_icons = extract_icons_from_pid (pid, &info->_small_icon, &info->_large_icon);
    if (!has_icons)
    {
      zed_host_process_icon_init (&info->_small_icon, 0, 0, 0, "");
      zed_host_process_icon_init (&info->_large_icon, 0, 0, 0, "");
    }
  }

  g_free (entries);

  return result;
}

void
zid_system_kill (guint pid)
{
  killpg (getpgid (pid), SIGTERM);
}

gboolean
extract_icons_from_pid (guint pid, ZedHostProcessIcon * small_icon, ZedHostProcessIcon * large_icon)
{
  gboolean result = FALSE;
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

      image = [UIImage imageWithData: png_data];

      init_icon_from_ui_image_scaled_to (small_icon, image, 16, 16);
      init_icon_from_ui_image_scaled_to (large_icon, image, 32, 32);

      result = TRUE;
    }

    [png_data release];
  }
  [identifier release];

  [pool release];

  return result;
}

static void
init_icon_from_ui_image_scaled_to (ZedHostProcessIcon * icon, UIImage * image, guint target_width, guint target_height)
{
  CGImageRef cgimage;
  CGSize full, scaled;
  guint pixel_buf_size;
  guint8 * pixel_buf;
  guint32 * pixels;
  guint i;
  CGColorSpaceRef colorspace;
  CGContextRef cgctx;
  CGRect target_rect = { { 0.0f, 0.0f }, { 0.0f, 0.0f } };

  icon->_width = target_width;
  icon->_height = target_height;
  icon->_rowstride = target_width * 4;

  cgimage = [image CGImage];

  full.width = CGImageGetWidth (cgimage);
  full.height = CGImageGetHeight (cgimage);

  if (full.height > full.width)
  {
    scaled.width = (CGFloat) full.width * ((CGFloat) target_height / full.height);
    scaled.height = target_height;
  }
  else
  {
    scaled.width = target_width;
    scaled.height = (CGFloat) full.height * ((CGFloat) target_width / full.width);
  }

  pixel_buf_size = icon->_width * icon->_rowstride;
  pixel_buf = g_malloc (pixel_buf_size);

  /*
   * HACK ALERT:
   *
   * CoreGraphics does not yet support non-premultiplied, so we make sure it multiplies with the same pixels as
   * those usually rendered onto by the zed GUI... ICK!
   */
  pixels = (guint32 *) pixel_buf;
  for (i = 0; i != icon->_width * icon->_height; i++)
    pixels[i] = GUINT32_TO_BE (0xf0f0f0ff);

  colorspace = CGColorSpaceCreateDeviceRGB ();
  cgctx = CGBitmapContextCreate (pixel_buf, icon->_width, icon->_height, 8, icon->_rowstride, colorspace,
      kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast);
  g_assert (cgctx != NULL);

  target_rect.size = scaled;

  CGContextDrawImage (cgctx, target_rect, cgimage);

  icon->_data = g_base64_encode (CGBitmapContextGetData (cgctx), pixel_buf_size);

  CGContextRelease (cgctx);
  CGColorSpaceRelease (colorspace);
  g_free (pixel_buf);
}

