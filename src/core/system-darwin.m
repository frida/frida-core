#include "zed-core.h"

#include <dlfcn.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sysctl.h>

#ifdef HAVE_IOS

# import <UIKit/UIKit.h>

typedef struct _ZedSpringboardApi ZedSpringboardApi;

struct _ZedSpringboardApi
{
  void * module;

  NSString * (* SBSCopyDisplayIdentifierForProcessID) (UInt32 pid);
  NSString * (* SBSCopyLocalizedApplicationNameForDisplayIdentifier) (NSString * identifier);
  NSData * (* SBSCopyIconImagePNGDataForDisplayIdentifier) (NSString * identifier);
};

static void extract_icons_from_identifier (NSString * identifier, ZedImageData * small_icon, ZedImageData * large_icon);
static void init_icon_from_ui_image_scaled_to (ZedImageData * icon, UIImage * image, guint target_width, guint target_height);

static ZedSpringboardApi * zed_springboard_api = NULL;

#else
# import <Foundation/Foundation.h>
#endif

typedef struct _ZedIconPair ZedIconPair;

struct _ZedIconPair
{
  ZedImageData small_icon;
  ZedImageData large_icon;
};

static void zed_icon_pair_free (ZedIconPair * pair);

static GHashTable * icon_pair_by_identifier = NULL;

static void
zed_system_init (void)
{
#ifdef HAVE_IOS
  if (zed_springboard_api == NULL)
#endif
  {
#ifdef HAVE_IOS
    ZedSpringboardApi * api;

    api = g_new (ZedSpringboardApi, 1);

    api->module = dlopen ("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_LAZY | RTLD_GLOBAL);
    g_assert (api->module != NULL);

    api->SBSCopyDisplayIdentifierForProcessID = dlsym (api->module, "SBSCopyDisplayIdentifierForProcessID");
    g_assert (api->SBSCopyDisplayIdentifierForProcessID != NULL);

    api->SBSCopyLocalizedApplicationNameForDisplayIdentifier = dlsym (api->module, "SBSCopyLocalizedApplicationNameForDisplayIdentifier");
    g_assert (api->SBSCopyLocalizedApplicationNameForDisplayIdentifier != NULL);

    api->SBSCopyIconImagePNGDataForDisplayIdentifier = dlsym (api->module, "SBSCopyIconImagePNGDataForDisplayIdentifier");
    g_assert (api->SBSCopyIconImagePNGDataForDisplayIdentifier != NULL);

    zed_springboard_api = api;
#endif

    icon_pair_by_identifier = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) zed_icon_pair_free);
  }
}

ZedHostProcessInfo *
zed_system_enumerate_processes (int * result_length1)
{
  NSAutoreleasePool * pool;
  int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
  struct kinfo_proc * entries;
  size_t length;
  gint err;
  guint count, i;
  ZedHostProcessInfo * result;

  zed_system_init ();

  pool = [[NSAutoreleasePool alloc] init];

  err = sysctl (name, G_N_ELEMENTS (name) - 1, NULL, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);

  entries = g_malloc0 (length);

  err = sysctl (name, G_N_ELEMENTS (name) - 1, entries, &length, NULL, 0);
  g_assert_cmpint (err, !=, -1);
  count = length / sizeof (struct kinfo_proc);

  result = g_new0 (ZedHostProcessInfo, count);
  *result_length1 = count;

  for (i = 0; i != count; i++)
  {
    struct kinfo_proc * e = &entries[i];
    ZedHostProcessInfo * info = &result[i];

    info->_pid = e->kp_proc.p_pid;

#ifdef HAVE_IOS
    NSString * identifier = zed_springboard_api->SBSCopyDisplayIdentifierForProcessID (info->_pid);
    if (identifier != nil)
    {
      NSString * app_name;

      app_name = zed_springboard_api->SBSCopyLocalizedApplicationNameForDisplayIdentifier (identifier);
      info->_name = g_strdup ([app_name UTF8String]);
      [app_name release];

      extract_icons_from_identifier (identifier, &info->_small_icon, &info->_large_icon);

      [identifier release];
    }
    else
#endif
    {
      info->_name = g_strdup (e->kp_proc.p_comm);

      zed_image_data_init (&info->_small_icon, 0, 0, 0, "");
      zed_image_data_init (&info->_large_icon, 0, 0, 0, "");
    }
  }

  g_free (entries);

  [pool release];

  return result;
}

void
zed_system_kill (guint pid)
{
  killpg (getpgid (pid), SIGTERM);
}

#ifdef HAVE_IOS

static void
extract_icons_from_identifier (NSString * identifier, ZedImageData * small_icon, ZedImageData * large_icon)
{
  ZedIconPair * pair;

  pair = g_hash_table_lookup (icon_pair_by_identifier, [identifier UTF8String]);
  if (pair == NULL)
  {
    NSData * png_data;
    UIImage * image;

    png_data = zed_springboard_api->SBSCopyIconImagePNGDataForDisplayIdentifier (identifier);

    pair = g_new (ZedIconPair, 1);
    image = [UIImage imageWithData: png_data];
    init_icon_from_ui_image_scaled_to (&pair->small_icon, image, 16, 16);
    init_icon_from_ui_image_scaled_to (&pair->large_icon, image, 32, 32);
    g_hash_table_insert (icon_pair_by_identifier, g_strdup ([identifier UTF8String]), pair);

    [png_data release];
  }

  zed_image_data_copy (&pair->small_icon, small_icon);
  zed_image_data_copy (&pair->large_icon, large_icon);
}

static void
init_icon_from_ui_image_scaled_to (ZedImageData * icon, UIImage * image, guint target_width, guint target_height)
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

  icon->_pixels = g_base64_encode (CGBitmapContextGetData (cgctx), pixel_buf_size);

  CGContextRelease (cgctx);
  CGColorSpaceRelease (colorspace);
  g_free (pixel_buf);
}

#endif /* HAVE_IOS */

static void
zed_icon_pair_free (ZedIconPair * pair)
{
  zed_image_data_destroy (&pair->small_icon);
  zed_image_data_destroy (&pair->large_icon);
  g_free (pair);
}

