#include "frida-core.h"

#include <dlfcn.h>
#include <libproc.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sysctl.h>

#ifdef HAVE_MAC

# import <AppKit/AppKit.h>
# import <Foundation/Foundation.h>

static void extract_icons_from_image (NSImage * image, FridaImageData * small_icon, FridaImageData * large_icon);
static void init_icon_from_ns_image_scaled_to (FridaImageData * icon, NSImage * image, guint target_width, guint target_height);

#endif

#ifdef HAVE_IOS

# import <UIKit/UIKit.h>

typedef struct _FridaSpringboardApi FridaSpringboardApi;

struct _FridaSpringboardApi
{
  void * module;

  NSString * (* SBSCopyDisplayIdentifierForProcessID) (UInt32 pid);
  NSString * (* SBSCopyLocalizedApplicationNameForDisplayIdentifier) (NSString * identifier);
  NSData * (* SBSCopyIconImagePNGDataForDisplayIdentifier) (NSString * identifier);
};

static void extract_icons_from_identifier (NSString * identifier, FridaImageData * small_icon, FridaImageData * large_icon);
static void init_icon_from_ui_image_scaled_to (FridaImageData * icon, UIImage * image, guint target_width, guint target_height);

static FridaSpringboardApi * frida_springboard_api = NULL;

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
#ifdef HAVE_IOS
  if (frida_springboard_api == NULL)
#endif
  {
#ifdef HAVE_IOS
    FridaSpringboardApi * api;

    api = g_new (FridaSpringboardApi, 1);

    api->module = dlopen ("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_LAZY | RTLD_GLOBAL);
    g_assert (api->module != NULL);

    api->SBSCopyDisplayIdentifierForProcessID = dlsym (api->module, "SBSCopyDisplayIdentifierForProcessID");
    g_assert (api->SBSCopyDisplayIdentifierForProcessID != NULL);

    api->SBSCopyLocalizedApplicationNameForDisplayIdentifier = dlsym (api->module, "SBSCopyLocalizedApplicationNameForDisplayIdentifier");
    g_assert (api->SBSCopyLocalizedApplicationNameForDisplayIdentifier != NULL);

    api->SBSCopyIconImagePNGDataForDisplayIdentifier = dlsym (api->module, "SBSCopyIconImagePNGDataForDisplayIdentifier");
    g_assert (api->SBSCopyIconImagePNGDataForDisplayIdentifier != NULL);

    frida_springboard_api = api;
#endif

    icon_pair_by_identifier = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify) frida_icon_pair_free);
  }
}

FridaHostProcessInfo *
frida_system_enumerate_processes (int * result_length1)
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
  *result_length1 = count;

  for (i = 0; i != count; i++)
  {
    struct kinfo_proc * e = &entries[i];
    FridaHostProcessInfo * info = &result[i];

    info->_pid = e->kp_proc.p_pid;

#ifdef HAVE_IOS
    NSString * identifier = frida_springboard_api->SBSCopyDisplayIdentifierForProcessID (info->_pid);
    if (identifier != nil)
    {
      NSString * app_name;

      app_name = frida_springboard_api->SBSCopyLocalizedApplicationNameForDisplayIdentifier (identifier);
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
      if (app != nil)
      {
        info->_name = g_strdup ([app.localizedName UTF8String]);

        extract_icons_from_image (app.icon, &info->_small_icon, &info->_large_icon);
      }
      else
#endif
      {
        gchar path[PROC_PIDPATHINFO_MAXSIZE];

        proc_pidpath (info->_pid, path, sizeof (path));
        info->_name = g_path_get_basename (path);

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
  init_icon_from_ns_image_scaled_to (small_icon, image, 16, 16);
  init_icon_from_ns_image_scaled_to (large_icon, image, 32, 32);
}

static void
init_icon_from_ns_image_scaled_to (FridaImageData * icon, NSImage * image, guint target_width, guint target_height)
{
  const guint bytes_per_row = target_width * 4;
  NSBitmapImageRep * rep;
  NSGraphicsContext * context;

  rep = [[NSBitmapImageRep alloc]
      initWithBitmapDataPlanes:nil
                    pixelsWide:target_width
                    pixelsHigh:target_height
                 bitsPerSample:8
               samplesPerPixel:4
                      hasAlpha:YES
                      isPlanar:NO
                colorSpaceName:NSCalibratedRGBColorSpace
                  bitmapFormat:0
                   bytesPerRow:0
                  bitsPerPixel:32];

  context = [NSGraphicsContext graphicsContextWithBitmapImageRep:rep];

  [NSGraphicsContext saveGraphicsState];
  [NSGraphicsContext setCurrentContext:context];
  [image drawAtPoint:NSZeroPoint
            fromRect:NSZeroRect
           operation:NSCompositeCopy
            fraction:1.0];
  [NSGraphicsContext restoreGraphicsState];

  icon->_pixels = g_base64_encode ([rep bitmapData], bytes_per_row * target_height);

  [rep release];
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

    png_data = frida_springboard_api->SBSCopyIconImagePNGDataForDisplayIdentifier (identifier);

    pair = g_new (FridaIconPair, 1);
    image = [UIImage imageWithData:png_data];
    init_icon_from_ui_image_scaled_to (&pair->small_icon, image, 16, 16);
    init_icon_from_ui_image_scaled_to (&pair->large_icon, image, 32, 32);
    g_hash_table_insert (icon_pair_by_identifier, g_strdup ([identifier UTF8String]), pair);

    [png_data release];
  }

  frida_image_data_copy (&pair->small_icon, small_icon);
  frida_image_data_copy (&pair->large_icon, large_icon);
}

static void
init_icon_from_ui_image_scaled_to (FridaImageData * icon, UIImage * image, guint target_width, guint target_height)
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
   * those usually rendered onto by the frida GUI... ICK!
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
frida_icon_pair_free (FridaIconPair * pair)
{
  frida_image_data_destroy (&pair->small_icon);
  frida_image_data_destroy (&pair->large_icon);
  g_free (pair);
}
