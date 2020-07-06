#include "icon-helpers.h"

#ifdef HAVE_MACOS
# import <AppKit/AppKit.h>
# if __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_12
#  define NSCompositingOperationCopy NSCompositeCopy
# endif
#else
# import <UIKit/UIKit.h>
#endif

FridaImageData *
_frida_image_data_from_file (const gchar * filename, guint target_width, guint target_height)
{
#ifdef HAVE_MACOS
  FridaImageData * result = NULL;
  NSAutoreleasePool * pool;
  NSImage * image;

  pool = [[NSAutoreleasePool alloc] init];

  image = [[NSImage alloc] initWithContentsOfFile:[NSString stringWithUTF8String:filename]];
  if (image != nil)
  {
    result = g_new (FridaImageData, 1);
    _frida_image_data_init_from_native_image_scaled_to (result, image, target_width, target_height);
    [image release];
  }

  [pool release];

  return result;
#else
  return NULL;
#endif
}

void
_frida_image_data_init_from_native_image_scaled_to (FridaImageData * data, FridaNativeImage native_image, guint target_width, guint target_height)
{
#ifdef HAVE_MACOS
  NSImage * image = (NSImage *) native_image;
  NSBitmapImageRep * rep;
  NSGraphicsContext * context;

  data->_width = target_width;
  data->_height = target_height;
  data->_rowstride = target_width * 4;

  rep = [[NSBitmapImageRep alloc]
      initWithBitmapDataPlanes:nil
                    pixelsWide:data->_width
                    pixelsHigh:data->_height
                 bitsPerSample:8
               samplesPerPixel:4
                      hasAlpha:YES
                      isPlanar:NO
                colorSpaceName:NSCalibratedRGBColorSpace
                  bitmapFormat:0
                   bytesPerRow:data->_rowstride
                  bitsPerPixel:32];

  context = [NSGraphicsContext graphicsContextWithBitmapImageRep:rep];

  [NSGraphicsContext saveGraphicsState];
  [NSGraphicsContext setCurrentContext:context];
  [image drawInRect:NSMakeRect (0, 0, data->_width, data->_height)
           fromRect:NSZeroRect
          operation:NSCompositingOperationCopy
           fraction:1.0];
  [context flushGraphics];
  [NSGraphicsContext restoreGraphicsState];

  data->_pixels = g_base64_encode ([rep bitmapData], data->_rowstride * data->_height);

  [rep release];
#else
  UIImage * image = (UIImage *) native_image;
  CGImageRef cgimage;
  CGSize full, scaled;
  guint pixel_buf_size;
  guint8 * pixel_buf;
  guint32 * pixels;
  guint i;
  CGColorSpaceRef colorspace;
  CGContextRef cgctx;
  CGRect target_rect = { { 0.0f, 0.0f }, { 0.0f, 0.0f } };

  data->_width = target_width;
  data->_height = target_height;
  data->_rowstride = target_width * 4;

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

  pixel_buf_size = data->_width * data->_rowstride;
  pixel_buf = g_malloc (pixel_buf_size);

  /*
   * HACK ALERT:
   *
   * CoreGraphics does not yet support non-premultiplied, so we make sure it multiplies with the same pixels as
   * those usually rendered onto by the frida GUI... ICK!
   */
  pixels = (guint32 *) pixel_buf;
  for (i = 0; i != data->_width * data->_height; i++)
    pixels[i] = GUINT32_TO_BE (0xf0f0f0ff);

  colorspace = CGColorSpaceCreateDeviceRGB ();
  cgctx = CGBitmapContextCreate (pixel_buf, data->_width, data->_height, 8, data->_rowstride, colorspace,
      kCGBitmapByteOrder32Big | kCGImageAlphaPremultipliedLast);
  g_assert (cgctx != NULL);

  target_rect.size = scaled;

  CGContextDrawImage (cgctx, target_rect, cgimage);

  data->_pixels = g_base64_encode (CGBitmapContextGetData (cgctx), pixel_buf_size);

  CGContextRelease (cgctx);
  CGColorSpaceRelease (colorspace);
  g_free (pixel_buf);
#endif
}
