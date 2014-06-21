#ifndef __FRIDA_DARWIN_ICON_HELPERS_H__
#define __FRIDA_DARWIN_ICON_HELPERS_H__

#include "frida-core.h"

typedef gpointer FridaNativeImage;

FridaImageData * _frida_image_data_from_file (const gchar * filename, guint target_width, guint target_height);

void _frida_image_data_init_from_native_image_scaled_to (FridaImageData * data, FridaNativeImage native_image, guint target_width, guint target_height);

#endif
