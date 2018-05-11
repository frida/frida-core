#include "frida-core.h"

#include "frida-interfaces.h"

void
_frida_fruity_host_session_backend_extract_details_for_device (gint product_id, const char * udid, char ** name, FridaImageData ** icon, GError ** error)
{
  FridaImageData no_icon = { 0, };

  no_icon._pixels = "";

  *name = g_strdup ("iOS Device");
  *icon = frida_image_data_dup (&no_icon);
}
