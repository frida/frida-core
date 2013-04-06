#include "frida-core.h"

#include "frida-interfaces.h"

void
_frida_fruity_host_session_provider_extract_details_for_device_with_udid (const char * udid, char ** name, FridaImageData ** icon, GError ** error)
{
  FridaImageData empty_icon;

  frida_image_data_init (&empty_icon, 0, 0, 0, "");

  *name = g_strdup ("iPhone");
  *icon = frida_image_data_dup (&empty_icon);

  frida_image_data_destroy (&empty_icon);
}
