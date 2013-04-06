#include "zed-core.h"

#include "zed-interfaces.h"

void
_zed_fruity_host_session_provider_extract_details_for_device_with_udid (const char * udid, char ** name, ZedImageData ** icon, GError ** error)
{
  ZedImageData empty_icon;

  zed_image_data_init (&empty_icon, 0, 0, 0, "");

  *name = g_strdup ("iPhone");
  *icon = zed_image_data_dup (&empty_icon);

  zed_image_data_destroy (&empty_icon);
}
