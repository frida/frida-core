#include "zed-core.h"

extern const unsigned int zed_data_winjector_helper_32_size;
extern const unsigned char zed_data_winjector_helper_32_data[];
extern const unsigned int zed_data_winjector_helper_64_size;
extern const unsigned char zed_data_winjector_helper_64_data[];

extern const unsigned int zed_data_zed_winagent_32_size;
extern const unsigned char zed_data_zed_winagent_32_data[];
extern const unsigned int zed_data_zed_winagent_64_size;
extern const unsigned char zed_data_zed_winagent_64_data[];

void *
zed_service_winjector_resource_store_get_helper_32_data (void)
{
  return (void *) zed_data_winjector_helper_32_data;
}

guint
zed_service_winjector_resource_store_get_helper_32_size (void)
{
  return zed_data_winjector_helper_32_size;
}

void *
zed_service_winjector_resource_store_get_helper_64_data (void)
{
  return (void *) zed_data_winjector_helper_64_data;
}

guint
zed_service_winjector_resource_store_get_helper_64_size (void)
{
  return zed_data_winjector_helper_64_size;
}

void *
zed_presenter_host_session_get_winagent_32_data (void)
{
  return (void *) zed_data_zed_winagent_32_data;
}

guint
zed_presenter_host_session_get_winagent_32_size (void)
{
  return zed_data_zed_winagent_32_size;
}

void *
zed_presenter_host_session_get_winagent_64_data (void)
{
  return (void *) zed_data_zed_winagent_64_data;
}

guint
zed_presenter_host_session_get_winagent_64_size (void)
{
  return zed_data_zed_winagent_64_size;
}
