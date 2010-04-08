#include <windows.h>
#include <tlhelp32.h>

typedef struct _ZedServiceWinjectorInjectAsyncData
    ZedServiceWinjectorInjectAsyncData;

static void zed_service_winjector_inject_async_co (
    ZedServiceWinjectorInjectAsyncData * data);

#include "src/service/winjector.c"

static void zed_service_winjector_ensure_helper_started (
    ZedServiceWinjector * self);

extern const unsigned int zed_data_winjector_helper_32_size;
extern const unsigned char zed_data_winjector_helper_32_data[];

static void
zed_service_winjector_process_request (ZedServiceWinjector * self,
    void * request)
{
  zed_service_winjector_ensure_helper_started (self);
}

static void
zed_service_winjector_free_request (ZedServiceWinjector * self,
    void * request)
{
  ZedServiceWinjectorInjectAsyncData * data = request;

  if (data->_async_result != NULL)
    g_object_unref (data->_async_result);
  zed_service_winjector_inject_async_data_free (data);
}

static void
zed_service_winjector_inject_async_co (
    ZedServiceWinjectorInjectAsyncData * data)
{
  zed_service_winjector_ensure_worker_running (data->self);
  zed_service_winjector_queue_request (data->self, data);
}

static void
zed_service_winjector_ensure_helper_started (ZedServiceWinjector * self)
{
}
