typedef struct _ZedServiceWinjectorInjectAsyncData
    ZedServiceWinjectorInjectAsyncData;

static void zed_service_winjector_inject_async_co (
    ZedServiceWinjectorInjectAsyncData * data);

#include "src/service/winjector.c"

static void
zed_service_winjector_inject_async_co (
    ZedServiceWinjectorInjectAsyncData * data)
{
  g_print ("injecting %s into pid %d\n", data->filename, data->target_pid);
}

