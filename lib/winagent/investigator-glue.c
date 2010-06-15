#include "zed-winagent.h"

#define VC_EXTRALEAN
#include <windows.h>
#include <psapi.h>
#include <tchar.h>

typedef struct _ResolveFuncNameContext ResolveFuncNameContext;

struct _ResolveFuncNameContext
{
  gsize address_to_resolve;
  ZedFunctionAddress * function_address;
};

static gpointer resolve_trigger_function (ZedTriggerInfo * trigger);
static gboolean attach_listener_to_trigger_function (ZedInvestigator * self,
    gpointer func, ZedTriggerType type);

static GumInterceptor * interceptor = NULL;

gboolean
zed_investigator_attach (ZedInvestigator * self,
    ZedTriggerInfo * start_trigger, ZedTriggerInfo * stop_trigger)
{
  static gpointer start_trigger_func, stop_trigger_func;

#ifndef _M_X64
  g_assert (interceptor == NULL);
  interceptor = gum_interceptor_obtain ();
#endif

  start_trigger_func = resolve_trigger_function (start_trigger);
  stop_trigger_func = resolve_trigger_function (stop_trigger);
  if (start_trigger_func == NULL || stop_trigger_func == NULL)
    goto error;

  if (stop_trigger_func == start_trigger_func)
  {
    if (!attach_listener_to_trigger_function (self, start_trigger_func,
        (ZedTriggerType) (ZED_TRIGGER_TYPE_START | ZED_TRIGGER_TYPE_STOP)))
    {
      goto error;
    }
  }
  else
  {
    if (!attach_listener_to_trigger_function (self, start_trigger_func,
        ZED_TRIGGER_TYPE_START))
    {
      goto error;
    }

    if (!attach_listener_to_trigger_function (self, stop_trigger_func,
        ZED_TRIGGER_TYPE_STOP))
    {
      goto error;
    }
  }

  return TRUE;

error:
  zed_investigator_detach (self);
  return FALSE;
}

void
zed_investigator_detach (ZedInvestigator * self)
{
  if (interceptor == NULL)
    return;

#ifndef _M_X64
  gum_interceptor_detach_listener (interceptor,
      GUM_INVOCATION_LISTENER (self));

  g_object_unref (interceptor);
  interceptor = NULL;
#endif
}

static gpointer
resolve_trigger_function (ZedTriggerInfo * trigger)
{
  gpointer result = NULL;
  WCHAR * module_name_utf16;
  HMODULE module;

  module_name_utf16 = (WCHAR *) g_utf8_to_utf16 (
      zed_trigger_info_get_module_name (trigger), -1, NULL, NULL, NULL);
  module = GetModuleHandleW (module_name_utf16);
  g_free (module_name_utf16);
  if (module != NULL)
  {
    result = GetProcAddress (module,
        zed_trigger_info_get_function_name (trigger));
  }

  return result;
}

static gboolean
attach_listener_to_trigger_function (ZedInvestigator * self, gpointer func,
    ZedTriggerType type)
{
#ifndef _M_X64
  GumAttachReturn attach_ret;

  attach_ret = gum_interceptor_attach_listener (interceptor, func,
      GUM_INVOCATION_LISTENER (self), GSIZE_TO_POINTER (type));

  return (attach_ret == GUM_ATTACH_OK);
#else
  return FALSE;
#endif
}
