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

static gboolean attach_listener_for_trigger (ZedInvestigator * self,
    ZedTriggerInfo * trigger, ZedTriggerType type);
static gboolean try_to_resolve_function_name (const gchar * name,
    gpointer address, gpointer user_data);

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

ZedFunctionAddress *
zed_function_address_resolve (gsize address)
{
  ZedFunctionAddress * result = NULL;
  HANDLE this_process = GetCurrentProcess ();
  HMODULE first_module;
  DWORD modules_size = 0;
  HMODULE * modules = NULL;
  guint mod_idx;

  if (!EnumProcessModules (this_process, &first_module, sizeof (first_module),
      &modules_size))
  {
    goto beach;
  }

  modules = (HMODULE *) g_malloc (modules_size);

  if (!EnumProcessModules (this_process, modules, modules_size, &modules_size))
  {
    goto beach;
  }

  for (mod_idx = 0; mod_idx != modules_size / sizeof (HMODULE); mod_idx++)
  {
    MODULEINFO mi;

    if (!GetModuleInformation (this_process, modules[mod_idx], &mi, sizeof (mi)))
      continue;

    if (address >= GPOINTER_TO_SIZE (mi.lpBaseOfDll) &&
        address < GPOINTER_TO_SIZE (mi.lpBaseOfDll) + mi.SizeOfImage)
    {
      ResolveFuncNameContext resolve_ctx;
      WCHAR module_name_utf16[MAX_PATH];
      gchar * module_name;

      GetModuleBaseNameW (this_process, modules[mod_idx],
          module_name_utf16, MAX_PATH);
      module_name = g_utf16_to_utf8 ((const gunichar2 *) module_name_utf16, -1,
          NULL, NULL, NULL);

      result = zed_function_address_new (module_name,
          address - GPOINTER_TO_SIZE (mi.lpBaseOfDll));

      resolve_ctx.address_to_resolve = address;
      resolve_ctx.function_address = result;

      gum_module_enumerate_exports (module_name, try_to_resolve_function_name,
          &resolve_ctx);

      g_free (module_name);

      break;
    }
  }

beach:
  g_free (modules);

  return result;
}

static gboolean
try_to_resolve_function_name (const gchar * name, gpointer address,
    gpointer user_data)
{
  ResolveFuncNameContext * resolve_ctx = (ResolveFuncNameContext *) user_data;

  if (GPOINTER_TO_SIZE (address) == resolve_ctx->address_to_resolve)
  {
    zed_function_address_set_function_name (resolve_ctx->function_address,
        name);
    return FALSE;
  }

  return TRUE;
}
