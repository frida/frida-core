#include "zed-winagent.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tchar.h>

typedef struct _ResolveFuncNameContext ResolveFuncNameContext;

struct _ResolveFuncNameContext
{
  gsize address_to_resolve;
  ZedFunctionAddress * function_address;
};

static gboolean try_to_resolve_function_name (const gchar * name,
    gpointer address, gpointer user_data);

static GumInterceptor * interceptor = NULL;

void
zed_func_tracer_attach (ZedFuncTracer * self)
{
  HMODULE winsock_mod;
  GumAttachReturn attach_ret;
  const gchar * function_names[] = { "recv", "WSARecv" };
  guint i, success_count = 0;

#ifndef _M_X64

  winsock_mod = GetModuleHandle (_T ("ws2_32.dll"));
  if (winsock_mod == NULL)
    return;

  interceptor = gum_interceptor_obtain ();

  for (i = 0; i != G_N_ELEMENTS (function_names); i++)
  {
    const gchar * function_name = function_names[i];
    gpointer function_address;

    function_address = GetProcAddress (winsock_mod, function_name);
    if (function_address == NULL)
      continue;

    attach_ret = gum_interceptor_attach_listener (interceptor, function_address,
        GUM_INVOCATION_LISTENER (self), (gpointer) function_name);
    switch (attach_ret)
    {
      case GUM_ATTACH_OK:
        success_count++;
        break;
      case GUM_ATTACH_WRONG_SIGNATURE:
      {
        MessageBoxA (NULL, "Function signature of recv not supported by Gum.", "Error", MB_ICONERROR | MB_OK);
        break;
      }
      case GUM_ATTACH_ALREADY_ATTACHED:
        MessageBoxA (NULL, "Already attached to gst_pad_push.", "Error",
            MB_ICONERROR | MB_OK);
        break;
    }
  }

#endif

  if (success_count == 0)
  {
    MessageBoxA (NULL, "Crap.", "Error", MB_ICONERROR | MB_OK);
    g_object_unref (interceptor);
    interceptor = NULL;
  }
}

void
zed_func_tracer_detach (ZedFuncTracer * self)
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

void *
zed_func_tracer_ref_object_hack (ZedFuncTracer * self, GObject * obj)
{
  return g_object_ref (obj);
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
