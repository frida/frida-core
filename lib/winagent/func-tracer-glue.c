#include "zed-winagent.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>

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
