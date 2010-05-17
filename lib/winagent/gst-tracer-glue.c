#include "zed-winagent.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>
#ifndef _M_X64
#include <udis86.h>
#endif

typedef gchar * (* ZedGstObjectGetPathStringFunc) (gpointer object);
typedef void (* ZedGstHeapFreeFunc) (gpointer mem);

static GumInterceptor * interceptor = NULL;
static gpointer pad_push_func, instance_free_func;

static ZedGstObjectGetPathStringFunc object_get_path_string_func;
static ZedGstHeapFreeFunc heap_free_func;

typedef struct _ZedGstPadPushArgs ZedGstPadPushArgs;

struct _ZedGstPadPushArgs {
  gpointer pad;
  gpointer buffer;
};

void
zed_gst_tracer_attach (ZedGstTracer * self)
{
  HMODULE glib_mod, gobj_mod, gst_mod;
  GumAttachReturn attach_ret;

  glib_mod = GetModuleHandle (_T ("libglib-2.0-0.dll"));
  gobj_mod = GetModuleHandle (_T ("libgobject-2.0-0.dll"));
  gst_mod = GetModuleHandle (_T ("libgstreamer-0.10-0.dll"));
  if (glib_mod == NULL || gobj_mod == NULL || gst_mod == NULL)
    return;

  instance_free_func = GetProcAddress (gobj_mod, "g_type_free_instance");
  pad_push_func = GetProcAddress (gst_mod, "gst_pad_push");
  if (instance_free_func == NULL || pad_push_func == NULL)
    return;

  object_get_path_string_func = (ZedGstObjectGetPathStringFunc)
      GetProcAddress (gst_mod, "gst_object_get_path_string");
  heap_free_func = (ZedGstHeapFreeFunc) GetProcAddress (glib_mod, "g_free");
  if (object_get_path_string_func == NULL || heap_free_func == NULL)
    return;

#ifndef _M_X64

  interceptor = gum_interceptor_obtain ();

  attach_ret = gum_interceptor_attach_listener (interceptor, pad_push_func,
      GUM_INVOCATION_LISTENER (self),
      GSIZE_TO_POINTER (ZED_GST_FUNCTION_PAD_PUSH));
  switch (attach_ret)
  {
    case GUM_ATTACH_OK:
      MessageBoxA (NULL, "Attached successfully!", "Yay",
          MB_ICONINFORMATION | MB_OK);
      break;
    case GUM_ATTACH_WRONG_SIGNATURE:
    {
      GString * msg;
      ud_t ud_obj;
      guint count = 0;

      msg = g_string_new ("Function signature of gst_pad_push is not "
          "supported by Gum.\r\n\r\nSignature:");

      ud_init (&ud_obj);
      ud_set_mode (&ud_obj, 32);
      ud_set_syntax (&ud_obj, UD_SYN_INTEL);
      ud_set_input_buffer (&ud_obj, pad_push_func, 4096);

      while (count < 5)
      {
        guint insn_size;
        guint i;

        g_string_append (msg, "\r\n");

        insn_size = ud_disassemble (&ud_obj);
        g_assert (insn_size != 0);

        for (i = 0; i != insn_size; i++)
        {
          if (i != 0)
            g_string_append_c (msg, ' ');
          g_string_append_printf (msg, "%02x",
              ((guint8 *) pad_push_func)[count + i]);
        }

        g_string_append_c (msg, '\t');
        if (insn_size < 3)
          g_string_append_c (msg, '\t');

        g_string_append (msg, ud_insn_asm (&ud_obj));

        count += insn_size;
      }

      MessageBoxA (NULL, msg->str, "Error", MB_ICONERROR | MB_OK);
      g_string_free (msg, TRUE);

      break;
    }
    case GUM_ATTACH_ALREADY_ATTACHED:
      MessageBoxA (NULL, "Already attached to gst_pad_push.", "Error",
          MB_ICONERROR | MB_OK);
      break;
  }

  /*
  gum_interceptor_attach_listener (interceptor, instance_free_func,
      GUM_INVOCATION_LISTENER (self),
      GSIZE_TO_POINTER (ZED_GST_FUNCTION_OBJECT_FREE));
  */

  if (attach_ret != GUM_ATTACH_OK)
  {
    g_object_unref (interceptor);
    interceptor = NULL;
  }

#endif
}

void
zed_gst_tracer_detach (ZedGstTracer * self)
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

void
zed_gst_tracer_on_pad_push (ZedGstTracer * self, void * arguments)
{
  ZedGstPadPushArgs * push_args = arguments;
  gchar * name;

  name = object_get_path_string_func (push_args->pad);
  zed_gst_tracer_submit_pad_push_event (self, name);
  heap_free_func (name);
}

void
zed_gst_tracer_on_object_free (ZedGstTracer * self, void * arguments)
{
}
