#include "frida-gadget.h"

/*
 * FIXME
 *
 * This code is in its own file so we can play with the GNU linker's
 * command-line and put this specific object file last, effectively
 * making our initializer run _after_ V8's initializer has been run.
 *
 * This is obviously a terrible hack, but will have to do until we find
 * a better solution.
 */

#ifdef HAVE_DARWIN

static gboolean frida_dylib_range_try_get (const gchar * apple[], GumMemoryRange * range);

__attribute__ ((constructor)) static void
on_load (int argc, const char * argv[], const char * envp[], const char * apple[])
{
  GumMemoryRange frida_dylib_range;

  if (frida_dylib_range_try_get (apple, &frida_dylib_range))
    frida_gadget_load (&frida_dylib_range);
  else
    frida_gadget_load (NULL);
}

static gboolean
frida_dylib_range_try_get (const gchar * apple[], GumMemoryRange * range)
{
  const gchar * entry;
  guint i = 0;

  while ((entry = apple[i++]) != NULL)
  {
    if (g_str_has_prefix (entry, "frida_dylib_range="))
    {
      if (sscanf (entry, "frida_dylib_range=0x%" G_GINT64_MODIFIER "x,0x%" G_GSIZE_MODIFIER "x",
          &range->base_address, &range->size) == 2)
        return TRUE;
    }
  }

  return FALSE;
}

#else

__attribute__ ((constructor)) static void
on_load (void)
{
  frida_gadget_load (NULL);
}

#endif
