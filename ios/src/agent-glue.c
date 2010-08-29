#include <glib-object.h>

__attribute__ ((constructor)) static void
on_load (void)
{
  g_type_init ();
}

