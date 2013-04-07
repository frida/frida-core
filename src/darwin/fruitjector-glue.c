#include "frida-core.h"

guint
frida_fruitjector_helper_factory_spawn (const gchar * path, gchar ** argv, int argv_length, GError ** error)
{
  g_print ("frida_fruitjector_helper_factory_spawn!\n");
  g_assert_not_reached ();
  return 42;
}
