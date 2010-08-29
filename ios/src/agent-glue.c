#include <glib-object.h>
#include <gum/gum.h>

__attribute__ ((constructor)) static void
on_load (void)
{
  g_type_init ();
  gum_init_with_features (GUM_FEATURE_ALL & ~GUM_FEATURE_SYMBOL_LOOKUP);
}

