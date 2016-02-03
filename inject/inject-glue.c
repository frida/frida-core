#include "frida-inject.h"

#ifdef HAVE_ANDROID
# include "frida-selinux.h"
#endif

#include <gio/gio.h>

void
frida_inject_environment_init (void)
{
  gio_init ();

  gum_init ();

#ifdef HAVE_ANDROID
  frida_selinux_patch_policy ();
#endif
}

void
frida_inject_environment_deinit (void)
{
  gum_deinit ();

  gio_deinit ();
}


