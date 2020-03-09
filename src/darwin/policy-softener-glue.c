#include "frida-helper-backend.h"

#ifdef HAVE_IOS
# include "substitutedclient.h"
# include <mach/mach.h>

typedef int (* JbdCallFunc) (mach_port_t service_port, guint command, guint pid);

extern kern_return_t bootstrap_look_up (mach_port_t bootstrap_port, char * service_name, mach_port_t * service_port);

guint
_frida_electra_policy_softener_internal_jb_connect (void)
{
  mach_port_t service_port = MACH_PORT_NULL;
  kern_return_t kr;

  kr = bootstrap_look_up (bootstrap_port, "org.coolstar.jailbreakd", &service_port);
  if (kr != KERN_SUCCESS)
    return MACH_PORT_NULL;

  return service_port;
}

void
_frida_electra_policy_softener_internal_jb_disconnect (guint service_port)
{
  mach_port_deallocate (mach_task_self (), service_port);
}

gint
_frida_electra_policy_softener_internal_jb_entitle_now (void * jbd_call, guint service_port, guint pid)
{
  JbdCallFunc jbd_call_func = jbd_call;

  return jbd_call_func (service_port, 1, pid);
}

guint
_frida_unc0ver_policy_softener_internal_connect (void)
{
  mach_port_t service_port = MACH_PORT_NULL;
  kern_return_t kr;

  kr = task_get_special_port (mach_task_self (), TASK_SEATBELT_PORT, &service_port);
  if (kr != KERN_SUCCESS)
    return MACH_PORT_NULL;

  return service_port;
}

void
_frida_unc0ver_policy_softener_internal_disconnect (guint service_port)
{
  mach_port_deallocate (mach_task_self (), service_port);
}

void
_frida_unc0ver_policy_softener_internal_substitute_setup_process (guint service_port, guint pid)
{
  kern_return_t kr;

  if (service_port == MACH_PORT_NULL)
    return;

  /*
   * DISCLAIMER:
   * Don't do this at home. This is not recommended outside of the
   * Frida use case and may change in the future. Instead, just
   * drop your stuff in /Library/MobileSubstrate/DynamicLibraries
   */
  kr = substitute_setup_process (service_port, pid, FALSE, FALSE);
  if (kr != KERN_SUCCESS)
    g_warning ("substitute_setup_process failed for pid %u", pid);
}
#endif
