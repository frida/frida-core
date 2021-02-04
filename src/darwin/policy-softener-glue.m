#include "frida-helper-backend.h"

#ifdef HAVE_IOS
# import "policy-types.h"
# include "substitutedclient.h"

# include <mach/mach.h>
# include <objc/message.h>

typedef int (* JbdCallFunc) (mach_port_t service_port, guint command, guint pid);

extern kern_return_t bootstrap_look_up (mach_port_t bootstrap_port, char * service_name, mach_port_t * service_port);

static NSError * frida_pending_policy_error = nil;

static id<FridaPolicyBackend>
frida_try_get_policy_backend (void)
{
  id<FridaPolicyBackend> backend;
  static gsize backend_value = 0;

  if (g_once_init_enter (&backend_value))
  {
    NSXPCConnection * connection;
    NSXPCConnection * (* send_init_message) (NSXPCConnection *, SEL, NSString *, NSXPCConnectionOptions) = (void *) objc_msgSend;

    connection = send_init_message ([NSXPCConnection alloc], @selector(initWithMachServiceName:options:), FRIDA_POLICYD_SERVICE_NAME, 0);
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(FridaPolicyBackend)];
    [connection resume];

    backend = [connection synchronousRemoteObjectProxyWithErrorHandler:^(NSError * e) {
      [frida_pending_policy_error release];
      frida_pending_policy_error = [e retain];
    }];

    /* FIXME: This will always succeed. We need to autodetect that the service isn't available. */

    g_once_init_leave (&backend_value, 1 + GPOINTER_TO_SIZE (backend));
  }

  backend = GSIZE_TO_POINTER (backend_value - 1);

  return backend;
}

gboolean
frida_pure_ios_policy_softener_is_available (void)
{
  return frida_try_get_policy_backend () != NULL;
}

void
_frida_pure_ios_policy_softener_soften (guint pid,
                                        GError ** error)
{
  id<FridaPolicyBackend> backend = frida_try_get_policy_backend ();

  [backend soften:pid reply:^(NSError * e) {
    if (e != nil)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_PERMISSION_DENIED,
          "Unable to soften process with PID %u (errno=%ld)",
          pid,
          (long) e.code);
    }
  }];

  if (frida_pending_policy_error != nil)
  {
    if (error != NULL && *error == NULL)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_PERMISSION_DENIED,
          "Unable to soften process with PID %u: %s",
          pid,
          frida_pending_policy_error.description.UTF8String);
    }

    [frida_pending_policy_error release];
    frida_pending_policy_error = nil;
  }
}

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
