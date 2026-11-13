#if defined (HAVE_TVOS) || defined (HAVE_WATCHOS)
# include <Availability.h>
# undef __TVOS_PROHIBITED
# define __TVOS_PROHIBITED
# undef __WATCHOS_PROHIBITED
# define __WATCHOS_PROHIBITED
#endif

#include "frida-gadget.h"

#include "frida-base.h"

#import <Foundation/Foundation.h>
#include <arpa/inet.h>
#include <errno.h>
#include <gum/gumdarwin.h>
#include <mach-o/loader.h>
#include <netinet/in.h>
#include <objc/runtime.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>

static void frida_on_breakpoints_steal_attempt (GumInvocationContext * ic, gpointer user_data);
static void frida_wait_until_interrupt_listener_named (void);
static void frida_wake_interrupt_listener (void);
static void * frida_run_interrupt_listener (void * data);
static void frida_announce_interrupt_listener_named (void);
static void frida_break_and_interrupt_if_armed (void);
static void frida_lock_interrupt_arming (void);
static void frida_unlock_interrupt_arming (void);
static void frida_break_and_interrupt (void);
static void frida_init_loopback_address (struct sockaddr_in * addr, guint16 port);
static int frida_open_tcp_socket (void);
static int frida_bind (int fd, const struct sockaddr_in * addr);
static int frida_listen (int fd, int backlog);
static int frida_get_bound_address (int fd, struct sockaddr_in * addr);
static int frida_accept (int fd);
static int frida_connect (int fd, const struct sockaddr_in * addr);
static void frida_close (int fd);
static gssize frida_syscall (gsize number, gsize a0, gsize a1, gsize a2);

static GumInvocationListener * frida_dont_steal_my_breakpoints;

static pthread_t frida_interrupt_listener_thread;
static int frida_interrupt_listener_fd = -1;
static guint16 frida_interrupt_listener_port;
static volatile gboolean frida_interrupt_listener_stopping;
static pthread_mutex_t frida_interrupt_listener_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t frida_interrupt_listener_cond = PTHREAD_COND_INITIALIZER;
static gboolean frida_interrupt_listener_named;
static volatile guint8 frida_interrupt_listener_armed;
static GumAddress frida_our_base_address;
static gsize frida_our_size;
static volatile gint frida_interrupt_arming_lock;

gchar *
frida_gadget_environment_detect_bundle_id (void)
{
  @autoreleasepool
  {
    NSString * identifier = NSBundle.mainBundle.bundleIdentifier;
    return g_strdup (identifier.UTF8String);
  }
}

gchar *
frida_gadget_environment_detect_bundle_name (void)
{
  @autoreleasepool
  {
    NSString * name = [NSBundle.mainBundle objectForInfoDictionaryKey:@"CFBundleName"];
    return g_strdup (name.UTF8String);
  }
}

gchar *
frida_gadget_environment_detect_documents_dir (void)
{
#if defined (HAVE_IOS) || defined (HAVE_TVOS) || defined (HAVE_XROS)
  @autoreleasepool
  {
    NSArray<NSString *> * paths = NSSearchPathForDirectoriesInDomains (NSDocumentDirectory, NSUserDomainMask, YES);
    NSString * first = paths.firstObject;
    return g_strdup (first.UTF8String);
  }
#else
  return NULL;
#endif
}

gboolean
frida_gadget_environment_has_objc_class (const gchar * name)
{
  return objc_getClass (name) != NULL;
}

void
frida_gadget_environment_set_thread_name (const gchar * name)
{
  /* For now only implemented on i/macOS as Fruity.Injector relies on it there. */
  pthread_setname_np (name);
}

void
frida_gadget_environment_detect_darwin_location_fields (GumAddress our_address, gchar ** executable_name, gchar ** our_path,
    GumMemoryRange ** our_range)
{
  mach_port_t task;
  GumDarwinModuleResolver * resolver;
  GPtrArray * modules;
  guint i;

  task = mach_task_self ();

  resolver = gum_darwin_module_resolver_new (task, NULL);
  if (resolver == NULL)
    return;

  gum_darwin_module_resolver_fetch_modules (resolver, &modules, NULL);

  for (i = 0; i != modules->len; i++)
  {
    GumModule * module;
    const GumMemoryRange * range;

    module = g_ptr_array_index (modules, i);
    range = gum_module_get_range (module);

    if (*executable_name == NULL)
    {
      gum_mach_header_t * header = GSIZE_TO_POINTER (range->base_address);
      if (header->filetype == MH_EXECUTE)
        *executable_name = g_strdup (gum_module_get_name (module));
    }

    if (our_address >= range->base_address && our_address < range->base_address + range->size)
    {
      if (*our_path == NULL)
        *our_path = g_strdup (gum_module_get_path (module));

      if (*our_range == NULL)
        *our_range = gum_memory_range_copy (range);
    }

    if (*executable_name != NULL && *our_path != NULL && *our_range != NULL)
      break;
  }

  g_ptr_array_unref (modules);

  g_object_unref (resolver);
}

void
frida_gadget_environment_ensure_debugger_breakpoints_only (void)
{
  task_set_exception_ports (
      mach_task_self (),
      EXC_MASK_ALL & ~EXC_MASK_BREAKPOINT,
      MACH_PORT_NULL,
      EXCEPTION_DEFAULT,
      THREAD_STATE_NONE
  );

  if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_OPTIONAL &&
      frida_dont_steal_my_breakpoints == NULL &&
      gum_darwin_is_debugger_mapping_enforced ())
  {
    gpointer exceptions_set, exceptions_swap;
    GumInterceptor * interceptor;

    exceptions_set = &task_set_exception_ports;
    exceptions_swap = &task_swap_exception_ports;

    frida_dont_steal_my_breakpoints = gum_make_call_listener (frida_on_breakpoints_steal_attempt,
      NULL, NULL, NULL);

    interceptor = gum_interceptor_obtain ();

    gum_interceptor_attach (interceptor, exceptions_set, frida_dont_steal_my_breakpoints, NULL);
    gum_interceptor_attach (interceptor, exceptions_swap, frida_dont_steal_my_breakpoints, NULL);

    g_object_unref (interceptor);
  }
}

void
frida_gadget_environment_allow_stolen_breakpoints (void)
{
  GumInterceptor * interceptor;

  if (frida_dont_steal_my_breakpoints == NULL)
    return;

  interceptor = gum_interceptor_obtain ();

  gum_interceptor_detach (interceptor, frida_dont_steal_my_breakpoints);

  g_object_unref (frida_dont_steal_my_breakpoints);
  frida_dont_steal_my_breakpoints = NULL;

  g_object_unref (interceptor);
}

static void
frida_on_breakpoints_steal_attempt (GumInvocationContext * ic, gpointer user_data)
{
  exception_mask_t exception_mask;

  exception_mask = GPOINTER_TO_SIZE (gum_invocation_context_get_nth_argument (ic, 1));
  exception_mask &= ~EXC_MASK_BREAKPOINT;
  gum_invocation_context_replace_nth_argument (ic, 1, GSIZE_TO_POINTER (exception_mask));
}

void
frida_gadget_environment_start_interrupt_listener (GumAddress our_base_address, gsize our_size)
{
  int fd;
  struct sockaddr_in addr;

  if (frida_interrupt_listener_fd != -1)
    return;

  frida_our_base_address = our_base_address;
  frida_our_size = our_size;

  fd = frida_open_tcp_socket ();
  if (fd < 0)
    return;

  frida_init_loopback_address (&addr, 0);
  if (frida_bind (fd, &addr) != 0 ||
      frida_listen (fd, 1) != 0 ||
      frida_get_bound_address (fd, &addr) != 0)
  {
    frida_close (fd);
    return;
  }

  frida_interrupt_listener_fd = fd;
  frida_interrupt_listener_port = ntohs (addr.sin_port);
  frida_interrupt_listener_stopping = FALSE;
  frida_interrupt_listener_named = FALSE;
  frida_interrupt_listener_armed = TRUE;

  if (pthread_create (&frida_interrupt_listener_thread, NULL, frida_run_interrupt_listener, NULL) != 0)
  {
    frida_close (fd);
    frida_interrupt_listener_fd = -1;
    return;
  }

  frida_wait_until_interrupt_listener_named ();
}

void
frida_gadget_environment_stop_interrupt_listener (void)
{
  if (frida_interrupt_listener_fd == -1)
    return;

  frida_interrupt_listener_stopping = TRUE;
  frida_wake_interrupt_listener ();

  pthread_join (frida_interrupt_listener_thread, NULL);

  frida_close (frida_interrupt_listener_fd);
  frida_interrupt_listener_fd = -1;
}

void
frida_gadget_environment_disarm_interrupt_listener (void)
{
  if (frida_interrupt_listener_fd == -1)
    return;

  frida_lock_interrupt_arming ();
  frida_interrupt_listener_armed = FALSE;
  frida_unlock_interrupt_arming ();
}

static void
frida_wait_until_interrupt_listener_named (void)
{
  pthread_mutex_lock (&frida_interrupt_listener_mutex);
  while (!frida_interrupt_listener_named)
    pthread_cond_wait (&frida_interrupt_listener_cond, &frida_interrupt_listener_mutex);
  pthread_mutex_unlock (&frida_interrupt_listener_mutex);
}

static void
frida_wake_interrupt_listener (void)
{
  int fd;
  struct sockaddr_in addr;

  fd = frida_open_tcp_socket ();
  if (fd < 0)
    return;

  frida_init_loopback_address (&addr, frida_interrupt_listener_port);
  frida_connect (fd, &addr);
  frida_close (fd);
}

static void *
frida_run_interrupt_listener (void * data)
{
  char name[64];
  GumThreadId self;

  snprintf (name, sizeof (name), "frida-gadget-interrupt-%u-%" G_GINT64_MODIFIER "x", frida_interrupt_listener_port,
      (guint64) GPOINTER_TO_SIZE (&frida_interrupt_listener_armed));
  pthread_setname_np (name);

  self = gum_process_get_current_thread_id ();
  gum_cloak_add_thread (self);

  frida_announce_interrupt_listener_named ();

  while (TRUE)
  {
    int client = frida_accept (frida_interrupt_listener_fd);
    if (client < 0)
    {
      if (client == -EINTR || client == -ECONNABORTED)
        continue;
      break;
    }

    if (!frida_interrupt_listener_stopping)
      frida_break_and_interrupt_if_armed ();

    frida_close (client);

    if (frida_interrupt_listener_stopping)
      break;
  }

  gum_cloak_remove_thread (self);

  return NULL;
}

static void
frida_announce_interrupt_listener_named (void)
{
  pthread_mutex_lock (&frida_interrupt_listener_mutex);
  frida_interrupt_listener_named = TRUE;
  pthread_cond_signal (&frida_interrupt_listener_cond);
  pthread_mutex_unlock (&frida_interrupt_listener_mutex);
}

static void
frida_break_and_interrupt_if_armed (void)
{
  frida_lock_interrupt_arming ();
  if (frida_interrupt_listener_armed)
    frida_break_and_interrupt ();
  frida_unlock_interrupt_arming ();
}

static void
frida_lock_interrupt_arming (void)
{
  while (__atomic_exchange_n (&frida_interrupt_arming_lock, 1, __ATOMIC_ACQUIRE) != 0)
    ;
}

static void
frida_unlock_interrupt_arming (void)
{
  __atomic_store_n (&frida_interrupt_arming_lock, 0, __ATOMIC_RELEASE);
}

static void
frida_break_and_interrupt (void)
{
#ifdef HAVE_ARM64
  asm volatile (
      "mov x1, #1337\n\t"
      "mov x2, #1337\n\t"
      "mov x3, %0\n\t"
      "mov x4, %1\n\t"
      "mov x5, %2\n\t"
      "brk #1337\n\t"
      :
      : "r" ((gsize) FRIDA_GADGET_BREAKPOINT_ACTION_INTERRUPT),
        "r" ((gsize) frida_our_base_address),
        "r" (frida_our_size)
      : "x1", "x2", "x3", "x4", "x5"
  );
#endif
}

static void
frida_init_loopback_address (struct sockaddr_in * addr, guint16 port)
{
  *addr = (struct sockaddr_in) {
    .sin_len = sizeof (struct sockaddr_in),
    .sin_family = AF_INET,
    .sin_port = htons (port),
    .sin_addr.s_addr = htonl (INADDR_LOOPBACK),
  };
}

static int
frida_open_tcp_socket (void)
{
  return frida_syscall (SYS_socket, AF_INET, SOCK_STREAM, 0);
}

static int
frida_bind (int fd, const struct sockaddr_in * addr)
{
  return frida_syscall (SYS_bind, fd, GPOINTER_TO_SIZE (addr), sizeof (struct sockaddr_in));
}

static int
frida_listen (int fd, int backlog)
{
  return frida_syscall (SYS_listen, fd, backlog, 0);
}

static int
frida_get_bound_address (int fd, struct sockaddr_in * addr)
{
  socklen_t addr_len = sizeof (struct sockaddr_in);

  return frida_syscall (SYS_getsockname, fd, GPOINTER_TO_SIZE (addr), GPOINTER_TO_SIZE (&addr_len));
}

static int
frida_accept (int fd)
{
  return frida_syscall (SYS_accept, fd, 0, 0);
}

static int
frida_connect (int fd, const struct sockaddr_in * addr)
{
  return frida_syscall (SYS_connect, fd, GPOINTER_TO_SIZE (addr), sizeof (struct sockaddr_in));
}

static void
frida_close (int fd)
{
  frida_syscall (SYS_close, fd, 0, 0);
}

static gssize
frida_syscall (gsize number, gsize a0, gsize a1, gsize a2)
{
#ifdef HAVE_ARM64
  register gsize x0 asm ("x0") = a0;
  register gsize x1 asm ("x1") = a1;
  register gsize x2 asm ("x2") = a2;
  register gsize x16 asm ("x16") = number;
  gsize failed;

  asm volatile (
      "svc 0x80\n\t"
      "cset %2, cs\n\t"
      : "+r" (x0),
        "+r" (x1),
        "=&r" (failed)
      : "r" (x2),
        "r" (x16)
      : "cc", "memory"
  );

  return failed ? -(gssize) x0 : (gssize) x0;
#else
  register gsize rdi asm ("rdi") = a0;
  register gsize rsi asm ("rsi") = a1;
  register gsize rdx asm ("rdx") = a2;
  register gsize rax asm ("rax") = 0x2000000 | number;
  guint8 failed;

  asm volatile (
      "syscall\n\t"
      "setc %2\n\t"
      : "+r" (rax),
        "+r" (rdx),
        "=&q" (failed)
      : "r" (rdi),
        "r" (rsi)
      : "rcx", "r11", "cc", "memory"
  );

  return failed ? -(gssize) rax : (gssize) rax;
#endif
}

void
frida_gadget_environment_break_and_resume (void)
{
#ifdef HAVE_ARM64
  asm volatile (
      "mov x1, #1337\n\t"
      "mov x2, #1337\n\t"
      "mov x3, %0\n\t"
      "brk #1337\n\t"
      :
      : "r" ((gsize) FRIDA_GADGET_BREAKPOINT_ACTION_RESUME)
      : "x1", "x2", "x3"
  );
#else
  g_assert_not_reached ();
#endif
}

void
frida_gadget_environment_break_and_detach (void)
{
#ifdef HAVE_ARM64
  asm volatile (
      "mov x1, #1337\n\t"
      "mov x2, #1337\n\t"
      "mov x3, %0\n\t"
      "brk #1337\n\t"
      :
      : "r" ((gsize) FRIDA_GADGET_BREAKPOINT_ACTION_DETACH)
      : "x1", "x2", "x3"
  );
#else
  g_assert_not_reached ();
#endif
}
