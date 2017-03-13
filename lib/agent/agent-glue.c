#include "frida-agent.h"

#ifndef G_OS_WIN32
# include <frida-interfaces.h>
#endif
#include <gio/gio.h>
#include <gum/gum.h>
#include <gumjs/gumscriptbackend.h>

#ifdef G_OS_WIN32
# include <crtdbg.h>
# include <process.h>
#else
# include <dlfcn.h>
# include <pthread.h>
#endif

static void frida_agent_auto_ignorer_shutdown (FridaAgentAutoIgnorer * self);

static void * frida_linker_stub_warmup_thread (void * data);

void
frida_agent_environment_init (void)
{
  gum_init_embedded ();

  gum_script_backend_get_type (); /* Warm up */
  frida_error_quark (); /* Initialize early so GDBus will pick it up */

  (void) frida_linker_stub_warmup_thread;
}

void
frida_agent_environment_deinit (FridaAgentAutoIgnorer * ignorer)
{
  gum_shutdown ();
  gio_shutdown ();
  glib_shutdown ();

  frida_agent_auto_ignorer_shutdown (ignorer);
  g_object_unref (ignorer);

  gum_deinit_embedded ();
}

GumScriptBackend *
frida_agent_environment_obtain_script_backend (gboolean jit_enabled)
{
  GumScriptBackend * backend = NULL;

#ifdef HAVE_DIET
  backend = gum_script_backend_obtain_duk ();
#else
  if (jit_enabled)
    backend = gum_script_backend_obtain_v8 ();
  if (backend == NULL)
    backend = gum_script_backend_obtain_duk ();
#endif

  return backend;
}

typedef struct _FridaThreadCreateContext FridaThreadCreateContext;

#ifdef G_OS_WIN32
typedef unsigned NativeThreadFuncReturnType;
# define NATIVE_THREAD_FUNC_API __stdcall
#else
typedef void * NativeThreadFuncReturnType;
# define NATIVE_THREAD_FUNC_API
#endif
typedef NativeThreadFuncReturnType (NATIVE_THREAD_FUNC_API * NativeThreadFunc) (void * data);

struct _FridaThreadCreateContext
{
  NativeThreadFunc thread_func;
  void * thread_data;

  gboolean has_cloaked_range;
  GumMemoryRange cloaked_range;
  FridaAgentAutoIgnorer * ignorer;
};

#ifndef G_OS_WIN32

typedef struct _FridaTlsKeyContext FridaTlsKeyContext;

struct _FridaTlsKeyContext
{
  void (* destructor) (void *);
  gboolean replaced;

  FridaAgentAutoIgnorer * ignorer;
};

static void frida_tls_key_context_free (FridaTlsKeyContext * ctx);

#endif

static gpointer frida_get_address_of_thread_create_func (void);
static NativeThreadFuncReturnType NATIVE_THREAD_FUNC_API frida_thread_create_proxy (void * data);
static void frida_thread_create_context_free (FridaThreadCreateContext * ctx);

static GPrivate frida_thread_create_context_key = G_PRIVATE_INIT ((GDestroyNotify) frida_thread_create_context_free);

static void
frida_agent_auto_ignorer_shutdown (FridaAgentAutoIgnorer * self)
{
#ifdef G_OS_WIN32
  (void) self;
#else
  GumInterceptor * interceptor = self->interceptor;

  gum_interceptor_revert_function (interceptor, pthread_key_create);

  g_mutex_lock (&self->mutex);
  g_slist_foreach (self->tls_contexts, (GFunc) frida_tls_key_context_free, NULL);
  g_slist_free (self->tls_contexts);
  self->tls_contexts = NULL;
  g_mutex_unlock (&self->mutex);
#endif
}

#ifdef G_OS_WIN32
static uintptr_t
frida_replacement_thread_create (
    void * security,
    unsigned stack_size,
    unsigned (__stdcall * func) (void *),
    void * data,
    unsigned initflag,
    unsigned * thrdaddr)
#else
static int
frida_replacement_thread_create (
    pthread_t * thread,
    const pthread_attr_t * attr,
    void * (* func) (void *),
    void * data)
#endif
{
  GumInvocationContext * ic;
  FridaAgentAutoIgnorer * self;

  ic = gum_interceptor_get_current_invocation ();
  self = FRIDA_AGENT_AUTO_IGNORER (gum_invocation_context_get_replacement_function_data (ic));

  if (GUM_MEMORY_RANGE_INCLUDES (&self->agent_range, GUM_ADDRESS (GUM_FUNCPTR_TO_POINTER (func))))
  {
    FridaThreadCreateContext * ctx;

    ctx = g_slice_new (FridaThreadCreateContext);
    ctx->has_cloaked_range = FALSE;
    ctx->ignorer = g_object_ref (self);
    ctx->thread_func = func;
    ctx->thread_data = data;

    func = frida_thread_create_proxy;
    data = ctx;
  }

#ifdef G_OS_WIN32
  return _beginthreadex (security, stack_size, func, data, initflag, thrdaddr);
#else
  return pthread_create (thread, attr, func, data);
#endif
}

#ifndef G_OS_WIN32

static void
frida_tls_key_context_free (FridaTlsKeyContext * ctx)
{
  if (ctx->replaced)
    gum_interceptor_revert_function (ctx->ignorer->interceptor, ctx->destructor);
  g_object_unref (ctx->ignorer);
  g_slice_free (FridaTlsKeyContext, ctx);
}

static void
frida_replacement_tls_key_destructor (void * data)
{
  GumInvocationContext * ctx;
  FridaTlsKeyContext * tkc;
  GumInterceptor * interceptor;

  ctx = gum_interceptor_get_current_invocation ();
  tkc = gum_invocation_context_get_replacement_function_data (ctx);
  interceptor = tkc->ignorer->interceptor;

  g_object_ref (interceptor);
  gum_interceptor_ignore_current_thread (interceptor);
  tkc->destructor (data);
  gum_interceptor_unignore_current_thread (interceptor);
  g_object_unref (interceptor);
}

static int
frida_replacement_tls_key_create (
    pthread_key_t * key,
    void (* destructor) (void *))
{
  GumInvocationContext * ctx;
  FridaAgentAutoIgnorer * self;
  GumInterceptor * interceptor;
  int res;

  ctx = gum_interceptor_get_current_invocation ();
  self = FRIDA_AGENT_AUTO_IGNORER (gum_invocation_context_get_replacement_function_data (ctx));
  interceptor = self->interceptor;

  res = pthread_key_create (key, destructor);
  if (res != 0)
    return res;

  if (GUM_MEMORY_RANGE_INCLUDES (&self->agent_range, GUM_ADDRESS (GUM_FUNCPTR_TO_POINTER (destructor))))
  {
    FridaTlsKeyContext * tkc;

    gum_interceptor_ignore_current_thread (interceptor);

    tkc = g_slice_new (FridaTlsKeyContext);
    tkc->destructor = destructor;
    tkc->replaced = FALSE;

    tkc->ignorer = g_object_ref (self);

    if (gum_interceptor_replace_function (interceptor, destructor, frida_replacement_tls_key_destructor, tkc) == GUM_REPLACE_OK)
    {
      tkc->replaced = TRUE;

      g_mutex_lock (&self->mutex);
      self->tls_contexts = g_slist_prepend (self->tls_contexts, tkc);
      g_mutex_unlock (&self->mutex);
    }
    else
    {
      frida_tls_key_context_free (tkc);
    }

    gum_interceptor_unignore_current_thread (interceptor);
  }

  return 0;
}

#endif

void
frida_agent_auto_ignorer_replace_apis (FridaAgentAutoIgnorer * self)
{
  gum_interceptor_begin_transaction (self->interceptor);

  gum_interceptor_replace_function (self->interceptor,
      frida_get_address_of_thread_create_func (),
      GUM_FUNCPTR_TO_POINTER (frida_replacement_thread_create),
      self);

#ifndef G_OS_WIN32
  gum_interceptor_replace_function (self->interceptor,
      pthread_key_create,
      GUM_FUNCPTR_TO_POINTER (frida_replacement_tls_key_create),
      self);
#endif

  gum_interceptor_end_transaction (self->interceptor);
}

void
frida_agent_auto_ignorer_revert_apis (FridaAgentAutoIgnorer * self)
{
  gum_interceptor_revert_function (self->interceptor, frida_get_address_of_thread_create_func ());
}

static gpointer
frida_get_address_of_thread_create_func (void)
{
#if defined (G_OS_WIN32)
  return GUM_FUNCPTR_TO_POINTER (_beginthreadex);
#elif defined (HAVE_DARWIN) || defined (HAVE_ANDROID)
  return GUM_FUNCPTR_TO_POINTER (pthread_create);
#elif defined (HAVE_UCLIBC)
  gpointer handle, func;

  handle = dlopen ("libpthread.so.0", RTLD_GLOBAL | RTLD_LAZY);
  func = dlsym (handle, "pthread_create");
  dlclose (handle);

  return func;
#else
  static gsize gonce_value = 0;

  if (g_once_init_enter (&gonce_value))
  {
    pthread_t linker_stub_warmup_thread;

    pthread_create (&linker_stub_warmup_thread, NULL, frida_linker_stub_warmup_thread, NULL);
    pthread_detach (linker_stub_warmup_thread);

    g_once_init_leave (&gonce_value, TRUE);
  }

  return GUM_FUNCPTR_TO_POINTER (pthread_create);
#endif
}

static NativeThreadFuncReturnType NATIVE_THREAD_FUNC_API
frida_thread_create_proxy (void * data)
{
  FridaThreadCreateContext * ctx = data;

#ifdef HAVE_DARWIN
  pthread_t thread;
  gpointer stack_top;
  gsize stack_size, guard_size;

  thread = pthread_self ();

  stack_top = pthread_get_stackaddr_np (thread);
  stack_size = pthread_get_stacksize_np (thread);
  guard_size = gum_query_page_size ();

  ctx->has_cloaked_range = TRUE;
  ctx->cloaked_range.base_address = GUM_ADDRESS (stack_top) - stack_size - guard_size;
  ctx->cloaked_range.size = stack_size + guard_size;

  gum_cloak_add_range (&ctx->cloaked_range);
#endif

  gum_script_backend_ignore (gum_process_get_current_thread_id ());

  /* This allows us to free the data no matter how the thread exits */
  g_private_set (&frida_thread_create_context_key, ctx);

  return ctx->thread_func (ctx->thread_data);
}

static void
frida_thread_create_context_free (FridaThreadCreateContext * ctx)
{
  if (ctx->has_cloaked_range)
    gum_cloak_remove_range (&ctx->cloaked_range);
  g_object_unref (ctx->ignorer);
  g_slice_free (FridaThreadCreateContext, ctx);

  gum_script_backend_unignore_later (gum_process_get_current_thread_id ());
}

static void *
frida_linker_stub_warmup_thread (void * data)
{
  (void) data;

  return NULL;
}

#ifdef HAVE_DARWIN

/*
 * Get rid of the -lresolv dependency until we actually need it, i.e. if/when
 * we expose GLib's resolvers to JavaScript. This is however not needed for
 * our current Socket.connect() API, which is neat.
 */

#include <resolv.h>

int
res_9_init (void)
{
  g_assert_not_reached ();
  return 0;
}

int
res_9_query (const char * dname, int klass, int type, u_char * answer, int anslen)
{
  g_assert_not_reached ();
  return -1;
}

int
res_9_dn_expand (const u_char * msg, const u_char * eomorig, const u_char * comp_dn, char * exp_dn, int length)
{
  g_assert_not_reached ();
  return -1;
}

#endif
