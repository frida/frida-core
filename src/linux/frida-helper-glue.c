#include "frida-helper.h"

typedef struct _FridaHelperContext FridaHelperContext;
typedef struct _FridaSpawnInstance FridaSpawnInstance;
typedef struct _FridaInjectInstance FridaInjectInstance;

struct _FridaHelperContext
{
  gboolean foo;
};

struct _FridaSpawnInstance
{
  gboolean foo;
};

struct _FridaInjectInstance
{
  gboolean foo;
};

void
_frida_helper_service_create_context (FridaHelperService * self)
{
  FridaHelperContext * ctx;

  ctx = g_slice_new (FridaHelperContext);

  self->context = ctx;
}

void
_frida_helper_service_destroy_context (FridaHelperService * self)
{
  FridaHelperContext * ctx = self->context;

  g_slice_free (FridaHelperContext, ctx);
}

guint
_frida_helper_service_do_spawn (FridaHelperService * self, const gchar * path, gchar ** argv, int argv_length, gchar ** envp, int envp_length, GError ** error)
{
}

void
_frida_helper_service_resume_spawn_instance (FridaHelperService * self, void * instance)
{
  frida_spawn_instance_resume (instance);
}

void
_frida_helper_service_free_spawn_instance (FridaHelperService * self, void * instance)
{
  frida_spawn_instance_free (instance);
}

guint
_frida_helper_service_do_inject (FridaHelperService * self, guint pid, const gchar * dylib_path, const char * data_string, GError ** error)
{
}

void
_frida_helper_service_free_inject_instance (FridaHelperService * self, void * instance)
{
  frida_inject_instance_free (instance);
}

static FridaSpawnInstance *
frida_spawn_instance_new (FridaHelperService * service)
{
  FridaSpawnInstance * instance;

  instance = g_slice_new0 (FridaSpawnInstance);

  return instance;
}

static void
frida_spawn_instance_free (FridaSpawnInstance * instance)
{
  g_slice_free (FridaSpawnInstance, instance);
}

static void
frida_spawn_instance_resume (FridaSpawnInstance * self)
{
}

static FridaInjectInstance *
frida_inject_instance_new (FridaHelperService * service, guint id)
{
  FridaInjectInstance * instance;

  instance = g_slice_new (FridaInjectInstance);

  return instance;
}

static void
frida_inject_instance_free (FridaInjectInstance * instance)
{
  g_slice_free (FridaInjectInstance, instance);
}
