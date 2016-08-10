#include "frida-core.h"

#include "icon-helpers.h"

#include <sys/sysctl.h>

#ifdef HAVE_MAC

typedef struct _FridaMacModel FridaMacModel;

struct _FridaMacModel
{
  const gchar * name;
  const gchar * icon;
};

static const FridaMacModel mac_models[] =
{
  { NULL,         "com.apple.led-cinema-display-27" },
  { "MacBookAir", "com.apple.macbookair-11-unibody" },
  { "MacBookPro", "com.apple.macbookpro-13-unibody" },
  { "MacBook",    "com.apple.macbook-unibody" },
  { "iMac",       "com.apple.imac-unibody-21" },
  { "Macmini",    "com.apple.macmini-unibody" },
  { "MacPro",     "com.apple.macpro" }
};

#endif

FridaImageData *
_frida_darwin_host_session_provider_extract_icon (void)
{
#ifdef HAVE_MAC
  size_t size;
  gchar * model_name;
  const FridaMacModel * model;
  guint i;
  gchar * filename;
  FridaImageData * icon;

  size = 0;
  sysctlbyname ("hw.model", NULL, &size, NULL, 0);
  model_name = g_malloc (size);
  sysctlbyname ("hw.model", model_name, &size, NULL, 0);

  for (model = NULL, i = 1; i != G_N_ELEMENTS (mac_models) && model == NULL; i++)
  {
    if (g_str_has_prefix (model_name, mac_models[i].name))
      model = &mac_models[i];
  }
  if (model == NULL)
    model = &mac_models[0];

  filename = g_strconcat ("/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/", model->icon, ".icns", NULL);
  icon = _frida_image_data_from_file (filename, 16, 16);
  g_free (filename);

  g_free (model_name);

  return icon;
#else
  return NULL;
#endif
}

gboolean
_frida_darwin_host_session_is_running_on_ios (void)
{
#ifdef HAVE_IOS
  return TRUE;
#else
  return FALSE;
#endif
}

#ifdef HAVE_IOS

#include <dispatch/dispatch.h>
#include <os/object.h>

#define XPC_CONNECTION_MACH_SERVICE_LISTENER (1 << 0)

typedef const struct _xpc_type_s * xpc_type_t;
#define XPC_TYPE(type) const struct _xpc_type_s type
#define XPC_EXPORT extern __attribute__((visibility ("default")))
#define XPC_GLOBAL_OBJECT(object) ((OS_OBJECT_BRIDGE xpc_object_t) &(object))

OS_OBJECT_DECL (xpc_object);
#define XPC_DECL(name) typedef xpc_object_t name##_t

XPC_EXPORT XPC_TYPE (_xpc_type_connection);
XPC_DECL (xpc_connection);

#define XPC_TYPE_ERROR (&_xpc_type_error)
XPC_EXPORT XPC_TYPE (_xpc_type_error);

#define XPC_ERROR_CONNECTION_INVALID XPC_GLOBAL_OBJECT (_xpc_error_connection_invalid)
XPC_EXPORT const struct _xpc_dictionary_s _xpc_error_connection_invalid;

typedef void (^ xpc_handler_t) (xpc_object_t object);

XPC_EXPORT xpc_object_t xpc_retain (xpc_object_t object);
XPC_EXPORT void xpc_release (xpc_object_t object);
XPC_EXPORT xpc_type_t xpc_get_type (xpc_object_t object);

XPC_EXPORT xpc_connection_t xpc_connection_create_mach_service (const char * name, dispatch_queue_t targetq, uint64_t flags);
XPC_EXPORT void xpc_connection_set_event_handler (xpc_connection_t connection, xpc_handler_t handler);
XPC_EXPORT void xpc_connection_resume (xpc_connection_t connection);
XPC_EXPORT void xpc_connection_send_message (xpc_connection_t connection, xpc_object_t message);
XPC_EXPORT void xpc_connection_cancel (xpc_connection_t connection);

XPC_EXPORT xpc_object_t xpc_dictionary_create (const char * const * keys, const xpc_object_t * values, size_t count);
XPC_EXPORT const char * xpc_dictionary_get_string (xpc_object_t xdict, const char * key);

XPC_EXPORT xpc_object_t xpc_string_create (const char * string);

static void frida_fruit_launcher_handle_xpc_client (FridaFruitLauncher * self, xpc_connection_t connection);

void
frida_fruit_launcher_open_xpc_service (FridaFruitLauncher * self)
{
  self->service = xpc_connection_create_mach_service ("com.apple.uikit.viewservice.frida", NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
  xpc_connection_set_event_handler (self->service, ^(xpc_object_t event) {
    if (xpc_get_type (event) == XPC_TYPE_ERROR)
    {
      if (event == XPC_ERROR_CONNECTION_INVALID)
        frida_fruit_launcher_on_service_closed (self);
    }
    else
    {
      frida_fruit_launcher_handle_xpc_client (self, event);
    }
  });
  xpc_connection_resume (self->service);
}

void
frida_fruit_launcher_close_xpc_service (FridaFruitLauncher * self)
{
  xpc_connection_cancel (self->service);
  xpc_release (self->service);
  self->service = NULL;
}

static void
frida_fruit_launcher_handle_xpc_client (FridaFruitLauncher * self, xpc_connection_t connection)
{
  FridaFruitLauncherLoader * loader;

  loader = frida_fruit_launcher_loader_new (xpc_retain (connection), self->main_context);
  frida_fruit_launcher_on_incoming_connection (self, loader);
  g_object_unref (loader);

  xpc_connection_set_event_handler (connection, ^(xpc_object_t event) {
    if (xpc_get_type (event) == XPC_TYPE_ERROR)
    {
      if (event == XPC_ERROR_CONNECTION_INVALID)
        frida_fruit_launcher_loader_on_connection_closed (loader);
    }
    else
    {
      frida_fruit_launcher_loader_on_message (loader, xpc_dictionary_get_string (event, "payload"));
    }
  });
  xpc_connection_resume (connection);
}

void
frida_fruit_launcher_loader_close_connection (FridaFruitLauncherLoader * self)
{
  xpc_connection_cancel (self->connection);
  xpc_release (self->connection);
  self->connection = NULL;
}

void
frida_fruit_launcher_loader_send_string_to_connection (FridaFruitLauncherLoader * self, const gchar * str)
{
  const gchar * key = "payload";
  xpc_object_t value, message;

  value = xpc_string_create (str);
  message = xpc_dictionary_create (&key, &value, 1);
  xpc_release (value);

  xpc_connection_send_message (self->connection, message);

  xpc_release (message);
}

#else

void
frida_fruit_launcher_open_xpc_service (FridaFruitLauncher * self)
{
}

void
frida_fruit_launcher_close_xpc_service (FridaFruitLauncher * self)
{
}

void
frida_fruit_launcher_loader_close_connection (FridaFruitLauncherLoader * self)
{
}

void
frida_fruit_launcher_loader_send_string_to_connection (FridaFruitLauncherLoader * self, const gchar * str)
{
}

#endif
