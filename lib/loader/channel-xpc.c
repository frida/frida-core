#include "channel.h"

#include <dispatch/dispatch.h>
#include <os/object.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

typedef const struct _xpc_type_s * xpc_type_t;
#define XPC_TYPE(type) const struct _xpc_type_s type
#define XPC_EXPORT extern __attribute__((visibility ("default")))
#define XPC_GLOBAL_OBJECT(object) (&(object))

typedef void * xpc_object_t;
#define XPC_DECL(name) typedef struct _##name##_s * name##_t

XPC_EXPORT XPC_TYPE (_xpc_type_connection);
XPC_DECL (xpc_connection);

#define XPC_TYPE_ERROR (&_xpc_type_error)
XPC_EXPORT XPC_TYPE (_xpc_type_error);

#define XPC_ERROR_CONNECTION_INTERRUPTED XPC_GLOBAL_OBJECT (_xpc_error_connection_interrupted)
XPC_EXPORT const struct _xpc_dictionary_s _xpc_error_connection_interrupted;

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

struct _FridaChannel
{
  xpc_connection_t connection;

  pthread_mutex_t mutex;
  pthread_cond_t cond;
  volatile bool closed;
  volatile bool interrupted;
  volatile xpc_object_t pending_message;
};

static void frida_channel_on_event (FridaChannel * self, xpc_object_t event);

FridaChannel *
frida_channel_open (const char * frida_data_dir)
{
  FridaChannel * channel;

  channel = malloc (sizeof (FridaChannel));

  pthread_mutex_init (&channel->mutex, NULL);
  pthread_cond_init (&channel->cond, NULL);
  channel->closed = false;
  channel->interrupted = false;
  channel->pending_message = NULL;

  channel->connection = xpc_connection_create_mach_service ("com.apple.uikit.viewservice.frida", NULL, 0);
  xpc_connection_set_event_handler (channel->connection, ^(xpc_object_t event) {
    frida_channel_on_event (channel, event);
  });
  xpc_connection_resume (channel->connection);

  return channel;
}

void
frida_channel_close (FridaChannel * self)
{
  xpc_connection_cancel (self->connection);
  xpc_release (self->connection);

  pthread_mutex_lock (&self->mutex);

  while (!self->closed)
    pthread_cond_wait (&self->cond, &self->mutex);

  if (self->pending_message != NULL)
    xpc_release (self->pending_message);

  pthread_mutex_unlock (&self->mutex);

  pthread_cond_destroy (&self->cond);
  pthread_mutex_destroy (&self->mutex);

  free (self);
}

bool
frida_channel_send_string (FridaChannel * self, const char * str)
{
  const char * key = "payload";
  xpc_object_t value, message;

  value = xpc_string_create (str);
  message = xpc_dictionary_create (&key, &value, 1);
  xpc_release (value);

  xpc_connection_send_message (self->connection, message);

  xpc_release (message);

  return true;
}

char *
frida_channel_recv_string (FridaChannel * self)
{
  char * result = NULL;
  xpc_object_t message;

  pthread_mutex_lock (&self->mutex);

  while (self->pending_message == NULL && !self->closed && !self->interrupted)
    pthread_cond_wait (&self->cond, &self->mutex);

  message = self->pending_message;
  self->pending_message = NULL;

  pthread_mutex_unlock (&self->mutex);

  if (message != NULL)
  {
    result = strdup (xpc_dictionary_get_string (message, "payload"));
    xpc_release (message);
  }

  return result;
}

static void
frida_channel_on_event (FridaChannel * self, xpc_object_t event)
{
  pthread_mutex_lock (&self->mutex);

  if (event == XPC_ERROR_CONNECTION_INVALID)
    self->closed = true;
  else if (event == XPC_ERROR_CONNECTION_INTERRUPTED)
    self->interrupted = true;
  else if (xpc_get_type (event) != XPC_TYPE_ERROR && self->pending_message == NULL)
    self->pending_message = xpc_retain (event);

  pthread_cond_signal (&self->cond);
  pthread_mutex_unlock (&self->mutex);
}
