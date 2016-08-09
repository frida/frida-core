#include "channel.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct _FridaChannel
{
  int fd;
};

static bool frida_channel_send_bytes (FridaChannel * self, const void * bytes, size_t size);
static bool frida_channel_recv_bytes (FridaChannel * self, void * bytes, size_t size);

FridaChannel *
frida_channel_open (const char * frida_data_dir)
{
  char * callback_path;
  int fd;
  struct sockaddr_un callback;
  socklen_t callback_len;
  FridaChannel * channel;

  asprintf (&callback_path, "%s/callback", frida_data_dir);

  fd = socket (AF_UNIX, SOCK_STREAM, 0);
  if (fd == -1)
    goto handle_error;

#ifdef HAVE_DARWIN
  callback.sun_len = sizeof (callback.sun_len) + sizeof (callback.sun_family) + strlen (callback_path);
  callback_len = callback.sun_len;
#else
  callback_len = sizeof (callback);
#endif
  callback.sun_family = AF_UNIX;
  strcpy (callback.sun_path, callback_path);
  if (connect (fd, (struct sockaddr *) &callback, callback_len) == -1)
    goto handle_error;

  channel = malloc (sizeof (FridaChannel));
  channel->fd = fd;

  free (callback_path);

  return channel;

handle_error:
  {
    if (fd != -1)
      close (fd);

    free (callback_path);

    return NULL;
  }
}

void
frida_channel_close (FridaChannel * self)
{
  close (self->fd);

  free (self);
}

bool
frida_channel_send_string (FridaChannel * self, const char * str)
{
  uint8_t size = strlen (str);
  if (!frida_channel_send_bytes (self, &size, sizeof (size)))
    return false;

  return frida_channel_send_bytes (self, str, size);
}

char *
frida_channel_recv_string (FridaChannel * self)
{
  uint8_t size;
  char * buf;

  if (!frida_channel_recv_bytes (self, &size, sizeof (size)))
    return NULL;

  buf = malloc (size + 1);
  buf[size] = '\0';
  if (!frida_channel_recv_bytes (self, buf, size))
  {
    free (buf);
    return NULL;
  }

  return buf;
}

static bool
frida_channel_send_bytes (FridaChannel * self, const void * bytes, size_t size)
{
  size_t offset = 0;

  while (offset != size)
  {
    ssize_t n;

    n = send (self->fd, bytes + offset, size - offset, 0);
    if (n != -1)
      offset += n;
    else if (errno != EINTR)
      return false;
  }

  return true;
}

static bool
frida_channel_recv_bytes (FridaChannel * self, void * bytes, size_t size)
{
  size_t offset = 0;

  while (offset != size)
  {
    ssize_t n;

    n = recv (self->fd, bytes + offset, size - offset, 0);
    if (n > 0)
      offset += n;
    else if (n == 0)
      return false;
    else if (n == -1 && errno != EINTR)
      return false;
  }

  return true;
}
