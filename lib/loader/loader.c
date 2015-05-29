#ifdef HAVE_IOS

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define FRIDA_LOADER_CALLBACK_PATH_MAGIC "3zPLi3BupiesaB9diyimME74fJw4jvj6"

static char frida_callback_path[256] = FRIDA_LOADER_CALLBACK_PATH_MAGIC;

static void
frida_log (const char * format, ...)
{
  FILE * f;
  va_list vl;

  f = fopen ("/private/var/mobile/Containers/Data/Application/286C7ECF-2AD6-4E83-B9B7-8A2BCC38E589/tmp/loader.log", "ab");
  if (f != NULL)
  {
    va_start (vl, format);
    vfprintf (f, format, vl);
    va_end (vl);
    fclose (f);
  }
}

__attribute__ ((constructor)) static void
frida_loader_on_load (void)
{
  int s, len;
  struct sockaddr_un callback;

  frida_log ("frida_loader_on_load\n");

  s = socket (AF_UNIX, SOCK_STREAM, 0);
  if (s == -1)
    goto beach;

  callback.sun_family = AF_UNIX;
  frida_log ("trying to open '%s'\n", frida_callback_path);
  strcpy (callback.sun_path, frida_callback_path);
  len = sizeof (callback.sun_family) + strlen (callback.sun_path);
  if (connect (s, (struct sockaddr *) &callback, len) == -1)
  {
    frida_log ("failed to open '%s': %s\n", frida_callback_path, strerror (errno));
    goto beach;
  }

  send (s, "Hello", 5, 0);

beach:
  if (s != -1)
    close (s);

}

#endif
