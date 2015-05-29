#ifdef HAVE_IOS

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
  char buf[256];
  FILE * f;
  va_list vl;

  sprintf (buf, "/var/tmp/loader-%d.log", getpid ());
  f = fopen (buf, "ab");
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
  strcpy (callback.sun_path, frida_callback_path);
  len = sizeof (callback.sun_family) + strlen (callback.sun_path);
  if (connect (s, (struct sockaddr *) &callback, len) == -1)
    goto beach;

  send (s, "Hello", 5, 0);

beach:
  if (s != -1)
    close (s);

}

#endif
