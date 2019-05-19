#define FRIDA_PRINTF_BUFFER_SIZE (512 * 1024)

#include <errno.h>
#include <gum/gum.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_XLOCALE_H
# include <xlocale.h>
#endif

#undef sprintf
#undef snprintf
#undef vsnprintf

static gboolean shim_deinitialized = FALSE;

void
frida_init_libc_shim (void)
{
}

void
frida_deinit_libc_shim (void)
{
  shim_deinitialized = TRUE;
}

#if !defined (HAVE_WINDOWS) && !defined (HAVE_ASAN)

void *
malloc (size_t size)
{
  g_assert (!shim_deinitialized);

  gum_memory_init ();

  return gum_malloc (size);
}

void *
calloc (size_t count, size_t size)
{
  g_assert (!shim_deinitialized);

  gum_memory_init ();

  return gum_calloc (count, size);
}

void *
realloc (void * ptr, size_t size)
{
  g_assert (!shim_deinitialized);

  gum_memory_init ();

  return gum_realloc (ptr, size);
}

int
posix_memalign (void ** memptr, size_t alignment, size_t size)
{
  gpointer result;

  g_assert (!shim_deinitialized);

  gum_memory_init ();

  result = gum_memalign (alignment, size);
  if (result == NULL)
    return ENOMEM;

  *memptr = result;
  return 0;
}

void
free (void * ptr)
{
  if (shim_deinitialized)
    return;

  gum_memory_init ();

  gum_free (ptr);
}

char *
strdup (const char * s)
{
  return g_strdup (s);
}

int
printf (const char * format, ...)
{
  int result;
  va_list args;
  gchar * message;

  va_start (args, format);
  result = gum_vasprintf (&message, format, args);
  va_end (args);

  fputs (message, stdout);

  g_free (message);

  return result;
}

int
fprintf (FILE * stream, const char * format, ...)
{
  int result;
  va_list args;
  gchar * message;

  va_start (args, format);
  result = gum_vasprintf (&message, format, args);
  va_end (args);

  fputs (message, stream);

  g_free (message);

  return result;
}

int
sprintf (char * string, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, FRIDA_PRINTF_BUFFER_SIZE, format, args);
  va_end (args);

  return result;
}

int
snprintf (char * string, size_t size, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

int
vprintf (const char * format, va_list args)
{
  int result;
  gchar * message;

  result = gum_vasprintf (&message, format, args);

  fputs (message, stdout);

  g_free (message);

  return result;
}

int
vfprintf (FILE * stream, const char * format, va_list args)
{
  int result;
  gchar * message;

  result = gum_vasprintf (&message, format, args);

  fputs (message, stream);

  g_free (message);

  return result;
}

int
vsnprintf (char * string, size_t size, const char * format, va_list args)
{
  return gum_vsnprintf (string, size, format, args);
}

int
__sprintf_chk (char * string, int flag, size_t size, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

int
__snprintf_chk (char * string, size_t size, int flags, size_t len, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

int
__vsnprintf_chk (char * string, size_t size, int flags, size_t len, const char * format, va_list args)
{
  return gum_vsnprintf (string, size, format, args);
}

#ifdef HAVE_XLOCALE_H

int
sprintf_l (char * string, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, FRIDA_PRINTF_BUFFER_SIZE, format, args);
  va_end (args);

  return result;
}

int
snprintf_l (char * string, size_t size, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

int
asprintf_l (char ** ret, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vasprintf (ret, format, args);
  va_end (args);

  return result;
}

#endif

#endif

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
  return -1;
}

int
res_9_ninit (res_9_state state)
{
  g_assert_not_reached ();
  return -1;
}

void
res_9_ndestroy (res_9_state state)
{
  g_assert_not_reached ();
}

int
res_9_nquery (res_9_state state, const char * dname, int klass, int type, u_char * answer, int anslen)
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

#ifdef HAVE_LINUX

G_GNUC_INTERNAL long
_frida_set_errno (int n)
{
  errno = n;

  return -1;
}

#endif
