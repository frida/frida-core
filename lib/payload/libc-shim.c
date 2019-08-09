#define FRIDA_PRINTF_BUFFER_SIZE (512 * 1024)

#include <errno.h>
#include <gum/gum.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_XLOCALE_H
# include <xlocale.h>
#endif

#undef memcpy
#undef sprintf
#undef snprintf
#undef vsnprintf

#if defined (HAVE_WINDOWS) || defined (HAVE_ASAN)

void
frida_run_atexit_handlers (void)
{
}

#else

#define FRIDA_SHIM_LOCK() gum_spinlock_acquire (&shim_lock)
#define FRIDA_SHIM_UNLOCK() gum_spinlock_release (&shim_lock)

typedef struct _FridaExitEntry FridaExitEntry;
typedef void (* FridaExitFunc) (gpointer user_data);

struct _FridaExitEntry
{
  FridaExitFunc func;
  gpointer user_data;
};

static FridaExitEntry * atexit_entries = NULL;
static guint atexit_count = 0;

static GumSpinlock shim_lock = GUM_SPINLOCK_INIT;

__attribute__ ((constructor)) static void
frida_init_memory (void)
{
  gum_internal_heap_ref ();
}

/*
 * Avoid destructors on i/macOS as modern toolchain versions now emit a
 * constructor per destructor, each calling __cxa_atexit().
 *
 * We want to make sure we release our heap as the very last thing we do,
 * so we shim __cxa_atexit() to make sure any destructors registered that
 * way will be run before we deallocate our internal heap.
 */

#ifndef HAVE_DARWIN

__attribute__ ((destructor)) static void
frida_deinit_memory (void)
{
  gum_internal_heap_unref ();
}

#endif

void
frida_run_atexit_handlers (void)
{
  gint i;

  for (i = (gint) atexit_count - 1; i >= 0; i--)
  {
    const FridaExitEntry * entry = &atexit_entries[i];

    entry->func (entry->user_data);
  }

  gum_free (atexit_entries);
  atexit_entries = 0;
  atexit_count = 0;
}

int
__cxa_atexit (void (* func) (void *), void * arg, void * dso_handle)
{
  FridaExitEntry * entry;

  FRIDA_SHIM_LOCK ();
  atexit_count++;
  atexit_entries = gum_realloc (atexit_entries, atexit_count * sizeof (FridaExitEntry));
  entry = &atexit_entries[atexit_count - 1];
  FRIDA_SHIM_UNLOCK ();

  entry->func = func;
  entry->user_data = arg;

  return 0;
}

#ifdef HAVE_DARWIN

int
atexit (void (* func) (void))
{
  __cxa_atexit ((FridaExitFunc) func, NULL, NULL);

  return 0;
}

#endif

void *
malloc (size_t size)
{
  return gum_malloc (size);
}

void *
calloc (size_t count, size_t size)
{
  return gum_calloc (count, size);
}

void *
realloc (void * ptr, size_t size)
{
  return gum_realloc (ptr, size);
}

int
posix_memalign (void ** memptr, size_t alignment, size_t size)
{
  gpointer result;

  result = gum_memalign (alignment, size);
  if (result == NULL)
    return ENOMEM;

  *memptr = result;
  return 0;
}

void
free (void * ptr)
{
  gum_free (ptr);
}

void *
memcpy (void * dst, const void * src, size_t n)
{
  return gum_memcpy (dst, src, n);
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
