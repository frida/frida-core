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

typedef enum _FridaShimState FridaShimState;

enum _FridaShimState
{
  FRIDA_SHIM_CREATED,
  FRIDA_SHIM_INITIALIZED,
  FRIDA_SHIM_DEINITIALIZED,
};

static FridaShimState shim_state = FRIDA_SHIM_CREATED;

void
frida_init_libc_shim (void)
{
  shim_state = FRIDA_SHIM_INITIALIZED;
}

void
frida_deinit_libc_shim (void)
{
  shim_state = FRIDA_SHIM_DEINITIALIZED;
}

#if !defined (HAVE_WINDOWS) && !defined (HAVE_ASAN)

/*
 * The thread-local storage emulation in libgcc results in three early
 * allocations, and unlike libc++ it does actually use this memory in
 * its destructor function after we have been deinitialized.
 *
 * We work around this by attempting to satisfy these tiny allocations
 * with a dumb fallback allocator.
 */

#define FRIDA_FIXED_BLOCK_CAPACITY (256 - sizeof (gboolean))

typedef struct _FridaFixedBlock FridaFixedBlock;

struct _FridaFixedBlock
{
  guint8 buf[FRIDA_FIXED_BLOCK_CAPACITY];
  gboolean in_use;
};

static FridaFixedBlock frida_fallback_blocks[8] __attribute__((aligned(16)));

__attribute__ ((constructor)) static void
frida_preinit_libc_shim (void)
{
  gum_memory_init ();
}

static gpointer
frida_fallback_allocator_request (gsize size)
{
  guint i;

  if (size > FRIDA_FIXED_BLOCK_CAPACITY)
    return NULL;

  for (i = 0; i != G_N_ELEMENTS (frida_fallback_blocks); i++)
  {
    FridaFixedBlock * block = &frida_fallback_blocks[i];

    if (!block->in_use)
    {
      block->in_use = TRUE;
      return block->buf;
    }
  }

  abort ();
}

static gboolean
frida_fallback_allocator_try_release (gpointer mem)
{
  FridaFixedBlock * block = mem;

  if (block == NULL)
    return TRUE;

  if (block < frida_fallback_blocks ||
      block >= frida_fallback_blocks + G_N_ELEMENTS (frida_fallback_blocks))
  {
    return FALSE;
  }

  memset (block, 0, sizeof (FridaFixedBlock));

  return TRUE;
}

void *
malloc (size_t size)
{
  void * result = NULL;

  if (shim_state == FRIDA_SHIM_CREATED)
    result = frida_fallback_allocator_request (size);

  if (result == NULL)
    result = gum_malloc (size);

  return result;
}

void *
calloc (size_t count, size_t size)
{
  void * result = NULL;

  if (shim_state == FRIDA_SHIM_CREATED)
    result = frida_fallback_allocator_request (count * size);

  if (result == NULL)
    result = gum_calloc (count, size);

  return result;
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
  if (frida_fallback_allocator_try_release (ptr))
    return;

  switch (shim_state)
  {
    case FRIDA_SHIM_CREATED:
    case FRIDA_SHIM_INITIALIZED:
      gum_free (ptr);
      break;
    case FRIDA_SHIM_DEINITIALIZED:
      /*
       * Memory has already been released. We assume that it is not touched after deinit.
       * This assumption needs to be re-verified whenever the toolchain changes significantly,
       * i.e. when libc++ internals change.
       */
      break;
  }
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
