#define FRIDA_PRINTF_BUFFER_SIZE (512 * 1024)
#define _GNU_SOURCE

#include <errno.h>
#include <gum/gum.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef HAVE_WINDOWS
# include <fcntl.h>
# include <unistd.h>
# include <sys/syscall.h>
#endif
#ifdef HAVE_LOCALE_H
# include <locale.h>
#endif
#ifdef HAVE_XLOCALE_H
# include <xlocale.h>
#endif

#undef memcpy
#undef sprintf
#undef snprintf
#undef vsnprintf
#undef stdin
#undef stdout
#undef stderr

#if defined (HAVE_WINDOWS) || defined (HAVE_ASAN)

void
frida_run_atexit_handlers (void)
{
}

# ifdef HAVE_ASAN

__attribute__ ((constructor)) static void
frida_libc_shim_init (void)
{
  asm volatile ("");
}

#  ifndef HAVE_DARWIN
__attribute__ ((destructor)) static void
frida_libc_shim_deinit (void)
{
  asm volatile ("");
}
#  endif

# endif

#else

#define FRIDA_SHIM_LOCK() gum_spinlock_acquire (&frida_shim_lock)
#define FRIDA_SHIM_UNLOCK() gum_spinlock_release (&frida_shim_lock)

#ifndef _IONBF
# define _IONBF 0
# define _IOFBF 1
# define _IOLBF 2
#endif

#ifndef O_DIRECTORY
# define O_DIRECTORY 0
#endif

#define FRIDA_FILE_MAGIC 0x46524944u /* 'FRID' */
#define FRIDA_DIR_MAGIC  0x46444952u /* 'FDIR' */

#define FRIDA_STDIO_BUFSIZE 4096
#define FRIDA_GETLINE_INITIAL_SIZE 128

typedef struct _FridaExitEntry FridaExitEntry;
typedef void (* FridaExitFunc) (gpointer user_data);

typedef struct _FridaFile FridaFile;
typedef struct _FridaFileHandle FridaFileHandle;
typedef struct _FridaDir FridaDir;

struct _FridaExitEntry
{
  FridaExitFunc func;
  gpointer user_data;
};

struct _FridaFile
{
  int fd;
  gboolean close_fd;

  int buf_mode;

  gboolean eof;
  int err;

  guint8 * rbuf;
  size_t rcap;
  size_t rpos;
  size_t rlen;

  guint8 * wbuf;
  size_t wcap;
  size_t wlen;

  int ungot;
  gboolean has_ungot;
};

struct _FridaFileHandle
{
  guint32 magic;
  FridaFile * impl;
};

struct _FridaDir
{
  guint32 magic;

  int fd;
  gboolean close_fd;

  guint8 * buf;
  size_t cap;
  size_t pos;
  size_t len;

  struct dirent cur;
};

static void frida_stdio_register_stream (FILE * stream);
static void frida_stdio_unregister_stream (FILE * stream);
static void frida_stdio_register_dir (DIR * dirp);
static void frida_stdio_unregister_dir (DIR * dirp);
static void frida_flush_all_streams (int * result);

static FridaFile * frida_file_get_impl (FILE * stream);
static void frida_file_bind_slot (FILE * slot, FridaFile * impl);
static FILE * frida_file_wrap (FridaFile * impl);
static void frida_file_unwrap (FILE * stream);

static FridaFile * frida_file_new (int fd, gboolean close_fd, int buf_mode);
static void frida_file_free (FridaFile * f);
static int frida_file_flush_write (FridaFile * f);
static ssize_t frida_file_fill_read (FridaFile * f);

static gboolean frida_parse_fopen_mode (const char * mode, int * oflags);

static int frida_write_formatted_to_fd (int fd, const char * format, va_list args);

static FridaDir * frida_dir_get_impl (DIR * dirp);
static DIR * frida_dir_wrap (FridaDir * impl);
static void frida_dir_free (FridaDir * d);

#if defined (SYS_getdents64)
static ssize_t frida_getdirents_nointr (int fd, void * buf, size_t size);
#elif defined (SYS_getdirentries64)
static ssize_t frida_getdirents_nointr (int fd, void * buf, size_t size);
#else
# error Unsupported platform: no getdents-style syscall available
#endif

static int frida_open_nointr (const char * pathname, int flags, mode_t mode);
static ssize_t frida_read_nointr (int fd, void * buf, size_t count);
static ssize_t frida_write_nointr (int fd, const void * buf, size_t count);
static int frida_close_nointr (int fd);
static off_t frida_lseek_nointr (int fd, off_t offset, int whence);

G_GNUC_INTERNAL FILE __sF[3];

G_GNUC_INTERNAL FILE * stdin = &__sF[0];
G_GNUC_INTERNAL FILE * stdout = &__sF[1];
G_GNUC_INTERNAL FILE * stderr = &__sF[2];

G_GNUC_INTERNAL FILE * __stdinp = &__sF[0];
G_GNUC_INTERNAL FILE * __stdoutp = &__sF[1];
G_GNUC_INTERNAL FILE * __stderrp = &__sF[2];

static gboolean frida_libc_shim_initialized = FALSE;

static FridaExitEntry * frida_atexit_entries = NULL;
static guint frida_atexit_count = 0;

static GumSpinlock frida_shim_lock = GUM_SPINLOCK_INIT;

G_LOCK_DEFINE_STATIC (frida_stdio);

static GHashTable * frida_streams = NULL;
static GHashTable * frida_dirs = NULL;

__attribute__ ((constructor)) static void
frida_libc_shim_init (void)
{
  FridaFile * f0, * f1, * f2;

  if (frida_libc_shim_initialized)
    return;

  gum_init_embedded ();

  f0 = NULL;
  f1 = NULL;
  f2 = NULL;

  G_LOCK (frida_stdio);

  frida_streams = g_hash_table_new (g_direct_hash, g_direct_equal);
  frida_dirs = g_hash_table_new (g_direct_hash, g_direct_equal);

  G_UNLOCK (frida_stdio);

  f0 = frida_file_new (0, FALSE, _IOFBF);
  frida_file_bind_slot (&__sF[0], f0);

  f1 = frida_file_new (1, FALSE, _IOLBF);
  frida_file_bind_slot (&__sF[1], f1);

  f2 = frida_file_new (2, FALSE, _IONBF);
  frida_file_bind_slot (&__sF[2], f2);

  frida_libc_shim_initialized = TRUE;
}

/*
 * Avoid destructors on i/macOS as modern toolchain versions now emit a
 * constructor per destructor, each calling __cxa_atexit().
 *
 * We want to make sure we release our heap as the very last thing we do,
 * so we shim __cxa_atexit() to make sure any destructors registered that
 * way will be run before we deallocate our internal heap.
 */

#ifdef HAVE_DARWIN
void
#else
__attribute__ ((destructor)) static void
#endif
frida_libc_shim_deinit (void)
{
  FridaFileHandle * sh;
  GHashTableIter iter;
  gpointer key;

  g_assert (frida_libc_shim_initialized);

  fflush (NULL);

  G_LOCK (frida_stdio);

  g_hash_table_iter_init (&iter, frida_streams);

  while (g_hash_table_iter_next (&iter, &key, NULL))
  {
    FILE * stream;
    FridaFile * f;
    int fd;

    stream = key;
    f = frida_file_get_impl (stream);
    fd = f->fd;

    frida_file_flush_write (f);

    if (f->close_fd)
      frida_close_nointr (fd);

    frida_file_free (f);
    frida_file_unwrap (stream);

    g_hash_table_iter_remove (&iter);
  }

  g_clear_pointer (&frida_streams, g_hash_table_unref);

  g_hash_table_iter_init (&iter, frida_dirs);

  while (g_hash_table_iter_next (&iter, &key, NULL))
  {
    DIR * dirp;
    FridaDir * d;
    int fd;

    dirp = key;
    d = frida_dir_get_impl (dirp);
    fd = d->fd;

    if (d->close_fd)
      frida_close_nointr (fd);

    frida_dir_free (d);

    g_hash_table_iter_remove (&iter);
  }

  g_clear_pointer (&frida_dirs, g_hash_table_unref);

  G_UNLOCK (frida_stdio);

  sh = (FridaFileHandle *) &__sF[0];
  g_clear_pointer (&sh->impl, frida_file_free);
  sh->magic = 0;

  sh = (FridaFileHandle *) &__sF[1];
  g_clear_pointer (&sh->impl, frida_file_free);
  sh->magic = 0;

  sh = (FridaFileHandle *) &__sF[2];
  g_clear_pointer (&sh->impl, frida_file_free);
  sh->magic = 0;

  gum_deinit_embedded ();
}

void
frida_run_atexit_handlers (void)
{
  gint i;

  for (i = (gint) frida_atexit_count - 1; i >= 0; i--)
  {
    const FridaExitEntry * entry = &frida_atexit_entries[i];

    entry->func (entry->user_data);
  }

  gum_free (frida_atexit_entries);
  frida_atexit_entries = 0;
  frida_atexit_count = 0;
}

G_GNUC_INTERNAL int
__cxa_atexit (void (* func) (void *), void * arg, void * dso_handle)
{
  FridaExitEntry * entry;

  frida_libc_shim_init ();

  FRIDA_SHIM_LOCK ();
  frida_atexit_count++;
  frida_atexit_entries = gum_realloc (frida_atexit_entries, frida_atexit_count * sizeof (FridaExitEntry));
  entry = &frida_atexit_entries[frida_atexit_count - 1];
  FRIDA_SHIM_UNLOCK ();

  entry->func = func;
  entry->user_data = arg;

  return 0;
}

#ifdef HAVE_DARWIN

G_GNUC_INTERNAL int
atexit (void (* func) (void))
{
  __cxa_atexit ((FridaExitFunc) func, NULL, NULL);

  return 0;
}

#endif

G_GNUC_INTERNAL void *
malloc (size_t size)
{
  return gum_malloc (size);
}

G_GNUC_INTERNAL void *
calloc (size_t count, size_t size)
{
  return gum_calloc (count, size);
}

G_GNUC_INTERNAL void *
realloc (void * ptr, size_t size)
{
  return gum_realloc (ptr, size);
}

G_GNUC_INTERNAL void *
memalign (size_t alignment, size_t size)
{
  return gum_memalign (alignment, size);
}

G_GNUC_INTERNAL int
posix_memalign (void ** memptr, size_t alignment, size_t size)
{
  gpointer result;

  result = gum_memalign (alignment, size);
  if (result == NULL)
    return ENOMEM;

  *memptr = result;
  return 0;
}

G_GNUC_INTERNAL void
free (void * ptr)
{
  gum_free (ptr);
}

G_GNUC_INTERNAL size_t
malloc_size (const void * ptr)
{
  return gum_malloc_usable_size (ptr);
}

G_GNUC_INTERNAL size_t
malloc_usable_size (const void * ptr)
{
  return gum_malloc_usable_size (ptr);
}

G_GNUC_INTERNAL void *
memcpy (void * dst, const void * src, size_t n)
{
  return gum_memcpy (dst, src, n);
}

G_GNUC_INTERNAL char *
strdup (const char * s)
{
  return g_strdup (s);
}

G_GNUC_INTERNAL int
printf (const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = frida_write_formatted_to_fd (1, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
fprintf (FILE * stream, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = frida_write_formatted_to_fd (frida_file_get_impl (stream)->fd, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
sprintf (char * string, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, FRIDA_PRINTF_BUFFER_SIZE, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
snprintf (char * string, size_t size, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
vprintf (const char * format, va_list args)
{
  return frida_write_formatted_to_fd (1, format, args);
}

G_GNUC_INTERNAL int
vfprintf (FILE * stream, const char * format, va_list args)
{
  return frida_write_formatted_to_fd (frida_file_get_impl (stream)->fd, format, args);
}

G_GNUC_INTERNAL int
vsnprintf (char * string, size_t size, const char * format, va_list args)
{
  return gum_vsnprintf (string, size, format, args);
}

G_GNUC_INTERNAL int
__sprintf_chk (char * string, int flag, size_t size, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
__snprintf_chk (char * string, size_t size, int flags, size_t len, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
__vsnprintf_chk (char * string, size_t size, int flags, size_t len, const char * format, va_list args)
{
  return gum_vsnprintf (string, size, format, args);
}

#ifdef HAVE_XLOCALE_H

G_GNUC_INTERNAL int
sprintf_l (char * string, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, FRIDA_PRINTF_BUFFER_SIZE, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
snprintf_l (char * string, size_t size, locale_t loc, const char * format, ...)
{
  int result;
  va_list args;

  va_start (args, format);
  result = gum_vsnprintf (string, size, format, args);
  va_end (args);

  return result;
}

G_GNUC_INTERNAL int
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

G_GNUC_INTERNAL FILE *
fopen (const char * pathname, const char * mode)
{
  FILE * result;
  int oflags, fd;
  FridaFile * impl;

  if (!frida_parse_fopen_mode (mode, &oflags))
    goto invalid_mode;

  fd = frida_open_nointr (pathname, oflags, 0666);
  if (fd == -1)
    return NULL;

  impl = frida_file_new (fd, TRUE, _IOFBF);

  result = frida_file_wrap (impl);
  frida_stdio_register_stream (result);

  return result;

invalid_mode:
  {
    errno = EINVAL;
    return NULL;
  }
}

G_GNUC_INTERNAL FILE *
fdopen (int fd, const char * mode)
{
  FILE * result;
  int oflags;
  FridaFile * impl;

  if (!frida_parse_fopen_mode (mode, &oflags))
    goto invalid_mode;

  impl = frida_file_new (fd, TRUE, _IOFBF);

  result = frida_file_wrap (impl);
  frida_stdio_register_stream (result);

  return result;

invalid_mode:
  {
    errno = EINVAL;
    return NULL;
  }
}

G_GNUC_INTERNAL int
fclose (FILE * stream)
{
  FridaFile * f;

  f = frida_file_get_impl (stream);

  fflush (stream);

  if (f->close_fd)
  {
    if (frida_close_nointr (f->fd) == -1)
      return EOF;
  }

  frida_stdio_unregister_stream (stream);

  frida_file_free (f);
  frida_file_unwrap (stream);

  return 0;
}

G_GNUC_INTERNAL int
setvbuf (FILE * stream, char * buf, int mode, size_t size)
{
  FridaFile * f;

  f = frida_file_get_impl (stream);

  if (mode != _IONBF && mode != _IOFBF && mode != _IOLBF)
    goto invalid_mode;

  if (fflush (stream) != 0)
    return -1;

  f->buf_mode = mode;

  if (mode == _IONBF)
  {
    g_clear_pointer (&f->rbuf, g_free);
    g_clear_pointer (&f->wbuf, g_free);

    f->rcap = 0;
    f->wcap = 0;
    f->rpos = 0;
    f->rlen = 0;
    f->wlen = 0;

    return 0;
  }

  if (size == 0)
    size = FRIDA_STDIO_BUFSIZE;

  f->rbuf = g_realloc (f->rbuf, size);
  f->wbuf = g_realloc (f->wbuf, size);

  f->rcap = size;
  f->wcap = size;
  f->rpos = 0;
  f->rlen = 0;
  f->wlen = 0;

  return 0;

invalid_mode:
  {
    errno = EINVAL;
    return -1;
  }
}

G_GNUC_INTERNAL int
fflush (FILE * stream)
{
  int result = 0;

  if (stream != NULL)
  {
    FridaFile * f = frida_file_get_impl (stream);

    if (frida_file_flush_write (f) != 0)
      result = EOF;

    return result;
  }

  {
    FridaFile * f0, * f1, * f2;

    f0 = frida_file_get_impl (&__sF[0]);
    f1 = frida_file_get_impl (&__sF[1]);
    f2 = frida_file_get_impl (&__sF[2]);

    if (frida_file_flush_write (f0) != 0)
      result = EOF;
    if (frida_file_flush_write (f1) != 0)
      result = EOF;
    if (frida_file_flush_write (f2) != 0)
      result = EOF;
  }

  frida_flush_all_streams (&result);

  return result;
}

G_GNUC_INTERNAL int
fileno (FILE * stream)
{
  return frida_file_get_impl (stream)->fd;
}

G_GNUC_INTERNAL int
feof (FILE * stream)
{
  return frida_file_get_impl (stream)->eof ? 1 : 0;
}

G_GNUC_INTERNAL int
ferror (FILE * stream)
{
  return (frida_file_get_impl (stream)->err != 0) ? 1 : 0;
}

G_GNUC_INTERNAL int
getc_unlocked (FILE * stream)
{
  int result = EOF;
  FridaFile * f;

  f = frida_file_get_impl (stream);

  if (f->has_ungot)
  {
    f->has_ungot = FALSE;
    result = f->ungot;
    goto beach;
  }

  if (f->buf_mode == _IONBF)
  {
    unsigned char ch;
    ssize_t n;

    n = frida_read_nointr (f->fd, &ch, 1);
    if (n == -1)
    {
      f->err = errno;
      goto beach;
    }

    if (n == 0)
    {
      f->eof = TRUE;
      goto beach;
    }

    result = ch;
    goto beach;
  }

  if (f->rpos == f->rlen)
  {
    if (frida_file_fill_read (f) == -1)
      goto beach;

    if (f->rlen == 0)
      goto beach;
  }

  result = f->rbuf[f->rpos++];

beach:
  return result;
}

G_GNUC_INTERNAL int
getc (FILE * stream)
{
  return getc_unlocked (stream);
}

G_GNUC_INTERNAL int
ungetc (int c, FILE * stream)
{
  int result = EOF;
  FridaFile * f;

  f = frida_file_get_impl (stream);

  if (c == EOF)
    goto beach;

  if (f->has_ungot)
    goto beach;

  f->ungot = c;
  f->has_ungot = TRUE;
  f->eof = FALSE;

  result = c;

beach:
  return result;
}

G_GNUC_INTERNAL size_t
fread (void * ptr, size_t size, size_t nmemb, FILE * stream)
{
  size_t result = 0;
  FridaFile * f;
  size_t want, got;
  guint8 * out;

  f = frida_file_get_impl (stream);

  if (size == 0 || nmemb == 0)
    goto beach;

  want = size * nmemb;
  got = 0;
  out = ptr;

  while (got != want)
  {
    if (f->has_ungot)
    {
      out[got++] = (guint8) f->ungot;
      f->has_ungot = FALSE;
      continue;
    }

    if (f->buf_mode == _IONBF)
    {
      ssize_t n;

      n = frida_read_nointr (f->fd, out + got, want - got);
      if (n == -1)
      {
        f->err = errno;
        break;
      }

      if (n == 0)
      {
        f->eof = TRUE;
        break;
      }

      got += n;
      continue;
    }

    if (f->rpos == f->rlen)
    {
      if (frida_file_fill_read (f) == -1)
        break;

      if (f->rlen == 0)
        break;
    }

    {
      size_t avail, take;

      avail = f->rlen - f->rpos;
      take = (want - got < avail) ? (want - got) : avail;

      memcpy (out + got, f->rbuf + f->rpos, take);

      f->rpos += take;
      got += take;
    }
  }

  result = got / size;

beach:
  return result;
}

G_GNUC_INTERNAL size_t
fwrite (const void * ptr, size_t size, size_t nmemb, FILE * stream)
{
  size_t result = 0;
  FridaFile * f;
  size_t total, off;
  const guint8 * in;

  f = frida_file_get_impl (stream);

  if (size == 0 || nmemb == 0)
    goto beach;

  total = size * nmemb;
  off = 0;
  in = ptr;

  if (f->buf_mode == _IONBF)
  {
    while (off != total)
    {
      ssize_t n;

      n = frida_write_nointr (f->fd, in + off, total - off);
      if (n == -1)
      {
        f->err = errno;
        break;
      }

      off += n;
    }

    result = off / size;
    goto beach;
  }

  while (off != total)
  {
    size_t space, take;

    space = (f->wcap > f->wlen) ? (f->wcap - f->wlen) : 0;

    if (space == 0)
    {
      if (frida_file_flush_write (f) != 0)
        break;

      space = f->wcap;
    }

    take = (total - off < space) ? (total - off) : space;

    memcpy (f->wbuf + f->wlen, in + off, take);

    f->wlen += take;
    off += take;

    if (f->buf_mode == _IOLBF)
    {
      if (memchr (in + (off - take), '\n', take) != NULL)
      {
        if (frida_file_flush_write (f) != 0)
          break;
      }
    }
  }

  result = off / size;

beach:
  return result;
}

G_GNUC_INTERNAL int
fputc (int c, FILE * stream)
{
  unsigned char ch;
  size_t n;

  ch = c;

  n = fwrite (&ch, 1, 1, stream);
  if (n != 1)
    return EOF;

  return ch;
}

G_GNUC_INTERNAL int
fputs (const char * s, FILE * stream)
{
  size_t len, n;

  len = strlen (s);

  n = fwrite (s, 1, len, stream);
  if (n != len)
    return EOF;

  return len;
}

G_GNUC_INTERNAL char *
fgets (char * s, int size, FILE * stream)
{
  int i = 0;

  if (size <= 0)
    return NULL;

  while (i < size - 1)
  {
    int c;

    c = getc_unlocked (stream);
    if (c == EOF)
      break;

    s[i++] = c;

    if (c == '\n')
      break;
  }

  if (i == 0)
    return NULL;

  s[i] = '\0';

  return s;
}

G_GNUC_INTERNAL int
fseek (FILE * stream, long offset, int whence)
{
  FridaFile * f;
  off_t r;

  f = frida_file_get_impl (stream);

  if (fflush (stream) != 0)
    return -1;

  f->rpos = 0;
  f->rlen = 0;
  f->has_ungot = FALSE;
  f->eof = FALSE;

  r = frida_lseek_nointr (f->fd, (off_t) offset, whence);
  if (r == (off_t) -1)
  {
    f->err = errno;
    return -1;
  }

  return 0;
}

G_GNUC_INTERNAL long
ftell (FILE * stream)
{
  FridaFile * f;
  off_t pos;

  f = frida_file_get_impl (stream);

  pos = frida_lseek_nointr (f->fd, 0, SEEK_CUR);
  if (pos == (off_t) -1)
  {
    f->err = errno;
    return -1;
  }

  if (f->buf_mode != _IONBF)
    pos -= (off_t) (f->rlen - f->rpos);

  if (f->has_ungot)
    pos -= 1;

  return (long) pos;
}

G_GNUC_INTERNAL void
rewind (FILE * stream)
{
  FridaFile * f;

  fseek (stream, 0, SEEK_SET);

  f = frida_file_get_impl (stream);
  f->err = 0;
  f->eof = FALSE;
}

G_GNUC_INTERNAL ssize_t
getdelim (char ** lineptr, size_t * n, int delimiter, FILE * stream)
{
  size_t len;

  if (lineptr == NULL || n == NULL)
    goto invalid_args;

  if (*lineptr == NULL || *n == 0)
  {
    *n = FRIDA_GETLINE_INITIAL_SIZE;
    *lineptr = g_realloc (*lineptr, *n);
  }

  len = 0;

  while (TRUE)
  {
    int c;

    c = getc_unlocked (stream);
    if (c == EOF)
    {
      if (len == 0)
        return -1;

      break;
    }

    if (len + 2 > *n)
    {
      size_t new_n;

      new_n = (*n) * 2;
      if (new_n < len + 2)
        new_n = len + 2;

      *lineptr = g_realloc (*lineptr, new_n);
      *n = new_n;
    }

    (*lineptr)[len++] = (char) c;

    if (c == delimiter)
      break;
  }

  (*lineptr)[len] = '\0';

  return len;

invalid_args:
  {
    errno = EINVAL;
    return -1;
  }
}

G_GNUC_INTERNAL ssize_t
getline (char ** lineptr, size_t * n, FILE * stream)
{
  return getdelim (lineptr, n, '\n', stream);
}

G_GNUC_INTERNAL FILE *
tmpfile (void)
{
  FILE * result;
  int fd;
  gchar * path;
  FridaFile * impl;

  fd = g_file_open_tmp ("frida-XXXXXX", &path, NULL);
  if (fd == -1)
    return NULL;

  (void) unlink (path);

  g_free (path);

  impl = frida_file_new (fd, TRUE, _IOFBF);

  result = frida_file_wrap (impl);
  frida_stdio_register_stream (result);

  return result;
}

G_GNUC_INTERNAL int
putchar (int c)
{
  unsigned char ch = c;
  ssize_t n;

  n = frida_write_nointr (1, &ch, 1);
  if (n != 1)
    return EOF;

  return ch;
}

G_GNUC_INTERNAL int
puts (const char * s)
{
  size_t len;
  ssize_t n;

  len = strlen (s);

  n = frida_write_nointr (1, s, len);
  if (n != (ssize_t) len)
    return EOF;

  n = frida_write_nointr (1, "\n", 1);
  if (n != 1)
    return EOF;

  return 1;
}

G_GNUC_INTERNAL DIR *
opendir (const char * name)
{
  DIR * result;
  int fd;
  FridaDir * d;

  fd = frida_open_nointr (name, O_RDONLY | O_DIRECTORY, 0);
  if (fd == -1)
    return NULL;

  d = g_new0 (FridaDir, 1);
  d->magic = FRIDA_DIR_MAGIC;
  d->fd = fd;
  d->close_fd = TRUE;
  d->cap = FRIDA_STDIO_BUFSIZE;
  d->buf = g_realloc (d->buf, d->cap);

  result = frida_dir_wrap (d);
  frida_stdio_register_dir (result);

  return result;
}

G_GNUC_INTERNAL DIR *
fdopendir (int fd)
{
  DIR * result;
  FridaDir * d;

  d = g_new0 (FridaDir, 1);
  d->magic = FRIDA_DIR_MAGIC;
  d->fd = fd;
  d->close_fd = TRUE;
  d->cap = FRIDA_STDIO_BUFSIZE;
  d->buf = g_realloc (d->buf, d->cap);

  result = frida_dir_wrap (d);
  frida_stdio_register_dir (result);

  return result;
}

G_GNUC_INTERNAL int
closedir (DIR * dirp)
{
  FridaDir * d;

  d = frida_dir_get_impl (dirp);

  if (d->close_fd)
  {
    if (frida_close_nointr (d->fd) == -1)
      return -1;
  }

  frida_stdio_unregister_dir (dirp);

  frida_dir_free (d);

  return 0;
}

G_GNUC_INTERNAL struct dirent *
readdir (DIR * dirp)
{
  FridaDir * d;

  d = frida_dir_get_impl (dirp);

  while (TRUE)
  {
    if (d->pos >= d->len)
    {
      ssize_t n;

      d->pos = 0;
      d->len = 0;

      n = frida_getdirents_nointr (d->fd, d->buf, d->cap);
      if (n == -1)
        return NULL;

      if (n == 0)
        return NULL;

      d->len = n;
    }

#if defined (SYS_getdents64)
    {
      struct linux_dirent64
      {
        guint64 d_ino;
        gint64  d_off;
        guint16 d_reclen;
        guint8  d_type;
        char    d_name[];
      };
      struct linux_dirent64 * e;
      size_t name_len;

      e = (struct linux_dirent64 *) (d->buf + d->pos);
      d->pos += e->d_reclen;

      memset (&d->cur, 0, sizeof (d->cur));

      d->cur.d_ino = (ino_t) e->d_ino;
# ifdef _DIRENT_HAVE_D_TYPE
      d->cur.d_type = e->d_type;
# endif

      name_len = strnlen (e->d_name, sizeof (d->cur.d_name) - 1);
      memcpy (d->cur.d_name, e->d_name, name_len);
      d->cur.d_name[name_len] = '\0';

      return &d->cur;
    }
#else
    {
      struct dirent * e;
      size_t reclen;

      e = (struct dirent *) (d->buf + d->pos);
      reclen = e->d_reclen;

      if (reclen == 0)
        return NULL;

      d->pos += reclen;

      memcpy (&d->cur, e, sizeof (struct dirent));

      return &d->cur;
    }
#endif
  }
}

static void
frida_stdio_register_stream (FILE * stream)
{
  G_LOCK (frida_stdio);

  g_hash_table_add (frida_streams, stream);

  G_UNLOCK (frida_stdio);
}

static void
frida_stdio_unregister_stream (FILE * stream)
{
  G_LOCK (frida_stdio);

  g_hash_table_remove (frida_streams, stream);

  G_UNLOCK (frida_stdio);
}

static void
frida_stdio_register_dir (DIR * dirp)
{
  G_LOCK (frida_stdio);

  g_hash_table_add (frida_dirs, dirp);

  G_UNLOCK (frida_stdio);
}

static void
frida_stdio_unregister_dir (DIR * dirp)
{
  G_LOCK (frida_stdio);

  g_hash_table_remove (frida_dirs, dirp);

  G_UNLOCK (frida_stdio);
}

static void
frida_flush_all_streams (int * result)
{
  GHashTableIter iter;
  gpointer key;

  G_LOCK (frida_stdio);

  g_hash_table_iter_init (&iter, frida_streams);

  while (g_hash_table_iter_next (&iter, &key, NULL))
  {
    FILE * s = key;
    FridaFile * f;

    f = frida_file_get_impl (s);

    if (frida_file_flush_write (f) != 0)
      *result = EOF;
  }

  G_UNLOCK (frida_stdio);
}

static FridaFile *
frida_file_get_impl (FILE * stream)
{
  FridaFileHandle * h;

  g_assert (stream != NULL);

  h = (FridaFileHandle *) stream;

  g_assert (h->magic == FRIDA_FILE_MAGIC);
  g_assert (h->impl != NULL);

  return h->impl;
}

static void
frida_file_bind_slot (FILE * slot, FridaFile * impl)
{
  FridaFileHandle * h;

  g_assert (slot != NULL);
  g_assert (impl != NULL);
  g_assert (sizeof (FILE) >= sizeof (FridaFileHandle));

  h = (FridaFileHandle *) slot;

  h->magic = FRIDA_FILE_MAGIC;
  h->impl = impl;
}

static FILE *
frida_file_wrap (FridaFile * impl)
{
  FILE * stream;
  FridaFileHandle * h;

  g_assert (impl != NULL);
  g_assert (sizeof (FILE) >= sizeof (FridaFileHandle));

  stream = g_new0 (FILE, 1);

  h = (FridaFileHandle *) stream;
  h->magic = FRIDA_FILE_MAGIC;
  h->impl = impl;

  return stream;
}

static void
frida_file_unwrap (FILE * stream)
{
  FridaFileHandle * h;

  g_assert (stream != NULL);

  h = (FridaFileHandle *) stream;

  g_assert (h->magic == FRIDA_FILE_MAGIC);

  h->magic = 0;
  h->impl = NULL;

  g_free (stream);
}

static FridaFile *
frida_file_new (int fd, gboolean close_fd, int buf_mode)
{
  FridaFile * f;

  f = g_new0 (FridaFile, 1);

  f->fd = fd;
  f->close_fd = close_fd;
  f->buf_mode = buf_mode;

  if (buf_mode != _IONBF)
  {
    f->rcap = FRIDA_STDIO_BUFSIZE;
    f->wcap = FRIDA_STDIO_BUFSIZE;

    f->rbuf = g_realloc (f->rbuf, f->rcap);
    f->wbuf = g_realloc (f->wbuf, f->wcap);
  }

  return f;
}

static void
frida_file_free (FridaFile * f)
{
  if (f == NULL)
    return;

  g_clear_pointer (&f->rbuf, g_free);
  g_clear_pointer (&f->wbuf, g_free);

  g_free (f);
}

static int
frida_file_flush_write (FridaFile * f)
{
  size_t off = 0;

  while (off < f->wlen)
  {
    ssize_t n;

    n = frida_write_nointr (f->fd, f->wbuf + off, f->wlen - off);
    if (n == -1)
      goto io_failed;

    off += n;
  }

  f->wlen = 0;

  return 0;

io_failed:
  {
    f->err = errno;
    return -1;
  }
}

static ssize_t
frida_file_fill_read (FridaFile * f)
{
  ssize_t n;

  f->rpos = 0;
  f->rlen = 0;

  if (f->buf_mode == _IONBF)
    return 0;

  n = frida_read_nointr (f->fd, f->rbuf, f->rcap);
  if (n == -1)
    goto io_failed;

  if (n == 0)
  {
    f->eof = TRUE;
    return 0;
  }

  f->rlen = (size_t) n;

  return n;

io_failed:
  {
    f->err = errno;
    return -1;
  }
}

static gboolean
frida_parse_fopen_mode (const char * mode, int * oflags)
{
  char c0;
  gboolean plus;

  c0 = mode[0];
  plus = (strchr (mode, '+') != NULL);

  if (c0 == 'r')
  {
    *oflags = plus ? O_RDWR : O_RDONLY;
    return TRUE;
  }

  if (c0 == 'w')
  {
    *oflags = (plus ? O_RDWR : O_WRONLY) | O_CREAT | O_TRUNC;
    return TRUE;
  }

  if (c0 == 'a')
  {
    *oflags = (plus ? O_RDWR : O_WRONLY) | O_CREAT | O_APPEND;
    return TRUE;
  }

  return FALSE;
}

static int
frida_write_formatted_to_fd (int fd, const char * format, va_list args)
{
  int result = 0;
  gchar * message;
  size_t len, off;

  gum_vasprintf (&message, format, args);

  len = strlen (message);
  off = 0;

  while (off < len)
  {
    ssize_t n;

    n = frida_write_nointr (fd, message + off, len - off);
    if (n == -1)
      goto io_failed;

    off += n;
  }

  goto beach;

io_failed:
  {
    result = -1;
    goto beach;
  }
beach:
  {
    g_free (message);

    return result;
  }
}

static FridaDir *
frida_dir_get_impl (DIR * dirp)
{
  FridaDir * d;

  g_assert (dirp != NULL);

  d = (FridaDir *) dirp;

  g_assert (d->magic == FRIDA_DIR_MAGIC);

  return d;
}

static DIR *
frida_dir_wrap (FridaDir * impl)
{
  g_assert (impl != NULL);
  g_assert (impl->magic == FRIDA_DIR_MAGIC);

  return (DIR *) impl;
}

static void
frida_dir_free (FridaDir * d)
{
  if (d == NULL)
    return;

  g_assert (d->magic == FRIDA_DIR_MAGIC);

  d->magic = 0;

  g_clear_pointer (&d->buf, g_free);

  g_free (d);
}

static int
frida_open_nointr (const char * pathname, int flags, mode_t mode)
{
  while (TRUE)
  {
    int fd;

    if ((flags & O_CREAT) != 0)
      fd = open (pathname, flags, mode);
    else
      fd = open (pathname, flags);

    if (fd != -1)
      return fd;

    if (errno == EINTR)
      continue;

    return -1;
  }
}

static ssize_t
frida_read_nointr (int fd, void * buf, size_t count)
{
  while (TRUE)
  {
    ssize_t n;

    n = read (fd, buf, count);
    if (n != -1)
      return n;

    if (errno == EINTR)
      continue;

    return -1;
  }
}

static ssize_t
frida_write_nointr (int fd, const void * buf, size_t count)
{
  while (TRUE)
  {
    ssize_t n;

    n = write (fd, buf, count);
    if (n != -1)
      return n;

    if (errno == EINTR)
      continue;

    return -1;
  }
}

static int
frida_close_nointr (int fd)
{
  while (TRUE)
  {
    int r;

    r = close (fd);
    if (r != -1)
      return 0;

    if (errno == EINTR)
      continue;

    return -1;
  }
}

static off_t
frida_lseek_nointr (int fd, off_t offset, int whence)
{
  while (TRUE)
  {
    off_t r;

    r = lseek (fd, offset, whence);
    if (r != (off_t) -1)
      return r;

    if (errno == EINTR)
      continue;

    return -1;
  }
}

#if defined (SYS_getdents64)
static ssize_t
frida_getdirents_nointr (int fd, void * buf, size_t size)
{
  while (TRUE)
  {
    ssize_t n;

    n = (ssize_t) syscall (SYS_getdents64, fd, buf, size);
    if (n != -1)
      return n;

    if (errno == EINTR)
      continue;

    return -1;
  }
}
#elif defined (SYS_getdirentries64)
static ssize_t
frida_getdirents_nointr (int fd, void * buf, size_t size)
{
  while (TRUE)
  {
    ssize_t n;

    n = (ssize_t) syscall (SYS_getdirentries64, fd, buf, size, &basep);
    if (n != -1)
      return n;

    if (errno == EINTR)
      continue;

    return -1;
  }
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

G_GNUC_INTERNAL int
res_9_init (void)
{
  g_assert_not_reached ();
  return -1;
}

G_GNUC_INTERNAL int
res_9_ninit (res_9_state state)
{
  g_assert_not_reached ();
  return -1;
}

G_GNUC_INTERNAL void
res_9_ndestroy (res_9_state state)
{
  g_assert_not_reached ();
}

G_GNUC_INTERNAL int
res_9_nquery (res_9_state state, const char * dname, int klass, int type, u_char * answer, int anslen)
{
  g_assert_not_reached ();
  return -1;
}

G_GNUC_INTERNAL int
res_9_dn_expand (const u_char * msg, const u_char * eomorig, const u_char * comp_dn, char * exp_dn, int length)
{
  g_assert_not_reached ();
  return -1;
}

#endif

#ifdef HAVE_LINUX

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_dup3
# if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
#  define __NR_dup3 330
# elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
#  define __NR_dup3 292
# elif defined (HAVE_ARM)
#  define __NR_dup3 (__NR_SYSCALL_BASE + 358)
# elif defined (HAVE_MIPS)
#  if _MIPS_SIM == _MIPS_SIM_ABI32
#   define __NR_dup3 4327
#  elif _MIPS_SIM == _MIPS_SIM_ABI64
#   define __NR_dup3 5286
#  elif _MIPS_SIM == _MIPS_SIM_NABI32
#   define __NR_dup3 6290
#  else
#   error Unexpected MIPS ABI
#  endif
# elif defined (HAVE_RISCV)
#  if GLIB_SIZEOF_VOID_P == 8
#   define __NR_dup3 24
#  else
#   error RISC-V 32-bit not yet supported
#  endif
# endif
#endif

int dup3 (int old_fd, int new_fd, int flags);

G_GNUC_INTERNAL int
dup (int old_fd)
{
  return syscall (__NR_dup, old_fd);
}

G_GNUC_INTERNAL int
dup2 (int old_fd, int new_fd)
{
  if (new_fd == old_fd)
  {
    if (fcntl (new_fd, F_GETFD) == -1)
      return -1;
    return new_fd;
  }

  return dup3 (old_fd, new_fd, 0);
}

G_GNUC_INTERNAL int
dup3 (int old_fd, int new_fd, int flags)
{
  return syscall (__NR_dup3, old_fd, new_fd, flags);
}

G_GNUC_INTERNAL long
_frida_set_errno (int n)
{
  errno = n;

  return -1;
}

#endif

#if defined (HAVE_DARWIN) && GLIB_SIZEOF_VOID_P == 8

# undef read
# undef write
# undef mmap
# undef munmap

ssize_t
read (int fildes, void * buf, size_t nbyte)
{
  ssize_t result;

# ifdef HAVE_I386
  register          gint rdi asm ("rdi") = fildes;
  register gconstpointer rsi asm ("rsi") = buf;
  register         gsize rdx asm ("rdx") = nbyte;
  register         guint eax asm ("eax") = 0x2000003;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (rdx),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 2\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x16, [sp, #16 * 1]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x16, 0x3\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x16, [sp, #16 * 1]\n\t"
      "add sp, sp, #16 * 2\n\t"
      : "=r" (result)
      : "r" ((gsize) fildes),
        "r" (buf),
        "r" (nbyte)
      : "x0", "x1", "x2", "x16"
  );
# endif

  return result;
}

ssize_t
write (int fildes, const void * buf, size_t nbyte)
{
  ssize_t result;

# ifdef HAVE_I386
  register          gint rdi asm ("rdi") = fildes;
  register gconstpointer rsi asm ("rsi") = buf;
  register         gsize rdx asm ("rdx") = nbyte;
  register         guint eax asm ("eax") = 0x2000004;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (rdx),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 2\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x16, [sp, #16 * 1]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x16, 0x4\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x16, [sp, #16 * 1]\n\t"
      "add sp, sp, #16 * 2\n\t"
      : "=r" (result)
      : "r" ((gsize) fildes),
        "r" (buf),
        "r" (nbyte)
      : "x0", "x1", "x2", "x16"
  );
# endif

  return result;
}

void *
mmap (void * addr, size_t len, int prot, int flags, int fd, off_t offset)
{
  void * result;

# ifdef HAVE_I386
  register      gpointer rdi asm ("rdi") = addr;
  register         gsize rsi asm ("rsi") = len;
  register         gsize rdx asm ("rdx") = (gsize) prot;
  register         gsize r10 asm ("r10") = (gsize) flags;
  register         gsize  r8 asm ( "r8") = (gsize) fd;
  register         gsize  r9 asm ( "r9") = offset;
  register         guint eax asm ("eax") = 0x20000c5;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (rdx),
        "r" (r10),
        "r" (r8),
        "r" (r9),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 4\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x3, [sp, #16 * 1]\n\t"
      "stp x4, x5, [sp, #16 * 2]\n\t"
      "str x16, [sp, #16 * 3]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x3, %4\n\t"
      "mov x4, %5\n\t"
      "mov x5, %6\n\t"
      "mov x16, 0xc5\n\t"
      "svc 0x80\n\t"
      "mov %0, x0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x3, [sp, #16 * 1]\n\t"
      "ldp x4, x5, [sp, #16 * 2]\n\t"
      "ldr x16, [sp, #16 * 3]\n\t"
      "add sp, sp, #16 * 4\n\t"
      : "=r" (result)
      : "r" (addr),
        "r" (len),
        "r" ((gsize) prot),
        "r" ((gsize) flags),
        "r" ((gsize) fd),
        "r" (offset)
      : "x0", "x1", "x2", "x3", "x4", "x5", "x16"
  );
# endif

  return result;
}

int
munmap (void * addr, size_t len)
{
  int result;

# ifdef HAVE_I386
  register      gpointer rdi asm ("rdi") = addr;
  register         gsize rsi asm ("rsi") = len;
  register         guint eax asm ("eax") = 0x2000049;

  asm volatile (
      "syscall\n\t"
      : "=a" (result)
      : "r" (rdi),
        "r" (rsi),
        "r" (eax)
      : "rcx", "r11", "cc", "memory"
  );
# else
  asm volatile (
      "sub sp, sp, #16 * 2\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "str x16, [sp, #16 * 1]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x16, 0x49\n\t"
      "svc 0x80\n\t"
      "mov %w0, w0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldr x16, [sp, #16 * 1]\n\t"
      "add sp, sp, #16 * 2\n\t"
      : "=r" (result)
      : "r" (addr),
        "r" (len)
      : "x0", "x1", "x16"
  );
# endif

  return result;
}

#endif
