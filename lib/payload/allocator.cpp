#ifndef HAVE_WINDOWS

#include <gum/gum.h>
#include <new>

void *
operator new (std::size_t size)
{
  return gum_malloc (size);
}

void
operator delete (void * mem) noexcept
{
  gum_free (mem);
}

#endif
