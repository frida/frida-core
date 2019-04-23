#include <gum/gum.h>
#include <new>

void *
operator new (std::size_t n)
{
  return gum_malloc (n);
}

void
operator delete (void * p)
{
  gum_free (p);
}
