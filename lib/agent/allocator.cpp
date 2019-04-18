#include <gum/gum.h>
#include <new>

void *
operator new (std::size_t n) throw (std::bad_alloc)
{
  return gum_malloc (n);
}

void
operator delete (void * p) throw ()
{
  gum_free (p);
}
