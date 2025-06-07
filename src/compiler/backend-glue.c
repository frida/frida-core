#ifdef _MSC_VER

#include <glib.h>

#ifdef HAVE_ARM64
# define FRIDA_CGO_INIT_FUNC _st0_arm64_windows_lib
#elif GLIB_SIZEOF_VOID_P == 8
# define FRIDA_CGO_INIT_FUNC _st0_amd64_windows_lib
#else
# define FRIDA_CGO_INIT_FUNC st0_386_windows_lib
#endif

extern void FRIDA_CGO_INIT_FUNC ();

void
frida_compiler_backend_init (void)
{
  FRIDA_CGO_INIT_FUNC ();
}

#else

void
frida_compiler_backend_init (void)
{
}

#endif
