#if defined (_MSC_VER) || defined (HAVE_LINUX)

#include <glib.h>

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
# ifdef _MSC_VER
#  define FRIDA_CGO_INIT_FUNC st0_386_windows_lib
# else
#  define FRIDA_CGO_INIT_FUNC _st0_386_linux_lib
# endif
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# ifdef _MSC_VER
#  define FRIDA_CGO_INIT_FUNC _st0_amd64_windows_lib
# else
#  define FRIDA_CGO_INIT_FUNC _st0_amd64_linux_lib
# endif
#elif defined (HAVE_ARM)
# ifdef _MSC_VER
#  define FRIDA_CGO_INIT_FUNC _st0_arm_windows_lib
# else
#  define FRIDA_CGO_INIT_FUNC _st0_arm_linux_lib
# endif
#elif defined (HAVE_ARM64)
# ifdef _MSC_VER
#  define FRIDA_CGO_INIT_FUNC _st0_arm64_windows_lib
# else
#  define FRIDA_CGO_INIT_FUNC _st0_arm64_linux_lib
# endif
#endif

extern void FRIDA_CGO_INIT_FUNC (int argc, char ** argv);

void
_frida_compiler_backend_init_go_runtime (void)
{
  static char * fake_argv[] = { NULL };
  FRIDA_CGO_INIT_FUNC (0, fake_argv);
}

#else

void
_frida_compiler_backend_init_go_runtime (void)
{
}

#endif
