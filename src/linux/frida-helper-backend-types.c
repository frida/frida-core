#include "frida-helper-backend.h"
#include "helpers/inject-context.h"

#include <sys/user.h>

G_STATIC_ASSERT (sizeof (FridaHelperBootstrapContext) == sizeof (FridaBootstrapContext));
G_STATIC_ASSERT (sizeof (FridaHelperLoaderContext) == sizeof (FridaLoaderContext));
G_STATIC_ASSERT (sizeof (FridaHelperLibcApi) == sizeof (FridaLibcApi));
G_STATIC_ASSERT (sizeof (FridaHelperByeMessage) == sizeof (FridaByeMessage));
#if defined (HAVE_I386)
G_STATIC_ASSERT (sizeof (FridaGPRegs) == sizeof (struct user_regs_struct));
G_STATIC_ASSERT (sizeof (FridaFPRegs) == sizeof (struct user_fpregs_struct));
#elif defined (HAVE_ARM64)
G_STATIC_ASSERT (sizeof (FridaGPRegs) == sizeof (struct user_regs_struct));
G_STATIC_ASSERT (sizeof (FridaFPRegs) == sizeof (struct user_fpsimd_struct));
#elif !defined (HAVE_MIPS)
G_STATIC_ASSERT (sizeof (FridaGPRegs) == sizeof (struct user_regs));
G_STATIC_ASSERT (sizeof (FridaFPRegs) == sizeof (struct user_fpregs));
#endif
