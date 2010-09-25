#include <glib-object.h>
#include <gum/gum.h>

#ifdef G_OS_WIN32

#define VC_EXTRALEAN
#include <windows.h>

static void on_load (void);

BOOL APIENTRY
DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  (void) hModule;
  (void) ul_reason_for_call;
  (void) lpReserved;

  if (ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    on_load ();
  }

  return TRUE;
}

#endif

#ifdef __GNUC__
__attribute__ ((constructor))
#endif
static void
on_load (void)
{
  g_type_init ();
  gum_init_with_features (GUM_FEATURE_ALL & ~GUM_FEATURE_SYMBOL_LOOKUP);
}
