#include <glib-object.h>
#include <gio/gio.h>
#include <gum/gum.h>

#ifdef G_OS_WIN32

#define VC_EXTRALEAN
#include <windows.h>

static void on_load (void);
static void on_unload (void);

BOOL APIENTRY
DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  (void) hModule;
  (void) ul_reason_for_call;
  (void) lpReserved;

  switch (ul_reason_for_call)
  {
    case DLL_PROCESS_ATTACH:
      on_load ();
      break;

    case DLL_PROCESS_DETACH:
      on_unload ();
      break;

    default:
      break;
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

#ifdef __GNUC__
__attribute__ ((destructor))
#endif
static void
on_unload (void)
{
  g_io_deinit ();
}
