#include <glib-object.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

BOOL APIENTRY
DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  (void) hModule;
  (void) ul_reason_for_call;
  (void) lpReserved;

  if (ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    g_type_init ();
  }

  return TRUE;
}
