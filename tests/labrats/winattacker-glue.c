#include <glib-object.h>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

BOOL APIENTRY
DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  (void) hModule;
  (void) ul_reason_for_call;
  (void) lpReserved;

  return TRUE;
}

void
zed_agent_initialize (void)
{
  g_type_init ();
}

void
zed_agent_exit_process (guint exit_code)
{
  ExitProcess (exit_code);
}
