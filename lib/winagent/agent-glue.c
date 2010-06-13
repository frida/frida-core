#include "zed-winagent.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

static gboolean append_function_info (const gchar * name, gpointer address,
    gpointer user_data);

BOOL APIENTRY
DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  (void) hModule;
  (void) ul_reason_for_call;
  (void) lpReserved;

  if (ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    g_type_init ();
    gum_init ();
  }

  return TRUE;
}

ZedAgentModuleInfo **
zed_agent_query_modules (int * result_length1)
{
  GPtrArray * result;
  HANDLE this_process = GetCurrentProcess ();
  HMODULE first_module;
  DWORD modules_size = 0;
  HMODULE * modules = NULL;
  guint mod_idx;

  result = g_ptr_array_new ();

  if (!EnumProcessModules (this_process, &first_module, sizeof (first_module),
      &modules_size))
  {
    goto beach;
  }

  modules = (HMODULE *) g_malloc (modules_size);

  if (!EnumProcessModules (this_process, modules, modules_size, &modules_size))
  {
    goto beach;
  }

  for (mod_idx = 0; mod_idx != modules_size / sizeof (HMODULE); mod_idx++)
  {
    MODULEINFO mi;
    WCHAR module_name_utf16[MAX_PATH];
    gchar * module_name;
    ZedAgentModuleInfo * module_info;

    if (!GetModuleInformation (this_process, modules[mod_idx], &mi, sizeof (mi)))
      continue;

    GetModuleBaseNameW (this_process, modules[mod_idx],
        module_name_utf16, MAX_PATH);
    module_name = g_utf16_to_utf8 ((const gunichar2 *) module_name_utf16, -1,
        NULL, NULL, NULL);

    module_info = zed_agent_module_info_new (module_name,
        (guint64) mi.lpBaseOfDll, mi.SizeOfImage);
    g_ptr_array_add (result, module_info);

    g_free (module_name);
  }

beach:
  g_free (modules);

  *result_length1 = result->len;
  return (ZedAgentModuleInfo **) g_ptr_array_free (result, FALSE);
}

ZedAgentFunctionInfo **
zed_agent_query_module_functions (const char * module_name,
    int * result_length1)
{
  GPtrArray * result;

  result = g_ptr_array_new ();
  gum_module_enumerate_exports (module_name, append_function_info, result);
  *result_length1 = result->len;

  return (ZedAgentFunctionInfo **) g_ptr_array_free (result, FALSE);
}

static gboolean
append_function_info (const gchar * name, gpointer address, gpointer user_data)
{
  GPtrArray * result = (GPtrArray *) user_data;
  ZedAgentFunctionInfo * func_info;

  func_info = zed_agent_function_info_new (name, (guint64) address);
  g_ptr_array_add (result, func_info);

  return TRUE;
}
