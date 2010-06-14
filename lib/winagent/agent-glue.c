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

GVariant *
zed_agent_query_modules (void)
{
  GVariantType * type;
  GVariantBuilder builder;
  HANDLE this_process = GetCurrentProcess ();
  HMODULE first_module;
  DWORD modules_size = 0;
  HMODULE * modules = NULL;
  guint mod_idx;

  type = g_variant_type_new ("a(stt)");
  g_variant_builder_init (&builder, type);
  g_variant_type_free (type);

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

    if (!GetModuleInformation (this_process, modules[mod_idx], &mi, sizeof (mi)))
      continue;

    GetModuleBaseNameW (this_process, modules[mod_idx],
        module_name_utf16, MAX_PATH);
    module_name = g_utf16_to_utf8 ((const gunichar2 *) module_name_utf16, -1,
        NULL, NULL, NULL);

    g_variant_builder_add (&builder, "(stt)", module_name,
        (guint64) mi.lpBaseOfDll, (guint64) mi.SizeOfImage);

    g_free (module_name);
  }

beach:
  g_free (modules);

  return g_variant_builder_end (&builder);
}

GVariant *
zed_agent_query_module_functions (const char * module_name)
{
  GVariantType * type;
  GVariantBuilder builder;

  type = g_variant_type_new ("a(st)");
  g_variant_builder_init (&builder, type);
  g_variant_type_free (type);

  gum_module_enumerate_exports (module_name, append_function_info, &builder);

  return g_variant_builder_end (&builder);
}

static gboolean
append_function_info (const gchar * name, gpointer address, gpointer user_data)
{
  GVariantBuilder * builder = (GVariantBuilder *) user_data;

  g_variant_builder_add (builder, "(st)", name, (guint64) address);

  return TRUE;
}
