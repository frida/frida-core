#define DEBUG_HEAP_LEAKS  0
#define ENABLE_DEBUG      0

#include "zed-winagent.h"

#define VC_EXTRALEAN
#include <windows.h>
#include <psapi.h>
#if DEBUG_HEAP_LEAKS
#include <crtdbg.h>
#endif
#if ENABLE_DEBUG
#include <io.h>
#include <stdio.h>
#endif

#define ZED_MAX_DUMP_SIZE (0xffff)

static gboolean append_function_info (const gchar * name, gpointer address,
    gpointer user_data);

static gchar * compute_md5sum_for_file_at (const gchar * path);

BOOL APIENTRY
DllMain (HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  (void) hModule;
  (void) ul_reason_for_call;
  (void) lpReserved;

#if ENABLE_DEBUG
  if (ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    AllocConsole ();

    stdout->_file = _open_osfhandle ((intptr_t) GetStdHandle (STD_OUTPUT_HANDLE), 0);
    stderr->_file = _open_osfhandle ((intptr_t) GetStdHandle (STD_ERROR_HANDLE), 0);
  }
#endif

  return TRUE;
}

void
zed_agent_environment_init (void)
{
#if DEBUG_HEAP_LEAKS
  int tmp_flag;

  /*_CrtSetBreakAlloc (1337);*/

  _CrtSetReportMode (_CRT_ERROR, _CRTDBG_MODE_FILE);
  _CrtSetReportFile (_CRT_ERROR, _CRTDBG_FILE_STDERR);

  tmp_flag = _CrtSetDbgFlag (_CRTDBG_REPORT_FLAG);

  tmp_flag |= _CRTDBG_ALLOC_MEM_DF;
  tmp_flag |= _CRTDBG_LEAK_CHECK_DF;
  tmp_flag &= ~_CRTDBG_CHECK_CRT_DF;

  _CrtSetDbgFlag (tmp_flag);
#endif

  g_setenv ("G_DEBUG", "fatal-warnings:fatal-criticals", TRUE);
#if DEBUG_HEAP_LEAKS || ENABLE_DEBUG
  g_setenv ("G_SLICE", "always-malloc", TRUE);
#endif
#ifdef _DEBUG
  g_thread_init_with_errorcheck_mutexes (NULL);
#else
  g_thread_init (NULL);
#endif
  g_type_init ();
  gum_init_with_features ((GumFeatureFlags)
      (GUM_FEATURE_ALL & ~GUM_FEATURE_SYMBOL_LOOKUP));
}

void
zed_agent_environment_deinit (void)
{
  gum_deinit ();
  g_type_deinit ();
  g_thread_deinit ();
  g_mem_deinit ();
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

  type = g_variant_type_new ("a(sstt)");
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
    WCHAR module_path_utf16[MAX_PATH];
    gchar * module_path, * module_name, * module_uid;

    if (!GetModuleInformation (this_process, modules[mod_idx], &mi, sizeof (mi)))
      continue;

    GetModuleFileNameW (modules[mod_idx], module_path_utf16, MAX_PATH);
    module_path_utf16[MAX_PATH - 1] = '\0';
    module_path = g_utf16_to_utf8 ((const gunichar2 *) module_path_utf16, -1,
        NULL, NULL, NULL);

    module_name = g_path_get_basename (module_path);
    module_uid = compute_md5sum_for_file_at (module_path);
    g_assert (module_uid != NULL);

    g_variant_builder_add (&builder, "(sstt)", module_name, module_uid,
        (guint64) mi.SizeOfImage, (guint64) mi.lpBaseOfDll);
    g_free (module_uid);
    g_free (module_name);

    g_free (module_path);
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

GVariant *
zed_agent_dump_memory (guint64 address, guint size)
{
  GVariant * result;
  gboolean success = FALSE;
  gchar * error_message = NULL;
  GVariantBuilder * builder;
  guint8 * cur;
  guint64 remaining;

  builder = g_variant_builder_new (G_VARIANT_TYPE ("ay"));

  if (size > ZED_MAX_DUMP_SIZE)
    goto way_too_much;

  for (remaining = size; remaining != 0;)
  {
    MEMORY_BASIC_INFORMATION mbi;
    guint len, i;

    cur = (guint8 *) (address + size - remaining);

    if (VirtualQuery (cur, &mbi, sizeof (mbi)) == 0)
      goto virtual_query_failed;

    if (mbi.State != MEM_COMMIT)
      goto address_not_readable;

    switch (mbi.Protect & 0xff)
    {
      case PAGE_EXECUTE_READ:
      case PAGE_EXECUTE_READWRITE:
      case PAGE_READONLY:
      case PAGE_READWRITE:
        break;
      default:
        goto address_not_readable;
    }

    len = MIN (remaining, (guint64)
        ((guint8 *) mbi.BaseAddress + mbi.RegionSize - cur));
    for (i = 0; i != len; i++)
    {
      /* FIXME: This is clearly not efficient. Easily fixable by updating *
       *        to the latest version of GLib/GVariant                    */
      g_variant_builder_add (builder, "y", cur[i]);
    }

    remaining -= len;
  }

  success = TRUE;
  error_message = g_strdup ("");

beach:
  result = g_variant_new ("(bsay)", success, error_message, builder);
  g_free (error_message);

  return result;

  /* ERRORS */
way_too_much:
  {
    error_message = g_strdup ("sorry, that's way too much");
    goto beach;
  }
virtual_query_failed:
  {
    error_message =
        g_strdup_printf ("VirtualQuery failed: 0x%08x", GetLastError ());
    goto beach;
  }
address_not_readable:
  {
    error_message = g_strdup ("specified memory region is not readable");
    goto beach;
  }
}

static gboolean
append_function_info (const gchar * name, gpointer address, gpointer user_data)
{
  GVariantBuilder * builder = (GVariantBuilder *) user_data;

  g_variant_builder_add (builder, "(st)", name, (guint64) address);

  return TRUE;
}

static gchar *
compute_md5sum_for_file_at (const gchar * path)
{
  gchar * result = NULL;
  guchar * data;
  gsize length;

  if (g_file_get_contents (path, (gchar **) &data, &length, NULL))
  {
    result = g_compute_checksum_for_data (G_CHECKSUM_MD5, data, length);

    g_free (data);
  }

  return result;
}
