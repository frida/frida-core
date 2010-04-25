#include "winjector-helper.h"

#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

static HANDLE try_to_grab_a_thread_in (DWORD process_id, GError ** error);
static void trick_thread_into_loading_dll (HANDLE process_handle,
    HANDLE thread_handle, const WCHAR * dll_path, GError ** error);

static gboolean file_exists_and_is_readable (const WCHAR * filename);
static void set_grab_thread_error_from_os_error (const gchar * func_name,
    GError ** error);
static void set_trick_thread_error_from_os_error (const gchar * func_name,
    GError ** error);

gboolean
winjector_system_is_x64 (void)
{
  static gboolean initialized = FALSE;
  static gboolean system_is_x64;

  if (!initialized) {
    SYSTEM_INFO si;

    GetNativeSystemInfo (&si);
    system_is_x64 = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;

    initialized = TRUE;
  }

  return system_is_x64;
}

gboolean
winjector_process_is_x64 (guint32 process_id)
{
  HANDLE process_handle;
  BOOL is_wow64, success;

  if (!winjector_system_is_x64 ())
    return FALSE;

  process_handle = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, process_id);
  if (process_handle == NULL)
    goto error;
  success = IsWow64Process (process_handle, &is_wow64);
  CloseHandle (process_handle);
  if (!success)
    goto error;

  return !is_wow64;

error:
  return FALSE;
}

void
winjector_process_inject (guint32 process_id, const char * dll_path,
    GError ** error)
{
  WCHAR * dll_path_utf16;
  HANDLE process_handle = NULL;
  HANDLE thread_handle = NULL;

  dll_path_utf16 = g_utf8_to_utf16 (dll_path, -1, NULL, NULL, NULL);

  if (!file_exists_and_is_readable (dll_path_utf16))
  {
    g_set_error (error,
        ZED_SERVICE_WINJECTOR_ERROR,
        ZED_SERVICE_WINJECTOR_ERROR_FAILED,
        "Specified DLL path '%s' does not exist or cannot be opened",
        dll_path);
    goto beach;
  }

  process_handle = OpenProcess (
      PROCESS_DUP_HANDLE    | /* duplicatable handle                  */
      PROCESS_VM_OPERATION  | /* for VirtualProtectEx and mem access  */
      PROCESS_VM_READ       | /*   ReadProcessMemory                  */
      PROCESS_VM_WRITE,       /*   WriteProcessMemory                 */
      FALSE,                  /* children should not inherit this     */
      process_id);
  if (process_handle == NULL)
  {
    DWORD os_error;
    gint code;

    os_error = GetLastError ();

    if (os_error == ERROR_ACCESS_DENIED)
      code = ZED_SERVICE_WINJECTOR_ERROR_ACCESS_DENIED;
    else
      code = ZED_SERVICE_WINJECTOR_ERROR_FAILED;

    g_set_error (error, ZED_SERVICE_WINJECTOR_ERROR, code,
        "OpenProcess(pid=%u) failed: %d",
        process_id, os_error);
    goto beach;
  }

  thread_handle = try_to_grab_a_thread_in (process_id, error);
  if (*error != NULL)
    goto beach;

  if (thread_handle == NULL)
  {
    g_set_error (error,
        ZED_SERVICE_WINJECTOR_ERROR,
        ZED_SERVICE_WINJECTOR_ERROR_FAILED,
        "No usable thread found in pid=%ld", process_id);
    goto beach;
  }

  trick_thread_into_loading_dll (process_handle, thread_handle, dll_path_utf16,
      error);

  ResumeThread (thread_handle);

beach:
  if (thread_handle != NULL)
    CloseHandle (thread_handle);

  if (process_handle != NULL)
    CloseHandle (process_handle);

  g_free (dll_path_utf16);
}

static HANDLE
try_to_grab_a_thread_in (DWORD process_id, GError ** error)
{
  HANDLE snapshot_handle;
  THREADENTRY32 entry = { 0, };
  HANDLE thread_handle = NULL;

  snapshot_handle = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, process_id);
  if (snapshot_handle == INVALID_HANDLE_VALUE)
  {
    set_grab_thread_error_from_os_error ("CreateToolhelp32Snapshot", error);
    goto beach;
  }

  entry.dwSize = sizeof (entry);

  if (!Thread32First (snapshot_handle, &entry))
  {
    set_grab_thread_error_from_os_error ("Thread32First", error);
    goto beach;
  }

  do
  {
    DWORD prev_suspend_count;

    if (entry.th32OwnerProcessID != process_id)
      continue;

    thread_handle = OpenThread (
        THREAD_GET_CONTEXT      | /* for GetThreadContext             */
        THREAD_SET_CONTEXT      | /*   SetThreadContext               */
        THREAD_SUSPEND_RESUME   | /*   {Suspend,Resume}Thread         */
        THREAD_QUERY_INFORMATION, /*   GetExitCodeThread etc.         */
        FALSE,                    /* children should not inherit this */
        entry.th32ThreadID);
    if (thread_handle == NULL)
      continue;

    prev_suspend_count = SuspendThread (thread_handle);
    if (prev_suspend_count == 0)
      break; /* yay, the thread was running! */

    /* thread was not running; undo our suspend */
    if (prev_suspend_count != (DWORD) -1)
      ResumeThread (thread_handle);

    CloseHandle (thread_handle);
    thread_handle = NULL;
  } while (Thread32Next (snapshot_handle, &entry));

beach:
  if (snapshot_handle != INVALID_HANDLE_VALUE)
    CloseHandle (snapshot_handle);

  return thread_handle;
}

typedef struct _TrickContext TrickContext;
typedef struct _WorkerContext WorkerContext;

struct _TrickContext
{
  gpointer virtual_alloc_impl;
  gpointer create_thread_impl;
  gpointer close_handle_impl;

  guint32 saved_xax;
  guint32 saved_xbx;
  guint32 saved_xcx;
  guint32 saved_xdx;
  guint32 saved_xbp;
  guint32 saved_xsp;
  guint32 saved_xsi;
  guint32 saved_xdi;
  guint32 saved_flags;
  guint32 saved_xip;
};

struct _WorkerContext
{
  gpointer load_library_impl;
  gpointer virtual_free_impl;

  WCHAR dll_path[MAX_PATH + 1];
};

static void
trick_thread_into_loading_dll (HANDLE process_handle, HANDLE thread_handle,
    const WCHAR * dll_path, GError ** error)
{
#ifndef _M_X64 /* FIXME */
  HMODULE kmod;
  guint8 trick_code[] = {
    /*
     * guint8 * worker_data = VirtualAlloc (...);
     */
    0x6A, 0x40,             /* push PAGE_EXECUTE_READWRITE        (flProtect) */
    0x68,                   /* push MEM_COMMIT|MEM_RESERVE (flAllocationType) */
    0x00, 0x30, 0x00, 0x00,
    0x68,                   /* push 0xDDCCBBAA                       (dwSize) */
    /* offset 8: */ 0xAA, 0xBB, 0xCC, 0xDD,
    0x6A, 0x00,             /* push 0                             (lpAddress) */
    0xFF, 0x53, G_STRUCT_OFFSET (TrickContext, virtual_alloc_impl),   /* call */

    /*
     * memcpy (worker_data, ctx->worker_data, sizeof (ctx->worker_data));
     */
    0x89, 0xC7,                           /* mov edi, eax                     */
    0x8D, 0xB3,                           /* lea esi, [ebx + 0xDDCCBBAA]      */
    /* offset 21: */ 0xAA, 0xBB, 0xCC, 0xDD,
    0xB9,                                 /* mov ecx, 0xDDCCBBAA              */
    /* offset 26: */ 0xAA, 0xBB, 0xCC, 0xDD,
    0xFC,                                 /* cld                              */
    0xF3, 0xA5,                           /* rep movsd                        */

    /*
     * HANDLE worker_thread = CreateThread (...);
     */
    0x6A, 0x00,                           /* push NULL           (lpThreadId) */
    0x6A, 0x00,                           /* push 0         (dwCreationFlags) */
    0x50,                                 /* push eax           (lpParameter) */
    0x05,                                 /* add eax, 0xDDCCBBAA              */
    /* offset 39: */ 0xAA, 0xBB, 0xCC, 0xDD,
    0x50,                                 /* push eax        (lpStartAddress) */
    0x6A, 0x00,                           /* push 0             (dwStackSize) */
    0x6A, 0x00,                           /* push NULL   (lpThreadAttributes) */
    0xFF, 0x53, G_STRUCT_OFFSET (TrickContext, create_thread_impl),   /* call */

    /*
     * CloseHandle (worker_thread);
     */
    0x50,                                 /* push eax               (hObject) */
    0xFF, 0x53, G_STRUCT_OFFSET (TrickContext, close_handle_impl),    /* call */

    /*
     * Restore registers and continue execution from where we cut it off.
     */
    0x8B, 0x43, G_STRUCT_OFFSET (TrickContext, saved_xax),      /* mov eax, S */
    0x8B, 0x4B, G_STRUCT_OFFSET (TrickContext, saved_xcx),      /* mov ecx, S */
    0x8B, 0x53, G_STRUCT_OFFSET (TrickContext, saved_xdx),      /* mov edx, S */
    0x8B, 0x6B, G_STRUCT_OFFSET (TrickContext, saved_xbp),      /* mov ebp, S */
    0x8B, 0x63, G_STRUCT_OFFSET (TrickContext, saved_xsp),      /* mov esp, S */
    0x8B, 0x73, G_STRUCT_OFFSET (TrickContext, saved_xsi),      /* mov esi, S */
    0x8B, 0x7B, G_STRUCT_OFFSET (TrickContext, saved_xdi),      /* mov edi, S */
    0xFF, 0x73, G_STRUCT_OFFSET (TrickContext, saved_flags),    /* push ... S */
    0xFF, 0x73, G_STRUCT_OFFSET (TrickContext, saved_xip),      /* push ... S */
    0x8B, 0x5B, G_STRUCT_OFFSET (TrickContext, saved_xbx),      /* mov ebx, S */
    0x83, 0xC4, 0x04,                                           /* add esp, 4 */
    0x9D,                                                       /* popfd      */
    0xFF, 0x64, 0x24, 0xF8                                      /* jmp [esp-8]*/
  };
  TrickContext trick_ctx;
  const guint trick_size = sizeof (trick_code) + sizeof (trick_ctx);
  guint8 worker_code[] = {
    /*
     * Remove argument and return address, so VirtualFree will return directly
     * to our caller instead of freed memory.
     */
    0x5E,                         /* pop esi                 (return address) */
    0x5B,                         /* pop ebx         (WorkerContext argument) */

    /*
     * LoadLibraryW (ctx->dll_path);
     */
    0x8D, 0x43, G_STRUCT_OFFSET (WorkerContext, dll_path),  /* lea eax, ebx+X */
    0x50,                                                   /* push eax       */
    0xFF, 0x53, G_STRUCT_OFFSET (WorkerContext, load_library_impl),   /* call */

    /*
     * VirtualFree (worker_data, ...);
     */
    0x68, 0x00, 0x80, 0x00, 0x00, /* push MEM_RELEASE      (arg3: dwFreeType) */
    0x6A, 0x00,                   /* push 0                    (arg2: dwSize) */
    0x53,                         /* push ebx   (VirtualFree arg1: lpAddress) */
    0x56,                         /* push esi           (fake return address) */
    0xFF, 0x63, G_STRUCT_OFFSET (WorkerContext, virtual_free_impl),    /* jmp */

    0xCC, 0xCC, 0xCC              /* pad to multiple of 4                     */
  };
  WorkerContext worker_ctx;
  const guint worker_size = sizeof (worker_code) + sizeof (worker_ctx);
  TrickContext * remote_trick_ctx;
  WorkerContext * remote_worker_ctx;
  CONTEXT ctx = { 0, };

  kmod = GetModuleHandleW (L"kernel32.dll");

  *((guint32 *) (trick_code +  8)) = worker_size;
  *((guint32 *) (trick_code + 21)) = trick_size;
  g_assert (worker_size % 4 == 0);
  *((guint32 *) (trick_code + 26)) = worker_size / 4;
  *((guint32 *) (trick_code + 39)) = sizeof (worker_ctx);

  trick_ctx.virtual_alloc_impl = GetProcAddress (kmod, "VirtualAlloc");
  trick_ctx.create_thread_impl = GetProcAddress (kmod, "CreateThread");
  trick_ctx.close_handle_impl = GetProcAddress (kmod, "CloseHandle");

  ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
  if (!GetThreadContext (thread_handle, &ctx))
  {
    set_trick_thread_error_from_os_error ("GetThreadContext", error);
    goto beach;
  }
  trick_ctx.saved_xax = ctx.Eax;
  trick_ctx.saved_xbx = ctx.Ebx;
  trick_ctx.saved_xcx = ctx.Ecx;
  trick_ctx.saved_xdx = ctx.Edx;
  trick_ctx.saved_xbp = ctx.Ebp;
  trick_ctx.saved_xsp = ctx.Esp;
  trick_ctx.saved_xsi = ctx.Esi;
  trick_ctx.saved_xdi = ctx.Edi;
  trick_ctx.saved_flags = ctx.EFlags;
  trick_ctx.saved_xip = ctx.Eip;

  worker_ctx.load_library_impl = GetProcAddress (kmod, "LoadLibraryW");
  worker_ctx.virtual_free_impl = GetProcAddress (kmod, "VirtualFree");

  StringCbCopyW (worker_ctx.dll_path, sizeof (worker_ctx.dll_path), dll_path);

  /* Allocate on stack so we don't have to clean up afterwards. */
  remote_trick_ctx = VirtualAllocEx (process_handle,
      (gpointer) (trick_ctx.saved_xsp - (2 * 4096)), 4096,
      MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (remote_trick_ctx == NULL)
  {
    set_trick_thread_error_from_os_error ("VirtualAllocEx", error);
    goto beach;
  }

  remote_worker_ctx =
      (WorkerContext *) (((guint8 *) remote_trick_ctx) + trick_size);

  if (!WriteProcessMemory (process_handle, remote_trick_ctx, &trick_ctx,
      sizeof (trick_ctx), NULL) ||
      !WriteProcessMemory (process_handle, remote_trick_ctx + 1, trick_code,
      sizeof (trick_code), NULL))
  {
    set_trick_thread_error_from_os_error ("WriteProcessMemory", error);
    goto beach;
  }

  if (!WriteProcessMemory (process_handle, remote_worker_ctx, &worker_ctx,
      sizeof (worker_ctx), NULL) ||
      !WriteProcessMemory (process_handle, remote_worker_ctx + 1, worker_code,
      sizeof (worker_code), NULL))
  {
    set_trick_thread_error_from_os_error ("WriteProcessMemory", error);
    goto beach;
  }

  ctx.Ebx = (DWORD) remote_trick_ctx;
  ctx.Eip = (DWORD) (remote_trick_ctx + 1);

  if (!SetThreadContext (thread_handle, &ctx))
  {
    set_trick_thread_error_from_os_error ("SetThreadContext", error);
    goto beach;
  }

beach:
  return;
#endif
}

static gboolean
file_exists_and_is_readable (const WCHAR * filename)
{
  HANDLE file;

  file = CreateFile (filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING, 0, NULL);
  if (file == INVALID_HANDLE_VALUE)
    return FALSE;
  CloseHandle (file);
  return TRUE;
}

static void
set_grab_thread_error_from_os_error (const gchar * func_name, GError ** error)
{
  g_set_error (error,
      ZED_SERVICE_WINJECTOR_ERROR,
      ZED_SERVICE_WINJECTOR_ERROR_FAILED,
      "%s failed while trying to grab thread: %d",
      func_name, GetLastError ());
}

static void
set_trick_thread_error_from_os_error (const gchar * func_name, GError ** error)
{
  g_set_error (error,
      ZED_SERVICE_WINJECTOR_ERROR,
      ZED_SERVICE_WINJECTOR_ERROR_FAILED,
      "%s failed while trying to trick thread: %d",
      func_name, GetLastError ());
}
