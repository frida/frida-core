#include "winjector-helper.h"

#include <glib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

#define ZED_WINJECTOR_ERROR zed_winjector_error_quark ()

typedef struct _WinjectorTarget WinjectorTarget;
typedef struct _InjectContext InjectContext;

struct _WinjectorTarget
{
  gulong pid;
  gunichar2 * dll_path;
};

struct _InjectContext
{
  WinjectorTarget * target;
  HANDLE cancel_event;
  GError * err;
};

static DWORD WINAPI do_injection (LPVOID parameter);
static gboolean inject_into_target (WinjectorTarget * target, HANDLE cancel_event,
    GError ** err);
static HANDLE try_to_grab_a_thread_in (DWORD process_id, GError ** err);
static void trick_thread_into_loading_dll (HANDLE process_handle,
    HANDLE thread_handle, const WCHAR * dll_path, GError ** err);

static gboolean parse_target_line (WCHAR * line, WinjectorTarget * target);
static gboolean file_exists_and_is_readable (const WCHAR * filename);

static void set_grab_thread_error_from_os_error (const gchar * func_name,
    GError ** err);
static void set_trick_thread_error_from_os_error (const gchar * func_name,
    GError ** err);

static GQuark zed_winjector_error_quark (void);

gint
wmain (gint argc, WCHAR * argv[])
{
  gint ret = 1;
  const guint max_chars_per_line = 10 + 1 + MAX_PATH + 1;
  WCHAR * line;
  HANDLE cancel_event;

  line = g_malloc0 (max_chars_per_line * sizeof (WCHAR));
  cancel_event = CreateEvent (NULL, TRUE, FALSE, NULL);

  while (StringCchGetsW (line, max_chars_per_line) == S_OK)
  {
    WinjectorTarget target;
    InjectContext inject_ctx;
    HANDLE worker_thread;
    HANDLE wait_handles[2];
    gboolean input_error = FALSE;

    if (wcscmp (line, L"exit") == 0)
      break;

    if (!parse_target_line (line, &target))
      goto beach;

    inject_ctx.target = &target;
    inject_ctx.cancel_event = cancel_event;
    inject_ctx.err = NULL;

    worker_thread = CreateThread (NULL, 0, do_injection, &inject_ctx, 0, NULL);

    wait_handles[0] = worker_thread;
    wait_handles[1] = GetStdHandle (STD_INPUT_HANDLE);

    if (WaitForMultipleObjects (G_N_ELEMENTS (wait_handles), wait_handles,
        FALSE, INFINITE) == WAIT_OBJECT_0)
    {
      if (inject_ctx.err == NULL)
      {
        _putws (L"SUCCESS");
      }
      else
      {
        wprintf (L"ERROR %d %S\n", inject_ctx.err->code,
            inject_ctx.err->message);
        g_clear_error (&inject_ctx.err);
      }
    }
    else
    {
      input_error = TRUE;

      if (StringCchGetsW (line, max_chars_per_line) == S_OK)
      {
        if (wcscmp (line, L"cancel") == 0)
        {
          SetEvent (cancel_event);
          input_error = FALSE;
        }
      }

      if (input_error)
        SetEvent (cancel_event);

      WaitForSingleObject (worker_thread, INFINITE);
    }

    CloseHandle (worker_thread);

    if (input_error)
      goto beach;
  }

  ret = 0;

beach:
  CloseHandle (cancel_event);
  g_free (line);

  return ret;
}

static DWORD WINAPI
do_injection (LPVOID parameter)
{
  InjectContext * ctx = parameter;

  return inject_into_target (ctx->target, ctx->cancel_event, &ctx->err);
}

static gboolean
inject_into_target (WinjectorTarget * target, HANDLE cancel_event,
    GError ** err)
{
  gboolean result = FALSE;
  HANDLE process_handle = NULL;
  HANDLE thread_handle = NULL;

  process_handle = OpenProcess (
      PROCESS_DUP_HANDLE    | /* duplicatable handle                  */
      PROCESS_VM_OPERATION  | /* for VirtualProtectEx and mem access  */
      PROCESS_VM_READ       | /*   ReadProcessMemory                  */
      PROCESS_VM_WRITE,       /*   WriteProcessMemory                 */
      FALSE,                  /* children should not inherit this     */
      target->pid);
  if (process_handle == NULL)
  {
    g_set_error (err,
        ZED_WINJECTOR_ERROR,
        ZED_WINJECTOR_ERROR_OPEN_PROCESS_FAILED,
        "OpenProcess(pid=%ld) failed: %d",
        target->pid, GetLastError ());
    goto beach;
  }

  do
  {
    thread_handle = try_to_grab_a_thread_in (target->pid, err);
    if (*err != NULL)
      goto beach;

    if (thread_handle != NULL)
      break;
  }
  while (WaitForSingleObject (cancel_event, 100) == WAIT_TIMEOUT);

  trick_thread_into_loading_dll (process_handle, thread_handle,
      target->dll_path, err);

  ResumeThread (thread_handle);

  if (*err != NULL)
    goto beach;

  result = TRUE;

beach:
  if (thread_handle != NULL)
    CloseHandle (thread_handle);

  if (process_handle != NULL)
    CloseHandle (process_handle);

  return result;
}

static HANDLE
try_to_grab_a_thread_in (DWORD process_id, GError ** err)
{
  HANDLE snapshot_handle;
  THREADENTRY32 entry = { 0, };
  HANDLE thread_handle = NULL;

  snapshot_handle = CreateToolhelp32Snapshot (TH32CS_SNAPTHREAD, process_id);
  if (snapshot_handle == INVALID_HANDLE_VALUE)
  {
    set_grab_thread_error_from_os_error ("CreateToolhelp32Snapshot", err);
    goto beach;
  }

  entry.dwSize = sizeof (entry);

  if (!Thread32First (snapshot_handle, &entry))
  {
    set_grab_thread_error_from_os_error ("Thread32First", err);
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
    const WCHAR * dll_path, GError ** err)
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
    0xCC,

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

    0xCC, 0xCC                    /* pad to multiple of 4                     */
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
    set_trick_thread_error_from_os_error ("GetThreadContext", err);
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
    set_trick_thread_error_from_os_error ("VirtualAllocEx", err);
    goto beach;
  }

  remote_worker_ctx =
      (WorkerContext *) (((guint8 *) remote_trick_ctx) + trick_size);

  if (!WriteProcessMemory (process_handle, remote_trick_ctx, &trick_ctx,
      sizeof (trick_ctx), NULL) ||
      !WriteProcessMemory (process_handle, remote_trick_ctx + 1, trick_code,
      sizeof (trick_code), NULL))
  {
    set_trick_thread_error_from_os_error ("WriteProcessMemory", err);
    goto beach;
  }

  if (!WriteProcessMemory (process_handle, remote_worker_ctx, &worker_ctx,
      sizeof (worker_ctx), NULL) ||
      !WriteProcessMemory (process_handle, remote_worker_ctx + 1, worker_code,
      sizeof (worker_code), NULL))
  {
    set_trick_thread_error_from_os_error ("WriteProcessMemory", err);
    goto beach;
  }

  ctx.Ebx = (DWORD) remote_trick_ctx;
  ctx.Eip = (DWORD) (remote_trick_ctx + 1);

  if (!SetThreadContext (thread_handle, &ctx))
  {
    set_trick_thread_error_from_os_error ("SetThreadContext", err);
    goto beach;
  }

beach:
  return;
#endif
}

static gboolean
parse_target_line (WCHAR * line, WinjectorTarget * target)
{
  WCHAR * pid_end, * expected_pid_end;

  target->pid = wcstoul (line, &pid_end, 10);
  if (target->pid == 0 || target->pid == ULONG_MAX)
    return FALSE;

  expected_pid_end = wcschr (line, L' ');
  if (pid_end != expected_pid_end)
    return FALSE;

  target->dll_path = expected_pid_end + 1;
  if (!file_exists_and_is_readable (target->dll_path))
    return FALSE;

  return TRUE;
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
set_grab_thread_error_from_os_error (const gchar * func_name, GError ** err)
{
  g_set_error (err,
    ZED_WINJECTOR_ERROR,
    ZED_WINJECTOR_ERROR_GRAB_THREAD_FAILED,
    "%s failed: %d", func_name, GetLastError ());
}

static void
set_trick_thread_error_from_os_error (const gchar * func_name, GError ** err)
{
  g_set_error (err,
    ZED_WINJECTOR_ERROR,
    ZED_WINJECTOR_ERROR_TRICK_THREAD_FAILED,
    "%s failed: %d", func_name, GetLastError ());
}

static GQuark
zed_winjector_error_quark (void)
{
  return g_quark_from_static_string ("winjector-error-quark");
}
