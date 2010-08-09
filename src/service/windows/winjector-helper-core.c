#include "winjector-helper.h"

#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

typedef struct _InjectionDetails InjectionDetails;
typedef struct _RemoteWorkerContext RemoteWorkerContext;
typedef struct _TrickContext TrickContext;

struct _InjectionDetails
{
  HANDLE process_handle;
  const WCHAR * dll_path;
  const gchar * ipc_server_address;
};

struct _RemoteWorkerContext
{
  gpointer load_library_impl;
  gpointer get_proc_address_impl;
  gpointer free_library_impl;
  gpointer virtual_free_impl;
  gpointer exit_thread_impl;

  gchar zed_agent_main_string[14 + 1];

  WCHAR dll_path[MAX_PATH + 1];
  gchar ipc_server_address[MAX_PATH + 1];

  gpointer entrypoint;
  gpointer argument;
};

struct _TrickContext
{
  /* These fields must be addressable with int8 --> */
  gpointer entrypoint;
  gpointer argument;

  gpointer create_thread_impl;
  gpointer close_handle_impl;

  /* Remaining fields must be addressable with uint8 --> */
  gsize saved_xax;
  gsize saved_xbx;
  gsize saved_xcx;
  gsize saved_xdx;
  gsize saved_xdi;
  gsize saved_xsi;
  gsize saved_xbp;
  gsize saved_xsp;

#ifdef _M_X64
  gsize saved_r8;
  gsize saved_r9;
  gsize saved_r10;
  gsize saved_r11;
  gsize saved_r12;
  gsize saved_r13;
  gsize saved_r14;
  gsize saved_r15;
#endif

  gsize saved_flags;
  gsize saved_xip;
};

static HANDLE try_to_grab_a_thread_in (DWORD process_id, GError ** error);
static void trick_thread_into_spawning_worker_thread (HANDLE process_handle, HANDLE thread_handle, RemoteWorkerContext * rwc, GError ** error);

static gboolean initialize_remote_worker_context (RemoteWorkerContext * rwc, InjectionDetails * details, GError ** error);
static void cleanup_remote_worker_context (RemoteWorkerContext * rwc, InjectionDetails * details);

static gboolean file_exists_and_is_readable (const WCHAR * filename);
static void set_grab_thread_error_from_os_error (const gchar * func_name, GError ** error);
static void set_trick_thread_error_from_os_error (const gchar * func_name, GError ** error);

static const gboolean enable_stealth_mode = FALSE;

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
    const gchar * ipc_server_address, GError ** error)
{
  gboolean success = FALSE;
  InjectionDetails details;
  DWORD desired_access;
  HANDLE thread_handle = NULL;
  gboolean rwc_initialized = FALSE;
  RemoteWorkerContext rwc;

  details.dll_path = g_utf8_to_utf16 (dll_path, -1, NULL, NULL, NULL);
  details.ipc_server_address = ipc_server_address;
  details.process_handle = NULL;

  if (!file_exists_and_is_readable (details.dll_path))
  {
    g_set_error (error,
        ZED_SERVICE_WINJECTOR_ERROR,
        ZED_SERVICE_WINJECTOR_ERROR_FAILED,
        "Specified DLL path '%s' does not exist or cannot be opened",
        dll_path);
    goto beach;
  }

  desired_access = 
      PROCESS_DUP_HANDLE    | /* duplicatable handle                  */
      PROCESS_VM_OPERATION  | /* for VirtualProtectEx and mem access  */
      PROCESS_VM_READ       | /*   ReadProcessMemory                  */
      PROCESS_VM_WRITE;       /*   WriteProcessMemory                 */
  if (!enable_stealth_mode)
    desired_access |= PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;

  details.process_handle = OpenProcess (desired_access, FALSE, process_id);
  if (details.process_handle == NULL)
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

  if (!initialize_remote_worker_context (&rwc, &details, error))
    goto beach;
  rwc_initialized = TRUE;

  if (enable_stealth_mode)
  {
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

    trick_thread_into_spawning_worker_thread (details.process_handle, thread_handle, &rwc, error);

    ResumeThread (thread_handle);
  }
  else
  {
    thread_handle = CreateRemoteThread (details.process_handle, NULL, 0, (LPTHREAD_START_ROUTINE) rwc.entrypoint, rwc.argument, 0, NULL);
    if (thread_handle == NULL)
    {
      g_set_error (error,
          ZED_SERVICE_WINJECTOR_ERROR,
          ZED_SERVICE_WINJECTOR_ERROR_FAILED,
          "CreateRemoteThread(pid=%u) failed: %d",
          process_id, (gint) GetLastError ());
      goto beach;
    }
  }

  success = TRUE;

beach:
  if (!success && rwc_initialized)
    cleanup_remote_worker_context (&rwc, &details);

  if (thread_handle != NULL)
    CloseHandle (thread_handle);

  if (details.process_handle != NULL)
    CloseHandle (details.process_handle);

  g_free ((gpointer) details.dll_path);
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

static void
trick_thread_into_spawning_worker_thread (HANDLE process_handle, HANDLE thread_handle, RemoteWorkerContext * rwc, GError ** error)
{
  HMODULE kmod;
  guint8 code[] = {
#ifdef _M_X64
    /*
     * Align stack on a 16 byte boundary
     */
    0x48, 0x31, 0xC0,                                                             /* xor rax, rax */
    0x48, 0xFF, 0xC8,                                                             /* dec rax      */
    0x48, 0xC1, 0xE0, 0x04,                                                       /* shl rax, 4   */
    0x48, 0x21, 0xC4,                                                             /* and rsp, rax */

    /*
     * Reserve stack space for arguments (48), rounded up to next 16 byte boundary (64)
     */
    0x48, 0x83, 0xEC, 64,                                                         /* sub rsp, 64 */

    /*
     * HANDLE worker_thread = CreateThread (...);
     */
    0x48, 0xC7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00,                         /* mov qword [rsp + 0x28], 0 */
    0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,                               /* mov dword [rsp + 0x20], 0 */
    0x4c, 0x8b, 0x4b, offsetof (TrickContext, argument),                          /* mov r9, [rbx + X]         */
    0x4c, 0x8b, 0x43, offsetof (TrickContext, entrypoint),                        /* mov r8, [rbx + X]         */
    0x31, 0xD2,                                                                   /* xor edx, edx              */
    0x48, 0x31, 0xC9,                                                             /* xor rcx, rcx              */
    0xFF, 0x53, offsetof (TrickContext, create_thread_impl),                      /* call qword [rbx + 0xAA]   */

    /*
     * CloseHandle (worker_thread);
     */
    0x48, 0x89, 0xC1,                                                             /* mov rcx, rax            */
    0xFF, 0x53, offsetof (TrickContext, close_handle_impl),                       /* call qword [rbx + 0xAA] */

    /*
     * Restore registers and continue execution from where we cut it off.
     */
    0x48, 0x8B, 0x83, offsetof (TrickContext, saved_xax),   0, 0, 0,              /* mov rax, S   */
    0x48, 0x8B, 0x8B, offsetof (TrickContext, saved_xcx),   0, 0, 0,              /* mov rcx, S   */
    0x48, 0x8B, 0x93, offsetof (TrickContext, saved_xdx),   0, 0, 0,              /* mov rdx, S   */
    0x48, 0x8B, 0xBB, offsetof (TrickContext, saved_xdi),   0, 0, 0,              /* mov rdi, S   */
    0x48, 0x8B, 0xB3, offsetof (TrickContext, saved_xsi),   0, 0, 0,              /* mov rsi, S   */
    0x48, 0x8B, 0xAB, offsetof (TrickContext, saved_xbp),   0, 0, 0,              /* mov rbp, S   */
    0x48, 0x8B, 0xA3, offsetof (TrickContext, saved_xsp),   0, 0, 0,              /* mov rsp, S   */
    0x4C, 0x8B, 0x83, offsetof (TrickContext, saved_r8),    0, 0, 0,              /* mov  r8, S   */
    0x4C, 0x8B, 0x8B, offsetof (TrickContext, saved_r9),    0, 0, 0,              /* mov  r9, S   */
    0x4C, 0x8B, 0x93, offsetof (TrickContext, saved_r10),   0, 0, 0,              /* mov r10, S   */
    0x4C, 0x8B, 0x9B, offsetof (TrickContext, saved_r11),   0, 0, 0,              /* mov r11, S   */
    0x4C, 0x8B, 0xA3, offsetof (TrickContext, saved_r12),   0, 0, 0,              /* mov r12, S   */
    0x4C, 0x8B, 0xAB, offsetof (TrickContext, saved_r13),   0, 0, 0,              /* mov r13, S   */
    0x4C, 0x8B, 0xB3, offsetof (TrickContext, saved_r14),   0, 0, 0,              /* mov r14, S   */
    0x4C, 0x8B, 0xBB, offsetof (TrickContext, saved_r15),   0, 0, 0,              /* mov r15, S   */
    0xFF, 0xB3,       offsetof (TrickContext, saved_flags), 0, 0, 0,              /* push ... S   */
    0xFF, 0xB3,       offsetof (TrickContext, saved_xip),   0, 0, 0,              /* push ... S   */
    0x48, 0x8B, 0x9B, offsetof (TrickContext, saved_xbx),   0, 0, 0,              /* mov rbx, S   */
    0x83, 0xC4, 0x08,                                                             /* add esp, 8   */
    0x9D,                                                                         /* popfq        */
    0x67, 0xFF, 0x64, 0x24, 0xF0,                                                 /* jmp [esp-16] */
#else
    /*
     * HANDLE worker_thread = CreateThread (...);
     */
    0x6A, 0x00,                                                                   /* push NULL           (lpThreadId) */
    0x6A, 0x00,                                                                   /* push 0         (dwCreationFlags) */
    0xff, 0x73, offsetof (TrickContext, argument),                                /* push [ebx + X]     (lpParameter) */
    0xff, 0x73, offsetof (TrickContext, entrypoint),                              /* push [ebx + X]  (lpStartAddress) */
    0x6A, 0x00,                                                                   /* push 0             (dwStackSize) */
    0x6A, 0x00,                                                                   /* push NULL   (lpThreadAttributes) */
    0xFF, 0x53, offsetof (TrickContext, create_thread_impl),                      /* call                             */

    /*
     * CloseHandle (worker_thread);
     */
    0x50,                                                                         /* push eax               (hObject) */
    0xFF, 0x53, offsetof (TrickContext, close_handle_impl),                       /* call                             */

    /*
     * Restore registers and continue execution from where we cut it off.
     */
    0x8B, 0x43, offsetof (TrickContext, saved_xax),                               /* mov eax, S */
    0x8B, 0x4B, offsetof (TrickContext, saved_xcx),                               /* mov ecx, S */
    0x8B, 0x53, offsetof (TrickContext, saved_xdx),                               /* mov edx, S */
    0x8B, 0x7B, offsetof (TrickContext, saved_xdi),                               /* mov edi, S */
    0x8B, 0x73, offsetof (TrickContext, saved_xsi),                               /* mov esi, S */
    0x8B, 0x6B, offsetof (TrickContext, saved_xbp),                               /* mov ebp, S */
    0x8B, 0x63, offsetof (TrickContext, saved_xsp),                               /* mov esp, S */
    0xFF, 0x73, offsetof (TrickContext, saved_flags),                             /* push ... S */
    0xFF, 0x73, offsetof (TrickContext, saved_xip),                               /* push ... S */
    0x8B, 0x5B, offsetof (TrickContext, saved_xbx),                               /* mov ebx, S */
    0x83, 0xC4, 0x04,                                                             /* add esp, 4 */
    0x9D,                                                                         /* popfd      */
    0xFF, 0x64, 0x24, 0xF8                                                        /* jmp [esp-8]*/
#endif
  };
  TrickContext trick_ctx;
  TrickContext * remote_trick_ctx;
  CONTEXT ctx = { 0, };

  kmod = GetModuleHandleW (L"kernel32.dll");

  trick_ctx.entrypoint = rwc->entrypoint;
  trick_ctx.argument = rwc->argument;

  trick_ctx.create_thread_impl = GetProcAddress (kmod, "CreateThread");
  trick_ctx.close_handle_impl = GetProcAddress (kmod, "CloseHandle");

  ctx.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
  if (!GetThreadContext (thread_handle, &ctx))
  {
    set_trick_thread_error_from_os_error ("GetThreadContext", error);
    goto beach;
  }
#ifdef _M_X64
  trick_ctx.saved_xax = ctx.Rax;
  trick_ctx.saved_xbx = ctx.Rbx;
  trick_ctx.saved_xcx = ctx.Rcx;
  trick_ctx.saved_xdx = ctx.Rdx;
  trick_ctx.saved_xdi = ctx.Rdi;
  trick_ctx.saved_xsi = ctx.Rsi;
  trick_ctx.saved_xbp = ctx.Rbp;
  trick_ctx.saved_xsp = ctx.Rsp;
  trick_ctx.saved_r8 = ctx.R8;
  trick_ctx.saved_r9 = ctx.R9;
  trick_ctx.saved_r10 = ctx.R10;
  trick_ctx.saved_r11 = ctx.R11;
  trick_ctx.saved_r12 = ctx.R12;
  trick_ctx.saved_r13 = ctx.R13;
  trick_ctx.saved_r14 = ctx.R14;
  trick_ctx.saved_r15 = ctx.R15;

  trick_ctx.saved_flags = ctx.EFlags;
  trick_ctx.saved_xip = ctx.Rip;
#else
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
#endif

  /* Allocate on stack so we don't have to clean up afterwards. */
  remote_trick_ctx = VirtualAllocEx (process_handle, (gpointer) (trick_ctx.saved_xsp - (2 * 4096)), 4096,
      MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (remote_trick_ctx == NULL)
  {
    set_trick_thread_error_from_os_error ("VirtualAllocEx", error);
    goto beach;
  }

  if (!WriteProcessMemory (process_handle, remote_trick_ctx, &trick_ctx, sizeof (trick_ctx), NULL) ||
      !WriteProcessMemory (process_handle, remote_trick_ctx + 1, code, sizeof (code), NULL))
  {
    set_trick_thread_error_from_os_error ("WriteProcessMemory", error);
    goto beach;
  }

#ifdef _M_X64
  ctx.Rbx = (DWORD64) remote_trick_ctx;
  ctx.Rip = (DWORD64) (remote_trick_ctx + 1);
#else
  ctx.Ebx = (DWORD) remote_trick_ctx;
  ctx.Eip = (DWORD) (remote_trick_ctx + 1);
#endif

  if (!SetThreadContext (thread_handle, &ctx))
  {
    set_trick_thread_error_from_os_error ("SetThreadContext", error);
    goto beach;
  }

beach:
  return;
}

static gboolean
initialize_remote_worker_context (RemoteWorkerContext * rwc,
    InjectionDetails * details, GError ** error)
{
  HMODULE kmod;
  const guint data_alignment = 4;
  guint8 code[] = {
#ifdef _M_X64
    /*
     * Remove return address, so VirtualFree will return directly to
     * ExitThread instead of freed memory.
     */
    0x5E,                                              /* pop rsi              (return address) */
    0x48, 0x89, 0xCB,                                  /* mov rbx, rcx (WorkerContext argument) */

    /*
     * Reserve stack space for arguments (24), rounded up to next 16 byte boundary (32)
     */
    0x48, 0x83, 0xEC, 32,                              /* sub rsp, 32                           */

    /*
     * HANDLE mod = LoadLibraryW (ctx->dll_path);
     */
    0x48, 0x8D, 0x4B, offsetof (RemoteWorkerContext, dll_path),          /* lea rcx, [rbx+X]    */
    0xFF, 0x53,       offsetof (RemoteWorkerContext, load_library_impl), /* call qword [rbx+X]  */
    0x48, 0x89, 0xC7,                                                    /* mov rdi, rax        */

    /*
     * ZedAgentMainFunc func = (ZedAgentMainFunc) GetProcAddress (mod, "zed_agent_main");
     */
    0x48, 0x8D, 0x53,                                                /* lea rdx, [rbx + 0xAA]   */
                      offsetof (RemoteWorkerContext, zed_agent_main_string),
    0x48, 0x89, 0xF9,                                                /* mov rcx, rdi            */
    0xFF, 0x53, offsetof (RemoteWorkerContext, get_proc_address_impl),/* call qword [rbx + X]   */

    /*
     * func (ctx->ipc_server_address);
     */
    0x48, 0x8D, 0x8B,
        offsetof (RemoteWorkerContext, ipc_server_address) & 0xff,          /* lea rcx, rbx + X */
        (offsetof (RemoteWorkerContext, ipc_server_address) >> 8) & 0xff,
        0,
        0,
    0xFF, 0xD0,                                                             /* call rax         */

    /*
     * FreeLibrary (mod);
     */
    0x48, 0x89, 0xF9,                                                /* mov rcx, rdi            */
    0xFF, 0x53, offsetof (RemoteWorkerContext, free_library_impl),   /* call qword [rbx + 0xAA] */

    /*
     * VirtualFree (worker_data, ...); -> ExitThread ();
     */
    0x41, 0xB8, 0x00, 0x80, 0x00, 0x00,       /* mov r8d, MEM_RELEASE        (arg3: dwFreeType) */
    0x48, 0x31, 0xD2,                         /* xor rdx, rdx                    (arg2: dwSize) */
    0x48, 0x89, 0xD9,                         /* mov rcx, rbx     (VirtualFree arg1: lpAddress) */
    0xFF, 0x73, offsetof (RemoteWorkerContext, exit_thread_impl), /* push (fake return address) */
    0xFF, 0x63, offsetof (RemoteWorkerContext, virtual_free_impl),                       /* jmp */
#else
    /*
     * Remove argument and return address, so VirtualFree will return directly
     * to our caller instead of freed memory.
     */
    0x5E,                                           /* pop esi                 (return address) */
    0x5B,                                           /* pop ebx         (WorkerContext argument) */

    /*
     * HANDLE mod = LoadLibraryW (ctx->dll_path);
     */
    0x8D, 0x43, offsetof (RemoteWorkerContext, dll_path),                     /* lea eax, ebx+X */
    0x50,                                                                     /* push eax       */
    0xFF, 0x53, offsetof (RemoteWorkerContext, load_library_impl),            /* call           */
    0x89, 0xC7,                                                               /* mov edi, eax   */

    /*
     * ZedAgentMainFunc func = (ZedAgentMainFunc) GetProcAddress (mod, "zed_agent_main");
     */
    0x8D, 0x43, offsetof (RemoteWorkerContext, zed_agent_main_string),        /* lea eax, ebx+X */
    0x50,                                                                     /* push eax       */
    0x57,                                                                     /* push edi       */
    0xFF, 0x53, offsetof (RemoteWorkerContext, get_proc_address_impl),        /* call           */

    /*
     * func (ctx->ipc_server_address);
     */
    0x8D, 0xAB, offsetof (RemoteWorkerContext, ipc_server_address) & 0xff,    /* lea ebp, [ebx + X] */
                (offsetof (RemoteWorkerContext, ipc_server_address) >> 8) & 0xff,
                0,
                0,
    0x55,                                                                           /* push ebp */
    0xFF, 0xD0,                                                                     /* call eax */
    0x5D,                                                                           /* pop ebp  */

    /*
     * FreeLibrary (mod);
     */
    0x57,                                                                           /* push edi */
    0xFF, 0x53, offsetof (RemoteWorkerContext, free_library_impl),                  /* call     */

    /*
     * VirtualFree (worker_data, ...);
     */
    0x68, 0x00, 0x80, 0x00, 0x00,                    /* push MEM_RELEASE      (arg3: dwFreeType) */
    0x6A, 0x00,                                      /* push 0                    (arg2: dwSize) */
    0x53,                                            /* push ebx   (VirtualFree arg1: lpAddress) */
    0x56,                                            /* push esi           (fake return address) */
    0xFF, 0x63, offsetof (RemoteWorkerContext, virtual_free_impl),                        /* jmp */
#endif
  };

  memset (rwc, 0, sizeof (RemoteWorkerContext));

  kmod = GetModuleHandleW (L"kernel32.dll");

  rwc->load_library_impl = GetProcAddress (kmod, "LoadLibraryW");
  rwc->get_proc_address_impl = GetProcAddress (kmod, "GetProcAddress");
  rwc->free_library_impl = GetProcAddress (kmod, "FreeLibrary");
  rwc->virtual_free_impl = GetProcAddress (kmod, "VirtualFree");
  rwc->exit_thread_impl = GetProcAddress (kmod, "ExitThread");

  StringCbCopyA (rwc->zed_agent_main_string, sizeof (rwc->zed_agent_main_string), "zed_agent_main");

  StringCbCopyW (rwc->dll_path, sizeof (rwc->dll_path), details->dll_path);
  StringCbCopyA (rwc->ipc_server_address, sizeof (rwc->ipc_server_address), details->ipc_server_address);

  rwc->entrypoint = VirtualAllocEx (details->process_handle, NULL,
      sizeof (code) + data_alignment + sizeof (RemoteWorkerContext), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (rwc->entrypoint == NULL)
    goto virtual_alloc_failed;

  if (!WriteProcessMemory (details->process_handle, rwc->entrypoint, code, sizeof (code), NULL))
    goto write_process_memory_failed;

  rwc->argument = GSIZE_TO_POINTER (
      (GPOINTER_TO_SIZE (rwc->entrypoint) + sizeof (code) + data_alignment - 1) & ~(data_alignment - 1));
  if (!WriteProcessMemory (details->process_handle, rwc->argument, rwc, sizeof (RemoteWorkerContext), NULL))
    goto write_process_memory_failed;

  return TRUE;

  /* ERRORS */
virtual_alloc_failed:
  {
    g_set_error (error,
        ZED_SERVICE_WINJECTOR_ERROR,
        ZED_SERVICE_WINJECTOR_ERROR_FAILED,
        "VirtualAlloc failed: %d",
        (gint) GetLastError ());
    goto error_common;
  }
write_process_memory_failed:
  {
    g_set_error (error,
        ZED_SERVICE_WINJECTOR_ERROR,
        ZED_SERVICE_WINJECTOR_ERROR_FAILED,
        "WriteProcessMemory failed: %d",
        (gint) GetLastError ());
    goto error_common;
  }
error_common:
  {
    cleanup_remote_worker_context (rwc, details);
    return FALSE;
  }
}

static void
cleanup_remote_worker_context (RemoteWorkerContext * rwc, InjectionDetails * details)
{
  if (rwc->entrypoint != NULL)
  {
    VirtualFreeEx (details->process_handle, rwc->entrypoint, 0, MEM_RELEASE);
    rwc->entrypoint = NULL;
  }
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
