#include "winjector-helper.h"

#include <gum/gum.h>
#include <gum/arch-x86/gumx86writer.h>

#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!((n1) cmp (n2))) \
  { \
    failed_operation = op; \
    goto handle_os_error; \
  }

typedef struct _InjectionDetails InjectionDetails;
typedef struct _RemoteWorkerContext RemoteWorkerContext;
typedef struct _TrickContext TrickContext;

struct _InjectionDetails
{
  HANDLE process_handle;
  const WCHAR * dll_path;
  const gchar * data_string;
};

struct _RemoteWorkerContext
{
  gpointer load_library_impl;
  gpointer get_proc_address_impl;
  gpointer free_library_impl;
  gpointer virtual_free_impl;

  WCHAR dll_path[MAX_PATH + 1];
  gchar zed_agent_main_string[14 + 1];
  gchar data_string[MAX_PATH + 1];

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

static gboolean remote_worker_context_has_resolved_all_kernel32_functions (const RemoteWorkerContext * rwc);
static gboolean remote_worker_context_collect_kernel32_export (const gchar * name, GumAddress address, gpointer user_data);

static gboolean file_exists_and_is_readable (const WCHAR * filename);
static void set_grab_thread_error_from_os_error (const gchar * func_name, GError ** error);
static void set_trick_thread_error_from_os_error (const gchar * func_name, GError ** error);

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

void *
winjector_process_inject (guint32 process_id, const char * dll_path,
    const gchar * data_string, GError ** error)
{
  gboolean success = FALSE;
  const gchar * failed_operation;
  HANDLE waitable_remote_thread_handle = NULL;
  InjectionDetails details;
  gboolean enable_stealth_mode = FALSE;
  DWORD our_session_id, target_session_id, desired_access;
  HANDLE thread_handle = NULL;
  gboolean rwc_initialized = FALSE;
  RemoteWorkerContext rwc;

  details.dll_path = (WCHAR *) g_utf8_to_utf16 (dll_path, -1, NULL, NULL, NULL);
  details.data_string = data_string;
  details.process_handle = NULL;

  if (!file_exists_and_is_readable (details.dll_path))
    goto file_does_not_exist;

  if (ProcessIdToSessionId (GetCurrentProcessId (), &our_session_id) &&
      ProcessIdToSessionId (process_id, &target_session_id) &&
      target_session_id != our_session_id)
  {
    enable_stealth_mode = TRUE;
  }

  desired_access = 
      PROCESS_DUP_HANDLE    | /* duplicatable handle                  */
      PROCESS_VM_OPERATION  | /* for VirtualProtectEx and mem access  */
      PROCESS_VM_READ       | /*   ReadProcessMemory                  */
      PROCESS_VM_WRITE;       /*   WriteProcessMemory                 */
  if (!enable_stealth_mode)
    desired_access |= PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;

  details.process_handle = OpenProcess (desired_access, FALSE, process_id);
  CHECK_OS_RESULT (details.process_handle, !=, NULL, "OpenProcess");

  if (!initialize_remote_worker_context (&rwc, &details, error))
    goto beach;
  rwc_initialized = TRUE;

  if (enable_stealth_mode)
  {
    thread_handle = try_to_grab_a_thread_in (process_id, error);
    if (*error != NULL)
      goto beach;
    else if (thread_handle == NULL)
      goto no_usable_thread_found;

    trick_thread_into_spawning_worker_thread (details.process_handle, thread_handle, &rwc, error);

    ResumeThread (thread_handle);
  }
  else
  {
    thread_handle = CreateRemoteThread (details.process_handle, NULL, 0, GUM_POINTER_TO_FUNCPTR (LPTHREAD_START_ROUTINE, rwc.entrypoint), rwc.argument, 0, NULL);
    CHECK_OS_RESULT (thread_handle, !=, NULL, "CreateRemoteThread");

    waitable_remote_thread_handle = thread_handle;
    thread_handle = NULL;
  }

  success = TRUE;

  goto beach;

  /* ERRORS */
file_does_not_exist:
  {
    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_NOT_FOUND,
        "specified DLL path '%s' does not exist or cannot be opened",
        dll_path);
    goto beach;
  }
no_usable_thread_found:
  {
    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_NOT_FOUND,
        "no usable thread found in pid=%u", process_id);
    goto beach;
  }
handle_os_error:
  {
    DWORD os_error;
    gint code;

    os_error = GetLastError ();

    if (os_error == ERROR_ACCESS_DENIED)
      code = G_IO_ERROR_PERMISSION_DENIED;
    else
      code = G_IO_ERROR_FAILED;

    g_set_error (error, G_IO_ERROR, code,
        "%s(pid=%u) failed: %d",
        failed_operation, process_id, os_error);
    goto beach;
  }

beach:
  {
    if (!success && rwc_initialized)
      cleanup_remote_worker_context (&rwc, &details);

    if (thread_handle != NULL)
      CloseHandle (thread_handle);

    if (details.process_handle != NULL)
      CloseHandle (details.process_handle);

    g_free ((gpointer) details.dll_path);

    return waitable_remote_thread_handle;
  }
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

  trick_ctx.create_thread_impl = GUM_FUNCPTR_TO_POINTER (GetProcAddress (kmod, "CreateThread"));
  trick_ctx.close_handle_impl = GUM_FUNCPTR_TO_POINTER (GetProcAddress (kmod, "CloseHandle"));

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
  gpointer code;
  guint code_size;
  GumX86Writer cw;
  const gsize data_alignment = 4;
  const gchar * loadlibrary_failed_label = "loadlibrary_failed";

  gum_init_with_features ((GumFeatureFlags) (GUM_FEATURE_ALL & ~GUM_FEATURE_SYMBOL_LOOKUP));

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX); /* executable so debugger can be used to inspect code */
  gum_x86_writer_init (&cw, code);

  /* Put a placeholder for chaining to VirtualFree */
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XAX);

  /* Will clobber these */
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XSI);

  /* xbx = (RemoteWorkerContext *) lpParameter */
#if GLIB_SIZEOF_VOID_P == 4
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EBX, GUM_REG_ESP, (3 + 1) * sizeof (gpointer));
#else
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_RBX, GUM_REG_RCX);
#endif

  /* xsi = LoadLibrary (xbx->dll_path) */
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_REG_XCX, GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, dll_path));
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, GUM_CALL_SYSAPI, GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, load_library_impl),
      1,
      GUM_ARG_REGISTER, GUM_REG_XCX);
  gum_x86_writer_put_test_reg_reg (&cw, GUM_REG_XAX, GUM_REG_XAX);
  gum_x86_writer_put_jcc_near_label (&cw, GUM_X86_JZ, loadlibrary_failed_label, GUM_UNLIKELY);
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_XSI, GUM_REG_XAX);

  /* xax = GetProcAddress (xsi, xbx->zed_agent_main_string) */
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_REG_XDX,
      GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, zed_agent_main_string));
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, GUM_CALL_SYSAPI, GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, get_proc_address_impl),
      2,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDX);

  /* xax (xbx->data_string) */
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_REG_XCX, GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, data_string));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      1,
      GUM_ARG_REGISTER, GUM_REG_XCX);

  /* FreeLibrary (xsi) */
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, GUM_CALL_SYSAPI,
      GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, free_library_impl),
      1,
      GUM_ARG_REGISTER, GUM_REG_XSI);

#if GLIB_SIZEOF_VOID_P == 4
  /* Store away return address before we overwrite it on the stack */
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_ECX, GUM_REG_ESP, 3 * sizeof (gpointer));

  /* And address of VirtualFree also */
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EDX, GUM_REG_EBX, G_STRUCT_OFFSET (RemoteWorkerContext, virtual_free_impl));

  /* Set up argument list for VirtualFree on the stack */
  gum_x86_writer_put_mov_reg_offset_ptr_u32 (&cw, GUM_REG_ESP, (2 + 2) * sizeof (gpointer), MEM_RELEASE);
  gum_x86_writer_put_mov_reg_offset_ptr_u32 (&cw, GUM_REG_ESP, (2 + 1) * sizeof (gpointer), 0);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EAX, GUM_REG_EBX, G_STRUCT_OFFSET (RemoteWorkerContext, entrypoint));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_REG_ESP, (2 + 0) * sizeof (gpointer), GUM_REG_EAX);
#else
  /* Set up argument list for VirtualFree */
  gum_x86_writer_put_mov_reg_u32 (&cw, GUM_REG_R8D, MEM_RELEASE);
  gum_x86_writer_put_xor_reg_reg (&cw, GUM_REG_RDX, GUM_REG_RDX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RCX, GUM_REG_RBX, G_STRUCT_OFFSET (RemoteWorkerContext, entrypoint));

  /* Then fill in the placeholder */
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_RAX, GUM_REG_RBX, G_STRUCT_OFFSET (RemoteWorkerContext, virtual_free_impl));
  gum_x86_writer_put_mov_reg_offset_ptr_reg (&cw, GUM_REG_RSP, 2 * sizeof (gpointer), GUM_REG_RAX);
#endif

  /* Restore registers */
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XSI);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBX);

#if GLIB_SIZEOF_VOID_P == 4
  /* Make VirtualFree return to where we would have returned */
  gum_x86_writer_put_push_reg (&cw, GUM_REG_ECX);

  /* Put address of VirtualFree at the top of the stack so the ret will jump to it */
  gum_x86_writer_put_push_reg (&cw, GUM_REG_EDX);
#endif

  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, loadlibrary_failed_label);
  gum_x86_writer_put_int3 (&cw);

  gum_x86_writer_flush (&cw);
  code_size = gum_x86_writer_offset (&cw);
  gum_x86_writer_free (&cw);

  memset (rwc, 0, sizeof (RemoteWorkerContext));

  gum_module_enumerate_exports ("kernel32.dll", remote_worker_context_collect_kernel32_export, rwc);
  if (!remote_worker_context_has_resolved_all_kernel32_functions (rwc))
    goto failed_to_resolve_kernel32_functions;

  StringCbCopyA (rwc->zed_agent_main_string, sizeof (rwc->zed_agent_main_string), "zed_agent_main");

  StringCbCopyW (rwc->dll_path, sizeof (rwc->dll_path), details->dll_path);
  StringCbCopyA (rwc->data_string, sizeof (rwc->data_string), details->data_string);

  rwc->entrypoint = VirtualAllocEx (details->process_handle, NULL,
      code_size + data_alignment + sizeof (RemoteWorkerContext), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (rwc->entrypoint == NULL)
    goto virtual_alloc_failed;

  if (!WriteProcessMemory (details->process_handle, rwc->entrypoint, code, code_size, NULL))
    goto write_process_memory_failed;

  rwc->argument = GSIZE_TO_POINTER (
      (GPOINTER_TO_SIZE (rwc->entrypoint) + code_size + data_alignment - 1) & ~(data_alignment - 1));
  if (!WriteProcessMemory (details->process_handle, rwc->argument, rwc, sizeof (RemoteWorkerContext), NULL))
    goto write_process_memory_failed;

  gum_free_pages (code);
  return TRUE;

  /* ERRORS */
failed_to_resolve_kernel32_functions:
  {
    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_NOT_FOUND,
        "failed to resolve needed kernel32 functions");
    goto error_common;
  }
virtual_alloc_failed:
  {
    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "VirtualAlloc failed: %d",
        (gint) GetLastError ());
    goto error_common;
  }
write_process_memory_failed:
  {
    g_set_error (error,
        G_IO_ERROR,
        G_IO_ERROR_FAILED,
        "WriteProcessMemory failed: %d",
        (gint) GetLastError ());
    goto error_common;
  }
error_common:
  {
    cleanup_remote_worker_context (rwc, details);
    gum_free_pages (code);
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
remote_worker_context_has_resolved_all_kernel32_functions (const RemoteWorkerContext * rwc)
{
  return (rwc->load_library_impl != NULL) && (rwc->get_proc_address_impl != NULL) &&
      (rwc->free_library_impl != NULL) && (rwc->virtual_free_impl != NULL);
}

static gboolean
remote_worker_context_collect_kernel32_export (const gchar * name, GumAddress address, gpointer user_data)
{
  RemoteWorkerContext * rwc = (RemoteWorkerContext *) user_data;

  if (strcmp (name, "LoadLibraryW") == 0)
    rwc->load_library_impl = GSIZE_TO_POINTER (address);
  else if (strcmp (name, "GetProcAddress") == 0)
    rwc->get_proc_address_impl = GSIZE_TO_POINTER (address);
  else if (strcmp (name, "FreeLibrary") == 0)
    rwc->free_library_impl = GSIZE_TO_POINTER (address);
  else if (strcmp (name, "VirtualFree") == 0)
    rwc->virtual_free_impl = GSIZE_TO_POINTER (address);

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
set_grab_thread_error_from_os_error (const gchar * func_name, GError ** error)
{
  g_set_error (error,
      G_IO_ERROR,
      G_IO_ERROR_FAILED,
      "%s failed while trying to grab thread: %d",
      func_name, GetLastError ());
}

static void
set_trick_thread_error_from_os_error (const gchar * func_name, GError ** error)
{
  g_set_error (error,
      G_IO_ERROR,
      G_IO_ERROR_FAILED,
      "%s failed while trying to trick thread: %d",
      func_name, GetLastError ());
}
