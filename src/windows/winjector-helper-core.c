#include "winjector-helper.h"

#include <gio/gio.h>
#include <gum/gum.h>
#include <gum/arch-x86/gumx86writer.h>

#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>

#define CHECK_OS_RESULT(n1, cmp, n2, op) \
  if (!((n1) cmp (n2))) \
  { \
    failed_operation = op; \
    goto os_failure; \
  }

#define CHECK_NT_RESULT(n1, cmp, n2, op) \
  if (!((n1) cmp (n2))) \
  { \
    failed_operation = op; \
    goto nt_failure; \
  }

typedef struct _InjectInstance InjectInstance;
typedef struct _InjectionDetails InjectionDetails;
typedef struct _RemoteWorkerContext RemoteWorkerContext;

struct _InjectInstance
{
  HANDLE process_handle;
  gpointer free_address;
  gpointer stay_resident_address;
};

struct _InjectionDetails
{
  HANDLE process_handle;
  const WCHAR * dll_path;
  const gchar * entrypoint_name;
  const gchar * entrypoint_data;
};

struct _RemoteWorkerContext
{
  gboolean stay_resident;

  gpointer load_library_impl;
  gpointer get_proc_address_impl;
  gpointer free_library_impl;
  gpointer virtual_free_impl;
  gpointer get_last_error_impl;

  WCHAR dll_path[MAX_PATH + 1];
  gchar entrypoint_name[256];
  gchar entrypoint_data[MAX_PATH + 1];

  gpointer entrypoint;
  gpointer argument;
};

typedef struct _RtlClientId RtlClientId;

struct _RtlClientId
{
  SIZE_T unique_process;
  SIZE_T unique_thread;
};

typedef NTSTATUS (WINAPI * RtlCreateUserThreadFunc) (HANDLE process, SECURITY_DESCRIPTOR * sec,
    BOOLEAN create_suspended, ULONG stack_zero_bits, SIZE_T * stack_reserved, SIZE_T * stack_commit,
    LPTHREAD_START_ROUTINE start_address, LPVOID parameter, HANDLE * thread_handle, RtlClientId * result);

static gboolean enable_debug_privilege (void);

static gboolean initialize_remote_worker_context (RemoteWorkerContext * rwc, InjectionDetails * details, GError ** error);
static void cleanup_remote_worker_context (RemoteWorkerContext * rwc, InjectionDetails * details);

static gboolean remote_worker_context_has_resolved_all_kernel32_functions (const RemoteWorkerContext * rwc);
static gboolean remote_worker_context_collect_kernel32_export (const GumExportDetails * details, gpointer user_data);

static gboolean file_exists_and_is_readable (const WCHAR * filename);

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
winjector_process_is_x64 (guint32 pid)
{
  HANDLE process_handle;
  BOOL is_wow64, success;

  if (!winjector_system_is_x64 ())
    return FALSE;

  process_handle = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, pid);
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
winjector_process_inject_library_file (guint32 pid, const gchar * path, const gchar * entrypoint, const gchar * data,
    void ** inject_instance, void ** waitable_thread_handle, GError ** error)
{
  gboolean success = FALSE;
  const gchar * failed_operation;
  NTSTATUS nt_status;
  InjectionDetails details;
  DWORD desired_access;
  HANDLE thread_handle = NULL;
  gboolean rwc_initialized = FALSE;
  RemoteWorkerContext rwc;
  InjectInstance * instance;

  details.dll_path = (WCHAR *) g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
  details.entrypoint_name = entrypoint;
  details.entrypoint_data = data;
  details.process_handle = NULL;

  if (!file_exists_and_is_readable (details.dll_path))
    goto invalid_path;

  enable_debug_privilege ();

  desired_access =
      PROCESS_DUP_HANDLE    | /* duplicatable handle                  */
      PROCESS_VM_OPERATION  | /* for VirtualProtectEx and mem access  */
      PROCESS_VM_READ       | /*   ReadProcessMemory                  */
      PROCESS_VM_WRITE      | /*   WriteProcessMemory                 */
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;

  details.process_handle = OpenProcess (desired_access, FALSE, pid);
  CHECK_OS_RESULT (details.process_handle, !=, NULL, "OpenProcess");

  if (!initialize_remote_worker_context (&rwc, &details, error))
    goto beach;
  rwc_initialized = TRUE;

  thread_handle = CreateRemoteThread (details.process_handle, NULL, 0, GUM_POINTER_TO_FUNCPTR (LPTHREAD_START_ROUTINE, rwc.entrypoint), rwc.argument, 0, NULL);
  if (thread_handle == NULL)
  {
    RtlCreateUserThreadFunc rtl_create_user_thread;
    RtlClientId client_id;

    rtl_create_user_thread = (RtlCreateUserThreadFunc) GetProcAddress (GetModuleHandleW (L"ntdll.dll"), "RtlCreateUserThread");
    nt_status = rtl_create_user_thread (details.process_handle, NULL, FALSE, 0, NULL, NULL,
        GUM_POINTER_TO_FUNCPTR (LPTHREAD_START_ROUTINE, rwc.entrypoint), rwc.argument, &thread_handle, &client_id);
    CHECK_NT_RESULT (nt_status, == , 0, "RtlCreateUserThread");
  }

  instance = g_slice_new (InjectInstance);
  instance->process_handle = details.process_handle;
  details.process_handle = NULL;
  instance->free_address = rwc.entrypoint;
  instance->stay_resident_address = (guint8 *) rwc.argument + G_STRUCT_OFFSET (RemoteWorkerContext, stay_resident);
  *inject_instance = instance;

  *waitable_thread_handle = thread_handle;
  thread_handle = NULL;

  success = TRUE;

  goto beach;

  /* ERRORS */
invalid_path:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_INVALID_ARGUMENT,
        "Unable to find DLL at '%s'",
        path);
    goto beach;
  }
os_failure:
  {
    DWORD os_error;

    os_error = GetLastError ();

    if (details.process_handle == NULL && os_error == ERROR_INVALID_PARAMETER)
    {
      g_set_error (error,
          FRIDA_ERROR,
          FRIDA_ERROR_PROCESS_NOT_FOUND,
          "Unable to find process with pid %u",
          pid);
    }
    else
    {
      g_set_error (error,
          FRIDA_ERROR,
          (os_error == ERROR_ACCESS_DENIED) ? FRIDA_ERROR_PERMISSION_DENIED : FRIDA_ERROR_NOT_SUPPORTED,
          "Unexpected error while attaching to process with pid %u (%s returned 0x%08lx)",
          pid, failed_operation, os_error);
    }

    goto beach;
  }
nt_failure:
  {
    gint code;

    if (nt_status == 0xC0000022) /* STATUS_ACCESS_DENIED */
      code = FRIDA_ERROR_PERMISSION_DENIED;
    else
      code = FRIDA_ERROR_NOT_SUPPORTED;

    g_set_error (error,
        FRIDA_ERROR,
        code,
        "Unexpected error while attaching to process with pid %u (%s returned 0x%08lx)",
        pid, failed_operation, nt_status);
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
  }
}

void
winjector_process_free_inject_instance (void * inject_instance, gboolean * is_resident)
{
  InjectInstance * instance = inject_instance;
  gboolean stay_resident;
  SIZE_T n_bytes_read;

  if (ReadProcessMemory (instance->process_handle, instance->stay_resident_address, &stay_resident, sizeof (stay_resident), &n_bytes_read) &&
      n_bytes_read == sizeof (stay_resident))
  {
    *is_resident = stay_resident;
  }
  else
  {
    *is_resident = FALSE;
  }

  VirtualFreeEx (instance->process_handle, instance->free_address, 0, MEM_RELEASE);

  CloseHandle (instance->process_handle);

  g_slice_free (InjectInstance, instance);
}

static gboolean
enable_debug_privilege (void)
{
  static gboolean enabled = FALSE;
  gboolean success = FALSE;
  HANDLE token = NULL;
  TOKEN_PRIVILEGES privileges;
  LUID_AND_ATTRIBUTES * p = &privileges.Privileges[0];

  if (enabled)
    return TRUE;

  if (!OpenProcessToken (GetCurrentProcess (), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token))
    goto beach;

  privileges.PrivilegeCount = 1;
  if (!LookupPrivilegeValueW (NULL, L"SeDebugPrivilege", &p->Luid))
    goto beach;
  p->Attributes = SE_PRIVILEGE_ENABLED;

  if (!AdjustTokenPrivileges (token, FALSE, &privileges, 0, NULL, NULL))
    goto beach;

  if (GetLastError () == ERROR_NOT_ALL_ASSIGNED)
    goto beach;

  enabled = TRUE;
  success = TRUE;

beach:
  if (token != NULL)
    CloseHandle (token);

  return success;
}

static gboolean
initialize_remote_worker_context (RemoteWorkerContext * rwc,
    InjectionDetails * details, GError ** error)
{
  gpointer code;
  guint code_size;
  GumX86Writer cw;
  const gsize data_alignment = 4;
  const gchar * loadlibrary_failed = "loadlibrary_failed";
  const gchar * skip_unload = "skip_unload";
  const gchar * return_result = "return_result";

  gum_init ();

  code = gum_alloc_n_pages (1, GUM_PAGE_RWX); /* Executable so debugger can be used to inspect code */
  gum_x86_writer_init (&cw, code);

  /* Will clobber these */
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XSI);
  gum_x86_writer_put_push_reg (&cw, GUM_REG_XDI); /* Alignment padding */

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
  gum_x86_writer_put_jcc_near_label (&cw, X86_INS_JE, loadlibrary_failed, GUM_UNLIKELY);
  gum_x86_writer_put_mov_reg_reg (&cw, GUM_REG_XSI, GUM_REG_XAX);

  /* xax = GetProcAddress (xsi, xbx->entrypoint_name) */
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_REG_XDX,
      GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, entrypoint_name));
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, GUM_CALL_SYSAPI, GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, get_proc_address_impl),
      2,
      GUM_ARG_REGISTER, GUM_REG_XSI,
      GUM_ARG_REGISTER, GUM_REG_XDX);

  /* xax (xbx->entrypoint_data, &stay_resident, NULL) */
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_REG_XCX, GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, entrypoint_data));
  gum_x86_writer_put_lea_reg_reg_offset (&cw, GUM_REG_XDX, GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, stay_resident));
  gum_x86_writer_put_call_reg_with_arguments (&cw, GUM_CALL_CAPI, GUM_REG_XAX,
      3,
      GUM_ARG_REGISTER, GUM_REG_XCX,
      GUM_ARG_REGISTER, GUM_REG_XDX,
      GUM_ARG_ADDRESS, GUM_ADDRESS (0));

  /* if (!stay_resident) { */
  gum_x86_writer_put_mov_reg_reg_offset_ptr (&cw, GUM_REG_EAX, GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, stay_resident));
  gum_x86_writer_put_test_reg_reg (&cw, GUM_REG_EAX, GUM_REG_EAX);
  gum_x86_writer_put_jcc_short_label (&cw, X86_INS_JNE, skip_unload, GUM_NO_HINT);

  /* FreeLibrary (xsi) */
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, GUM_CALL_SYSAPI,
      GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, free_library_impl),
      1,
      GUM_ARG_REGISTER, GUM_REG_XSI);

  /* } */
  gum_x86_writer_put_label (&cw, skip_unload);

  /* result = ERROR_SUCCESS */
  gum_x86_writer_put_xor_reg_reg (&cw, GUM_REG_EAX, GUM_REG_EAX);
  gum_x86_writer_put_jmp_short_label (&cw, return_result);

  gum_x86_writer_put_label (&cw, loadlibrary_failed);
  /* result = GetLastError() */
  gum_x86_writer_put_call_reg_offset_ptr_with_arguments (&cw, GUM_CALL_SYSAPI,
      GUM_REG_XBX, G_STRUCT_OFFSET (RemoteWorkerContext, get_last_error_impl),
      0);

  gum_x86_writer_put_label (&cw, return_result);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XDI);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XSI);
  gum_x86_writer_put_pop_reg (&cw, GUM_REG_XBX);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  code_size = gum_x86_writer_offset (&cw);
  gum_x86_writer_clear (&cw);

  memset (rwc, 0, sizeof (RemoteWorkerContext));

  gum_module_enumerate_exports ("kernel32.dll", remote_worker_context_collect_kernel32_export, rwc);
  if (!remote_worker_context_has_resolved_all_kernel32_functions (rwc))
    goto failed_to_resolve_kernel32_functions;

  StringCbCopyW (rwc->dll_path, sizeof (rwc->dll_path), details->dll_path);
  StringCbCopyA (rwc->entrypoint_name, sizeof (rwc->entrypoint_name), details->entrypoint_name);
  StringCbCopyA (rwc->entrypoint_data, sizeof (rwc->entrypoint_data), details->entrypoint_data);

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
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error while resolving kernel32 functions");
    goto error_common;
  }
virtual_alloc_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error allocating memory in target process (VirtualAlloc returned 0x%08lx)",
        GetLastError ());
    goto error_common;
  }
write_process_memory_failed:
  {
    g_set_error (error,
        FRIDA_ERROR,
        FRIDA_ERROR_NOT_SUPPORTED,
        "Unexpected error writing to memory in target process (WriteProcessMemory returned 0x%08lx)",
        GetLastError ());
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
remote_worker_context_collect_kernel32_export (const GumExportDetails * details, gpointer user_data)
{
  RemoteWorkerContext * rwc = (RemoteWorkerContext *) user_data;

  if (details->type != GUM_EXPORT_FUNCTION)
    return TRUE;

  if (strcmp (details->name, "LoadLibraryW") == 0)
    rwc->load_library_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "GetProcAddress") == 0)
    rwc->get_proc_address_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "FreeLibrary") == 0)
    rwc->free_library_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "VirtualFree") == 0)
    rwc->virtual_free_impl = GSIZE_TO_POINTER (details->address);
  else if (strcmp (details->name, "GetLastError") == 0)
    rwc->get_last_error_impl = GSIZE_TO_POINTER (details->address);

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
