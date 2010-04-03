#include <windows.h>
#include <tlhelp32.h>

typedef struct _ZedServiceWinjectorInjectAsyncData
    ZedServiceWinjectorInjectAsyncData;

static void zed_service_winjector_inject_async_co (
    ZedServiceWinjectorInjectAsyncData * data);

#include "src/service/winjector.c"

static void
set_grab_thread_error_from_os_error (const gchar * func_name, GError ** err)
{
  g_set_error (err,
      ZED_SERVICE_WINJECTOR_ERROR,
      ZED_SERVICE_WINJECTOR_ERROR_GRAB_THREAD_FAILED,
      "%s failed: %d", func_name, GetLastError ());
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

static void
trick_thread_into_loading_dll (HANDLE thread_handle, const gchar * dll_path,
    GError ** err)
{
  g_assert_not_reached (); /* FIXME: work in progress */
}

static gpointer
injection_worker (ZedServiceWinjectorInjectAsyncData * data)
{
  GSimpleAsyncResult * res;
  HANDLE process_handle = NULL;
  HANDLE thread_handle = NULL;
  GError * err = NULL;

  res = data->_async_result;
  data->_async_result = NULL;

  process_handle = OpenProcess (
      PROCESS_DUP_HANDLE    | /* duplicatable handle                  */
      PROCESS_VM_OPERATION  | /* for VirtualProtectEx and mem access  */
      PROCESS_VM_READ       | /*   ReadProcessMemory                  */
      PROCESS_VM_WRITE,       /*   WriteProcessMemory                 */
      FALSE,                  /* children should not inherit this     */
      data->target_pid);
  if (process_handle == NULL)
  {
    g_simple_async_result_set_error (res,
        ZED_SERVICE_WINJECTOR_ERROR,
        ZED_SERVICE_WINJECTOR_ERROR_OPEN_PROCESS_FAILED,
        "OpenProcess(pid=%ld) failed: %d",
        data->target_pid, GetLastError ());
    goto beach;
  }

  while (TRUE)
  {
    if (g_cancellable_is_cancelled (data->cancellable))
      goto beach;

    thread_handle = try_to_grab_a_thread_in (data->target_pid, &err);
    if (err != NULL)
    {
      g_simple_async_result_set_from_error (res, err);
      g_clear_error (&err);
      goto beach;
    }

    if (thread_handle != NULL)
      break;

    Sleep (100);
  }

  trick_thread_into_loading_dll (thread_handle, data->filename, &err);
  if (err != NULL)
  {
    /* undo our suspend */
    ResumeThread (thread_handle);

    g_simple_async_result_set_from_error (res, err);
    g_clear_error (&err);

    goto beach;
  }

beach:
  if (thread_handle != NULL)
    CloseHandle (thread_handle);

  if (process_handle != NULL)
    CloseHandle (process_handle);

  g_simple_async_result_complete_in_idle (res);
  g_object_unref (res);

  return NULL;
}

static void
zed_service_winjector_inject_async_co (
    ZedServiceWinjectorInjectAsyncData * data)
{
  g_thread_create ((GThreadFunc) injection_worker, data, TRUE, NULL);
}

