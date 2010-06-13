#include "zed-core.h"

#define VC_EXTRALEAN
#include <windows.h>
#include <psapi.h>

typedef struct _FindMainWindowCtx FindMainWindowCtx;
typedef enum _IconSize IconSize;

struct _FindMainWindowCtx
{
  DWORD pid;
  HWND main_window;
};

enum _IconSize
{
  ICON_SIZE_SMALL,
  ICON_SIZE_LARGE
};

static GdkPixbuf * extract_icon_from_process_or_file (DWORD pid,
    WCHAR * filename, IconSize size);

static GdkPixbuf * extract_icon_from_process (DWORD pid, IconSize size);
static GdkPixbuf * extract_icon_from_file (WCHAR * filename, IconSize size);

static GdkPixbuf * create_pixbuf_from_icon (HICON icon, IconSize size);
static void destroy_bitmap (guchar * pixels, gpointer data);
static HWND find_main_window_of_pid (DWORD pid);
static BOOL CALLBACK inspect_window (HWND hwnd, LPARAM lparam);

ZedProcessInfo **
zed_service_process_list_enumerate_processes (int * result_length1)
{
  GPtrArray * processes;
  DWORD * pids = NULL;
  DWORD size = 64 * sizeof (DWORD);
  DWORD bytes_returned;
  guint i;

  processes = g_ptr_array_new ();

  do
  {
    size *= 2;
    pids = (DWORD *) g_realloc (pids, size);
    if (!EnumProcesses (pids, size, &bytes_returned))
      bytes_returned = 0;
  }
  while (bytes_returned == size);

  for (i = 0; i != bytes_returned / sizeof (DWORD); i++)
  {
    HANDLE handle;

    handle = OpenProcess (PROCESS_QUERY_INFORMATION, FALSE, pids[i]);
    if (handle != NULL)
    {
      WCHAR name_utf16[MAX_PATH];
      DWORD name_length = MAX_PATH;

      if (QueryFullProcessImageNameW (handle, 0, name_utf16, &name_length))
      {
        gchar * name, * tmp;
        ZedProcessInfo * process_info;
        GdkPixbuf * small_icon, * large_icon;

        name = g_utf16_to_utf8 ((gunichar2 *) name_utf16, -1, NULL, NULL, NULL);
        tmp = g_path_get_basename (name);
        g_free (name);
        name = tmp;

        small_icon = extract_icon_from_process_or_file (pids[i], name_utf16,
            ICON_SIZE_SMALL);
        large_icon = extract_icon_from_process_or_file (pids[i], name_utf16,
            ICON_SIZE_LARGE);

        process_info = zed_process_info_new (pids[i], name, small_icon, large_icon);
        g_ptr_array_add (processes, process_info);

        g_free (name);
      }

      CloseHandle (handle);
    }
  }

  g_free (pids);

  *result_length1 = processes->len;
  return (ZedProcessInfo **) g_ptr_array_free (processes, FALSE);
}

static GdkPixbuf *
extract_icon_from_process_or_file (DWORD pid, WCHAR * filename, IconSize size)
{
  GdkPixbuf * icon;

  icon = extract_icon_from_process (pid, size);
  if (icon == NULL)
    icon = extract_icon_from_file (filename, size);

  return icon;
}

static GdkPixbuf *
extract_icon_from_process (DWORD pid, IconSize size)
{
  GdkPixbuf * pixbuf = NULL;
  HICON icon = NULL;
  HWND main_window;

  main_window = find_main_window_of_pid (pid);
  if (main_window != NULL)
  {
    UINT flags, timeout;

    flags = SMTO_ABORTIFHUNG | SMTO_BLOCK;
    timeout = 100;

    if (size == ICON_SIZE_SMALL)
    {
      SendMessageTimeout (main_window, WM_GETICON, ICON_SMALL2, 0,
          flags, timeout, (PDWORD_PTR) &icon);

      if (icon == NULL)
      {
        SendMessageTimeout (main_window, WM_GETICON, ICON_SMALL, 0,
            flags, timeout, (PDWORD_PTR) &icon);
      }

      if (icon == NULL)
        icon = (HICON) GetClassLongPtr (main_window, GCL_HICONSM);
    }
    else if (size == ICON_SIZE_LARGE)
    {
      SendMessageTimeout (main_window, WM_GETICON, ICON_BIG, 0,
          flags, timeout, (PDWORD_PTR) &icon);

      if (icon == NULL)
        icon = (HICON) GetClassLongPtr (main_window, GCL_HICON);

      if (icon == NULL)
      {
        SendMessageTimeout (main_window, WM_QUERYDRAGICON, 0, 0,
            flags, timeout, (PDWORD_PTR) &icon);
      }
    }
    else
    {
      g_assert_not_reached ();
    }
  }

  if (icon != NULL)
    pixbuf = create_pixbuf_from_icon (icon, size);

  return pixbuf;
}

static GdkPixbuf *
extract_icon_from_file (WCHAR * filename, IconSize size)
{
  GdkPixbuf * pixbuf = NULL;
  SHFILEINFO shfi = { 0, };
  UINT flags;

  flags = SHGFI_ICON;
  if (size == ICON_SIZE_SMALL)
    flags |= SHGFI_SMALLICON;
  else if (size == ICON_SIZE_LARGE)
    flags |= SHGFI_LARGEICON;
  else
    g_assert_not_reached ();

  SHGetFileInfoW (filename, 0, &shfi, sizeof (shfi), flags);
  if (shfi.hIcon != NULL)
    pixbuf = create_pixbuf_from_icon (shfi.hIcon, size);

  return pixbuf;
}

static GdkPixbuf *
create_pixbuf_from_icon (HICON icon, IconSize size)
{
  GdkPixbuf * pixbuf;
  HDC dc;
  gint width = -1, height = -1;
  BITMAPV5HEADER bi = { 0, };
  guint rowstride;
  guchar * data = NULL;
  HBITMAP bm;
  guint i;

  dc = CreateCompatibleDC (NULL);

  if (size == ICON_SIZE_SMALL)
  {
    width = GetSystemMetrics (SM_CXSMICON);
    height = GetSystemMetrics (SM_CYSMICON);
  }
  else if (size == ICON_SIZE_LARGE)
  {
    width = GetSystemMetrics (SM_CXICON);
    height = GetSystemMetrics (SM_CYICON);
  }
  else
  {
    g_assert_not_reached ();
  }

  bi.bV5Size = sizeof (bi);
  bi.bV5Width = width;
  bi.bV5Height = -height;
  bi.bV5Planes = 1;
  bi.bV5BitCount = 32;
  bi.bV5Compression = BI_BITFIELDS;
  bi.bV5RedMask   = 0x00ff0000;
  bi.bV5GreenMask = 0x0000ff00;
  bi.bV5BlueMask  = 0x000000ff;
  bi.bV5AlphaMask = 0xff000000;

  rowstride = width * (bi.bV5BitCount / 8);

  bm = CreateDIBSection (dc, (BITMAPINFO *) &bi, DIB_RGB_COLORS,
      (void **) &data, NULL, 0);

  SelectObject (dc, bm);
  DrawIconEx (dc, 0, 0, icon, width, height, 0, NULL, DI_NORMAL);
  GdiFlush ();

  for (i = 0; i != rowstride * height; i += 4)
  {
    guchar hold;

    hold = data[i + 0];
    data[i + 0] = data[i + 2];
    data[i + 2] = hold;
  }

  pixbuf = gdk_pixbuf_new_from_data (data, GDK_COLORSPACE_RGB, TRUE, 8,
      width, height, rowstride, destroy_bitmap, bm);

  DeleteDC (dc);

  return pixbuf;
}

static void
destroy_bitmap (guchar * pixels, gpointer data)
{
  HBITMAP bm = (HBITMAP) data;
  BOOL success;

  success = DeleteObject (bm);
  g_assert (success);
}

static HWND
find_main_window_of_pid (DWORD pid)
{
  FindMainWindowCtx ctx;

  ctx.pid = pid;
  ctx.main_window = NULL;

  EnumWindows (inspect_window, (LPARAM) &ctx);

  return ctx.main_window;
}

static BOOL CALLBACK
inspect_window (HWND hwnd, LPARAM lparam)
{
  if ((GetWindowLong (hwnd, GWL_STYLE) & WS_VISIBLE) != 0)
  {
    FindMainWindowCtx * ctx = (FindMainWindowCtx *) lparam;
    DWORD pid;

    GetWindowThreadProcessId (hwnd, &pid);
    if (pid == ctx->pid)
    {
      ctx->main_window = hwnd;
      return FALSE;
    }
  }

  return TRUE;
}
