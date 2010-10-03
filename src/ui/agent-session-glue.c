#include "zed-core.h"

#include <udis86.h>

#ifdef G_OS_WIN32
# ifdef WINVER
#  undef WINVER
# endif
# define WINVER 0x0600
# ifdef _WIN32_WINNT
#  undef _WIN32_WINNT
# endif
# define _WIN32_WINNT 0x0600
# define VC_EXTRALEAN
# include <windows.h>
# define CINTERFACE
# define COBJMACROS
# include <shobjidl.h>
static gchar * ask_for_filename_windows (const gchar * title);
#endif

static gchar * ask_for_filename_fallback (const gchar * title);

char *
zed_presenter_agent_session_disassemble (ZedPresenterAgentSession * self, guint64 pc, guint8 * bytes, int bytes_length1, guint * instruction_length)
{
  ud_t ud_obj;

  ud_init (&ud_obj);
  ud_set_mode (&ud_obj, 32);
  ud_set_syntax (&ud_obj, UD_SYN_INTEL);
  ud_set_pc (&ud_obj, pc);
  ud_set_input_buffer (&ud_obj, bytes, bytes_length1);

  *instruction_length = ud_disassemble (&ud_obj);

  return g_strdup (ud_insn_asm (&ud_obj));
}

char *
zed_file_open_dialog_ask_for_filename (const gchar * title)
{
#ifdef G_OS_WIN32
  OSVERSIONINFO osvi = { 0, };
  gboolean is_vista_or_later;

  osvi.dwOSVersionInfoSize = sizeof (osvi);

  GetVersionEx (&osvi);

  is_vista_or_later = (osvi.dwMajorVersion >= 6);
  if (is_vista_or_later)
    return ask_for_filename_windows (title);
#endif

  return ask_for_filename_fallback (title);
}

#ifdef G_OS_WIN32

static gchar *
ask_for_filename_windows (const gchar * title)
{
  gchar * result = NULL;
  gunichar2 * title_utf16 = NULL;
  HRESULT hr;
  IFileDialog * fd = NULL;
  IShellItem * si = NULL;
  LPWSTR filename_utf16 = NULL;

  title_utf16 = g_utf8_to_utf16 (title, -1, NULL, NULL, NULL);

  hr = CoCreateInstance (&CLSID_FileOpenDialog, NULL, CLSCTX_INPROC_SERVER, &IID_IFileDialog, (LPVOID *) &fd);
  if (!SUCCEEDED (hr))
    goto beach;

  hr = IFileDialog_SetTitle (fd, (LPCWSTR) title_utf16);
  if (!SUCCEEDED (hr))
    goto beach;

  hr = IFileDialog_Show (fd, NULL);
  if (!SUCCEEDED (hr))
    goto beach;

  hr = IFileDialog_GetResult (fd, &si);
  if (!SUCCEEDED (hr))
    goto beach;

  hr = IShellItem_GetDisplayName (si, SIGDN_FILESYSPATH, &filename_utf16);
  if (!SUCCEEDED (hr))
    goto beach;

  result = g_utf16_to_utf8 ((gunichar2 *) filename_utf16, -1, NULL, NULL, NULL);

beach:
  CoTaskMemFree (filename_utf16);

  if (si != NULL)
    IShellItem_Release (si);

  if (fd != NULL)
    IFileDialog_Release (fd);

  g_free (title_utf16);

  return result;
}

#endif /* G_OS_WIN32 */

static gchar *
ask_for_filename_fallback (const gchar * title)
{
  gchar * result = NULL;
  GtkWidget * dialog;

  dialog = gtk_file_chooser_dialog_new (title, NULL, GTK_FILE_CHOOSER_ACTION_OPEN,
      GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
      GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
      NULL);
  if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT)
    result = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
  gtk_widget_destroy (dialog);

  return result;
}
