#include "zed-core.h"

#define VC_EXTRALEAN
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>

typedef struct _FindLocationContext FindLocationContext;
typedef struct _ZedDeviceInfo ZedDeviceInfo;

typedef gboolean (* ZedEnumerateDeviceFunc) (const ZedDeviceInfo * device_info, gpointer user_data);

struct _FindLocationContext
{
  WCHAR * udid;
  WCHAR * location;
};

struct _ZedDeviceInfo
{
  WCHAR * device_path;
  WCHAR * instance_id;
  WCHAR * friendly_name;
  WCHAR * location;

  HDEVINFO device_info_set;
  PSP_DEVINFO_DATA device_info_data;
};

static WCHAR * find_location_of_device_with_udid (const char * udid);
static gboolean compare_udid_and_store_location_if_matching (const ZedDeviceInfo * device_info, gpointer user_data);

static void zed_foreach_usb_device (const GUID * guid, ZedEnumerateDeviceFunc func, gpointer user_data);

static WCHAR * zed_read_device_registry_string_property (HANDLE info_set, SP_DEVINFO_DATA * info_data, DWORD prop_id);
static WCHAR * zed_read_registry_string (HKEY key, WCHAR * value_name);
static WCHAR * zed_read_registry_multi_string (HKEY key, WCHAR * value_name);
static gpointer zed_read_registry_value (HKEY key, WCHAR * value_name, DWORD expected_type);

static GUID GUID_APPLE_USB = { 0xF0B32BE3, 0x6678, 0x4879, 0x92, 0x30, 0x0E4, 0x38, 0x45, 0xD8, 0x05, 0xEE };

ZedImageData *
_zed_service_fruity_host_session_provider_extract_icon_for_udid (const char * udid)
{
  WCHAR * location = NULL;

  location = find_location_of_device_with_udid (udid);
  if (location == NULL)
    goto beach;
  wprintf (L"found with location '%s'\n", location);

beach:
  g_free (location);
  return NULL;
}

static gboolean
print_device (const ZedDeviceInfo * device_info, gpointer user_data)
{
  WCHAR * instance_id = NULL;
  DWORD instance_id_size;
  BOOL ret;
  HKEY devkey;

  wprintf (L"Found device '%s' with friendly_name '%s' and instance id '%s'\n", device_info->device_path, device_info->friendly_name, device_info->instance_id);

  devkey = SetupDiOpenDevRegKey (device_info->device_info_set, device_info->device_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
  if (devkey != INVALID_HANDLE_VALUE)
  {
    WCHAR * friendly_name;
    WCHAR * icons;

    friendly_name = zed_read_registry_string (devkey, L"FriendlyName");
    if (friendly_name != NULL)
      wprintf (L"\tGot '%s'\n", friendly_name);
    g_free (friendly_name);

    icons = zed_read_registry_multi_string (devkey, L"Icons");
    if (icons != NULL)
    {
      WCHAR * str = icons;

      wprintf (L"\tGot icons:\n");
      while (*str != L'\0')
      {
        wprintf (L"\t\t'%s'\n", str);
        str += wcslen (str) + 1;
      }
    }
    g_free (icons);

    RegCloseKey (devkey);
  }

  return TRUE;
}

static WCHAR *
find_location_of_device_with_udid (const char * udid)
{
  FindLocationContext ctx;

  ctx.udid = (WCHAR *) g_utf8_to_utf16 (udid, -1, NULL, NULL, NULL);
  ctx.location = NULL;

  zed_foreach_usb_device (&GUID_APPLE_USB, compare_udid_and_store_location_if_matching, &ctx);

  g_free (ctx.udid);

  return ctx.location;
}

static gboolean
compare_udid_and_store_location_if_matching (const ZedDeviceInfo * device_info, gpointer user_data)
{
  FindLocationContext * ctx = (FindLocationContext *) user_data;
  WCHAR * udid;

  udid = wcsrchr (device_info->instance_id, L'\\');
  if (udid == NULL)
    goto keep_looking;
  udid++;

  if (_wcsicmp (udid, ctx->udid) != 0)
    goto keep_looking;

  ctx->location = (WCHAR *) g_memdup (device_info->location, (wcslen (device_info->location) + 1) * sizeof (WCHAR));

  return FALSE;

keep_looking:
  return TRUE;
}

static void
zed_foreach_usb_device (const GUID * guid, ZedEnumerateDeviceFunc func, gpointer user_data)
{
  HANDLE info_set;
  gboolean carry_on = TRUE;
  guint member_index;

  info_set = SetupDiGetClassDevs (guid, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
  if (info_set == INVALID_HANDLE_VALUE)
    goto beach;

  for (member_index = 0; carry_on; member_index++)
  {
    SP_DEVICE_INTERFACE_DATA iface_data = { 0, };
    SP_DEVINFO_DATA info_data = { 0, };
    DWORD detail_size;
    SP_DEVICE_INTERFACE_DETAIL_DATA_W * detail_data = NULL;
    BOOL success;
    ZedDeviceInfo device_info = { 0, };
    DWORD instance_id_size;

    iface_data.cbSize = sizeof (iface_data);
    if (!SetupDiEnumDeviceInterfaces (info_set, NULL, guid, member_index, &iface_data))
      break;

    info_data.cbSize = sizeof (info_data);
    success = SetupDiGetDeviceInterfaceDetailW (info_set, &iface_data, NULL, 0, &detail_size, &info_data);
    if (!success && GetLastError () != ERROR_INSUFFICIENT_BUFFER)
      goto skip_device;

    detail_data = (SP_DEVICE_INTERFACE_DETAIL_DATA_W *) g_malloc (detail_size);
    detail_data->cbSize = sizeof (SP_DEVICE_INTERFACE_DETAIL_DATA_W);
    success = SetupDiGetDeviceInterfaceDetailW (info_set, &iface_data, detail_data, detail_size, NULL, &info_data);
    if (!success)
      goto skip_device;

    device_info.device_path = detail_data->DevicePath;

    success = SetupDiGetDeviceInstanceIdW (info_set, &info_data, NULL, 0, &instance_id_size);
    if (!success && GetLastError () != ERROR_INSUFFICIENT_BUFFER)
      goto skip_device;

    device_info.instance_id = (WCHAR *) g_malloc (instance_id_size * sizeof (WCHAR));
    success = SetupDiGetDeviceInstanceIdW (info_set, &info_data, device_info.instance_id, instance_id_size, NULL);
    if (!success)
      goto skip_device;

    device_info.friendly_name = zed_read_device_registry_string_property (info_set, &info_data, SPDRP_FRIENDLYNAME);

    device_info.location = zed_read_device_registry_string_property (info_set, &info_data, SPDRP_LOCATION_INFORMATION);

    device_info.device_info_set = info_set;
    device_info.device_info_data = &info_data;

    carry_on = func (&device_info, user_data);

skip_device:
    g_free (device_info.location);
    g_free (device_info.friendly_name);
    g_free (device_info.instance_id);

    g_free (detail_data);
  }

beach:
  if (info_set != INVALID_HANDLE_VALUE)
    SetupDiDestroyDeviceInfoList (info_set);
}

static WCHAR *
zed_read_device_registry_string_property (HANDLE info_set, SP_DEVINFO_DATA * info_data, DWORD prop_id)
{
  gboolean success = FALSE;
  WCHAR * value_buffer = NULL;
  DWORD value_size;
  BOOL ret;

  ret = SetupDiGetDeviceRegistryPropertyW (info_set, info_data, prop_id, NULL, NULL, 0, &value_size);
  if (!ret && GetLastError () != ERROR_INSUFFICIENT_BUFFER)
    goto beach;

  value_buffer = (WCHAR *) g_malloc (value_size);
  if (!SetupDiGetDeviceRegistryPropertyW (info_set, info_data, prop_id, NULL, (PBYTE) value_buffer, value_size, NULL))
    goto beach;

  success = TRUE;

beach:
  if (!success)
  {
    g_free (value_buffer);
    value_buffer = NULL;
  }

  return value_buffer;
}

static WCHAR *
zed_read_registry_string (HKEY key, WCHAR * value_name)
{
  return (WCHAR *) zed_read_registry_value (key, value_name, REG_SZ);
}

static WCHAR *
zed_read_registry_multi_string (HKEY key, WCHAR * value_name)
{
  return (WCHAR *) zed_read_registry_value (key, value_name, REG_MULTI_SZ);
}

static gpointer
zed_read_registry_value (HKEY key, WCHAR * value_name, DWORD expected_type)
{
  gboolean success = FALSE;
  DWORD type;
  WCHAR * buffer = NULL;
  DWORD base_size = 0, real_size;
  LONG ret;

  ret = RegQueryValueExW (key, value_name, NULL, &type, NULL, &base_size);
  if (ret != ERROR_SUCCESS || type != expected_type)
    goto beach;

  if (type == REG_SZ)
    real_size = base_size + sizeof (WCHAR);
  else if (type == REG_MULTI_SZ)
    real_size = base_size + 2 * sizeof (WCHAR);
  else
    real_size = base_size;
  buffer = (WCHAR *) g_malloc0 (real_size);
  ret = RegQueryValueExW (key, value_name, NULL, &type, (LPBYTE) buffer, &base_size);
  if (ret != ERROR_SUCCESS || type != expected_type)
    goto beach;

  success = TRUE;

beach:
  if (!success)
  {
    g_free (buffer);
    buffer = NULL;
  }

  return buffer;
}
