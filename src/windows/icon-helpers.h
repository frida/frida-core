#ifndef __ZED_WINDOWS_ICON_HELPERS_H__
#define __ZED_WINDOWS_ICON_HELPERS_H__

#include "frida-core.h"

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

typedef enum _ZedIconSize FridaIconSize;

enum _ZedIconSize
{
  FRIDA_ICON_SMALL,
  FRIDA_ICON_LARGE
};

FridaImageData * _frida_image_data_from_process_or_file (DWORD pid, WCHAR * filename, FridaIconSize size);

FridaImageData * _frida_image_data_from_process (DWORD pid, FridaIconSize size);
FridaImageData * _frida_image_data_from_file (WCHAR * filename, FridaIconSize size);
FridaImageData * _frida_image_data_from_resource_url (WCHAR * resource_url, FridaIconSize size);

FridaImageData * _frida_image_data_from_native_icon_handle (HICON icon, FridaIconSize size);

#endif
