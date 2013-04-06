#ifndef __ZED_WINDOWS_ICON_HELPERS_H__
#define __ZED_WINDOWS_ICON_HELPERS_H__

#include "zed-core.h"

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

typedef enum _ZedIconSize ZedIconSize;

enum _ZedIconSize
{
  ZED_ICON_SMALL,
  ZED_ICON_LARGE
};

ZedImageData * _zed_image_data_from_process_or_file (DWORD pid, WCHAR * filename, ZedIconSize size);

ZedImageData * _zed_image_data_from_process (DWORD pid, ZedIconSize size);
ZedImageData * _zed_image_data_from_file (WCHAR * filename, ZedIconSize size);
ZedImageData * _zed_image_data_from_resource_url (WCHAR * resource_url, ZedIconSize size);

ZedImageData * _zed_image_data_from_native_icon_handle (HICON icon, ZedIconSize size);

#endif