#ifndef __FRIDA_QUICKJS_GLUE_H__
#define __FRIDA_QUICKJS_GLUE_H__

#include <quickjs.h>

int JSGlue_GetValueTag(JSValueConst v);
void JSGlue_FreeValue(JSContext *ctx, JSValue v);

#endif
