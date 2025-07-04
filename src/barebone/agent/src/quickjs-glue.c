#include "quickjs-glue.h"

int JSGlue_GetValueTag(JSValueConst v)
{
    return JS_VALUE_GET_TAG(v);
}

void JSGlue_FreeValue(JSContext *ctx, JSValue v)
{
    JS_FreeValue(ctx, v);
}
