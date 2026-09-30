#include <dlfcn.h>
#include <glib.h>

// 这个函数会被编译进 gd.so，Vala 层调的就是它
void LuoYe_Unblock(void) {
    typedef void (*UnblockFunc)(void);
    
    // 运行时动态去整个进程里抓取 Zygisk 引导 SO 里的 LuoYe_Unblock 符号
    UnblockFunc unblock = (UnblockFunc)dlsym(RTLD_DEFAULT, "LuoYe_Unblock");
    if (unblock) {
        unblock(); // 成功找到并调用，完成解冻
    } else {
        g_warning("Failed to find LuoYe_Unblock: %s", dlerror());
    }
}
