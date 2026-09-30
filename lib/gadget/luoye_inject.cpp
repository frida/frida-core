#include <dlfcn.h>
#include <glib.h>

// 桥接函数，编译进 gd.so，由 Vala 层调用
void notify_luoye_unblock_bridge(void) {
    typedef void (*UnblockFunc)(void);
    
    // 运行时动态去整个进程（全局 RTLD_DEFAULT）抓取 Zygisk 引导 SO 里的 LuoYe_Unblock 符号
    UnblockFunc unblock = (UnblockFunc)dlsym(RTLD_DEFAULT, "LuoYe_Unblock");
    if (unblock) {
        unblock(); // 成功跨 SO 调用到 Zygisk 侧，完成解冻
    } else {
        g_warning("Failed to find LuoYe_Unblock: %s", dlerror());
    }
}
