#include <cstdlib>
#include <cstdint>
#include <cstdio>
#include <android/log.h>
#include <glib.h>

#define LOG_TAG "LuoyeInject"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

extern "C" {
    void notify_luoye_unblock_bridge(void) {
        typedef void (*UnblockFunc)(void);
        
        // 直接从环境变量中读取 Zygisk 传过来的内存绝对地址
        const char* ptr_str = getenv("LUOYE_UNBLOCK_PTR");
        if (ptr_str) {
            uintptr_t addr = 0;
            // 将十六进制字符串（如 0x7b8c...）还原为数字指针
            if (sscanf(ptr_str, "%lx", &addr) == 1 && addr != 0) {
                UnblockFunc unblock = reinterpret_cast<UnblockFunc>(addr);
                unblock(); // 跨越 .so 边界，直接精准执行 Zygisk 里的唤醒函数！
                LOGI("[Gadget-Bridge] 成功通过环境变量内存地址唤醒 Zygisk 主线程！");
                return;
            }
        }
        
        g_warning("Failed to parse LUOYE_UNBLOCK_PTR from environment!");
    }
}
