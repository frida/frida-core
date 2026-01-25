[CCode (cheader_filename = "frida-atomics.h")]
namespace Frida.Atomics {
	public static uint64 load_u64_acquire (void * p);
	public static void store_u64_release (void * p, uint64 v);
	public static uint32 load_u32_acquire (void * p);
}
