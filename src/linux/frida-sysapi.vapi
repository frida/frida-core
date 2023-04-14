namespace Frida {
	[CCode (cheader_filename = "dlfcn.h", cname = "dlopen")]
	public void * dlopen (string filename, int flags);

	[CCode (cheader_filename = "dlfcn.h", cname = "dlclose")]
	public int dlclose (void * handle);

	[CCode (cheader_filename = "dlfcn.h", cname = "dlsym")]
	public void * dlsym (void * handle, string symbol);

	[CCode (cheader_filename = "dlfcn.h", cname = "dlerror")]
	public unowned string dlerror ();

	[CCode (cheader_filename = "sys/mman.h", cname = "MAP_ANONYMOUS")]
	public const int MAP_ANONYMOUS;

	[CCode (cheader_filename = "linux/frida-syscall.h", cprefix = "SYS_", has_type_id = false)]
	public enum SysCall {
		memfd_create,
		pidfd_getfd,
		pidfd_open,
		process_vm_readv,
		process_vm_writev,
		tgkill,
	}
}
