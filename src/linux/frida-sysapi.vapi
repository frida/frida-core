namespace Frida {
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
