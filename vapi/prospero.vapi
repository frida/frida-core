[CCode (lower_case_cprefix = "", gir_namespace = "Prospero", gir_version = "1.0")]
namespace Prospero {
	[CCode (cname = "FRIDA_PROSPERO_AGENT_ARGS_SYMBOL", cheader_filename = "frida-prospero.h")]
	public const string AGENT_ARGS_SYMBOL;

	[CCode (cname = "FridaProsperoAgentArgs", cheader_filename = "frida-prospero.h", has_type_id = false, has_copy_function = false,
		has_destroy_function = false)]
	public struct AgentArgs {
		public Gum.Address agent_parameters;
		public int fifo_fd;
		public int agent_ctrlfd;
		public Gum.MemoryRange mapped_range;
	}

	[CCode (cheader_filename = "frida-prospero.h")]
	public int sceUserServiceInitialize (void * params);

	[CCode (cheader_filename = "frida-prospero.h")]
	public int sceUserServiceGetForegroundUser (out uint32 user_id);

	[CCode (cheader_filename = "frida-prospero.h")]
	public int sceSystemServiceLaunchApp (string title_id,
		[CCode (array_length = false, array_null_terminated = true)] string[] argv, ref AppLaunchContext ctx);

	[CCode (cname = "FridaProsperoAppLaunchContext", cheader_filename = "frida-prospero.h", has_type_id = false,
		has_copy_function = false, has_destroy_function = false)]
	public struct AppLaunchContext {
		public uint32 size;
		public uint32 user_id;
		public uint32 app_opt;
		public uint64 crash_report;
		public uint32 check_flag;
	}

	[CCode (cheader_filename = "ps5/nid.h")]
	public unowned string nid_encode (string sym, [CCode (array_length = false)] char[] buf);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public const uint64 KERNEL_ADDRESS_DATA_BASE;

	[CCode (cheader_filename = "ps5/kernel.h")]
	public int kernel_mprotect (int pid, uint64 address, size_t size, int prot);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public int kernel_overlap_sockets (int pid, int master_sock, int victim_sock);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public uint64 kernel_get_proc_file (int pid, int fd);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public uint64 kernel_dynlib_resolve (int pid, uint32 handle, [CCode (array_length = false)] char[] nid);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public uint64 kernel_dynlib_entry_addr (int pid, uint32 handle);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public uint64 kernel_get_root_vnode ();

	[CCode (cheader_filename = "ps5/kernel.h")]
	public uint64 kernel_get_proc_rootdir (int pid);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public int32 kernel_set_proc_rootdir (int pid, uint64 vnode);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public uint64 kernel_get_proc_jaildir (int pid);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public int32 kernel_set_proc_jaildir (int pid, uint64 vnode);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public uint kernel_get_ucred_uid (int pid);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public int32 kernel_set_ucred_uid (int pid, uint uid);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public uint64 kernel_get_ucred_authid (int pid);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public int32 kernel_set_ucred_authid (int pid, uint64 authid);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public int32 kernel_get_ucred_caps (int pid, [CCode (array_length = false)] uint8[] caps);

	[CCode (cheader_filename = "ps5/kernel.h")]
	public int32 kernel_set_ucred_caps (int pid, [CCode (array_length = false)] uint8[] caps);
}
