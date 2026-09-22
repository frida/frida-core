[CCode (lower_case_cprefix = "", gir_namespace = "FreeBSD", gir_version = "1.0")]
namespace FreeBSD {
	[CCode (cheader_filename = "libutil.h")]
	public int openpty (out int amaster, out int aslave, [CCode (array_length=false, array_null_terminated=true)] char[] name,
		Posix.termios? termp, winsize? winp);

	[CCode (cname = "struct winsize", has_type_id = false, cheader_filename = "sys/ttycom.h", destroy_function = "")]
	public struct winsize {
		public ushort ws_row;
		public ushort ws_col;
		public ushort ws_xpixel;
		public ushort ws_ypixel;
	}

	[CCode (cheader_filename = "unistd.h")]
	public int execve (string path, [CCode (array_length = false, array_null_terminated = true)] string[] argv,
		[CCode (array_length = false, array_null_terminated = true)] string[]? envp);

	[CCode (cheader_filename = "unistd.h")]
	public int rfork_thread (RforkFlags flags, void * stack, RforkThreadFunc func, void * arg);

	[CCode (has_target = false)]
	public delegate int RforkThreadFunc (void * arg);

	[CCode (cheader_filename = "unistd.h", cname = "int", cprefix = "RF", has_type_id = false)]
	[Flags]
	public enum RforkFlags {
		PROC,
		CFDG,
		MEM,
	}

	[CCode (cheader_filename = "sys/event.h")]
	public int kqueue ();

	[CCode (cheader_filename = "sys/event.h")]
	public int kevent (int kq, KEvent * changelist, int nchanges, KEvent * eventlist, int nevents,
		Posix.timespec? timeout);

	[CCode (cname = "struct kevent", cheader_filename = "sys/event.h", has_type_id = false, has_copy_function = false,
		has_destroy_function = false)]
	public struct KEvent {
		public ulong ident;
		public EventFilter filter;
		public EventFlags flags;
		public ProcEvent fflags;
		public long data;
		public void * udata;
	}

	[CCode (cheader_filename = "sys/event.h", cname = "short", cprefix = "EVFILT_", has_type_id = false)]
	public enum EventFilter {
		PROC,
	}

	[CCode (cheader_filename = "sys/event.h", cname = "unsigned short", cprefix = "EV_", has_type_id = false)]
	[Flags]
	public enum EventFlags {
		ADD,
		ENABLE,
		CLEAR,
	}

	[CCode (cheader_filename = "sys/event.h", cname = "unsigned int", cprefix = "NOTE_", has_type_id = false)]
	[Flags]
	public enum ProcEvent {
		FORK,
		EXEC,
		TRACK,
		CHILD,
	}

	[CCode (cheader_filename = "sys/ptrace.h", cname = "int", cprefix = "PT_", has_type_id = false)]
	public enum PtraceRequest {
		TRACE_ME,
		CONTINUE,
		STEP,
		KILL,
		ATTACH,
		DETACH,
		IO,
		LWPINFO,
		GETLWPLIST,
		GETREGS,
		SETREGS,
		SUSPEND,
		LWP_EVENTS,
	}

	[CCode (cname = "struct ptrace_io_desc", cheader_filename = "sys/ptrace.h", has_type_id = false, has_copy_function = false,
		has_destroy_function = false)]
	public struct PtraceIoDesc {
		public PtraceIoOp piod_op;
		public void * piod_offs;
		public void * piod_addr;
		public size_t piod_len;
	}

	[CCode (cheader_filename = "sys/ptrace.h", cname = "int", cprefix = "PIOD_", has_type_id = false)]
	public enum PtraceIoOp {
		READ_D,
		WRITE_D,
	}

	[CCode (cname = "struct ptrace_lwpinfo", cheader_filename = "sys/ptrace.h", has_type_id = false, has_copy_function = false,
		has_destroy_function = false)]
	public struct PtraceLwpInfo {
		public int pl_lwpid;
		public int pl_event;
		public PtraceLwpFlags pl_flags;
	}

	[CCode (cheader_filename = "sys/ptrace.h", cname = "int", cprefix = "PL_FLAG_", has_type_id = false)]
	[Flags]
	public enum PtraceLwpFlags {
		EXEC,
	}

	[CCode (cname = "struct reg", cheader_filename = "machine/reg.h", has_type_id = false, has_copy_function = false,
		has_destroy_function = false)]
	public struct Regs {
		public int64 r_r10;
		public int64 r_r9;
		public int64 r_r8;
		public int64 r_rdi;
		public int64 r_rsi;
		public int64 r_rdx;
		public int64 r_rcx;
		public int64 r_rax;
		public int64 r_rip;
		public int64 r_rsp;
	}

	[CCode (cheader_filename = "unistd.h,sys/syscall.h")]
	public long syscall (Syscall number, ...);

	[CCode (cheader_filename = "sys/syscall.h", cname = "int", has_type_id = false)]
	public enum Syscall {
		[CCode (cname = "SYS_ptrace")]
		PTRACE,
		[CCode (cname = "SYS_mmap")]
		MMAP,
		[CCode (cname = "SYS_munmap")]
		MUNMAP,
		[CCode (cname = "SYS_close")]
		CLOSE,
		[CCode (cname = "SYS_dup2")]
		DUP2,
		[CCode (cname = "SYS_socket")]
		SOCKET,
		[CCode (cname = "SYS_setsockopt")]
		SETSOCKOPT,
		[CCode (cname = "SYS_thr_set_name")]
		THR_SET_NAME,
		[CCode (cname = "SYS_thr_kill2")]
		THR_KILL2,
	}

	[CCode (cheader_filename = "sys/mman.h")]
	public const int MAP_ANONYMOUS;

	[CCode (cheader_filename = "netinet/in.h")]
	public const int IPV6_TCLASS;

	[CCode (cheader_filename = "netinet/in.h")]
	public const int IPV6_PKTINFO;
}
