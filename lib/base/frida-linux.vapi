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

	[CCode (cheader_filename = "frida-linux-bpf.h", has_type_id = false)]
	public enum BpfCommand {
		MAP_CREATE,
		MAP_LOOKUP_ELEM,
		MAP_UPDATE_ELEM,
		PROG_LOAD,
	}

	[CCode (cheader_filename = "frida-linux-bpf.h", has_type_id = false)]
	public enum BpfMapType {
		HASH,
		ARRAY,
		PERCPU_ARRAY,
		STACK_TRACE,
		RINGBUF,
	}

	[CCode (cheader_filename = "frida-linux-bpf.h", has_type_id = false)]
	public enum BpfProgramType {
		TRACEPOINT,
		PERF_EVENT,
	}

	[CCode (cheader_filename = "frida-linux-bpf.h", cprefix = "FRIDA_BPF_STACK_TRACE_MAP_", has_type_id = false)]
	[Flags]
	public enum BpfStackTraceMapFlags {
		BUILD_ID,
	}

	[CCode (cheader_filename = "frida-linux-bpf.h", cprefix = "FRIDA_BPF_RINGBUF_", has_type_id = false)]
	[Flags]
	public enum BpfRingbufFlags {
		BUSY,
		DISCARD,
	}

	[CCode (cheader_filename = "frida-linux-bpf.h")]
	public const uint32 BPF_RINGBUF_HEADER_SIZE;

	[CCode (cheader_filename = "frida-linux-bpf.h", has_type_id = false)]
	public struct BpfAttrProgLoad {
		public uint32 prog_type;
		public uint32 insn_cnt;
		public uint64 insns;
		public uint64 license;
		public uint32 log_level;
		public uint32 log_size;
		public uint64 log_buf;
		public uint32 kern_version;
		public uint32 prog_flags;
		public char prog_name[16];
		public uint32 prog_ifindex;
		public uint32 expected_attach_type;
	}

	[CCode (cheader_filename = "frida-linux-bpf.h", has_type_id = false)]
	public struct BpfInsn {
		public uint8 code;
		public uint8 dst_src;
		public int16 off;
		public int32 imm;
	}

	[CCode (cheader_filename = "frida-linux-bpf.h", has_type_id = false)]
	public struct BpfAttrMapCreate {
		public BpfMapType map_type;
		public uint32 key_size;
		public uint32 value_size;
		public uint32 max_entries;
		public uint32 map_flags;
		public uint32 inner_map_fd;
		public uint32 numa_node;
		public char map_name[16];
		public uint32 map_ifindex;
		public uint32 btf_fd;
		public uint32 btf_key_type_id;
		public uint32 btf_value_type_id;
	}

	[CCode (cheader_filename = "frida-linux-bpf.h", has_type_id = false)]
	public struct BpfAttrMapElem {
		public uint32 map_fd;
		public uint64 key;
		public uint64 value;
		public uint64 flags;
	}

	[CCode (cheader_filename = "frida-linux-bpf.h")]
	public const uint BPF_ANY;

	[CCode (cheader_filename = "frida-linux-perf-event.h")]
	public const int PERF_EVENT_TYPE_SOFTWARE;

	[CCode (cheader_filename = "frida-linux-perf-event.h")]
	public const int PERF_EVENT_COUNT_SW_CPU_CLOCK;

	[CCode (cheader_filename = "frida-linux-perf-event.h", has_type_id = false)]
	public struct PerfEventAttr {
		public PerfEventType event_type;
		public uint32 size;
		public uint64 config;

		public uint64 sample_period;

		public uint64 sample_type;
		public uint64 read_format;

		public uint64 flags;

		public uint32 wakeup_events;
		public uint32 bp_type;

		public uint64 config1;
		public uint64 config2;
	}

	[CCode (cheader_filename = "frida-linux-perf-event.h", has_type_id = false)]
	public enum PerfEventType {
		SOFTWARE,
		TRACEPOINT,
	}

	[CCode (cheader_filename = "frida-linux-perf-event.h", has_type_id = false)]
	public enum PerfEventIoctl {
		ENABLE,
		DISABLE,
		SET_BPF,
	}
}
