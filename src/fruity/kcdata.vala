[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Kcdata {
	public delegate void ItemVisitor (ItemHeader header, BufferReader payload) throws Error;

	public struct ItemHeader {
		public ItemType type;
		public uint32 size;
		public uint64 flags;
	}

	public enum ItemType {
		INVALID							= 0x000u,
		STRING_DESC						= 0x001u,
		UINT32_DESC						= 0x002u,
		UINT64_DESC						= 0x003u,
		INT32_DESC						= 0x004u,
		INT64_DESC						= 0x005u,
		BINDATA_DESC						= 0x006u,

		ARRAY							= 0x011u,
		TYPEDEFINTION						= 0x012u,
		CONTAINER_BEGIN						= 0x013u,
		CONTAINER_END						= 0x014u,

		ARRAY_PAD0						= 0x020u,
		ARRAY_PAD1						= 0x021u,
		ARRAY_PAD2						= 0x022u,
		ARRAY_PAD3						= 0x023u,
		ARRAY_PAD4						= 0x024u,
		ARRAY_PAD5						= 0x025u,
		ARRAY_PAD6						= 0x026u,
		ARRAY_PAD7						= 0x027u,
		ARRAY_PAD8						= 0x028u,
		ARRAY_PAD9						= 0x029u,
		ARRAY_PADa						= 0x02au,
		ARRAY_PADb						= 0x02bu,
		ARRAY_PADc						= 0x02cu,
		ARRAY_PADd						= 0x02du,
		ARRAY_PADe						= 0x02eu,
		ARRAY_PADf						= 0x02fu,

		LIBRARY_LOADINFO					= 0x030u,
		LIBRARY_LOADINFO64					= 0x031u,
		TIMEBASE						= 0x032u,
		MACH_ABSOLUTE_TIME					= 0x033u,
		TIMEVAL							= 0x034u,
		USECS_SINCE_EPOCH					= 0x035u,
		PID							= 0x036u,
		PROCNAME						= 0x037u,
		NESTED_KCDATA						= 0x038u,
		LIBRARY_AOTINFO						= 0x039u,

		TASK_CRASHINFO_EXTMODINFO				= 0x801u,
		TASK_CRASHINFO_BSDINFOWITHUNIQID			= 0x802u,
		TASK_CRASHINFO_TASKDYLD_INFO				= 0x803u,
		TASK_CRASHINFO_UUID					= 0x804u,
		TASK_CRASHINFO_PID					= 0x805u,
		TASK_CRASHINFO_PPID					= 0x806u,
		TASK_CRASHINFO_RUSAGE					= 0x807u,
		TASK_CRASHINFO_RUSAGE_INFO				= 0x808u,
		TASK_CRASHINFO_PROC_NAME				= 0x809u,
		TASK_CRASHINFO_PROC_STARTTIME				= 0x80Bu,
		TASK_CRASHINFO_USERSTACK				= 0x80Cu,
		TASK_CRASHINFO_ARGSLEN					= 0x80Du,
		TASK_CRASHINFO_EXCEPTION_CODES				= 0x80Eu,
		TASK_CRASHINFO_PROC_PATH				= 0x80Fu,
		TASK_CRASHINFO_PROC_CSFLAGS				= 0x810u,
		TASK_CRASHINFO_PROC_STATUS				= 0x811u,
		TASK_CRASHINFO_UID					= 0x812u,
		TASK_CRASHINFO_GID					= 0x813u,
		TASK_CRASHINFO_PROC_ARGC				= 0x814u,
		TASK_CRASHINFO_PROC_FLAGS				= 0x815u,
		TASK_CRASHINFO_CPUTYPE					= 0x816u,
		TASK_CRASHINFO_WORKQUEUEINFO				= 0x817u,
		TASK_CRASHINFO_RESPONSIBLE_PID				= 0x818u,
		TASK_CRASHINFO_DIRTY_FLAGS				= 0x819u,
		TASK_CRASHINFO_CRASHED_THREADID				= 0x81Au,
		TASK_CRASHINFO_COALITION_ID				= 0x81Bu,
		TASK_CRASHINFO_UDATA_PTRS				= 0x81Cu,
		TASK_CRASHINFO_MEMORY_LIMIT				= 0x81Du,
		TASK_CRASHINFO_LEDGER_INTERNAL				= 0x81Eu,
		TASK_CRASHINFO_LEDGER_INTERNAL_COMPRESSED		= 0x81Fu,
		TASK_CRASHINFO_LEDGER_IOKIT_MAPPED			= 0x820u,
		TASK_CRASHINFO_LEDGER_ALTERNATE_ACCOUNTING		= 0x821u,
		TASK_CRASHINFO_LEDGER_ALTERNATE_ACCOUNTING_COMPRESSED	= 0x822u,
		TASK_CRASHINFO_LEDGER_PURGEABLE_NONVOLATILE		= 0x823u,
		TASK_CRASHINFO_LEDGER_PURGEABLE_NONVOLATILE_COMPRESSED	= 0x824u,
		TASK_CRASHINFO_LEDGER_PAGE_TABLE			= 0x825u,
		TASK_CRASHINFO_LEDGER_PHYS_FOOTPRINT			= 0x826u,
		TASK_CRASHINFO_LEDGER_PHYS_FOOTPRINT_LIFETIME_MAX	= 0x827u,
		TASK_CRASHINFO_LEDGER_NETWORK_NONVOLATILE		= 0x828u,
		TASK_CRASHINFO_LEDGER_NETWORK_NONVOLATILE_COMPRESSED	= 0x829u,
		TASK_CRASHINFO_LEDGER_WIRED_MEM				= 0x82Au,
		TASK_CRASHINFO_PROC_PERSONA_ID				= 0x82Bu,
		TASK_CRASHINFO_MEMORY_LIMIT_INCREASE			= 0x82Cu,
		TASK_CRASHINFO_LEDGER_TAGGED_FOOTPRINT			= 0x82Du,
		TASK_CRASHINFO_LEDGER_TAGGED_FOOTPRINT_COMPRESSED	= 0x82Eu,
		TASK_CRASHINFO_LEDGER_MEDIA_FOOTPRINT			= 0x82Fu,
		TASK_CRASHINFO_LEDGER_MEDIA_FOOTPRINT_COMPRESSED	= 0x830u,
		TASK_CRASHINFO_LEDGER_GRAPHICS_FOOTPRINT		= 0x831u,
		TASK_CRASHINFO_LEDGER_GRAPHICS_FOOTPRINT_COMPRESSED	= 0x832u,
		TASK_CRASHINFO_LEDGER_NEURAL_FOOTPRINT			= 0x833u,
		TASK_CRASHINFO_LEDGER_NEURAL_FOOTPRINT_COMPRESSED	= 0x834u,
		TASK_CRASHINFO_MEMORYSTATUS_EFFECTIVE_PRIORITY		= 0x835u,
		TASK_CRASHINFO_KERNEL_TRIAGE_INFO_V1			= 0x836u,
		TASK_CRASHINFO_TASK_IS_CORPSE_FORK			= 0x837u,
		TASK_CRASHINFO_EXCEPTION_TYPE				= 0x838u,
		TASK_CRASHINFO_CRASH_COUNT				= 0x839u,
		TASK_CRASHINFO_THROTTLE_TIMEOUT				= 0x83Au,
		TASK_CRASHINFO_CS_SIGNING_ID				= 0x83Bu,
		TASK_CRASHINFO_CS_TEAM_ID				= 0x83Cu,
		TASK_CRASHINFO_CS_VALIDATION_CATEGORY			= 0x83Du,
		TASK_CRASHINFO_CS_TRUST_LEVEL				= 0x83Eu,
		TASK_CRASHINFO_PROC_CPUTYPE				= 0x83Fu,
		TASK_CRASHINFO_JIT_ADDRESS_RANGE			= 0x840u,
		TASK_CRASHINFO_MB					= 0x841u,
		TASK_CRASHINFO_CS_AUXILIARY_INFO			= 0x842u,
		TASK_CRASHINFO_RLIM_CORE				= 0x843u,
		TASK_CRASHINFO_CORE_ALLOWED				= 0x844u,
		TASK_CRASHINFO_TASK_SECURITY_CONFIG			= 0x845u,

		STACKSHOT_IOSTATS					= 0x901u,
		STACKSHOT_GLOBAL_MEM_STATS				= 0x902u,
		STACKSHOT_CONTAINER_TASK				= 0x903u,
		STACKSHOT_CONTAINER_THREAD				= 0x904u,
		STACKSHOT_TASK_SNAPSHOT					= 0x905u,
		STACKSHOT_THREAD_SNAPSHOT				= 0x906u,
		STACKSHOT_DONATING_PIDS					= 0x907u,
		STACKSHOT_SHAREDCACHE_LOADINFO				= 0x908u,
		STACKSHOT_THREAD_NAME					= 0x909u,
		STACKSHOT_KERN_STACKFRAME				= 0x90Au,
		STACKSHOT_KERN_STACKFRAME64				= 0x90Bu,
		STACKSHOT_USER_STACKFRAME				= 0x90Cu,
		STACKSHOT_USER_STACKFRAME64				= 0x90Du,
		STACKSHOT_BOOTARGS					= 0x90Eu,
		STACKSHOT_OSVERSION					= 0x90Fu,
		STACKSHOT_KERN_PAGE_SIZE				= 0x910u,
		STACKSHOT_JETSAM_LEVEL					= 0x911u,
		STACKSHOT_DELTA_SINCE_TIMESTAMP				= 0x912u,
		STACKSHOT_KERN_STACKLR					= 0x913u,
		STACKSHOT_KERN_STACKLR64				= 0x914u,
		STACKSHOT_USER_STACKLR					= 0x915u,
		STACKSHOT_USER_STACKLR64				= 0x916u,
		STACKSHOT_NONRUNNABLE_TIDS				= 0x917u,
		STACKSHOT_NONRUNNABLE_TASKS				= 0x918u,
		STACKSHOT_CPU_TIMES					= 0x919u,
		STACKSHOT_STACKSHOT_DURATION				= 0x91au,
		STACKSHOT_STACKSHOT_FAULT_STATS				= 0x91bu,
		STACKSHOT_KERNELCACHE_LOADINFO				= 0x91cu,
		STACKSHOT_THREAD_WAITINFO				= 0x91du,
		STACKSHOT_THREAD_GROUP_SNAPSHOT				= 0x91eu,
		STACKSHOT_THREAD_GROUP					= 0x91fu,
		STACKSHOT_JETSAM_COALITION_SNAPSHOT			= 0x920u,
		STACKSHOT_JETSAM_COALITION				= 0x921u,
		STACKSHOT_THREAD_POLICY_VERSION				= 0x922u,
		STACKSHOT_INSTRS_CYCLES					= 0x923u,
		STACKSHOT_USER_STACKTOP					= 0x924u,
		STACKSHOT_ASID						= 0x925u,
		STACKSHOT_PAGE_TABLES					= 0x926u,
		STACKSHOT_SYS_SHAREDCACHE_LAYOUT			= 0x927u,
		STACKSHOT_THREAD_DISPATCH_QUEUE_LABEL			= 0x928u,
		STACKSHOT_THREAD_TURNSTILEINFO				= 0x929u,
		STACKSHOT_TASK_CPU_ARCHITECTURE				= 0x92au,
		STACKSHOT_LATENCY_INFO					= 0x92bu,
		STACKSHOT_LATENCY_INFO_TASK				= 0x92cu,
		STACKSHOT_LATENCY_INFO_THREAD				= 0x92du,
		STACKSHOT_LOADINFO64_TEXT_EXEC				= 0x92eu,
		STACKSHOT_AOTCACHE_LOADINFO				= 0x92fu,
		STACKSHOT_TRANSITIONING_TASK_SNAPSHOT			= 0x930u,
		STACKSHOT_CONTAINER_TRANSITIONING_TASK			= 0x931u,
		STACKSHOT_USER_ASYNC_START_INDEX			= 0x932u,
		STACKSHOT_USER_ASYNC_STACKLR64				= 0x933u,
		STACKSHOT_CONTAINER_PORTLABEL				= 0x934u,
		STACKSHOT_PORTLABEL					= 0x935u,
		STACKSHOT_PORTLABEL_NAME				= 0x936u,
		STACKSHOT_DYLD_COMPACTINFO				= 0x937u,
		STACKSHOT_SUSPENSION_INFO				= 0x938u,
		STACKSHOT_SUSPENSION_SOURCE				= 0x939u,
		STACKSHOT_TASK_DELTA_SNAPSHOT				= 0x940u,
		STACKSHOT_THREAD_DELTA_SNAPSHOT				= 0x941u,
		STACKSHOT_CONTAINER_SHAREDCACHE				= 0x942u,
		STACKSHOT_SHAREDCACHE_INFO				= 0x943u,
		STACKSHOT_SHAREDCACHE_AOTINFO				= 0x944u,
		STACKSHOT_SHAREDCACHE_ID				= 0x945u,
		STACKSHOT_CODESIGNING_INFO				= 0x946u,
		STACKSHOT_OS_BUILD_VERSION				= 0x947u,
		STACKSHOT_KERN_EXCLAVES_THREADINFO			= 0x948u,
		STACKSHOT_CONTAINER_EXCLAVES				= 0x949u,
		STACKSHOT_CONTAINER_EXCLAVE_SCRESULT			= 0x94au,
		STACKSHOT_EXCLAVE_SCRESULT_INFO				= 0x94bu,
		STACKSHOT_CONTAINER_EXCLAVE_IPCSTACKENTRY		= 0x94cu,
		STACKSHOT_EXCLAVE_IPCSTACKENTRY_INFO			= 0x94du,
		STACKSHOT_EXCLAVE_IPCSTACKENTRY_ECSTACK			= 0x94eu,
		STACKSHOT_CONTAINER_EXCLAVE_ADDRESSSPACE		= 0x94fu,
		STACKSHOT_EXCLAVE_ADDRESSSPACE_INFO			= 0x950u,
		STACKSHOT_EXCLAVE_ADDRESSSPACE_NAME			= 0x951u,
		STACKSHOT_CONTAINER_EXCLAVE_TEXTLAYOUT			= 0x952u,
		STACKSHOT_EXCLAVE_TEXTLAYOUT_INFO			= 0x953u,
		STACKSHOT_EXCLAVE_TEXTLAYOUT_SEGMENTS			= 0x954u,
		STACKSHOT_KERN_EXCLAVES_CRASH_THREADINFO		= 0x955u,
		STACKSHOT_LATENCY_INFO_CPU				= 0x956u,
		STACKSHOT_TASK_EXEC_META				= 0x957u,
		STACKSHOT_TASK_MEMORYSTATUS				= 0x958u,
		STACKSHOT_LATENCY_INFO_BUFFER				= 0x95au,

		TASK_BTINFO_PID						= 0xA01u,
		TASK_BTINFO_PPID					= 0xA02u,
		TASK_BTINFO_PROC_NAME					= 0xA03u,
		TASK_BTINFO_PROC_PATH					= 0xA04u,
		TASK_BTINFO_UID						= 0xA05u,
		TASK_BTINFO_GID						= 0xA06u,
		TASK_BTINFO_PROC_FLAGS					= 0xA07u,
		TASK_BTINFO_CPUTYPE					= 0xA08u,
		TASK_BTINFO_EXCEPTION_CODES				= 0xA09u,
		TASK_BTINFO_EXCEPTION_TYPE				= 0xA0Au,
		TASK_BTINFO_RUSAGE_INFO					= 0xA0Bu,
		TASK_BTINFO_COALITION_ID				= 0xA0Cu,
		TASK_BTINFO_CRASH_COUNT					= 0xA0Du,
		TASK_BTINFO_THROTTLE_TIMEOUT				= 0xA0Eu,
		TASK_BTINFO_THREAD_ID					= 0xA20u,
		TASK_BTINFO_THREAD_NAME					= 0xA21u,
		TASK_BTINFO_THREAD_STATE				= 0xA22u,
		TASK_BTINFO_THREAD_EXCEPTION_STATE			= 0xA23u,
		TASK_BTINFO_BACKTRACE					= 0xA24u,
		TASK_BTINFO_BACKTRACE64					= 0xA25u,
		TASK_BTINFO_ASYNC_BACKTRACE64				= 0xA26u,
		TASK_BTINFO_ASYNC_START_INDEX				= 0xA27u,
		TASK_BTINFO_PLATFORM					= 0xA28u,
		TASK_BTINFO_SC_LOADINFO					= 0xA29u,
		TASK_BTINFO_SC_LOADINFO64				= 0xA2Au,
		TASK_BTINFO_FLAGS					= 0xAFFu,

		BUFFER_BEGIN_XNUPOST_CONFIG				= 0x1e21c09fu,
		BUFFER_BEGIN_COMPRESSED					= 0x434f4d50u,
		BUFFER_BEGIN_BTINFO					= 0x46414E47u,
		BUFFER_BEGIN_STACKSHOT					= 0x59a25807u,
		BUFFER_BEGIN_OS_REASON					= 0x53A20900u,
		BUFFER_BEGIN_DELTA_STACKSHOT				= 0xDE17A59Au,
		BUFFER_BEGIN_CRASHINFO					= 0xDEADF157u,
		BUFFER_END						= 0xF19158EDu;

		public string to_nick () {
			return Marshal.enum_to_nick<ItemType> (this);
		}
	}

	[Flags]
	public enum StackshotFlagsLow {
		GET_DQ                           = (1U << 0),
		SAVE_LOADINFO                    = (1U << 1),
		GET_GLOBAL_MEM_STATS             = (1U << 2),
		SAVE_KEXT_LOADINFO               = (1U << 3),
		ACTIVE_KERNEL_THREADS_ONLY       = (1U << 8),
		GET_BOOT_PROFILE                 = (1U << 9),
		DO_COMPRESS                      = (1U << 10),
		SAVE_IMP_DONATION_PIDS           = (1U << 13),
		SAVE_IN_KERNEL_BUFFER            = (1U << 14),
		RETRIEVE_EXISTING_BUFFER         = (1U << 15),
		KCDATA_FORMAT                    = (1U << 16),
		ENABLE_BT_FAULTING               = (1U << 17),
		COLLECT_DELTA_SNAPSHOT           = (1U << 18),
		COLLECT_SHAREDCACHE_LAYOUT       = (1U << 19),
		TRYLOCK                          = (1U << 20),
		ENABLE_UUID_FAULTING             = (1U << 21),
		FROM_PANIC                       = (1U << 22),
		NO_IO_STATS                      = (1U << 23),
		THREAD_WAITINFO                  = (1U << 24),
		THREAD_GROUP                     = (1U << 25),
		SAVE_JETSAM_COALITIONS           = (1U << 26),
		INSTRS_CYCLES                    = (1U << 27),
		ASID                             = (1U << 28),
		PAGE_TABLES                      = (1U << 29),
		DISABLE_LATENCY_INFO             = (1U << 30),
		SAVE_DYLD_COMPACTINFO            = (1U << 31)
	}

	[Flags]
	public enum StackshotFlagsHigh {
		INCLUDE_DRIVER_THREADS_IN_KERNEL = (1U << 0),
		EXCLAVES                         = (1U << 1),
		SKIP_EXCLAVES                    = (1U << 2),
	}

	private const size_t HEADER_SIZE = 16;
	private const size_t ALIGNMENT_SIZE = 16;

	public sealed class Reader : Object {
		public size_t offset {
			get {
				return r.offset;
			}
		}

		public size_t available {
			get {
				return r.available;
			}
		}

		public bool eof {
			get {
				return r.available == 0;
			}
		}

		private Buffer buf;
		private BufferReader r;

		private Buffer payload_buf;
		private BufferReader payload_r;

		public Reader (Bytes bytes) {
			buf = new Buffer (bytes, LITTLE_ENDIAN);
			r = new BufferReader (buf);

			payload_buf = new Buffer.from_data ((uint8[]) null, buf.byte_order, buf.pointer_size);
			payload_r = new BufferReader (payload_buf);
		}

		public ItemHeader peek_header () throws Error {
			if (r.available < HEADER_SIZE)
				throw new Error.PROTOCOL ("KCDATA truncated at %zu (need header, avail=%zu)", r.offset, r.available);

			size_t item_start = r.offset;

			var h = ItemHeader ();
			h.type = (ItemType) buf.read_uint32 (item_start);
			h.size = buf.read_uint32 (item_start + 4);
			h.flags = buf.read_uint64 (item_start + 8);

			if (h.size > (r.available - HEADER_SIZE)) {
				throw new Error.PROTOCOL ("KCDATA truncated at %zu (type=0x%x size=%u avail=%zu)", item_start,
					(uint32) h.type, h.size, r.available - HEADER_SIZE);
			}

			return h;
		}

		public ItemHeader read_header () throws Error {
			if (r.available < HEADER_SIZE)
				throw new Error.PROTOCOL ("KCDATA truncated at %zu (need header, avail=%zu)", r.offset, r.available);

			size_t item_start = r.offset;

			var h = ItemHeader ();
			h.type = (ItemType) r.read_uint32 ();
			h.size = r.read_uint32 ();
			h.flags = r.read_uint64 ();

			if (h.size > r.available) {
				throw new Error.PROTOCOL ("KCDATA truncated at %zu (type=0x%x size=%u avail=%zu)", item_start,
					(uint32) h.type, h.size, r.available);
			}

			return h;
		}

		public unowned BufferReader read_payload (ItemHeader h) throws Error {
			unowned uint8[] payload = r.read_data (h.size);

			payload_buf.reset_data (payload);
			payload_r.reset (payload_buf);

			r.align (ALIGNMENT_SIZE);

			return payload_r;
		}

		public void skip_payload (ItemHeader h) throws Error {
			read_payload (h);
		}

		public bool read_item (out ItemHeader h, out unowned BufferReader payload) throws Error {
			if (r.available == 0) {
				h = ItemHeader ();
				payload = null;
				return false;
			}

			h = read_header ();
			payload = read_payload (h);
			return true;
		}
	}

	public void parse (Bytes bytes, ItemVisitor visitor) throws Error {
		var r = new Reader (bytes);

		ItemHeader h;
		unowned BufferReader payload;

		while (r.read_item (out h, out payload))
			visitor (h, payload);
	}

	public sealed class Dumper : Object {
		private uint indent;

		public void run (Bytes bytes) throws Error {
			Frida.Kcdata.parse (bytes, on_item);
		}

		private void on_item (ItemHeader h, BufferReader p) throws Error {
			if (h.type == ItemType.CONTAINER_END) {
				if (indent != 0)
					indent--;
			}

			print_prefix ();
			stdout.printf ("%s size=%u flags=0x%016" + uint64.FORMAT + "\n",
				h.type.to_nick (), h.size, h.flags);

			switch (h.type) {
				case BUFFER_BEGIN_STACKSHOT:
				case BUFFER_END:
					break;
				case CONTAINER_BEGIN:
					dump_container_begin (p);
					indent++;
					break;
				case UINT32_DESC:
					dump_uint32_desc (p);
					break;
				case UINT64_DESC:
					dump_uint64_desc (p);
					break;
				default:
					break;
			}
		}

		private void dump_container_begin (BufferReader p) throws Error {
			var container_type = (ItemType) p.read_uint32 ();
			uint32 container_id = p.read_uint32 ();

			print_prefix ();
			stdout.printf ("                type=%s id=0x%08x\n", container_type.to_nick (), container_id);
		}

		private void dump_uint32_desc (BufferReader p) throws Error {
			unowned string name = p.read_string ();
			p.seek (32);

			uint32 val = p.read_uint32 ();

			print_prefix ();
			stdout.printf ("uint32-desc %s=%u (0x%08x)\n", name, val, val);
		}

		private void dump_uint64_desc (BufferReader p) throws Error {
			unowned string name = p.read_string ();
			p.seek (32);

			uint64 val = p.read_uint64 ();

			print_prefix ();
			if (name == "stackshot_in_flags") {
				var low = (StackshotFlagsLow) (val & 0xffffffffU);
				var high = (StackshotFlagsHigh) (val >> 32);
				stdout.printf ("uint64-desc %s high=%s low=%s\n",
					name,
					high.to_string ().replace ("FRIDA_KCDATA_STACKSHOT_FLAGS_HIGH_", ""),
					low.to_string ().replace ("FRIDA_KCDATA_STACKSHOT_FLAGS_LOW_", ""));
			} else {
				stdout.printf ("uint64-desc %s=%" + uint64.FORMAT_MODIFIER + "u (0x%016" + uint64.FORMAT_MODIFIER + "x)\n",
					name, val, val);
			}
		}

		private void print_prefix () {
			for (uint i = 0; i != indent; i++)
				stdout.putc ('\t');
		}
	}
}
