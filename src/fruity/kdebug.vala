[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	public enum KdebugClass {
		MACH = 1,
		BSD = 4,
		TRACE = 7,
		PERF = 37,

		ANY = 0xff,
	}

	public enum KdebugMachSubclass {
		EXCP_SC = 12,
	}

	public enum KdebugBsdSubclass {
		EXCP_SC = 12,
	}

	public enum KdebugTraceSubclass {
		DATA,
		STRING,
		INFO,
	}

	public enum KdebugTraceDataEvent {
		NEWTHREAD = 1,
		EXEC,
		THREAD_TERMINATE,
		THREAD_TERMINATE_PID,
	}

	public enum KdebugTraceStringEvent {
		GLOBAL,
		NEWTHREAD,
		EXEC,
		PROC_EXIT,
		THREADNAME,
		THREADNAME_PREV,
	}

	public enum KdebugPerfSubclass {
		GENERIC,
		THREADINFO,
		CALLSTACK,
		TIMER,
		PET,
		AST,
		KPC,
		KDBG,
		TASK,
		LAZY,
		MEMINFO,
	}

	public enum KdebugPerfCallstackEvent {
		KSAMPLE,
		UPEND,
		USAMPLE,
		KDATA,
		UDATA,
		KHDR,
		UHDR,
		ERROR,
		BACKTRACE,
		LOG,
		EXHDR,
		EXDATA,
		EXSTACKHDR,
		EXSTACK,
		KEXOFFSET,
	}

	public const uint8 KDEBUG_SUBCLASS_ANY = 0xff;

	public const uint16 KDEBUG_CODE_ANY = 0x3fff;

	public enum KdebugFunctionQualifier {
		NONE,
		START,
		END,
	}

	public struct KdebugCode {
		public uint32 raw;

		public KdebugCode (uint32 raw) {
			this.raw = raw;
		}

		public KdebugCode.from_parts (
				KdebugClass klass,
				uint8 subclass = KDEBUG_SUBCLASS_ANY,
				uint16 code = KDEBUG_CODE_ANY,
				KdebugFunctionQualifier func_qual = NONE) {
			raw =
				(((uint32) klass & 0xff) << 24) |
				(((uint32) subclass & 0xff) << 16) |
				(((uint32) code & 0x3fff) << 2) |
				((uint32) func_qual & 0x3);
		}

		public KdebugClass klass {
			get {
				return (KdebugClass) ((raw >> 24) & 0xff);
			}
		}

		public uint8 subclass {
			get {
				return (uint8) ((raw >> 16) & 0xff);
			}
		}

		public uint16 code {
			get {
				return (uint16) ((raw >> 2) & 0x3fff);
			}
		}

		public KdebugFunctionQualifier func_qual {
			get {
				return (KdebugFunctionQualifier) (raw & 0x3);
			}
		}
	}
}
