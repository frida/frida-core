namespace Frida.Test {

	public static void run (string[] args) {
		Environment.init (ref args);

		Frida.SystemTest.add_tests ();

#if WINDOWS
		Frida.WinjectorTest.add_tests ();
#elif LINUX
		Frida.LinjectorTest.add_tests ();
#elif QNX
		Frida.QinjectorTest.add_tests ();
#elif DARWIN
		Frida.FruitjectorTest.add_tests ();
#endif

		Frida.AgentTest.add_tests ();
#if !WINDOWS
		Frida.GadgetTest.add_tests ();
#endif
		Frida.HostSessionTest.add_tests ();

		GLib.Test.run ();

		Environment.deinit ();
	}

	namespace Environment {
		public extern void init ([CCode (array_length_pos = 0.9)] ref unowned string[] args);
		public extern void deinit ();
	}

	public extern OS os ();

	public extern CPU cpu ();

	public extern Libc libc ();

	public string arch_suffix () {
		string os_name;
		switch (os ()) {
			case OS.LINUX:
				os_name = "linux";
				break;
			case OS.ANDROID:
				os_name = "android";
				break;
			case OS.QNX:
				os_name = "qnx";
				break;
			default:
				assert_not_reached ();
		}

		string cpu_name;
		switch (Frida.Test.cpu ()) {
			case CPU.X86_32:
				cpu_name = "i386";
				break;
			case CPU.X86_64:
				cpu_name = "x86_64";
				break;
			case CPU.ARM_32:
				cpu_name = "arm";
				break;
			case CPU.ARM_64:
				cpu_name = "arm64";
				break;
			case CPU.MIPS:
				cpu_name = "mips";
				break;
			case CPU.MIPSEL:
				cpu_name = "mipsel";
				break;
			default:
				assert_not_reached ();
		}

		return "-" + os_name + "-" + cpu_name;
	}

	public enum OS {
		WINDOWS,
		MAC,
		LINUX,
		IOS,
		ANDROID,
		QNX
	}

	public enum CPU {
		X86_32,
		X86_64,
		ARM_32,
		ARM_64,
		MIPS,
		MIPSEL
	}

	public enum Arch {
		CURRENT,
		OTHER
	}

	public enum Libc {
		MSVCRT,
		APPLE,
		GLIBC,
		UCLIBC,
		BIONIC
	}
}
