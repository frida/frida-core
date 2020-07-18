namespace Frida {
	public bool can_test_cross_arch_injection =
#if CROSS_ARCH
		true
#else
		false
#endif
		;
}

namespace Frida.Test {
	public static void run (string[] args) {
		Environment.init (ref args);

		if (os () == MACOS && cpu () == X86_64) {
			try {
				string raw_version;
				GLib.Process.spawn_command_line_sync ("sw_vers -productVersion", out raw_version);

				string[] tokens = raw_version.strip ().split (".");
				assert (tokens.length >= 2);

				uint major = uint.parse (tokens[0]);
				uint minor = uint.parse (tokens[1]);

				bool newer_than_mojave = major > 10 || (major == 10 && minor > 4);
				if (newer_than_mojave)
					can_test_cross_arch_injection = false;
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		Frida.SystemTest.add_tests ();

		Frida.InjectorTest.add_tests ();

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

	public static string path_to_temporary_file (string name) {
		var tests_dir = Path.get_dirname (Process.current.filename);
		return Path.build_filename (tests_dir, name);
	}

	public extern OS os ();

	public extern CPU cpu ();

	public extern Libc libc ();

	public string os_arch_suffix (Arch arch = Arch.CURRENT) {
		switch (os ()) {
			case OS.MACOS:
				return "-macos";
			case OS.IOS:
				return "-ios";
		}

		string os_name;
		switch (os ()) {
			case OS.WINDOWS:
				os_name = "windows";
				break;
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
				cpu_name = "x86";
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

	public string os_executable_suffix () {
		switch (os ()) {
			case OS.WINDOWS:
				return ".exe";
			case OS.MACOS:
			case OS.LINUX:
			case OS.IOS:
			case OS.ANDROID:
			case OS.QNX:
				return "";
			default:
				assert_not_reached ();
		}
	}

	public string os_library_suffix () {
		switch (os ()) {
			case OS.WINDOWS:
				return ".dll";
			case OS.MACOS:
			case OS.IOS:
				return ".dylib";
			case OS.LINUX:
			case OS.ANDROID:
			case OS.QNX:
				return ".so";
			default:
				assert_not_reached ();
		}
	}

	public enum OS {
		WINDOWS,
		MACOS,
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
		BIONIC,
		QNX
	}
}
