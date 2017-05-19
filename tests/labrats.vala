namespace Frida.Test.Labrats {
	public static string path_to_executable (string name, Arch arch = Arch.CURRENT) {
		return path_to_file (name + os_arch_suffix (arch) + os_executable_suffix ());
	}

	public static string path_to_library (string name, Arch arch = Arch.CURRENT) {
		return path_to_file (name + os_arch_suffix (arch) + os_library_suffix ());
	}

	public static string path_to_file (string name) {
		var tests_dir = Path.get_dirname (Process.current.filename);

		string data_dir;
		if (os () == OS.WINDOWS) {
			data_dir = Path.build_filename (Path.get_dirname (Path.get_dirname (Path.get_dirname (Path.get_dirname (tests_dir)))),
				"frida-core", "tests", "labrats");
		} else {
			data_dir = Path.build_filename (tests_dir, "labrats");
		}

		return Path.build_filename (data_dir, name);
	}
}
