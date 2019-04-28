namespace Frida {
	public extern void init_libc_shim ();
	public extern void deinit_libc_shim ();

	public extern uint get_process_id ();

	public extern void * get_current_pthread ();
	public extern void join_pthread (void * thread);

	public string get_executable_path () {
		var path = try_get_executable_path ();
		if (path != null)
			return path;

		Gum.Process.enumerate_modules ((details) => {
			path = details.name;
			return false;
		});
		assert (path != null);

		return path;
	}

	private extern string? try_get_executable_path ();

	private static Once<string> libc_name_value;

	public string detect_libc_name () {
		return libc_name_value.once (_detect_libc_name);
	}

	private string _detect_libc_name () {
#if WINDOWS
		return "msvcrt.dll";
#else
		string? libc_name = null;

		Gum.Address address_in_libc = (Gum.Address) Posix.opendir;
		Gum.Process.enumerate_modules ((details) => {
			var range = details.range;

			if (address_in_libc >= range.base_address && address_in_libc < range.base_address + range.size) {
				libc_name = details.path;
				return false;
			}

			return true;
		});

		assert (libc_name != null);

		return libc_name;
#endif
	}

	public Gum.MemoryRange detect_own_memory_range (Gum.MemoryRange? mapped_range) {
		Gum.MemoryRange? result = mapped_range;

		if (result == null) {
			Gum.Address our_address = (Gum.Address) detect_own_memory_range;

			Gum.Process.enumerate_modules ((details) => {
				var range = details.range;

				if (our_address >= range.base_address && our_address < range.base_address + range.size) {
					result = range;
					return false;
				}

				return true;
			});

			assert (result != null);
		}

		return result;
	}
}
