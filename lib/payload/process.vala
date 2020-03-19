namespace Frida {
	public extern void run_atexit_handlers ();

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

	public Gum.MemoryRange detect_own_memory_range (Gum.MemoryRange? mapped_range) {
		Gum.MemoryRange? result = mapped_range;

		if (result == null) {
			Gum.Address our_address = Gum.Address.from_pointer (Gum.strip_code_pointer ((void *) detect_own_memory_range));

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

	public interface ProcessInvader : Object {
		public abstract Gum.MemoryRange get_memory_range ();
		public abstract Gum.ScriptBackend get_script_backend (ScriptRuntime runtime) throws Error;
		public abstract Gum.ScriptBackend? get_active_script_backend ();
	}

	public enum TerminationReason {
		UNLOAD,
		EXIT,
		EXEC;

		public string to_nick () {
			return Marshal.enum_to_nick<TerminationReason> (this);
		}
	}
}
