namespace Zed {
	[DBus (name = "org.boblycat.frida.HostSession")]
	public interface HostSession : Object {
		public abstract async HostProcessInfo[] enumerate_processes () throws IOError;

		public abstract async AgentSessionId attach_to (uint pid) throws IOError;
	}

	[DBus (name = "org.boblycat.frida.AgentSession")]
	public interface AgentSession : Object {
		public abstract async void close () throws IOError;

		public abstract async AgentModuleInfo[] query_modules () throws IOError;
		public abstract async AgentFunctionInfo[] query_module_functions (string module_name) throws IOError;
		public abstract async uint8[] read_memory (uint64 address, uint size) throws IOError;

		public abstract async void start_investigation (AgentTriggerInfo start_trigger, AgentTriggerInfo stop_trigger) throws IOError;
		public abstract async void stop_investigation () throws IOError;
		public signal void new_batch_of_clues (AgentClue[] clues);
		public signal void investigation_complete ();

		public abstract async AgentScriptInfo attach_script_to (string script_text, uint64 address) throws IOError;
		public abstract async void detach_script (uint script_id) throws IOError;
		public signal void message_from_script (uint script_id, Variant msg);

		public abstract async void begin_instance_trace () throws IOError;
		public abstract async void end_instance_trace () throws IOError;
		public abstract async AgentInstanceInfo[] peek_instances () throws IOError;
	}

	public struct HostProcessInfo {
		public uint pid {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public ImageData small_icon {
			get;
			private set;
		}

		public ImageData large_icon {
			get;
			private set;
		}

		public HostProcessInfo (uint pid, string name, ImageData small_icon, ImageData large_icon) {
			this.pid = pid;
			this.name = name;
			this.small_icon = small_icon;
			this.large_icon = large_icon;
		}
	}

	public struct AgentSessionId {
		public uint handle {
			get;
			private set;
		}

		public AgentSessionId (uint handle) {
			this.handle = handle;
		}
	}

	public struct AgentModuleInfo {
		public string name {
			get;
			private set;
		}

		public string uid {
			get;
			private set;
		}

		public uint64 size {
			get;
			private set;
		}

		public uint64 address {
			get;
			private set;
		}

		public AgentModuleInfo (string name, string uid, uint64 size, uint64 address) {
			this.name = name;
			this.uid = uid;
			this.size = size;
			this.address = address;
		}
	}

	public struct AgentFunctionInfo {
		public string name {
			get;
			private set;
		}

		public uint64 address {
			get;
			private set;
		}

		public AgentFunctionInfo (string name, uint64 address) {
			this.name = name;
			this.address = address;
		}
	}

	public struct AgentTriggerInfo {
		public string module_name {
			get;
			private set;
		}

		public string function_name {
			get;
			private set;
		}

		public AgentTriggerInfo (string module_name, string function_name) {
			this.module_name = module_name;
			this.function_name = function_name;
		}
	}

	public struct AgentClue {
		public int depth {
			get;
			private set;
		}

		public uint64 location {
			get;
			private set;
		}

		public uint64 target {
			get;
			private set;
		}

		public AgentClue (int depth, uint64 location, uint64 target) {
			this.depth = depth;
			this.location = location;
			this.target = target;
		}
	}

	public struct AgentScriptInfo {
		public uint id {
			get;
			private set;
		}

		public uint64 code_address {
			get;
			private set;
		}

		public uint32 code_size {
			get;
			private set;
		}

		public AgentScriptInfo (uint id, uint64 code_address, uint32 code_size) {
			this.id = id;
			this.code_address = code_address;
			this.code_size = code_size;
		}
	}

	public struct AgentInstanceInfo {
		public uint64 address {
			get;
			private set;
		}

		public uint reference_count {
			get;
			private set;
		}

		public string type_name {
			get;
			private set;
		}

		public AgentInstanceInfo (uint64 address, uint reference_count, string type_name) {
			this.address = address;
			this.reference_count = reference_count;
			this.type_name = type_name;
		}
	}

	public struct ImageData {
		public int width {
			get;
			private set;
		}

		public int height {
			get;
			private set;
		}

		public int rowstride {
			get;
			private set;
		}

		public string pixels {
			get;
			private set;
		}

		public ImageData (int width, int height, int rowstride, string pixels) {
			this.width = width;
			this.height = height;
			this.rowstride = rowstride;
			this.pixels = pixels;
		}
	}

	namespace ObjectPath {
		public const string HOST_SESSION = "/org/boblycat/frida/HostSession";
		public const string AGENT_SESSION = "/org/boblycat/frida/AgentSession";
	}
}
