using Gee;

namespace Zed.Service {
	public class CodeService : Object {
		public void add_module (Module module) {
		}

		public void add_function (Function func) {
		}

		public Function? find_function_by_name (string name) {
			return null;
		}

		public Function? find_function_by_address (uint64 address) {
			return null;
		}
	}

	public class ModuleSpec : Object {
		public string name {
			get;
			construct;
		}

		public string uid {
			get;
			construct;
		}

		public uint64 size {
			get;
			construct;
		}

		public ModuleSpec (string name, string uid, uint64 size) {
			Object (name: name, uid: uid, size: size);
		}
	}

	public class FunctionSpec : Object {
		public string name {
			get;
			set;
		}

		public FunctionSpec (string name) {
			Object (name: name);
		}
	}

	public class Module : Object {
		public ModuleSpec spec {
			get;
			construct;
		}

		public uint64 address {
			get;
			construct;
		}

		public Module (ModuleSpec spec, uint64 address) {
			Object (spec: spec, address: address);
		}
	}

	public class Function : Object {
		public FunctionSpec spec {
			get;
			construct;
		}

		public uint64 address {
			get;
			construct;
		}

		public Function (FunctionSpec spec, uint64 address) {
			Object (spec: spec, address: address);
		}
	}
}

