using Gee;

namespace Zed.Service {
	public class CodeService : Object {
		private ArrayList<ModuleSpec> module_specs = new ArrayList<ModuleSpec> ();
		private ArrayList<Module> modules = new ArrayList<Module> ();

		public signal void module_spec_added (ModuleSpec module_spec);
		public signal void module_added (Module module);

		public async void add_module_spec (ModuleSpec module_spec) {
			module_specs.add (module_spec);

			module_spec_added (module_spec);
		}

		public async void add_module (Module module) {
			modules.add (module);

			foreach (var func_spec in module.spec.functions) {
				var func = new Function (func_spec, module.address + func_spec.offset);
				module.add_function (func);
			}

			module_added (module);
		}

		public async ModuleSpec? find_module_spec_by_uid (string uid) {
			foreach (var spec in module_specs) {
				if (spec.uid == uid)
					return spec;
			}

			return null;
		}

		public async Module? find_module_by_address (uint64 address) {
			foreach (var mod in modules) {
				if (address >= mod.address && address < mod.address + mod.spec.size)
					return mod;
			}

			return null;
		}

		public async Function? find_function_by_address (uint64 address) {
			var mod = yield find_module_by_address (address);
			if (mod == null)
				return null;

			foreach (var func in mod.functions) {
				if (func.address == address)
					return func;
			}

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

		public ArrayList<FunctionSpec> functions {
			get;
			private set;
		}

		public ModuleSpec (string name, string uid, uint64 size) {
			Object (name: name, uid: uid, size: size);

			functions = new ArrayList<FunctionSpec> ();
		}

		public void add_function (FunctionSpec spec) {
			functions.add (spec);
		}

		public Variant to_variant () {
			var builder = new VariantBuilder (new VariantType ("av"));
			foreach (var function in functions)
				builder.add ("v", function.to_variant ());
			return new Variant ("(sstav)", name, uid, size, builder);
		}

		public static ModuleSpec from_variant (Variant variant) {
			string name;
			string uid;
			uint64 size;
			VariantIter functions;
			variant.get ("(sstav)", out name, out uid, out size, out functions);

			var module_spec = new ModuleSpec (name, uid, size);
			Variant function_wrapper;
			while ((function_wrapper = functions.next_value ()) != null)
				module_spec.add_function (FunctionSpec.from_variant (function_wrapper.get_variant ()));

			return module_spec;
		}
	}

	public class FunctionSpec : Object {
		public string name {
			get;
			set;
		}

		public uint64 offset {
			get;
			construct;
		}

		public FunctionSpec (string name, uint64 offset) {
			Object (name: name, offset: offset);
		}

		public Variant to_variant () {
			return new Variant ("(st)", name, offset);
		}

		public static FunctionSpec from_variant (Variant variant) {
			string name;
			uint64 offset;
			variant.get ("(st)", out name, out offset);

			return new FunctionSpec (name, offset);
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

		public ArrayList<Function> functions {
			get;
			private set;
		}

		public Module (ModuleSpec spec, uint64 address) {
			Object (spec: spec, address: address);

			functions = new ArrayList<Function> ();
		}

		public void add_function (Function func) {
			functions.add (func);
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

