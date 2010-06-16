using Gee;

namespace Zed.Service {
	public class CodeService : Object {
		private ArrayList<ModuleSpec> module_specs = new ArrayList<ModuleSpec> ();
		private ArrayList<Module> modules = new ArrayList<Module> ();
		private ArrayList<Function> dynamic_functions = new ArrayList<Function> ();

		public signal void module_spec_added (ModuleSpec module_spec);
		public signal void module_spec_modified (ModuleSpec module_spec);

		public async void add_module_spec (ModuleSpec module_spec) {
			module_specs.add (module_spec);

			module_spec_added (module_spec);
		}

		public async void add_module (Module module) {
			modules.add (module);

			foreach (var func_spec in module.spec.functions) {
				var func = new Function (func_spec, module.address + func_spec.offset);
				module.internal_add_function (func);
			}
		}

		public async void add_function_to_module (Function function, Module module) {
			yield add_function_spec_to_module (function.spec, module.spec);
			module.internal_add_function (function);
		}

		public async void add_function_spec_to_module (FunctionSpec function_spec, ModuleSpec module_spec) {
			var existing_module_spec = yield find_module_spec_by_uid (module_spec.uid);
			assert (existing_module_spec != null);

			module_spec.internal_add_function (function_spec);

			module_spec_modified (module_spec);
		}

		public async void add_function (Function func) {
			var module = yield find_module_by_address (func.address);
			assert (module == null);

			dynamic_functions.add (func);
		}

		public async void rename_function (Function function, string new_name) {
			function.spec.internal_rename (new_name);

			var mod = yield find_module_by_address (function.address);
			module_spec_modified (mod.spec);
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
			if (mod != null) {
				foreach (var mod_func in mod.functions) {
					if (mod_func.address == address)
						return mod_func;
				}
			} else {
				foreach (var dyn_func in dynamic_functions) {
					if (dyn_func.address == address)
						return dyn_func;
				}
			}

			return null;
		}
	}

	public class ModuleSpec : Object {
		public string name {
			get;
			construct;
		}

		public string bare_name {
			get {
				if (_bare_name == null)
					_bare_name = name[0:-4];
				return _bare_name;
			}
		}
		private string _bare_name;

		public string uid {
			get;
			construct;
		}

		public uint64 size {
			get;
			construct;
		}

		public Iterable<FunctionSpec> functions {
			get { return _functions; }
		}
		private ArrayList<FunctionSpec> _functions = new ArrayList<FunctionSpec> ();

		public ModuleSpec (string name, string uid, uint64 size) {
			Object (name: name, uid: uid, size: size);
		}

		public int function_count () {
			return _functions.size;
		}

		public void internal_add_function (FunctionSpec spec) {
			_functions.add (spec);
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
				module_spec.internal_add_function (FunctionSpec.from_variant (function_wrapper.get_variant ()));

			return module_spec;
		}
	}

	public class FunctionSpec : Object {
		public string name {
			get;
			private set;
		}

		public uint64 offset {
			get;
			construct;
		}

		public FunctionSpec (string name, uint64 offset) {
			Object (offset: offset);

			this.name = name;
		}

		public void internal_rename (string name) {
			this.name = name;
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

		public Iterable<Function> functions {
			get { return _functions; }
		}
		private ArrayList<Function> _functions = new ArrayList<Function> ();

		public Module (ModuleSpec spec, uint64 address) {
			Object (spec: spec, address: address);
		}

		public void internal_add_function (Function func) {
			_functions.add (func);
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

