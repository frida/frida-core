[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	/**
	 * Barebone backend configuration. This is specified via the FRIDA_BAREBONE_CONFIG environment
	 * variable, which should point to the filesystem path of a JSON-encoded configuration file.
	 *
	 * Example JSON configurations:
	 *
	 * 1. Using all defaults:
	 * {
	 *   "connection": {
	 *     "host": "127.0.0.1",
	 *     "port": 3333
	 *   },
	 *   "allocator": {
	 *     "mode": "none"
	 *   }
	 * }
	 *
	 * 2. Using a physical memory allocator:
	 *  {
	 *    "connection": {
	 *      "host": "127.0.0.1",
	 *      "port": 9000
	 *    },
	 *    "allocator": {
	 *      "mode": "physical",
	 *      "physical_base": "0x8ec9b4000"
	 *    }
	 *  }
	 *
	 * 3. Using target-specific allocation functions:
	 *  {
	 *    "connection": {
	 *      "host": "127.0.0.1",
	 *      "port": 9000
	 *    },
	 *    "allocator": {
	 *      "mode": "target-functions",
	 *      "alloc_function": "0xfffffff007a3c278",
	 *      "free_function": "0xfffffff007a3c338"
	 *    }
	 *  }
	 *
	 * 4. Injecting a remote agent:
	 *  {
	 *    "agent": {
	 *      "path": "/path/to/target/aarch64-unknown-none/release/frida-barebone-agent"
	 *    }
	 *  }
	 */
	public sealed class Config : Object, Json.Serializable {
		public ConnectionConfig connection {
			get;
			set;
			default = new ConnectionConfig ();
		}

		public AllocatorConfig allocator {
			get;
			set;
			default = new NoAllocatorConfig ();
		}

		public AgentConfig? agent {
			get;
			set;
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "allocator" && property_node.get_node_type () == Json.NodeType.OBJECT) {
				var obj_node = property_node.get_object ();
				string? mode = obj_node.get_string_member ("mode");

				Type t = 0;
				switch (mode) {
				case "none":
					t = typeof (NoAllocatorConfig);
					break;
				case "physical":
					t = typeof (PhysicalAllocatorConfig);
					break;
				case "target-functions":
					t = typeof (TargetFunctionsAllocatorConfig);
					break;
				default:
					break;
				}

				if (t != 0) {
					var obj = (AllocatorConfig) Json.gobject_deserialize (t, property_node);
					if (obj != null && obj.is_valid) {
						var v = Value (t);
						v.set_object (obj);
						value = v;
						return true;
					}
				}
			}

			value = Value (pspec.value_type);
			return false;
		}
	}

	public sealed class ConnectionConfig : Object {
		public string host {
			get;
			set;
			default = "127.0.0.1";
		}

		public uint16 port {
			get;
			set;
			default = 3333;
		}
	}

	public abstract class AllocatorConfig : Object {
		public abstract bool is_valid {
			get;
		}
	}

	public sealed class NoAllocatorConfig : AllocatorConfig {
		public override bool is_valid {
			get {
				return true;
			}
		}
	}

	public sealed class PhysicalAllocatorConfig : AllocatorConfig, Json.Serializable {
		public override bool is_valid {
			get {
				return true;
			}
		}

		public uint64 physical_base {
			get;
			set;
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (try_deserialize_address ("physical_base", property_node, out value))
				return true;

			value = Value (pspec.value_type);
			return false;
		}
	}

	public sealed class TargetFunctionsAllocatorConfig : AllocatorConfig, Json.Serializable {
		public override bool is_valid {
			get {
				return alloc_function != 0 && free_function != 0;
			}
		}

		public uint64 alloc_function {
			get;
			set;
		}

		public uint64 free_function {
			get;
			set;
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (try_deserialize_address ("alloc_function", property_node, out value))
				return true;

			if (try_deserialize_address ("free_function", property_node, out value))
				return true;

			value = Value (pspec.value_type);
			return false;
		}
	}

	public sealed class AgentConfig : Object {
		public string path {
			get;
			set;
		}

		public AgentTransportConfig transport {
			get;
			set;
		}

		public string? symbol_source {
			get;
			set;
		}
	}

	public sealed class AgentTransportConfig : Object, Json.Serializable {
		public string path {
			get;
			set;
		}

		public uint64 base_address {
			get;
			set;
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (try_deserialize_address ("base_address", property_node, out value))
				return true;

			value = Value (pspec.value_type);
			return false;
		}
	}

	private bool try_deserialize_address (string name, Json.Node node, out Value val) {
		val = Value (typeof (uint64));

		if (node.get_value_type () != typeof (string))
			return false;

		uint64 v;
		if (!uint64.try_parse (node.get_string (), out v, null, 16))
			return false;

		val = v;
		return true;
	}
}
