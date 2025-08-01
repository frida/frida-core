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
	 *      "path": "/path/to/target/aarch64-unknown-none/release/frida-barebone-agent",
	 *      "transport": {
	 *        "type": "hostlink",
	 *        "qmp": "unix:/path/to/qmp.sock"
	 *      }
	 *    },
	 *    "image": {
	 *      "file": "/path/to/kernelcache.research.iphone12b",
	 *      "base": "0xfffffff007004000"
	 *    }
	 *  }
	 */
	public sealed class Config : Object, Json.Serializable {
		public ConnectionConfig connection {
			get;
			set;
			default = new ConnectionConfig ();
		}

		public AllocatorConfig? allocator {
			get;
			set;
		}

		public AgentConfig? agent {
			get;
			set;
		}

		public ImageConfig? image {
			get;
			set;
		}

		public void check () throws Error {
			if (allocator != null)
				allocator.check ();
			if (agent != null)
				agent.check ();
			if (image != null)
				image.check ();
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "allocator") {
				AllocatorConfig? allocator = null;
				Type t = typeof (InvalidAllocatorConfig);
				if (property_node.get_node_type () == Json.NodeType.OBJECT) {
					switch (property_node.get_object ().get_string_member_with_default ("mode", "invalid")) {
					case "physical":
						t = typeof (PhysicalAllocatorConfig);
						break;
					case "target-functions":
						t = typeof (TargetFunctionsAllocatorConfig);
						break;
					default:
						break;
					}
					allocator = (AllocatorConfig) Json.gobject_deserialize (t, property_node);
				} else {
					allocator = new InvalidAllocatorConfig ();
				}

				var v = Value (t);
				v.set_object (allocator);
				value = v;
				return true;
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
		public abstract void check () throws Error;
	}

	public sealed class InvalidAllocatorConfig : AllocatorConfig {
		public override void check () throws Error {
			throw new Error.NOT_SUPPORTED ("Config for 'allocator' is invalid");
		}
	}

	public sealed class PhysicalAllocatorConfig : AllocatorConfig, Json.Serializable {
		public MemoryAddress physical_base {
			get;
			set;
		}

		public override void check () throws Error {
			if (physical_base == null)
				throw new Error.NOT_SUPPORTED ("Config for 'allocator.physical_base' is missing");
			physical_base.check ();
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "physical_base") {
				value = deserialize_address ("allocator.physical_base", property_node);
				return true;
			}

			value = Value (pspec.value_type);
			return false;
		}
	}

	public sealed class TargetFunctionsAllocatorConfig : AllocatorConfig, Json.Serializable {
		public MemoryAddress alloc_function {
			get;
			set;
		}

		public MemoryAddress free_function {
			get;
			set;
		}

		public override void check () throws Error {
			if (alloc_function == null)
				throw new Error.NOT_SUPPORTED ("Config for 'allocator.alloc_function' is missing");
			alloc_function.check ();

			if (free_function == null)
				throw new Error.NOT_SUPPORTED ("Config for 'allocator.free_function' is missing");
			free_function.check ();
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "alloc-function") {
				value = deserialize_address ("allocator.alloc_function", property_node);
				return true;
			}

			if (property_name == "free-function") {
				value = deserialize_address ("allocator.free_function", property_node);
				return true;
			}

			value = Value (pspec.value_type);
			return false;
		}
	}

	public sealed class AgentConfig : Object, Json.Serializable {
		public string path {
			get;
			set;
		}

		public TransportConfig transport {
			get;
			set;
		}

		public void check () throws Error {
			if (path == null)
				throw new Error.NOT_SUPPORTED ("Config for 'agent.path' is missing");

			if (transport == null)
				throw new Error.NOT_SUPPORTED ("Config for 'agent.transport' is missing");
			transport.check ();
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "transport") {
				TransportConfig transport;
				Type t = typeof (InvalidTransportConfig);
				if (property_node.get_node_type () == Json.NodeType.OBJECT) {
					switch (property_node.get_object ().get_string_member_with_default ("type", "invalid")) {
					case "hostlink":
						t = typeof (HostlinkTransportConfig);
						break;
					default:
						break;
					}
					transport = (TransportConfig) Json.gobject_deserialize (t, property_node);
				} else {
					transport = new InvalidTransportConfig ();
				}

				var v = Value (t);
				v.set_object (transport);
				value = v;
				return true;
			}

			value = Value (pspec.value_type);
			return false;
		}
	}

	public abstract class TransportConfig : Object {
		public abstract void check () throws Error;
	}

	public sealed class InvalidTransportConfig : TransportConfig {
		public override void check () throws Error {
			throw new Error.NOT_SUPPORTED ("Config for 'agent.transport' is invalid");
		}
	}

	public sealed class HostlinkTransportConfig : TransportConfig {
		public string qmp {
			get;
			set;
		}

		public override void check () throws Error {
			if (qmp == null)
				throw new Error.NOT_SUPPORTED ("Config for 'agent.transport.qmp' is missing");
			if (!qmp.has_prefix ("unix:"))
				throw new Error.NOT_SUPPORTED ("Config for 'agent.transport.qmp' must be a UNIX socket for now");
		}
	}

	public sealed class ImageConfig : Object, Json.Serializable {
		public string file {
			get;
			set;
		}

		public MemoryAddress base {
			get;
			set;
		}

		public void check () throws Error {
			if (file == null)
				throw new Error.NOT_SUPPORTED ("Config for 'image.file' is missing");

			if (@base == null)
				throw new Error.NOT_SUPPORTED ("Config for 'image.base' is missing");
			@base.check ();
		}

		public bool deserialize_property (string property_name, out Value value, ParamSpec pspec, Json.Node property_node) {
			if (property_name == "base") {
				value = deserialize_address ("image.base", property_node);
				return true;
			}

			value = Value (pspec.value_type);
			return false;
		}
	}

	public abstract class MemoryAddress : Object {
		public string label {
			get;
			construct;
		}

		public uint64 address {
			get;
			construct;
		}

		public abstract void check () throws Error;
	}

	public sealed class InvalidMemoryAddress : MemoryAddress {
		public InvalidMemoryAddress (string label) {
			Object (label: label);
		}

		public override void check () throws Error {
			throw new Error.NOT_SUPPORTED ("Config for '%s' is invalid", label);
		}
	}

	public sealed class NonNullMemoryAddress : MemoryAddress {
		public NonNullMemoryAddress (string label, uint64 address) {
			Object (label: label, address: address);
		}

		public override void check () throws Error {
			if (address == 0)
				throw new Error.NOT_SUPPORTED ("Config for '%s' cannot be NULL", label);
		}
	}

	private MemoryAddress deserialize_address (string label, Json.Node node) {
		Type t = node.get_value_type ();
		if (t == typeof (string)) {
			uint64 address;
			if (!uint64.try_parse (node.get_string (), out address, null, 16))
				return new InvalidMemoryAddress (label);
			return new NonNullMemoryAddress (label, address);
		} else if (t == typeof (int64)) {
			return new NonNullMemoryAddress (label, node.get_int ());
		} else {
			return new InvalidMemoryAddress (label);
		}
	}
}
