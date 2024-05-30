[CCode (cheader_filename = "IOKit/IOKitLib.h", gir_namespace = "Darwin", gir_version = "1.0")]
namespace Darwin.IOKit {
	using CoreFoundation;
	using Darwin.XNU;

	[CCode (cname = "IOMasterPort")]
	public KernReturn main_port (MachPort bootstrap_port, out MachPort main_port);

	[CCode (cname = "IOServiceMatching")]
	public MutableDictionary service_matching (string name);

	[CCode (cname = "IOServiceGetMatchingServices")]
	public KernReturn get_matching_services (MachPort main_port, owned MutableDictionary matching_dict,
		out IOIterator iterator);

	[CCode (cname = "kIOEthernetInterfaceClass", cheader_filename = "IOKit/network/IOEthernetInterface.h")]
	public const string ETHERNET_INTERFACE_CLASS;

	[CCode (cname = "kIOBSDNameKey", cheader_filename = "IOKit/IOBSD.h")]
	public const string BSD_NAME_KEY;

	[CCode (cname = "kIOServicePlane", cheader_filename = "IOKit/IOKitKeys.h")]
	public const string IOSERVICE_PLANE;

	[CCode (cname = "io_registry_entry_t", destroy_function = "IOObjectRelease", has_type_id = false)]
	public struct IORegistryEntry : IOObject {
		[CCode (cname = "IORegistryEntryCreateCFProperties")]
		public KernReturn create_cf_properties (out MutableDictionary properties, Allocator? allocator, uint options);

		[CCode (cname = "IORegistryEntryCreateCFProperty")]
		public CoreFoundation.Type create_cf_property (String key, Allocator? allocator, uint options);

		[CCode (cname = "IORegistryEntryGetParentEntry")]
		public KernReturn get_parent_entry (string plane, out IOObject parent);
	}

	[CCode (cname = "io_iterator_t", destroy_function = "IOObjectRelease")]
	public struct IOIterator : MachPort {
		[CCode (cname = "IOIteratorReset")]
		public void reset ();

		[CCode (cname = "IOIteratorIsValid")]
		public bool is_valid ();

		[CCode (cname = "IOIteratorNext")]
		public IOObject next ();
	}

	[CCode (cname = "io_service_t", destroy_function = "IOObjectRelease", has_type_id = false)]
	public struct IOService : IOObject {
	}

	[CCode (cname = "io_object_t", destroy_function = "IOObjectRelease", has_type_id = false)]
	public struct IOObject : MachPort {
		[CCode (cname = "IO_OBJECT_NULL")]
		public const IOObject NULL;
	}
}
