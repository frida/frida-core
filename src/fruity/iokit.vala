namespace Frida {
	using CoreFoundation;
	using Darwin.XNU;

	internal class IORegistry {
		private MachPort main_port;

		public static IORegistry open () throws Error {
			MachPort port;
			kern_check (Darwin.IOKit.main_port (MachPort.NULL, out port));
			return new IORegistry (port);
		}

		private IORegistry (MachPort main_port) {
			this.main_port = main_port;
		}

		public IOIterator<IORegistryEntry> matching_services (owned MutableDictionary matching_dict) throws Error {
			Darwin.IOKit.IOIterator h;
			kern_check (Darwin.IOKit.get_matching_services (main_port, matching_dict, out h));
			return new IOIterator<IORegistryEntry> ((owned) h);
		}
	}

	internal class IORegistryEntry : GLib.Object {
		public IOObject io_object {
			get;
			construct;
		}

		internal IORegistryEntry (IOObject obj) {
			GLib.Object (io_object: obj);
		}

		public MutableDictionary get_properties () throws Error {
			MutableDictionary properties;
			kern_check (unwrap ().create_cf_properties (out properties, null, 0));
			return properties;
		}

		public string? get_string_property (string key) {
			var v = (String) unwrap ().create_cf_property (String.make (key), null, 0);
			return (v != null) ? v.to_string () : null;
		}

		public IORegistryEntry parent (string plane) throws Error {
			Darwin.IOKit.IOObject h;
			kern_check (unwrap ().get_parent_entry (plane, out h));
			return new IORegistryEntry (new IOObject ((owned) h));
		}

		private unowned Darwin.IOKit.IORegistryEntry unwrap () {
			return (Darwin.IOKit.IORegistryEntry) io_object.handle;
		}
	}

	internal class IOIterator<T> {
		private Darwin.IOKit.IOIterator handle;

		internal IOIterator (owned Darwin.IOKit.IOIterator handle) {
			this.handle = (owned) handle;
		}

		public IOIterator<T> iterator () {
			return this;
		}

		public T? next_value () {
			Darwin.IOKit.IOObject h = handle.next ();
			if (h == Darwin.IOKit.IOObject.NULL)
				return null;
			return GLib.Object.new (typeof (T), io_object: new IOObject ((owned) h));
		}
	}

	internal class IOObject {
		internal Darwin.IOKit.IOObject handle;

		internal IOObject (owned Darwin.IOKit.IOObject handle) {
			this.handle = (owned) handle;
		}
	}

	private void kern_check (KernReturn result) throws Error {
		if (result != KernReturn.SUCCESS)
			throw new Error.NOT_SUPPORTED ("%s", mach_error_string (result));
	}
}
