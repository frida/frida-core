using Efni;

namespace Frida {
	/**
	 * Identifies a Frida binary, such as Gadget or a Barebone agent, by the
	 * metadata it carries.
	 */
	public sealed class BinaryMetadata : Object {
		/**
		 * The name of the component, e.g. `frida-gadget`.
		 */
		public string name {
			get;
			construct;
		}

		/**
		 * The Frida version it was built from.
		 */
		public string version {
			get;
			construct;
		}

		/**
		 * The architectures it contains; more than one for a universal Mach-O.
		 */
		public string[] architectures {
			get;
			construct;
		}

		internal BinaryMetadata (string name, string version, string[] architectures) {
			Object (name: name, version: version, architectures: architectures);
		}

		/**
		 * Reads the metadata embedded in the Frida binary at @path. Understands
		 * PE, Mach-O, including universal ones, and ELF.
		 *
		 * @param path the binary to inspect
		 */
		public static BinaryMetadata from_file (string path) throws Error {
			uint8[] magic = read_magic (path);
			if (has_pe_magic (magic))
				return read_pe_metadata (path);
			if (has_macho_magic (magic))
				return read_macho_metadata (path);
			if (has_elf_magic (magic))
				return read_elf_metadata (path);
			throw new Error.INVALID_ARGUMENT ("Unsupported binary format");
		}
	}

	private BinaryMetadata read_pe_metadata (string path) throws Error {
		Gum.PeModule module;
		try {
			module = new Gum.PeModule.from_file (path);
		} catch (Gum.Error e) {
			throw new Error.INVALID_ARGUMENT ("%s", e.message);
		}

		string? json = null;
		module.enumerate_sections (s => {
			if (s.name == ".package") {
				unowned uint8[]? data = module.get_data_at_rva (s.virtual_address);
				if (data != null)
					json = string_from_padded_data (data[0:uint32.min (s.virtual_size, data.length)]);
			}
			return json == null;
		});
		if (json == null)
			throw new Error.NOT_SUPPORTED ("No Frida metadata found");

		var metadata = parse_metadata_json (json);
		return new BinaryMetadata (metadata.name, metadata.version, { pe_machine_to_architecture (module.machine) });
	}

	private BinaryMetadata read_macho_metadata (string path) throws Error {
		Bytes blob;
		try {
			blob = new MappedFile (path, false).get_bytes ();
		} catch (FileError e) {
			throw new Error.INVALID_ARGUMENT ("%s", e.message);
		}

		MachoFlavor[] flavors = {
			{ "arm64e", ARM64, SUPPORTED },
			{ "arm64", ARM64, UNSUPPORTED },
			{ "x86_64", AMD64, UNSUPPORTED },
			{ "x86", IA32, UNSUPPORTED },
			{ "arm", ARM, UNSUPPORTED },
		};

		PackageMetadata? metadata = null;
		string[] architectures = {};
		foreach (var flavor in flavors) {
			Gum.MachoModule module;
			try {
				module = new Gum.MachoModule.from_blob (blob, flavor.cpu_type, flavor.ptrauth_support);
			} catch (Gum.Error e) {
				continue;
			}

			unowned uint8[] image = (uint8[]) module.image.data;
			image.length = (int) module.image.size;

			string? json = null;
			module.enumerate_sections (s => {
				if (s.segment_name == "__TEXT" && s.section_name == "__package")
					json = string_from_padded_data (image[s.file_offset:s.file_offset + s.size]);
				return json == null;
			});
			if (json == null)
				continue;

			if (metadata == null)
				metadata = parse_metadata_json (json);
			architectures += flavor.name;
		}

		if (metadata == null)
			throw new Error.NOT_SUPPORTED ("No Frida metadata found");

		return new BinaryMetadata (metadata.name, metadata.version, architectures);
	}

	private BinaryMetadata read_elf_metadata (string path) throws Error {
		Gum.ElfModule module;
		try {
			module = new Gum.ElfModule.from_file (path);
		} catch (Gum.Error e) {
			throw new Error.INVALID_ARGUMENT ("%s", e.message);
		}

		var note_sections = new Gee.ArrayList<Gum.ElfSectionDetails> ();
		module.enumerate_sections (s => {
			if (s.type == NOTE)
				note_sections.add (s);
			return true;
		});

		unowned uint8[] file_data = module.get_file_data ();
		foreach (var section in note_sections) {
			unowned uint8[] notes = file_data[section.offset:section.offset + section.size];
			string? json = find_package_note (notes, module.byte_order);
			if (json != null) {
				var metadata = parse_metadata_json (json);
				return new BinaryMetadata (metadata.name, metadata.version, { metadata.architecture });
			}
		}

		throw new Error.NOT_SUPPORTED ("No Frida metadata found");
	}

	private PackageMetadata parse_metadata_json (string json) throws Error {
		try {
			var parser = new Json.Parser ();
			parser.load_from_data (json);

			var reader = new Json.Reader (parser.get_root ());
			var metadata = new PackageMetadata ();
			metadata.name = read_json_string (reader, "name");
			metadata.version = read_json_string (reader, "version");
			metadata.architecture = read_json_string (reader, "architecture");
			return metadata;
		} catch (GLib.Error e) {
			throw new Error.PROTOCOL ("Malformed Frida metadata: %s", e.message);
		}
	}

	private string read_json_string (Json.Reader reader, string member) throws Error {
		reader.read_member (member);
		string? val = reader.get_string_value ();
		reader.end_member ();
		if (val == null)
			throw new Error.PROTOCOL ("Malformed Frida metadata: missing '%s'", member);
		return val;
	}

	private string pe_machine_to_architecture (Gum.PeMachine machine) {
		switch (machine) {
			case I386:
				return "x86";
			case AMD64:
				return "x86_64";
			case ARMNT:
				return "arm";
			case ARM64:
				return "arm64";
			default:
				return "unknown";
		}
	}

	private string? find_package_note (uint8[] notes, ByteOrder byte_order) throws Error {
		try {
			var reader = new BufferReader (new Buffer.from_data (notes, byte_order));
			while (reader.available != 0) {
				uint32 name_size = reader.read_uint32 ();
				uint32 desc_size = reader.read_uint32 ();
				uint32 type = reader.read_uint32 ();
				string name = reader.read_fixed_string (name_size);
				reader.align (4);
				unowned uint8[] desc = reader.read_data (desc_size);
				reader.align (4);

				if (name == PACKAGE_NOTE_OWNER && type == PACKAGE_NOTE_TYPE)
					return string_from_padded_data (desc);
			}
		} catch (Efni.Error e) {
			throw new Error.PROTOCOL ("Malformed ELF note: %s", e.message);
		}

		return null;
	}

	private uint8[] read_magic (string path) throws Error {
		var magic = new uint8[4];
		try {
			size_t n;
			File.new_for_path (path).read ().read_all (magic, out n);
			magic.length = (int) n;
		} catch (GLib.Error e) {
			throw new Error.INVALID_ARGUMENT ("%s", e.message);
		}
		return magic;
	}

	private bool has_pe_magic (uint8[] data) {
		return data.length >= 2 && data[0] == 'M' && data[1] == 'Z';
	}

	private bool has_macho_magic (uint8[] data) {
		if (data.length < 4)
			return false;

		uint32 magic = ((uint32) data[0] << 24) | ((uint32) data[1] << 16) | ((uint32) data[2] << 8) | data[3];
		switch (magic) {
			case 0xfeedfaceU:
			case 0xfeedfacfU:
			case 0xcefaedfeU:
			case 0xcffaedfeU:
			case 0xcafebabeU:
			case 0xcafebabfU:
				return true;
			default:
				return false;
		}
	}

	private bool has_elf_magic (uint8[] data) {
		return data.length >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F';
	}

	private string string_from_padded_data (uint8[] data) {
		int length = 0;
		while (length != data.length && data[length] != 0)
			length++;
		return ((string) data).ndup (length);
	}

	private class PackageMetadata {
		public string name;
		public string version;
		public string architecture;
	}

	private struct MachoFlavor {
		public unowned string name;
		public Gum.CpuType cpu_type;
		public Gum.PtrauthSupport ptrauth_support;
	}

	private const string PACKAGE_NOTE_OWNER = "FDO";
	private const uint32 PACKAGE_NOTE_TYPE = 0xcafe1a7eU;
}
