class Vala.ResourceCompiler {
	private static string toolchain;
	private static bool enable_asm = false;
	private static string config_filename;
	private static string output_basename;
	[CCode (array_length = false, array_null_terminated = true)]
	private static string[] input_filenames;

	private const OptionEntry[] options = {
		{ "toolchain", 't', 0, OptionArg.STRING, ref toolchain, "Generate output for TOOLCHAIN", "TOOLCHAIN" },
		{ "enable-asm", 0, 0, OptionArg.NONE, ref enable_asm, "Enable assembly output to speed up build", null },
		{ "config-filename", 'c', 0, OptionArg.FILENAME, ref config_filename, "Read configuration from CONFIGFILE", "CONFIGFILE" },
		{ "output-basename", 'o', 0, OptionArg.FILENAME, ref output_basename, "Place output in BASENAME", "BASENAME" },
		{ "", 0, 0, OptionArg.FILENAME_ARRAY, ref input_filenames, null, "FILE..." },
		{ null }
	};

	private const char NIBBLE_TO_HEX_CHAR[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	private void run () throws Error {
		var input_dir = File.new_for_path (Path.get_dirname (config_filename));
		string output_namespace;

		var categories = new Gee.ArrayList<ResourceCategory> ();

		var root_category = new ResourceCategory ("root");
		foreach (var filename in input_filenames)
			root_category.files.add (filename);
		root_category.files.sort ();
		categories.add (root_category);

		var config = new KeyFile ();
		config.load_from_file (config_filename, KeyFileFlags.NONE);

		output_namespace = config.get_string ("resource-compiler", "namespace");

		foreach (var group in config.get_groups ()) {
			if (group == "resource-compiler")
				continue;

			ResourceCategory category = (group == "root") ? root_category : new ResourceCategory (group);

			foreach (var input in config.get_string_list (group, "inputs")) {
				var regex = new Regex (input);

				var enumerator = input_dir.enumerate_children (FILE_ATTRIBUTE_STANDARD_NAME, FileQueryInfoFlags.NONE);

				FileInfo file_info;
				while ((file_info = enumerator.next_file ()) != null) {
					var filename = file_info.get_name ();
					if (regex.match (filename)) {
						category.files.add (Path.build_filename (input_dir.get_path (), filename));
					}
				}

			}

			category.files.sort ();

			if (category != root_category)
				categories.add (category);
		}

		var vapi_file = File.new_for_commandline_arg (output_basename + ".vapi");
		var cheader_file = File.new_for_commandline_arg (output_basename + ".h");
		var csource_file = File.new_for_commandline_arg (output_basename + ".c");
		var asm_blob_file = File.new_for_commandline_arg (output_basename + "-blob.S");
		MemoryOutputStream vapi_content = new MemoryOutputStream (null, realloc, free);
		MemoryOutputStream cheader_content = new MemoryOutputStream (null, realloc, free);

		DataOutputStream vapi = new DataOutputStream (vapi_content);
		DataOutputStream cheader = new DataOutputStream (cheader_content);
		DataOutputStream csource = new DataOutputStream (csource_file.replace (null, false, FileCreateFlags.REPLACE_DESTINATION));
		DataOutputStream asource = null;
		if (enable_asm)
			asource = new DataOutputStream (asm_blob_file.replace (null, false, FileCreateFlags.REPLACE_DESTINATION));

		var incguard_name = "__" + output_namespace.up ().replace (".", "_") + "_H__";
		var blob_ctype = output_namespace.replace (".", "") + "Blob";
		var namespace_cprefix = c_namespace_from_vala (output_namespace);

		vapi.put_string (
			"// generated file, do not modify\n" +
			"\n" +
			"[CCode (cheader_filename = \"" + cheader_file.get_basename () + "\")]\n" +
			"namespace " + output_namespace +  " {\n" +
			"\n",
			null);

		cheader.put_string ((
			"/* generated file, do not modify */\n" +
			"\n" +
			"#ifndef %s\n" +
			"#define %s\n" +
			"\n" +
			"#include <glib.h>\n" +
			"\n" +
			"G_BEGIN_DECLS\n" +
			"\n" +
			"typedef struct _%s %s;\n" +
			"\n" +
			"struct _%s\n" +
			"{\n" +
			"  const gchar * name;\n" +
			"  gconstpointer data;\n" +
			"  guint data_length1;\n" +
			"};\n" +
			"\n").printf (incguard_name, incguard_name, blob_ctype, blob_ctype, blob_ctype),
			null);

		csource.put_string (
			"/* generated file, do not modify */\n" +
			"\n" +
			"#include \"" + cheader_file.get_basename () + "\"\n" +
			"\n",
			null);

		var compare_func_identifier = namespace_cprefix + "_blob_compare";

		if (categories.size > 1) {
			csource.put_string (
				"#include <stdlib.h>\n" +
				"#include <string.h>\n" +
				"\n" +
				"static int\n" +
				compare_func_identifier + " (const void * aptr, const void * bptr)\n" +
				"{\n" +
				"  const " + blob_ctype + " * a = aptr;\n" +
				"  const " + blob_ctype + " * b = bptr;\n" +
				"\n" +
				"  return strcmp (a->name, b->name);\n" +
				"}\n" +
				"\n",
				null);
		}

		if (enable_asm && toolchain == "apple")
			asource.put_string (".const\n");

		var asm_identifier_prefix = toolchain == "apple" ? "_" : "";

		foreach (var category in categories) {
			bool is_root_category = (category.name == "root");
			var category_identifier = identifier_from_filename (category.name);
			var identifier_by_index = new Gee.ArrayList<string> ();
			var blob_identifier_by_index = new Gee.ArrayList<string> ();
			var size_by_index = new Gee.ArrayList<uint64?> ();
			int file_count = category.files.size;

			foreach (string input_filename in category.files) {
				var input_file = File.new_for_commandline_arg (input_filename);

				var file_input_stream = input_file.read (null);
				var input_info = file_input_stream.query_info (FILE_ATTRIBUTE_STANDARD_SIZE);
				var identifier = identifier_from_filename (input_file.get_basename ());
				var file_size = input_info.get_attribute_uint64 (FILE_ATTRIBUTE_STANDARD_SIZE);

				identifier_by_index.add (identifier);
				size_by_index.add (file_size);

				if (enable_asm) {
					var blob_identifier = "_" + namespace_cprefix + "_" + identifier;
					blob_identifier_by_index.add (blob_identifier);

					csource.put_string ("extern const unsigned char " + blob_identifier + "[];\n\n");

					asource.put_string (".align 4\n");
					asource.put_string (".globl " + asm_identifier_prefix + blob_identifier + "\n");
					asource.put_string (asm_identifier_prefix + blob_identifier + ":\n");
					asource.put_string (".incbin \"" + input_file.get_path () + "\"\n");
					asource.put_string (".byte 0\n");
				} else {
					blob_identifier_by_index.add (identifier);

					csource.put_string ("static const unsigned char " + identifier + "[" + file_size.to_string () + " + 1] =\n{\n");
					serialize_to_c_array (file_input_stream, csource);
					csource.put_string ("\n};\n\n");
				}
			}

			var blob_list_identifier = category_identifier + "_blobs";

			csource.put_string ("static const " + blob_ctype + " " + blob_list_identifier + "[" + category.files.size.to_string () + "] =\n{");
			for (int file_index = 0; file_index != file_count; file_index++) {
				var filename = Path.get_basename (category.files[file_index]);
				var blob_identifier = blob_identifier_by_index[file_index];
				var size = size_by_index[file_index];
				if (enable_asm) {
					csource.put_string ("\n  { \"%s\", %s, %s },".printf (filename, blob_identifier, size.to_string ()));
				} else {
					csource.put_string ("\n  { \"%s\", %s, sizeof (%s) - 1 },".printf (filename, blob_identifier, blob_identifier));
				}
			}
			csource.put_string ("\n};\n\n");

			if (is_root_category) {
				for (int file_index = 0; file_index != file_count; file_index++) {
					var identifier = identifier_by_index[file_index];

					var func_name_and_arglist = namespace_cprefix + "_get_" + identifier + "_blob (" + blob_ctype + " * blob)";

					cheader.put_string (
						"void " + func_name_and_arglist + ";\n",
						null);

					csource.put_string (
						"void\n" +
						func_name_and_arglist + "\n" +
						"{\n" +
						"  *blob = " + blob_list_identifier + "[" + file_index.to_string () + "];\n" +
						"}\n" +
						"\n",
						null);

					vapi.put_string ("\tpublic static " + output_namespace + ".Blob get_" + identifier + "_blob ();\n");
				}

				if (categories.size > 1) {
					cheader.put_string ("\n");

					vapi.put_string ("\n");
				}
			} else {
				var func_name_and_arglist = namespace_cprefix + "_find_" + category_identifier + "_by_name (const char * name)";

				cheader.put_string (
					"const " + blob_ctype + " * " + func_name_and_arglist + ";\n",
					null);

				csource.put_string (
					"const " + blob_ctype + " *\n" +
					func_name_and_arglist + "\n" +
					"{\n" +
					"  " + blob_ctype + " needle;\n" +
					"\n" +
					"  needle.name = name;\n" +
					"  needle.data = NULL;\n" +
					"  needle.data_length1 = 0;\n" +
					"\n" +
					"  return bsearch (&needle, " + blob_list_identifier + ", G_N_ELEMENTS (" + blob_list_identifier + "), sizeof (" + blob_ctype + "), " + compare_func_identifier + ");\n" +
					"}\n",
					null);

				vapi.put_string ("\tpublic static unowned " + output_namespace + ".Blob? find_" + category_identifier + "_by_name (string name);\n");
			}
		}

		vapi.put_string (
			"\n" +
			"	public struct Blob {\n" +
			"		public unowned string name;\n" +
			"		public unowned uint8[] data;\n" +
			"\n" +
			"		public Blob (string name, uint8[] data) {\n" +
			"			this.name = name;\n" +
			"			this.data = data;\n" +
			"		}\n" +
			"	}\n" +
			"\n" +
			"}\n",
			null);

		cheader.put_string ("\nG_END_DECLS\n\n#endif\n");

		replace_file_if_different (vapi_file, vapi_content);
		replace_file_if_different (cheader_file, cheader_content);
	}

	private void serialize_to_c_array (InputStream input, DataOutputStream output) throws Error {
		var input_stream = new DataInputStream (input);

		var input_buf = new uint8[128 * 1024];
		var builder = new StringBuilder.sized (input_buf.length * 6);
		int line_offset = 0;

		while (true) {
			size_t bytes_read = input_stream.read (input_buf);
			if (bytes_read == 0)
				break;

			for (size_t i = 0; i != bytes_read; i++) {
				if (line_offset == 0)
					builder.append ("  ");

				append_hexbyte (input_buf[i], builder);
				builder.append_c (',');

				line_offset++;
				if (line_offset % 12 != 0) {
					builder.append_c (' ');
				} else {
					line_offset = 0;
					builder.append_c ('\n');
				}
			}

			builder.truncate (builder.len - 1);
			output.put_string (builder.str);
			builder.truncate (0);
		}

		output.put_string ("0x00"); /* so text file resources may be used as C strings */
	}

	private void replace_file_if_different (File file, MemoryOutputStream new_content) throws Error {
		bool different = true;

		try {
			var input = file.read ();
			var info = input.query_info (FILE_ATTRIBUTE_STANDARD_SIZE);
			var existing_size = (size_t) info.get_attribute_uint64 (FILE_ATTRIBUTE_STANDARD_SIZE);

			if (existing_size == new_content.get_data_size ()) {
				uint8[] existing_content_data = new uint8[existing_size];
				var existing_content = new MemoryOutputStream (existing_content_data, null, free);
				size_t bytes_read;
				if (input.read_all (existing_content.get_data (), out bytes_read) && bytes_read == existing_size)
					different = Memory.cmp (existing_content.get_data (), new_content.get_data (), existing_size) != 0;
			}
		} catch (Error e) {
		}

		if (!different)
			return;

		var blob_size = new_content.data_size;
		uint8[] blob = new uint8[blob_size];
		Memory.copy(blob, new_content.data, blob_size);
		var output = file.replace (null, false, FileCreateFlags.REPLACE_DESTINATION);
		output.write_all (blob);
	}

	private string c_namespace_from_vala (string vala_ns) {
		var builder = new StringBuilder ();

		bool previous_was_lowercase = false;

		for (int i = 0; i != vala_ns.length; i++) {
			unichar c = vala_ns[i];
			if (c == '.')
				continue;

			if (previous_was_lowercase && c.isupper ())
				builder.append_c ('_');
			else
				previous_was_lowercase = true;

			builder.append_unichar (c.tolower ());
		}

		return builder.str;
	}

	private string identifier_from_filename (string filename) {
		var builder = new StringBuilder ();

		for (int i = 0; i != filename.length; i++) {
			unichar c = filename[i];
			if (c == '-' || c == '.')
				c = '_';
			builder.append_unichar (c.tolower ());
		}

		return builder.str;
	}

	private void append_hexbyte (uint8 b, StringBuilder builder) {
		builder.append ("0x");
		builder.append_c (NIBBLE_TO_HEX_CHAR[b >> 4]);
		builder.append_c (NIBBLE_TO_HEX_CHAR[b & 0xf]);
	}

	static int main (string[] args) {
#if DARWIN
		toolchain = "apple";
#else
		toolchain = "gnu";
#endif

		try {
			var ctx = new OptionContext ("- Vala Resource Compiler");
			ctx.set_help_enabled (true);
			ctx.add_main_entries (options, null);
			ctx.parse (ref args);
		} catch (OptionError e) {
			stdout.printf ("%s\n", e.message);
			stdout.printf ("Run '%s --help' to see a full list of available command line options.\n", args[0]);
			return 1;
		}

		if (config_filename == null) {
			stderr.printf ("No config file specified.\n");
			return 1;
		}

		if (output_basename == null) {
			stderr.printf ("No output basename specified.\n");
			return 1;
		}

		var compiler = new ResourceCompiler ();
		try {
			compiler.run ();
		} catch (Error e) {
			stderr.printf ("%s\n", e.message);
			return 1;
		}

		return 0;
	}

	private class ResourceCategory {
		public string name {
			get;
			private set;
		}

		public Gee.ArrayList<string> files {
			get;
			private set;
		}

		public ResourceCategory (string name) {
			this.name = name;
			this.files = new Gee.ArrayList<string> ();
		}
	}
}

