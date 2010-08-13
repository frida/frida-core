class Vala.ResourceCompiler {
	[CCode (array_length = false, array_null_terminated = true)]
	private static string[] input_filenames;
	private static string output_basename;
	private static string output_namespace;

	private const OptionEntry[] options = {
		{ "namespace", 0, 0, OptionArg.STRING, ref output_namespace, "Output namespace", "NAMESPACE" },
		{ "output-basename", 'o', 0, OptionArg.FILENAME, ref output_basename, "Place output in BASENAME", "BASENAME" },
		{ "", 0, 0, OptionArg.FILENAME_ARRAY, ref input_filenames, null, "FILE..." },
		{ null }
	};

	private const char NIBBLE_TO_HEX_CHAR[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	private int run () {
		var vapi_file = File.new_for_commandline_arg (output_basename + ".vapi");
		var cheader_file = File.new_for_commandline_arg (output_basename + ".h");
		var csource_file = File.new_for_commandline_arg (output_basename + ".c");

		DataOutputStream vapi = null;
		DataOutputStream cheader = null;
		DataOutputStream csource = null;

		try {
			vapi = new DataOutputStream (vapi_file.replace (null, false, FileCreateFlags.REPLACE_DESTINATION, null));
			cheader = new DataOutputStream (cheader_file.replace (null, false, FileCreateFlags.REPLACE_DESTINATION, null));
			csource = new DataOutputStream (csource_file.replace (null, false, FileCreateFlags.REPLACE_DESTINATION, null));
		} catch (Error e) {
			stderr.printf ("%s\n", e.message);
			return 1;
		}

		try {
			uint8[] input_buf = new uint8[128 * 1024];
			var builder = new StringBuilder.sized (input_buf.length * 6);

			uint file_index = 0;

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
				"  const unsigned char * data;\n" +
				"  unsigned int size;\n" +
				"};\n" +
				"\n").printf (incguard_name, incguard_name, blob_ctype, blob_ctype, blob_ctype),
				null);

			csource.put_string (
				"/* generated file, do not modify */\n" +
				"\n" +
				"#include \"" + cheader_file.get_basename () + "\"\n" +
				"\n",
				null);

			foreach (string input_filename in input_filenames) {
				if (file_index != 0)
					csource.put_string ("\n", null);

				var input_file = File.new_for_commandline_arg (input_filename);

				if (!input_file.query_exists (null)) {
					stderr.printf ("File '%s' does not exist.\n", input_file.get_path ());
					return 1;
				}

				var file_input_stream = input_file.read (null);
				var input_info = file_input_stream.query_info (FILE_ATTRIBUTE_STANDARD_SIZE, null);
				var identifier = identifier_from_filename (input_file.get_basename ());
				var file_size = input_info.get_attribute_uint64 (FILE_ATTRIBUTE_STANDARD_SIZE);

				vapi.put_string ("\tpublic static " + output_namespace + ".Blob get_" + identifier + "_blob ();\n", null);

				csource.put_string ("static const unsigned char " + identifier + "[" + file_size.to_string () + "] =\n{\n"  , null);

				var input_stream = new DataInputStream (file_input_stream);
				int line_offset = 0;

				while (true) {
					size_t bytes_read = input_stream.read (input_buf, input_buf.length, null);
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

					csource.put_string (builder.str, null);
					builder.truncate (0);
				}

				csource.put_string ("\n};\n\n", null);

				var func_name_and_arglist = namespace_cprefix + "_get_" + identifier + "_blob (" + blob_ctype + " * blob)";
				cheader.put_string (
					"void " + func_name_and_arglist + ";\n",
					null);
				csource.put_string (
					"void\n" +
					func_name_and_arglist + "\n" +
					"{\n" +
					"  blob->data = " + identifier + ";\n" +
					"  blob->size = sizeof (" + identifier + ");\n" +
					"}\n",
					null);

				file_index++;
			}

			vapi.put_string (
				"\n" +
				"	public struct Blob {\n" +
				"		public void * data;\n" +
				"		public uint size;\n" +
				"\n" +
				"		public Blob (void * data, uint size) {\n" +
				"			this.data = data;\n" +
				"			this.size = size;\n" +
				"		}\n" +
				"	}\n" +
				"\n" +
				"}\n",
				null);

			cheader.put_string ("\nG_END_DECLS\n\n#endif\n", null);
		} catch (Error e) {
			stderr.printf ("IO Error: %s\n", e.message);
			return 1;
		}

		return 0;
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

		if (input_filenames == null) {
			stderr.printf ("No input file specified.\n");
			return 1;
		}

		if (output_basename == null) {
			stderr.printf ("No output basename specified.\n");
			return 1;
		}

		var compiler = new ResourceCompiler ();
		return compiler.run ();
	}
}

