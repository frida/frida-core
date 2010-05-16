class Vala.ResourceCompiler {
	[CCode (array_length = false, array_null_terminated = true)]
	private static string[] input_filenames;
	private static string output_filename;
	private static string output_namespace;

	private const OptionEntry[] options = {
		{ "namespace", 0, 0, OptionArg.STRING, ref output_namespace, "Output namespace", "NAMESPACE" },
		{ "output", 'o', 0, OptionArg.FILENAME, ref output_filename, "Place output in file FILE", "FILE" },
		{ "", 0, 0, OptionArg.FILENAME_ARRAY, ref input_filenames, null, "FILE..." },
		{ null }
	};

	private enum OutputFormat {
		INVALID,
		C,
		VALA
	}

	private OutputFormat output_format;

	private const char NIBBLE_TO_HEX_CHAR[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

	private int run () {
		var output_file = File.new_for_commandline_arg (output_filename);

		DataOutputStream output_stream = null;

		try {
			output_stream = new DataOutputStream (output_file.replace (null, false, FileCreateFlags.REPLACE_DESTINATION, null));
		} catch (Error e) {
			stderr.printf ("%s\n", e.message);
			return 1;
		}

		output_format = (output_filename.has_suffix (".vala") ? OutputFormat.VALA : OutputFormat.C);

		try {
			uint8[] input_buf = new uint8[128 * 1024];
			var builder = new StringBuilder.sized (input_buf.length * 6);

			uint file_index = 0;
			uint indent_depth = 0;

			output_stream.put_string ("/* generated file, do not modify */\n", null);

			if (output_namespace != null && output_format == OutputFormat.VALA) {
				output_stream.put_string ("namespace " + output_namespace + " {\n", null);
				indent_depth++;
			}

			foreach (string input_filename in input_filenames) {
				if (file_index != 0)
					output_stream.put_string ("\n", null);

				var input_file = File.new_for_commandline_arg (input_filename);

				if (!input_file.query_exists (null)) {
					stderr.printf ("File '%s' does not exist.\n", input_file.get_path ());
					return 1;
				}

				var file_input_stream = input_file.read (null);

				var input_info = file_input_stream.query_info (FILE_ATTRIBUTE_STANDARD_SIZE, null);

				string heading;
				if (output_format == OutputFormat.VALA) {
					var heading_format = "%spublic static const uint8 %s[%" + uint64.FORMAT + "] = {\n";
					heading = heading_format.printf (
						indent_string_for_depth (indent_depth),
						constant_name_from_filename (input_file.get_basename ()),
						input_info.get_attribute_uint64 (FILE_ATTRIBUTE_STANDARD_SIZE));
				} else {
					var indent_str = indent_string_for_depth (indent_depth);
					var array_name = c_array_name_from_filename (input_file.get_basename ());
					var file_size = input_info.get_attribute_uint64 (FILE_ATTRIBUTE_STANDARD_SIZE);

					var format = "%sconst unsigned int %s_size = %" + uint64.FORMAT + ";\n";
					output_stream.put_string (format.printf (indent_str, array_name, file_size), null);

					var heading_format = "%sconst unsigned char %s_data[%" + uint64.FORMAT + "] =\n{\n";
					heading = heading_format.printf (
						indent_str,
						array_name,
						file_size);
				}
				output_stream.put_string (heading, null);

				var input_stream = new DataInputStream (file_input_stream);
				int line_offset = 0;

				indent_depth++;

				while (true) {
					size_t bytes_read = input_stream.read (input_buf, input_buf.length, null);
					if (bytes_read == 0)
						break;

					for (size_t i = 0; i != bytes_read; i++) {
						if (line_offset == 0)
							append_indent (indent_depth, builder);

						append_hexbyte (input_buf[i], builder);
						builder.append_c (',');

						line_offset++;
						if (line_offset % 16 != 0) {
							builder.append_c (' ');
						} else {
							line_offset = 0;
							builder.append_c ('\n');
						}
					}

					output_stream.put_string (builder.str, null);
					builder.truncate (0);
				}

				indent_depth--;

				output_stream.put_string (indent_string_for_depth (indent_depth), null);
				output_stream.put_string ("};\n", null);

				file_index++;
			}

			if (output_namespace != null && output_format == OutputFormat.VALA) {
				indent_depth--;
				output_stream.put_string (indent_string_for_depth (indent_depth), null);
				output_stream.put_string ("}\n", null);
			}
		} catch (Error e) {
			stderr.printf ("IO Error: %s\n", e.message);
			return 1;
		}

		return 0;
	}

	private string c_array_name_from_filename (string filename) {
		var builder = new StringBuilder ();

		if (output_namespace != null) {
			builder.append (output_namespace);
			builder.append_c ('_');
		}

		for (int i = 0; i != filename.length; i++) {
			unichar c = filename[i];
			if (c == '.')
				break;

			if (c == '-')
				c = '_';
			builder.append_unichar (c.tolower ());
		}

		return builder.str;
	}

	private string constant_name_from_filename (string filename) {
		var builder = new StringBuilder ();
		for (int i = 0; i != filename.length; i++) {
			unichar c = filename[i];
			if (c == '.')
				break;

			if (c == '-')
				c = '_';
			builder.append_unichar (c.toupper ());
		}
		return builder.str;
	}

	private string indent_string_for_depth (uint depth) {
		var builder = new StringBuilder ();
		append_indent (depth, builder);
		return builder.str;
	}

	private void append_indent (uint depth, StringBuilder builder) {
		string indent_str = (output_format == OutputFormat.VALA) ? "\t" : "  ";
		for (uint i = 0; i != depth; i++)
			builder.append (indent_str);
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

		if (output_filename == null) {
			stderr.printf ("No output filename specified.\n");
			return 1;
		}

		var compiler = new ResourceCompiler ();
		return compiler.run ();
	}
}

