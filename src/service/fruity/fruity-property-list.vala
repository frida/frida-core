namespace Zed.Service.Fruity {
	public class PropertyList : Object {
		private Gee.HashMap<string, Value?> value_by_key = new Gee.HashMap<string, Value?> ();

		public PropertyList.from_xml (string xml) throws IOError {
			try {
				var parser = new XmlParser (this);
				parser.parse (xml);
			} catch (MarkupError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public string to_xml () {
			var builder = new StringBuilder ();
			var writer = new XmlWriter (builder);
			writer.write (this);
			return builder.str;
		}

		public string[] get_keys () {
			return value_by_key.keys.to_array ();
		}

		public string get_string (string key) throws IOError {
			return get_value (key, typeof (string)).get_string ();
		}

		public void set_string (string key, string str) {
			var gval = Value (typeof (string));
			gval.set_string (str);
			set_value (key, gval);
		}

		public int get_int (string key) throws IOError {
			return get_value (key, typeof (int)).get_int ();
		}

		public void set_int (string key, int val) {
			var gval = Value (typeof (int));
			gval.set_int (val);
			set_value (key, gval);
		}

		public PropertyList get_plist (string key) throws IOError {
			return get_value (key, typeof (PropertyList)).get_object () as PropertyList;
		}

		public void set_plist (string key, PropertyList plist) {
			var gval = Value (typeof (PropertyList));
			gval.set_object (plist);
			set_value (key, gval);
		}

		private Value get_value (string key, Type expected_type = Type.INVALID) throws IOError {
			var val = value_by_key[key];
			if (val == null)
				throw new IOError.FAILED ("no such key");
			if (expected_type != Type.INVALID && !val.holds (expected_type))
				throw new IOError.FAILED ("type mismatch");
			return val;
		}

		private void set_value (string key, Value val) {
			value_by_key[key] = val;
		}

		private class XmlParser : Object {
			public PropertyList plist {
				get;
				construct;
			}

			private const MarkupParser parser = {
				on_start_element,
				on_end_element,
				on_text,
				null,
				null
			};

			private Gee.Deque<PropertyList> stack;
			private KeyValuePair current_pair;

			public XmlParser (PropertyList plist) {
				Object (plist: plist);
			}

			public void parse (string xml) throws MarkupError {
				stack = new Gee.LinkedList<PropertyList> ();
				current_pair = null;

				var context = new MarkupParseContext (parser, 0, this, null);
				context.parse (xml, -1);

				stack = null;
				current_pair = null;
			}

			private void on_start_element (MarkupParseContext context, string element_name, string[] attribute_names, string[] attribute_values) throws MarkupError {
				if (stack.is_empty) {
					if (element_name == "dict")
						stack.offer_head (plist);
					return;
				} else if (current_pair == null) {
					if (element_name == "key")
						current_pair = new KeyValuePair ();
					return;
				}

				if (current_pair.type == null) {
					current_pair.type = element_name;

					if (current_pair.type == "dict") {
						var parent_plist = stack.peek ();

						var child_plist = new PropertyList ();
						stack.offer_head (child_plist);
						var child_plist_value = Value (typeof (PropertyList));
						child_plist_value.set_object (child_plist);
						parent_plist.set_value (current_pair.key, child_plist_value);

						current_pair = null;
					}
				}
			}

			private void on_end_element (MarkupParseContext context, string element_name) throws MarkupError {
				if (element_name == "dict")
					stack.poll ();
			}

			private void on_text (MarkupParseContext context, string text, size_t text_len) throws MarkupError {
				if (current_pair == null)
					return;

				if (current_pair.key == null) {
					current_pair.key = text;
				} else if (current_pair.type != null) {
					current_pair.val = text;

					var val = current_pair.to_value ();
					if (val != null) {
						var current_plist = stack.peek ();
						current_plist.set_value (current_pair.key, val);
					}

					current_pair = null;
				}
			}

			private class KeyValuePair {
				public string? key;
				public string? type;
				public string? val;

				public Value? to_value () {
					Value? result = null;

					if (type == "string") {
						result = Value (typeof (string));
						result.set_string (val);
					} else if (type == "integer") {
						result = Value (typeof (int));
						result.set_int (val.to_int ());
					}

					return result;
				}
			}
		}

		private class XmlWriter {
			private unowned StringBuilder builder;
			private uint level = 0;

			public XmlWriter (StringBuilder builder) {
				this.builder = builder;
			}

			public void write (PropertyList plist) {
				if (level == 0) {
					write_line ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
					write_line ("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">");
					write_line ("<plist version=\"1.0\">");
				}

				write_line ("<dict>");
				level++;

				var keys = new Gee.ArrayList<string> ();
				var key_array = plist.get_keys ();
				foreach (var key in key_array)
					keys.add (key);
				keys.sort ();

				foreach (var key in keys) {
					write_tag ("key", key);

					Value val;
					try {
						val = plist.get_value (key);
					} catch (IOError e) {
						assert_not_reached ();
					}
					var type = val.type ();
					if (type == typeof (string))
						write_tag ("string", val.get_string ());
					else if (type == typeof (int))
						write_tag ("integer", val.get_int ().to_string ());
					else if (type == typeof (PropertyList))
						write (val.get_object () as PropertyList);
				}

				level--;
				write_line ("</dict>");

				if (level == 0)
					write_line ("</plist>");
			}

			private void write_tag (string name, string content) {
				write_line ("<" + name + ">" + content + "</" + name + ">");
			}

			private void write_line (string line) {
				for (uint i = 0; i != level; i++)
					builder.append_c ('\t');
				builder.append (line);
				builder.append ("\n");
			}
		}
	}
}
