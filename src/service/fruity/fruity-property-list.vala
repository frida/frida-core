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

		public string[] get_keys () {
			return value_by_key.keys.to_array ();
		}

		public string get_string (string key) throws IOError {
			return get_value (key, typeof (string)).get_string ();
		}

		public int get_int (string key) throws IOError {
			return get_value (key, typeof (int)).get_int ();
		}

		public PropertyList get_plist (string key) throws IOError {
			return get_value (key, typeof (PropertyList)).get_object () as PropertyList;
		}

		private Value get_value (string key, Type expected_type) throws IOError {
			var val = value_by_key[key];
			if (val == null)
				throw new IOError.FAILED ("no such key");
			if (!val.holds (expected_type))
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
	}
}