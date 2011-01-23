using Gee;

namespace Zed {
	public class View.AgentSession : Object {
		public Gtk.Widget widget {
			get {
				return root_vbox;
			}
		}

		public Gtk.Frame control_frame {
			get;
			private set;
		}

		public ProcessInfoLabel process_info_label {
			get;
			private set;
		}

		public Gtk.Button go_button {
			get;
			private set;
		}

		public FunctionSelector start_selector {
			get;
			private set;
		}

		public FunctionSelector stop_selector {
			get;
			private set;
		}

		public Gtk.Notebook content_notebook {
			get;
			private set;
		}

		public Gtk.TreeView event_view {
			get;
			private set;
		}

		public Gtk.TextView console_view {
			get;
			private set;
		}

		public Gtk.TextTag console_input_tag {
			get;
			private set;
		}

		public Gtk.TextTag console_line_number_tag {
			get;
			private set;
		}

		public Gtk.TextTag console_code_text_tag {
			get;
			private set;
		}

		public Gtk.Entry console_entry {
			get;
			private set;
		}

		private Gtk.VBox root_vbox;

#if WINDOWS
		private Clutter.BehaviourRotate rotation;
		private Clutter.BehaviourScale scaling;
#endif

		public AgentSession () {
			try {
				var builder = new Gtk.Builder ();
				var blob = Zed.Data.Ui.get_agent_session_ui_blob ();
				builder.add_from_string ((string) blob.data, blob.size);

				root_vbox = builder.get_object ("root_vbox") as Gtk.VBox;

				control_frame = builder.get_object ("control_frame") as Gtk.Frame;
				go_button = builder.get_object ("go_button") as Gtk.Button;

				content_notebook = builder.get_object ("content_notebook") as Gtk.Notebook;

				var alignment = builder.get_object ("overview_alignment") as Gtk.Alignment;
				setup_overview (alignment);

				event_view = builder.get_object ("event_view") as Gtk.TreeView;

				console_view = builder.get_object ("console_view") as Gtk.TextView;

				console_input_tag = console_view.buffer.create_tag ("console-input",
					"foreground", "#ffffff");
				console_line_number_tag = console_view.buffer.create_tag ("console-line-number",
					"foreground", "#ffff00");
				console_code_text_tag = console_view.buffer.create_tag ("console-code-text",
					"foreground", "#ffffff");

				console_entry = builder.get_object ("console_entry") as Gtk.Entry;

				process_info_label = new ProcessInfoLabel ();
				var process_info_alignment = builder.get_object ("process_info_alignment") as Gtk.Alignment;
				process_info_alignment.add (process_info_label);

				start_selector = new FunctionSelector ();
				alignment = builder.get_object ("start_alignment") as Gtk.Alignment;
				alignment.add (start_selector);

				stop_selector = new FunctionSelector ();
				alignment = builder.get_object ("stop_alignment") as Gtk.Alignment;
				alignment.add (stop_selector);
			} catch (Error e) {
				error (e.message);
			}

			customize_widget_styles ();
		}

		private void setup_overview (Gtk.Container parent) {
#if WINDOWS
			var frame = new MxGtk.Frame ();
			parent.add (frame);

			var embed = new GtkClutter.Embed ();
			frame.add (embed);

			var stage = embed.get_stage () as Clutter.Stage;
			stage.color = Clutter.Color.from_string ("#c0c0c0ff");

			var button = new Mx.Button.with_label ("Hello");
			button.set_position (160.0f, 50.0f);

			var rotation_timeline = new Clutter.Timeline (5000);
			rotation_timeline.loop = true;

			var alpha = new Clutter.Alpha.full (rotation_timeline, Clutter.AnimationMode.LINEAR);
			rotation = new Clutter.BehaviourRotate (alpha, Clutter.RotateAxis.Z_AXIS, Clutter.RotateDirection.CW, 0.0, 360.0) as Clutter.BehaviourRotate;
			rotation.set_center (80, 60, 0);
			rotation.apply (button);

			var scaling_timeline = new Clutter.Timeline (2000);
			scaling_timeline.loop = true;

			alpha = new Clutter.Alpha.full (scaling_timeline, Clutter.AnimationMode.EASE_IN_OUT_SINE);
			scaling = new Clutter.BehaviourScale (alpha, 1.0, 1.0, 20.0, 20.0);
			scaling.apply (button);

			var start_count = 0;

			button.clicked.connect (() => {
				if (!rotation_timeline.is_playing ()) {
					rotation_timeline.start ();

					if (start_count == 1)
						scaling_timeline.start ();
					else if (start_count == 2)
						scaling_timeline.pause ();

					start_count++;
				} else {
					rotation_timeline.pause ();
				}

			});
			stage.add_actor (button);

			frame.show_all ();
			frame.map_event.connect ((ev) => {
				stage.show_all ();
				return false;
			});
#endif
		}

		private void customize_widget_styles () {
			var monospace_font = Pango.FontDescription.from_string ("Lucida Console 8");

			Gdk.Color view_bg;
			Gdk.Color.parse ("#333333", out view_bg);
			console_view.modify_base (Gtk.StateType.NORMAL, view_bg);
			Gdk.Color view_fg;
			Gdk.Color.parse ("#FFFF00", out view_fg);
			console_view.modify_text (Gtk.StateType.NORMAL, view_fg);
			console_view.modify_font (monospace_font);

			Gdk.Color entry_bg;
			Gdk.Color.parse ("#4d4d4d", out entry_bg);
			console_entry.modify_base (Gtk.StateType.NORMAL, entry_bg);
			Gdk.Color entry_fg;
			Gdk.Color.parse ("#ffffff", out entry_fg);
			console_entry.modify_text (Gtk.StateType.NORMAL, entry_fg);
			console_entry.modify_font (monospace_font);
		}
	}

	public class Presenter.AgentSession : Object {
		public View.AgentSession view {
			get;
			construct;
		}

		public HostSessionEntry host_session {
			get;
			construct;
		}

		public ProcessInfo process_info {
			get;
			construct;
		}

		public CodeService code_service {
			get;
			construct;
		}

		public enum State {
			UNINITIALIZED,
			ATTACHING,
			SYNCHRONIZING,
			ATTACHED,
			ERROR,
			TERMINATED
		}

		public State state {
			get;
			private set;
		}
		private string error_message;

		public Zed.AgentSession session {
			get;
			private set;
		}
		private bool is_closing = false;
		private ulong closed_handler_id;

		private ProcessInfoLabel process_info_label;
		private FunctionSelector start_selector;
		private FunctionSelector stop_selector;

		private Gtk.ListStore function_call_store = new Gtk.ListStore (1, typeof (FunctionCall));

		private Gtk.TextBuffer console_text_buffer;
		private Gtk.TextMark console_scroll_mark;
		private Gee.LinkedList<string> console_input_history = new Gee.LinkedList<string> ();
		private Gee.ListIterator<string> console_input_iter;

		private Investigation investigation;

		private const uint KEYVAL_ARROW_UP = 65362;
		private const uint KEYVAL_ARROW_DOWN = 65364;

		public AgentSession (View.AgentSession view, HostSessionEntry host_session, ProcessInfo process_info, CodeService code_service) {
			Object (view: view, host_session: host_session, process_info: process_info, code_service: code_service);

			update_state (State.UNINITIALIZED);

			process_info_label = new ProcessInfoLabel (view.process_info_label, process_info);
			start_selector = new FunctionSelector (view.start_selector);
			stop_selector = new FunctionSelector (view.stop_selector);

			configure_selectors ();
			configure_go_button ();
			configure_event_view ();
			configure_console ();
		}

		public void close () {
			/* break strong references */
			view.widget.destroy ();

			if (session != null) {
				assert (closed_handler_id != 0);
				host_session.provider.disconnect (closed_handler_id);
			}
		}

		public async void start () {
			try {
				update_state (State.ATTACHING);

				var session_id = yield host_session.session.attach_to (process_info.pid);
				session = yield host_session.provider.obtain_agent_session (session_id);
				closed_handler_id = host_session.provider.agent_session_closed.connect ((id, err) => {
					if (id != session_id)
						return;

					if (!is_closing && error != null)
						this.error (err.message);
					else
						this.update_state (State.TERMINATED);
				});
				session.message_from_script.connect (on_message_from_script);
				session.memory_read_detected.connect (on_memory_read_detected);

				update_state (State.SYNCHRONIZING);
				yield update_module_specs ();
				update_state (State.ATTACHED);

				start_selector.set_session (session);
				stop_selector.set_session (session);
			} catch (IOError e) {
				this.error (e.message);
			}
		}

		public async void terminate () {
			if (state == State.TERMINATED)
				return;

			if (state == State.ATTACHED) {
				try {
					is_closing = true;
					yield session.close ();
				} catch (IOError e) {
					this.error (e.message);
					return;
				}
			}

			update_state (State.TERMINATED);
		}

		private async void start_investigation () {
			function_call_store.clear ();

			investigation = new Investigation (session, code_service);
			investigation.new_function_call.connect (on_new_function_call);
			investigation.finished.connect (end_investigation);

			update_view ();

			yield update_module_specs ();

			var start_trigger = AgentTriggerInfo (start_selector.selected_module_name, start_selector.selected_function_name);
			var stop_trigger = AgentTriggerInfo (stop_selector.selected_module_name, stop_selector.selected_function_name);
			bool success = yield investigation.start (start_trigger, stop_trigger);
			if (!success)
				investigation = null;

			update_view ();
		}

		private void on_new_function_call (FunctionCall function_call) {
			Gtk.TreeIter iter;
			function_call_store.append (out iter);
			function_call_store.set (iter, 0, function_call);
		}

		private void end_investigation () {
			investigation = null;
			update_view ();
		}

		private void error (string message) {
			this.error_message = message;
			update_state (State.ERROR);
		}

		private void configure_selectors () {
			start_selector.notify["selection-is-set"].connect (update_view);
			stop_selector.notify["selection-is-set"].connect (update_view);
		}

		private void configure_go_button () {
			view.go_button.clicked.connect (() => start_investigation ());
		}

		private void configure_event_view () {
			var ev = view.event_view;

			ev.set_model (function_call_store);

			ev.insert_column_with_data_func (-1, "From", new Gtk.CellRendererText (), event_view_from_column_data_callback);

			var target_renderer = new Gtk.CellRendererText ();
			target_renderer.editable = true;
			target_renderer.edited.connect ((path_str, new_text) => {
				var path = new Gtk.TreePath.from_string (path_str);
				Gtk.TreeIter iter;
				function_call_store.get_iter (out iter, path);

				FunctionCall call;
				function_call_store.@get (iter, 0, out call);
				code_service.rename_function (call.target, new_text);
			});
			ev.insert_column_with_data_func (-1, "To", target_renderer, event_view_to_column_data_callback);
		}

		private void event_view_from_column_data_callback (Gtk.TreeViewColumn col, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			FunctionCall call;
			model.get (iter, 0, out call);

			var text_renderer = renderer as Gtk.CellRendererText;
			var module = call.module;
			if (module != null) {
				text_renderer.text = "%s+0x%08llx".printf (module.spec.name, call.offset);
			} else {
				text_renderer.text = "0x%08llx".printf (call.offset);
			}
		}

		private void event_view_to_column_data_callback (Gtk.TreeViewColumn col, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			FunctionCall call;
			model.get (iter, 0, out call);

			(renderer as Gtk.CellRendererText).text = call.target.spec.name;
		}

		private void update_view () {
			view.control_frame.sensitive = (state == State.ATTACHED);

			if (state == State.ATTACHED) {
				view.start_selector.sensitive = (investigation == null);
				view.stop_selector.sensitive = (investigation == null);
				view.go_button.sensitive = (start_selector.selection_is_set && stop_selector.selection_is_set && investigation == null);
			}
		}

		private void update_state (State new_state) {
			if (new_state == this.state)
				return;

			this.state = new_state;

			update_view ();
		}

		private async bool update_module_specs () {
			try {
				var module_info_list = yield session.query_modules ();
				foreach (var mi in module_info_list) {
					ModuleSpec module_spec = yield code_service.find_module_spec_by_uid (mi.uid);
					if (module_spec == null) {
						module_spec = new ModuleSpec (mi.name, mi.uid, mi.size);
						code_service.add_module_spec (module_spec);

						var function_info_list = yield session.query_module_functions (mi.name);
						foreach (var fi in function_info_list) {
							var func_spec = new FunctionSpec (fi.name, fi.address - mi.address);
							yield code_service.add_function_spec_to_module (func_spec, module_spec);
						}
					}

					Module module = yield code_service.find_module_by_address (mi.address);
					if (module == null) {
						module = new Module (module_spec, mi.address);
						code_service.add_module (module);
					}
				}
			} catch (IOError e) {
				return false;
			}

			return true;
		}

		public string state_to_string () {
			switch (state) {
				case State.UNINITIALIZED:
					return "Uninitialized";
				case State.ATTACHING:
					return "Attaching";
				case State.SYNCHRONIZING:
					return "Synchronizing";
				case State.ATTACHED:
					return "Attached";
				case State.ERROR:
					return "Error: %s".printf (error_message);
				case State.TERMINATED:
					return "Terminated";
				default:
					assert_not_reached ();
			}
		}

		/* TODO: consider moving console out into a separate View/Presenter */

		private void configure_console () {
			console_text_buffer = view.console_view.buffer;

			console_scroll_mark = new Gtk.TextMark ("scrollmark", false);
			Gtk.TextIter iter;
			console_text_buffer.get_end_iter (out iter);
			console_text_buffer.add_mark (console_scroll_mark, iter);

			view.console_entry.activate.connect (() => {
				var input = view.console_entry.text.strip ();
				if (input.length > 0)
					handle_console_input (input);
				view.console_entry.text = "";

				if (console_input_history.is_empty || input != console_input_history.last ())
					console_input_history.offer_tail (input);
				console_input_iter = null;
			});
			view.console_entry.key_press_event.connect ((ev) => {
				if (ev.state != 0)
					return false;

				int direction = 0;
				if (ev.keyval == KEYVAL_ARROW_UP)
					direction = 1;
				else if (ev.keyval == KEYVAL_ARROW_DOWN)
					direction = -1;
				else
					return false;

				if (!console_input_history.is_empty) {
					if (console_input_iter == null) {
						console_input_iter = console_input_history.list_iterator ();
						if (direction == 1) {
							console_input_iter.last ();
							view.console_entry.text = console_input_iter.get ();
						} else {
							console_input_iter.first ();
							view.console_entry.text = console_input_iter.get ();
						}
					} else {
						bool handled = true;

						if (direction == 1) {
							if (console_input_iter.previous ())
								view.console_entry.text = console_input_iter.get ();
							else
								handled = false;
						} else {
							if (console_input_iter.next ())
								view.console_entry.text = console_input_iter.get ();
							else
								handled = false;
						}

						if (!handled) {
							console_input_iter = null;
							view.console_entry.text = "";
						}
					}

					Signal.emit_by_name (view.console_entry, "move-cursor", Gtk.MovementStep.BUFFER_ENDS, 1, false);
				}

				return true;
			});

			view.content_notebook.switch_page.connect ((page, page_num) => {
				if (page_num == 2) {
					Idle.add (() => {
						view.console_entry.grab_focus ();
						return false;
					});
				}
			});
		}

		private async void handle_console_input (string input) {
			print_to_console ("> " + input, view.console_input_tag);

			string[] tokens;
			try {
				Shell.parse_argv (input, out tokens);
			} catch (ShellError parse_error) {
				print_to_console ("ERROR: " + parse_error.message);
				return;
			}

			var verb = tokens[0];
			string[] args;
			if (tokens.length > 1)
				args = tokens[1:tokens.length];
			else
				args = new string[0];

			switch (verb) {
				case "clear":
					yield handle_clear_command (args);
					break;
				case "encode":
					yield handle_encode_command (args);
					break;
				case "scan":
					yield handle_scan_command (args);
					break;
				case "dump":
					yield handle_dump_command (args);
					break;
				case "dasm":
					yield handle_dasm_command (args);
					break;
				case "write":
					yield handle_write_command (args);
					break;
				case "attach":
					yield handle_attach_command (args);
					break;
				case "detach":
					yield handle_detach_command (args);
					break;
				case "redirect":
					yield handle_redirect_command (args);
					break;
				case "monitor":
					yield handle_monitor_command (args);
					break;
				case "itracker":
					yield handle_itracker_command (args);
					break;
				case "pony":
					yield handle_pony_command (args);
					break;
				case "test":
					yield handle_test_command (args);
					break;
				default:
					print_to_console ("Unknown command '%s'".printf (verb));
					break;
			}
		}

		private void print_clear_usage () {
			print_to_console ("Usage: clear");
		}

		private async void handle_clear_command (string[] args) {
			if (args.length != 0) {
				print_clear_usage ();
				return;
			}

			clear_console ();
		}

		private void print_encode_usage () {
			print_to_console ("Usage: encode utf-8 <string>");
			print_to_console ("       encode utf-16 <string>");
			print_to_console ("       encode i32-be <value>");
			print_to_console ("       encode i32-le <value>");
		}

		private async void handle_encode_command (string[] args) {
			if (args.length != 2) {
				print_encode_usage ();
				return;
			}

			var format = args[0];
			var val = args[1];

			uint8[] bytes = null;

			if (format == "utf-8") {
				bytes = new uint8[val.size ()];
				Memory.copy (bytes, val, bytes.length);
			} else if (format == "utf-16") {
				try {
					long items_written;
					unichar * wideval = TextUtil.utf8_to_utf16 (val, -1, null, out items_written);
					var size = items_written * 2;
					bytes = new uint8[size];
					Memory.copy (bytes, wideval, size);
					free (wideval);
				} catch (Error convert_error) {
					print_to_console ("ERROR: " + convert_error.message);
					return;
				}
			} else if (format == "i32-be") {
				bytes = new uint8[4];
				int beval = val.to_int ().to_big_endian ();
				Memory.copy (bytes, &beval, 4);
			} else if (format == "i32-le") {
				bytes = new uint8[4];
				int leval = val.to_int ().to_little_endian ();
				Memory.copy (bytes, &leval, 4);
			} else {
				print_encode_usage ();
				return;
			}

			print_to_console (byte_array_to_hexdump (bytes));
		}

		private void print_scan_usage () {
			print_to_console ("Usage: scan memory <r|w|x> <pattern>");
			print_to_console ("       scan module <module-name> <pattern>");
		}

		private async void handle_scan_command (string[] args) {
			if (args.length != 3) {
				print_scan_usage ();
				return;
			}

			uint64[] matches;

			try {
				var what = args[0];
				var where = args[1];
				var pattern = args[2];

				if (what == "memory") {
					MemoryProtection required_protection = 0;
					for (uint i = 0; i != where.length; i++) {
						switch (where[i]) {
							case 'r': required_protection |= MemoryProtection.READ; break;
							case 'w': required_protection |= MemoryProtection.WRITE; break;
							case 'x': required_protection |= MemoryProtection.EXECUTE; break;
							default:
								  print_scan_usage ();
								  return;
						}
					}
					if (required_protection == 0) {
						print_scan_usage ();
						return;
					}
					matches = yield session.scan_memory_for_pattern (required_protection, pattern);
				} else if (what == "module") {
					matches = yield session.scan_module_for_code_pattern (where, pattern);
				} else {
					print_scan_usage ();
					return;
				}
			} catch (IOError read_error) {
				print_to_console ("ERROR: " + read_error.message);
				return;
			}

			if (matches.length > 0) {
				print_to_console ("found %u match%s:".printf (matches.length, (matches.length == 1) ? "" : "es"));

				uint match_no = 1;
				foreach (var address in matches) {
					print_to_console (("  match #%u found at 0x%08" + uint64.FORMAT_MODIFIER + "x").printf (match_no, address));

					if (match_no == 10) {
						var remainder = matches.length - match_no;
						if (remainder > 0) {
							print_to_console ("  (and %u more match%s)".printf (remainder, (remainder == 1) ? "" : "es"));
							break;
						}
					}

					match_no++;
				}
			} else {
				print_to_console ("no matches found");
			}
		}

		private void print_dump_usage () {
			print_to_console ("Usage: dump <address-specifier> <length>");
		}

		private async void handle_dump_command (string[] args) {
			uint64 address;
			uint size;

			if (args.length < 2) {
				print_dump_usage ();
				return;
			}

			try {
				var address_args = args[0:args.length - 1];
				address = yield resolve_address_specifier_arguments (address_args);
				size = (uint) uint64_from_string (args[args.length - 1]);
			} catch (IOError arg_error) {
				print_to_console ("ERROR: " + arg_error.message);
				print_to_console ("");
				print_dump_usage ();
				return;
			}

			try {
				uint8[] bytes = yield session.read_memory (address, size);
				print_to_console (byte_array_to_hexdump (bytes, address));
			} catch (IOError read_error) {
				print_to_console ("ERROR: " + read_error.message);
			}
		}

		private void print_dasm_usage () {
			print_to_console ("Usage: dasm <address-specifier> <length>");
		}

		private async void handle_dasm_command (string[] args) {
			uint64 address;
			uint size;

			if (args.length < 2) {
				print_dasm_usage ();
				return;
			}

			try {
				var address_args = args[0:args.length - 1];
				address = yield resolve_address_specifier_arguments (address_args);
				size = (uint) uint64_from_string (args[args.length - 1]);
			} catch (IOError arg_error) {
				print_to_console ("ERROR: " + arg_error.message);
				print_to_console ("");
				print_dasm_usage ();
				return;
			}

			try {
				uint8[] bytes = yield session.read_memory (address, size);

				var builder = new StringBuilder ();

				for (uint offset = 0; offset != bytes.length;) {
					uint64 pc = address + offset;

					builder.append_printf ("%08" + uint64.FORMAT_MODIFIER + "x:  ", pc);

					var slice = bytes[offset:bytes.length];
					uint instruction_length;
					var instruction_str = disassemble (pc, slice, out instruction_length);
					if (instruction_str == null) {
						print_to_console ("<bad instruction>");
						break;
					}

					slice = bytes[offset:offset + instruction_length];
					foreach (uint8 byte in slice)
						builder.append_printf ("%02x ", byte);
					builder.truncate (builder.len - 1);

					if (instruction_length < 2)
						builder.append_c ('\t');
					if (instruction_length < 5)
						builder.append_c ('\t');
					if (instruction_length < 8)
						builder.append_c ('\t');
					builder.append_c ('\t');

					builder.append (instruction_str);

					offset += instruction_length;
					if (offset != bytes.length)
						builder.append_c ('\n');
				}

				print_to_console (builder.str);

			} catch (IOError read_error) {
				print_to_console ("ERROR: " + read_error.message);
			}
		}

		private void print_write_usage () {
			print_to_console ("Usage: write <address-specifier> <hex-string>");
		}

		private async void handle_write_command (string[] args) {
			uint64 address;
			uint8[] bytes;

			if (args.length < 2) {
				print_write_usage ();
				return;
			}

			try {
				var address_args = args[0:args.length - 1];
				address = yield resolve_address_specifier_arguments (address_args);
				bytes = byte_array_from_hex_string (args[args.length - 1]);
			} catch (IOError arg_error) {
				print_to_console ("ERROR: " + arg_error.message);
				print_to_console ("");
				print_write_usage ();
				return;
			}

			try {
				yield session.write_memory (address, bytes);
				print_to_console ("wrote:");
				print_to_console (byte_array_to_hexdump (bytes, address));
			} catch (IOError read_error) {
				print_to_console ("ERROR: " + read_error.message);
			}
		}

		private void print_attach_usage () {
			print_to_console ("Usage: attach script to <address-specifier>");
		}

		private async void handle_attach_command (string[] args) {
			if (args.length < 3 || args[0] != "script" || args[1] != "to") {
				print_attach_usage ();
				return;
			}

			int function_count = 1;

			try {
				var raw_argument = args[args.length - 1];

				var re = new Regex ("^(.*)\\[(\\d+)\\]$");
				MatchInfo match_info;
				if (re.match (raw_argument, 0, out match_info)) {
					assert (match_info.get_match_count () == 3);
					args[args.length - 1] = match_info.fetch (1);
					function_count = match_info.fetch (2).to_int ();
				}
			} catch (RegexError re_error) {
				assert_not_reached ();
			}

			uint64 address;

			try {
				var address_args = args[2:args.length];
				address = yield resolve_address_specifier_arguments (address_args);
			} catch (IOError resolve_error) {
				print_to_console ("ERROR: " + resolve_error.message);
				print_to_console ("");
				print_attach_usage ();
				return;
			}

			var filename = FileOpenDialog.ask_for_filename ("Choose script to attach");
			if (filename == null) {
				print_to_console ("error: no filename specified");
				return;
			}

			string script_text;
			try {
				FileUtils.get_contents (filename, out script_text);
			} catch (FileError file_error) {
				print_to_console ("ERROR: " + file_error.message);
				return;
			}

			script_text = script_text.replace ("\r\n", "\n");

			print_to_console ("script:");
			var lines = script_text.split ("\n");
			uint line_number = 1;
			foreach (var line in lines) {
				if (line_number == lines.length && line == "")
					break;

				print_code_to_console (line_number, line);
				line_number++;
			}

			try {
				if (function_count == 1) {
					var script = yield session.attach_script_to (script_text, address);
					print_to_console (("compiled to %u bytes of code at 0x%08" + uint64.FORMAT_MODIFIER +
						"x").printf (script.code_size, script.code_address));
					print_to_console ("attached with id %u".printf (script.id));
				} else {
					uint8[] bytes = yield session.read_memory (address, (uint) (function_count * sizeof (uint32)));
					unowned uint32 * function_address = (uint32 *) bytes;

					var vtable = new MonitoredVTable ();
					uint first_script_id = 0;

					for (uint function_index = 0; function_index != function_count; function_index++) {
						var message = "function[%u] <0x%08x> => ".printf (function_index, function_address[function_index]);

						try {
							var cur_script = yield session.attach_script_to (script_text, function_address[function_index]);
							if (first_script_id == 0)
								first_script_id = cur_script.id;

							vtable_by_script_id[cur_script.id] = vtable;
							vtable.offset_by_script_id[cur_script.id] = function_index;

							message += "OK";
						} catch (IOError attach_error) {
							message += "failed (%s)".printf (attach_error.message);
						}

						print_to_console (message);
					}

					vtable.id = first_script_id;

					if (first_script_id != 0)
						print_to_console ("attached with id %u".printf (first_script_id));
					else
						print_to_console ("could not attach to any of the specified functions");
				}
			} catch (IOError any_error) {
				print_to_console ("ERROR: " + any_error.message);
			}
		}

		private void print_detach_usage () {
			print_to_console ("Usage: detach script <script-id>");
		}

		private async void handle_detach_command (string[] args) {
			if (args.length != 2 || args[0] != "script") {
				print_detach_usage ();
				return;
			}

			int id = args[1].to_int ();
			if (id <= 0) {
				print_detach_usage ();
				return;
			}

			try {
				var vtable = vtable_by_script_id[id];
				if (vtable == null) {
					yield session.detach_script (id);
				} else {
					foreach (var script_id in vtable.offset_by_script_id.keys) {
						yield session.detach_script (script_id);

						vtable_by_script_id.unset (script_id);
					}
				}

				print_to_console ("script detached");
			} catch (IOError detach_error) {
				print_to_console ("ERROR: " + detach_error.message);
			}
		}

		private void print_redirect_usage () {
			print_to_console ("Usage: redirect script <script-id> output to folder [keep N]");
		}

		private async void handle_redirect_command (string[] args) {
			if ((args.length != 5 && args.length != 7) || args[0] != "script" || args[2] != "output" || args[3] != "to" || args[4] != "folder") {
				print_redirect_usage ();
				return;
			}

			int id = args[1].to_int ();
			if (id <= 0) {
				print_redirect_usage ();
				return;
			}

			int keep_last_n = 0;
			if (args.length == 7) {
				keep_last_n = args[6].to_int ();
				if (args[5] != "keep" || keep_last_n <= 0) {
					print_redirect_usage ();
					return;
				}
			}

			var folder = FolderCreateDialog.ask_for_folder ("Choose output folder");
			if (folder == null) {
				print_to_console ("error: no folder specified");
				return;
			}

			try {
				yield session.redirect_script_messages_to (id, folder, keep_last_n);
				print_to_console ("output from script %u is now redirected to '%s'".printf (id, folder));
			} catch (IOError detach_error) {
				print_to_console ("ERROR: " + detach_error.message);
			}
		}

		private void on_message_from_script (uint script_id, Variant msg) {
			var vtable = vtable_by_script_id[script_id];
			if (vtable == null) {
				print_to_console ("[script %u: %s]".printf (script_id, msg.print (false)));
			} else {
				var offset = vtable.offset_by_script_id[script_id];
				print_to_console ("[script %u [%u]: %s]".printf (vtable.id, offset, msg.print (false)));
			}
		}

		private void print_monitor_usage () {
			print_to_console ("Usage: monitor <on|off> <module-name>");
		}

		private async void handle_monitor_command (string[] args) {
			if (args.length != 2) {
				print_monitor_usage ();
				return;
			}

			var request = args[0];
			if (request != "on" && request != "off") {
				print_monitor_usage ();
				return;
			}
			var module_name = args[1];
			bool enable = (request == "on");

			try {
				yield session.set_monitor_enabled (module_name, enable);
				print_to_console ("monitor %s for %s".printf (enable ? "enabled" : "disabled", module_name));
			} catch (IOError detach_error) {
				print_to_console ("ERROR: " + detach_error.message);
			}
		}

		private void on_memory_read_detected (uint64 from, uint64 address, string module_name) {
			print_to_console (("[%s: memory read detected from 0x%08" + uint64.FORMAT_MODIFIER + "x while accessing 0x%08" + uint64.FORMAT_MODIFIER + "x]").printf (module_name, from, address));
		}

		private void print_itracker_usage () {
			print_to_console ("Usage: itracker <begin|end|list>");
		}

		private async void handle_itracker_command (string[] args) {
			if (args.length != 1) {
				print_itracker_usage ();
				return;
			}

			string action = args[0];

			try {
				switch (action) {
					case "begin":
						yield session.begin_instance_trace ();
						print_to_console ("instance trace in progress");
						break;
					case "end":
						yield session.end_instance_trace ();
						print_to_console ("instance trace ended");
						break;
					case "list":
						yield handle_itracker_list_command ();
						break;
					default:
						print_itracker_usage ();
						return;
				}
			} catch (IOError e) {
				print_to_console ("ERROR: " + e.message);
			}
		}

		private async void handle_itracker_list_command () throws IOError {
			var entries = new Gee.ArrayList<AgentInstanceInfo?> ();
			var entries_array = yield session.peek_instances ();
			foreach (var e in entries_array)
				entries.add (e);

			entries.sort ((a_ptr, b_ptr) => {
				unowned AgentInstanceInfo? a = (AgentInstanceInfo?) a_ptr;
				unowned AgentInstanceInfo? b = (AgentInstanceInfo?) b_ptr;

				int name_equality = GLib.strcmp (a.type_name, b.type_name);
				if (name_equality != 0)
					return name_equality;

				if (a.reference_count > b.reference_count)
					return -1;
				else if (a.reference_count < b.reference_count)
					return 1;

				if (a.address < b.address)
					return -1;
				else if (a.address > b.address)
					return 1;
				else
					return 0;
			});

			print_to_console ("%d instances are currently alive".printf (entries.size));

			if (!entries.is_empty) {
				print_to_console ("");
				print_to_console ("\t   Address\tRefCount\tTypeName");
				print_to_console ("\t----------\t--------\t--------");

				foreach (var entry in entries) {
					print_to_console (("\t0x%08" + uint64.FORMAT_MODIFIER + "x\t%u\t\t%s").printf (entry.address, entry.reference_count, entry.type_name));
				}

				print_to_console ("");
			}
		}

		private void print_pony_usage () {
			print_to_console ("Usage: pony [address-specifier]");
		}

		private async void handle_pony_command (string[] args) {
			string hexdump = "";

			if (args.length != 0) {
				uint64 address = 0;
				uint size = 7;

				try {
					address = yield resolve_address_specifier_arguments (args);
				} catch (IOError arg_error) {
					print_to_console ("ERROR: " + arg_error.message);
					print_to_console ("");
					print_pony_usage ();
					return;
				}

				try {
					uint8[] bytes = yield session.read_memory (address, size);
					hexdump = byte_array_to_hexdump (bytes);
				} catch (IOError read_error) {
					print_to_console ("ERROR: " + read_error.message);
					return;
				}
			}

			// Stolen from http://svn.rcbowen.com/svn/public/mod_pony/mod_pony.c
			print_to_console ("  ,  ,.~\"\"\"\"\"~~..                                           ___");
			print_to_console ("  )\\,)\\`-,       `~._                                     .'   ``._");
			print_to_console ("  \\  \\ | )           `~._                   .-\"\"\"\"\"-._   /         ");
			print_to_console (" _/ ('  ( _(\\            `~~,__________..-\"'          `-<           \\");
			print_to_console (" )   )   `   )/)   )        \\                            \\           |");
			print_to_console ("') /)`      \\` \\,-')/\\      (                             \\          |");
			print_to_console ("(_(\\ /7      |.   /'  )'  _(`                              |         |");
			print_to_console ("    \\\\      (  `.     ')_/`                                |         /");
			print_to_console ("     \\       \\   \\              %-26s |        (".printf (hexdump));
			print_to_console ("      \\ )  /\\/   /                                         |         `~._");
			print_to_console ("       `-._)     |                                        /.            `~,");
			print_to_console ("                 |                          |           .'  `~.          (`");
			print_to_console ("                  \\                       _,\\          /       \\        (``");
			print_to_console ("                   `/      /       __..-i\"   \\         |        \\      (``");
			print_to_console ("                  .'     _/`-..--\"\"      `.   `.        \\        ) _.~<``");
			print_to_console ("                .'    _.j     /            `-.  `.       \\      '=< `");
			print_to_console ("              .'   _.'   \\    |               `.  `.      \\");
			print_to_console ("             |   .'       ;   ;               .'  .'`.     \\");
			print_to_console ("             \\_  `.       |   \\             .'  .'   /    .'");
			print_to_console ("               `.  `-, __ \\   /           .'  .'     |   (");
			print_to_console ("                 `.  `'` \\|  |           /  .-`     /   .'");
			print_to_console ("                   `-._.--t  ;          |_.-)      /  .'");
			print_to_console ("                          ; /           \\  /      / .'");
			print_to_console ("                         / /             `'     .' /");
			print_to_console ("                        /,_\\                  .',_(");
			print_to_console ("                       /___(                 /___( ");
		}

		private async void handle_test_command (string[] args) {
		}

		private void print_to_console (string line, Gtk.TextTag? with_tag = null) {
			var iter = prepare_console_for_insertion ();

			if (with_tag != null)
				console_text_buffer.insert_with_tags (iter, line, -1, with_tag);
			else
				console_text_buffer.insert (iter, line, -1);
		}

		private void print_code_to_console (uint line_number, string line) {
			var iter = prepare_console_for_insertion ();

			var buf = console_text_buffer;
			buf.insert (iter, "\t", -1);
			buf.insert_with_tags (iter, line_number.to_string (), -1, view.console_line_number_tag);
			buf.insert (iter, " ", -1);
			buf.insert_with_tags (iter, line, -1, view.console_code_text_tag);
		}

		private Gtk.TextIter prepare_console_for_insertion () {
			var buf = console_text_buffer;

			Gtk.TextIter iter;
			buf.get_end_iter (out iter);

			if (buf.get_char_count () > 0)
				buf.insert (iter, "\n", -1);

			view.console_view.scroll_to_mark (console_scroll_mark, 0.0, true, 0.0, 1.0);

			return iter;
		}

		private void clear_console () {
			Gtk.TextIter start_iter, end_iter;
			console_text_buffer.get_iter_at_offset (out start_iter, 0);
			console_text_buffer.get_iter_at_offset (out end_iter, -1);
			console_text_buffer.delete (start_iter, end_iter);
		}

		private async uint64 resolve_address_specifier_arguments (string[] args) throws IOError {
			uint64 address;

			if (args.length == 1) {
				address = uint64_from_string (args[0]);
				if (address == 0)
					throw new IOError.FAILED ("specified address '" + args[0] + "' is invalid");
			} else if (args.length == 2) {
				var module = yield code_service.find_module_by_name (args[0]);
				if (module == null)
					throw new IOError.FAILED ("specified module '" + args[0] + "' could not be found");

				var func_str = args[1];
				if (func_str.has_prefix ("0x")) {
					address = module.address + uint64_from_string (func_str);
				} else {
					var func = module.find_function_by_name (func_str);
					if (func == null)
						throw new IOError.FAILED ("specified function '" + func_str + "' could not be found");
					address = func.address;
				}
			} else {
				throw new IOError.FAILED ("invalid argument count");
			}

			return address;
		}

		private uint64 uint64_from_string (string str) throws IOError {
			uint64 result;

			string input;
			unowned string endptr;
			if (str.has_prefix ("0x")) {
				input = str[2:str.length];
				result = input.to_uint64 (out endptr, 16);
			} else if (str[0] == '-' || str[0] == '+') {
				throw new IOError.INVALID_ARGUMENT ("specified number '%s' should not have a sign prefixed".printf (str));
			} else {
				input = str;
				result = input.to_uint64 (out endptr, 10);
			}

			if (endptr == input)
				throw new IOError.INVALID_ARGUMENT ("specified number '%s' is invalid".printf (str));

			return result;
		}

		private string byte_array_to_hexdump (uint8[] bytes, uint64 address = 0) {
			uint total_offset = 0;
			uint line_offset = 0;
			size_t remaining = bytes.length;

			var result = new StringBuilder ();
			var ascii = new StringBuilder ();

			foreach (uint8 byte in bytes) {
				if (line_offset == 0) {
					if (address != 0)
						result.append_printf ("%08" + uint64.FORMAT_MODIFIER + "x:  ", address + total_offset);
				} else {
					result.append_c (' ');
					if (line_offset == 8)
						result.append_c (' ');
				}

				result.append_printf ("%02x", byte);
				if (byte >= 33 && byte <= 126)
					ascii.append_c ((char) byte);
				else
					ascii.append_c ('.');

				total_offset++;
				line_offset++;
				remaining--;

				if (line_offset == 16) {
					result.append ("  ");
					result.append (ascii.str);

					if (remaining != 0)
						result.append_c ('\n');

					line_offset = 0;
					ascii.truncate (0);
				}
			}

			if (line_offset != 0) {
				while (line_offset != 16) {
					result.append ("   ");
					if (line_offset == 8)
						result.append_c (' ');
					line_offset++;
				}

				result.append ("  ");
				result.append (ascii.str);
			}

			return result.str;
		}

		private uint8[] byte_array_from_hex_string (string hex_string) throws IOError {
			var result = new uint8[0];

			for (char * ch = hex_string; *ch != '\0'; ch++) {
				if (*ch == ' ')
					continue;

				int upper = ch[0].xdigit_value ();
				if (upper == -1)
					throw new IOError.FAILED ("invalid hex string");
				int lower = ch[1].xdigit_value ();
				if (lower == -1)
					throw new IOError.FAILED ("invalid hex string");
				uint8 val = (uint8) ((upper << 4) | lower);
				result += val;

				ch++;
			}

			return result;
		}

		/* TODO: move this to a Service later */
		public extern string disassemble (uint64 pc, uint8[] bytes, out uint instruction_length);

		private Gee.HashMap<uint, MonitoredVTable> vtable_by_script_id = new Gee.HashMap<uint, MonitoredVTable> ();

		private class MonitoredVTable {
			public uint id;
			public Gee.HashMap<uint, uint> offset_by_script_id = new Gee.HashMap<uint, uint> ();
		}
	}

	public class Investigation : Object {
		public signal void new_function_call (FunctionCall function_call);
		public signal void finished ();

		public AgentSession session {
			get;
			construct;
		}

		public CodeService code_service {
			get;
			construct;
		}

		private ulong new_batch_handler_id;
		private ulong complete_handler_id;

		private LinkedList<AgentClue?> pending_clues = new LinkedList<AgentClue?> ();
		private bool is_processing_clues;

		public Investigation (AgentSession session, CodeService code_service) {
			Object (session: session, code_service: code_service);
		}

		construct {
			new_batch_handler_id = session.new_batch_of_clues.connect (on_new_batch_of_clues);
			complete_handler_id = session.investigation_complete.connect (() => stop ());
		}

		~Investigation () {
			SignalHandler.disconnect (session, complete_handler_id);
			SignalHandler.disconnect (session, new_batch_handler_id);
		}

		public async bool start (AgentTriggerInfo start_trigger, AgentTriggerInfo stop_trigger) {
			try {
				yield session.start_investigation (start_trigger, stop_trigger);
				return true;
			} catch (IOError e) {
				return false;
			}
		}

		private async void stop () {
			try {
				yield session.stop_investigation ();
			} catch (IOError e) {
			}

			finished ();
		}

		private void on_new_batch_of_clues (AgentClue[] clues) {
			foreach (var clue in clues)
				pending_clues.add (clue);

			if (!is_processing_clues) {
				is_processing_clues = true;

				Idle.add (() => {
					process_clues ();
					return false;
				});
			}
		}

		private async void process_clues () {
			while (true) {
				var clue = pending_clues.poll ();
				if (clue == null)
					break;
				var location = clue.location;
				var target = clue.target;

				var location_module = yield code_service.find_module_by_address (location);
				uint64 location_offset = (location_module != null) ? location - location_module.address : location;

				var target_func = yield code_service.find_function_by_address (target);
				if (target_func == null) {
					var target_func_module = yield code_service.find_module_by_address (target);
					if (target_func_module != null) {
						var target_func_offset = target - target_func_module.address;
						var target_func_name = "%s_%08llx".printf (target_func_module.spec.bare_name, target_func_offset);
						var target_func_spec = new FunctionSpec (target_func_name, target_func_offset);
						target_func = new Function (target_func_spec, target);
						yield code_service.add_function_to_module (target_func, target_func_module);
					} else {
						var dynamic_func_name = "dynamic_%08llx".printf (target);
						var dynamic_func_spec = new FunctionSpec (dynamic_func_name, target);
						target_func = new Function (dynamic_func_spec, target);
						yield code_service.add_function (target_func);
					}
				}

				var func_call = new FunctionCall (clue.depth, location_module, location_offset, target_func);
				new_function_call (func_call);
			}

			is_processing_clues = false;
		}
	}

	public class FunctionCall : Object {
		public int depth {
			get;
			construct;
		}

		public Module? module {
			get;
			construct;
		}

		public uint64 offset {
			get;
			construct;
		}

		public Function target {
			get;
			construct;
		}

		public FunctionCall (int depth, Module? module, uint64 offset, Function target) {
			Object (depth: depth, module: module, offset: offset, target: target);
		}
	}

	namespace FileOpenDialog {
		public extern string? ask_for_filename (string title);
	}

	namespace FileSaveDialog {
		public extern string? ask_for_filename (string title);
	}

	namespace FolderSelectDialog {
		public extern string? ask_for_folder (string title);
	}

	namespace FolderCreateDialog {
		public extern string? ask_for_folder (string title);
	}
}

