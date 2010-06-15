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

		public Gtk.TreeView event_view {
			get;
			private set;
		}

		private Gtk.VBox root_vbox;

		public AgentSession () {
			try {
				var builder = new Gtk.Builder ();
				builder.add_from_string (Zed.Data.Ui.AGENT_SESSION_XML, -1);

				root_vbox = builder.get_object ("root_vbox") as Gtk.VBox;

				control_frame = builder.get_object ("control_frame") as Gtk.Frame;
				go_button = builder.get_object ("go_button") as Gtk.Button;
				event_view = builder.get_object ("event_view") as Gtk.TreeView;

				process_info_label = new ProcessInfoLabel ();
				var process_info_alignment = builder.get_object ("process_info_alignment") as Gtk.Alignment;
				process_info_alignment.add (process_info_label);

				start_selector = new FunctionSelector ();
				var start_alignment = builder.get_object ("start_alignment") as Gtk.Alignment;
				start_alignment.add (start_selector);

				stop_selector = new FunctionSelector ();
				var stop_alignment = builder.get_object ("stop_alignment") as Gtk.Alignment;
				stop_alignment.add (stop_selector);
			} catch (Error e) {
				error (e.message);
			}
		}
	}

	public class Presenter.AgentSession : Object {
		public View.AgentSession view {
			get;
			construct;
		}

		public enum State {
			UNINITIALIZED,
			INJECTING,
			INJECTED,
			ERROR,
			TERMINATED
		}

		public State state {
			get;
			private set;
		}

		public ProcessInfo process_info {
			get;
			private set;
		}

		private string error_message;

		private Service.Winjector winjector;
		private Service.AgentDescriptor agent_desc;

		private ProcessInfoLabel process_info_label;
		private FunctionSelector start_selector;
		private FunctionSelector stop_selector;

		private Gtk.ListStore event_store = new Gtk.ListStore (1, typeof (string));

		private Investigation investigation;

		public WinIpc.Proxy proxy {
			get;
			private set;
		}

		public AgentSession (View.AgentSession view, ProcessInfo process_info, Service.Winjector winjector, Service.AgentDescriptor agent_desc) {
			Object (view: view);

			update_state (State.UNINITIALIZED);
			this.process_info = process_info;
			this.winjector = winjector;
			this.agent_desc = agent_desc;

			process_info_label = new ProcessInfoLabel (view.process_info_label, process_info);
			start_selector = new FunctionSelector (view.start_selector);
			stop_selector = new FunctionSelector (view.stop_selector);

			configure_selectors ();
			configure_go_button ();
			configure_event_view ();
		}

		public async void inject () {
			try {
				update_state (State.INJECTING);
				proxy = yield winjector.inject (process_info.pid, agent_desc, null);
				update_state (State.INJECTED);

				start_selector.set_proxy (proxy);
				stop_selector.set_proxy (proxy);
			} catch (Service.WinjectorError e) {
				this.error (e.message);
			}
		}

		public async void terminate () {
			if (state == State.TERMINATED)
				return;

			if (state == State.INJECTED) {
				try {
					yield proxy.emit ("Stop");
				} catch (WinIpc.ProxyError e) {
					this.error (e.message);
					return;
				}
			}

			update_state (State.TERMINATED);
		}

		private async void start_investigation () {
			event_store.clear ();

			investigation = new Investigation (proxy);
			investigation.clues_received.connect (on_clues_received);
			investigation.finished.connect (end_investigation);

			update_view ();

			var start_trigger = new TriggerInfo (start_selector.selected_module_name, start_selector.selected_function_name);
			var stop_trigger = new TriggerInfo (stop_selector.selected_module_name, stop_selector.selected_function_name);
			bool success = yield investigation.start (start_trigger, stop_trigger);
			if (!success)
				investigation = null;

			update_view ();
		}

		private void on_clues_received (Variant clues) {
			foreach (var clue in clues) {
				Gtk.TreeIter iter;
				event_store.append (out iter);
				event_store.set (iter, 0, clue.print (false));
			}
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

			ev.set_model (event_store);

			ev.insert_column_with_attributes (-1, "Description", new Gtk.CellRendererText (), "text", 0);
		}

		private void update_view () {
			view.control_frame.sensitive = (state == State.INJECTED);

			if (state == State.INJECTED) {
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

		public string state_to_string () {
			switch (state) {
				case State.UNINITIALIZED:
					return "Uninitialized";
				case State.INJECTING:
					return "Injecting";
				case State.INJECTED:
					return "Injected";
				case State.ERROR:
					return "Error: %s".printf (error_message);
				case State.TERMINATED:
					return "Terminated";
				default:
					assert_not_reached ();
			}
		}
	}

	public class Investigation : Object {
		public signal void clues_received (Variant clues);
		public signal void finished ();

		private WinIpc.Proxy proxy;
		private uint new_batch_handler_id;
		private uint finish_handler_id;

		public Investigation (WinIpc.Proxy proxy) {
			this.proxy = proxy;

			new_batch_handler_id = proxy.add_notify_handler ("NewBatchOfClues", "a(i(ssu)(ssu))", on_new_batch_of_clues);
			finish_handler_id = proxy.add_notify_handler ("InvestigationFinished", "", (arg) => stop ());
		}

		~Investigation () {
			proxy.remove_notify_handler (finish_handler_id);
			proxy.remove_notify_handler (new_batch_handler_id);
		}

		public async bool start (TriggerInfo start_trigger, TriggerInfo stop_trigger) {
			try {
				var arg = new Variant ("(ssss)",
					start_trigger.module_name, start_trigger.function_name,
					stop_trigger.module_name, stop_trigger.function_name);
				var result = yield proxy.query ("StartInvestigation", arg, "b");
				return result.get_boolean ();
			} catch (WinIpc.ProxyError e) {
				print ("err: %s\n", e.message);
				return false;
			}
		}

		private async void stop () {
			try {
				yield proxy.query ("StopInvestigation");
			} catch (WinIpc.ProxyError e) {
			}

			finished ();
		}

		private void on_new_batch_of_clues (Variant? arg) {
			clues_received (arg);
		}
	}

	public class TriggerInfo {
		public string module_name {
			get;
			private set;
		}

		public string function_name {
			get;
			private set;
		}

		public TriggerInfo (string module_name, string function_name) {
			this.module_name = module_name;
			this.function_name = function_name;
		}
	}
}

