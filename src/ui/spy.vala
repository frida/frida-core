using Gee;

namespace Zed {
	public class View.Spy : Object {
		public Gtk.Widget widget {
			get {
				return hpaned;
			}
		}

		public Gtk.Entry pid_entry {
			get;
			private set;
		}

		public Gtk.Button add_button {
			get;
			private set;
		}

		public Gtk.TreeView session_view {
			get;
			private set;
		}

		public Gtk.TreeView event_view {
			get;
			private set;
		}

		private Gtk.HPaned hpaned;

		public Spy () {
			try {
				var builder = new Gtk.Builder ();
				builder.add_from_string (Zed.Data.Ui.SPY_XML, -1);

				hpaned = builder.get_object ("root_hpaned") as Gtk.HPaned;

				pid_entry = builder.get_object ("pid_entry") as Gtk.Entry;
				add_button = builder.get_object ("add_button") as Gtk.Button;
				session_view = builder.get_object ("process_treeview") as Gtk.TreeView;
				event_view = builder.get_object ("event_treeview") as Gtk.TreeView;
			} catch (Error e) {
				error (e.message);
			}
		}
	}

	public class Presenter.Spy : Object {
		public View.Spy view {
			get;
			construct;
		}

		public Service.Winjector winjector {
			get;
			construct;
		}

		private Gtk.ListStore session_store;
		private Gtk.ListStore event_store;

		private Service.AgentDescriptor agent_desc;

		private ProcessList process_list = new ProcessList ();
		private const double PROCESS_LIST_MIN_UPDATE_INTERVAL = 5.0;

		private const int KEYVAL_DELETE = 65535;

		public Spy (View.Spy view) {
			Object (view: view, winjector: new Service.Winjector () /* here for now */);

			configure_pid_entry ();
			configure_add_button ();
			configure_session_view ();

			session_store = new Gtk.ListStore (1, typeof (AgentSession));
			view.session_view.set_model (session_store);
			view.session_view.insert_column_with_data_func (-1, "PID", new Gtk.CellRendererText (), session_column_data_callback);
			view.session_view.insert_column_with_data_func (-1, "Status", new Gtk.CellRendererText (), session_column_data_callback);

			event_store = new Gtk.ListStore (1, typeof (string));
			view.event_view.set_model (event_store);
			view.event_view.insert_column_with_attributes (-1, "Function Name", new Gtk.CellRendererText (), "text", 0);

			agent_desc = new Service.AgentDescriptor ("zed-winagent-%u.dll",
				new MemoryInputStream.from_data (get_winagent_32_data (), get_winagent_32_size (), null),
				new MemoryInputStream.from_data (get_winagent_64_data (), get_winagent_64_size (), null));
		}

		public async void close () {
			Gtk.TreeIter iter;
			if (session_store.get_iter_first (out iter)) {
				do {
					AgentSession session;
					session_store.get (iter, 0, out session);
					session.terminate ();
				} while (session_store.iter_next (ref iter));
			}

			Thread.usleep (50000); /* HACK: give processes 50 ms to unload DLLs */

			yield winjector.close ();
		}

		private void configure_pid_entry () {
			view.pid_entry.activate.connect (() => {
				view.add_button.clicked ();
			});
			view.pid_entry.focus_in_event.connect ((event) => {
				if (process_list.time_since_last_update () >= PROCESS_LIST_MIN_UPDATE_INTERVAL)
					process_list.update ();
				return false;
			});

			var completion = new Gtk.EntryCompletion ();

			completion.set_model (process_list.model);
			completion.set_popup_completion (true);

			var icon_renderer = new Gtk.CellRendererPixbuf ();
			completion.pack_start (icon_renderer, false);
			completion.set_cell_data_func (icon_renderer, pid_entry_completion_data_callback);

			completion.set_text_column (0);

			var pid_renderer = new Gtk.CellRendererText ();
			completion.pack_end (pid_renderer, false);
			completion.set_cell_data_func (pid_renderer, pid_entry_completion_data_callback);

			completion.match_selected.connect ((model, iter) => {
				ProcessInfo pi;
				model.get (iter, 1, out pi);
				view.pid_entry.set_text (pi.pid.to_string ());
				view.pid_entry.move_cursor (Gtk.MovementStep.BUFFER_ENDS, 1, false);
				return true;
			});

			view.pid_entry.set_completion (completion);
		}

		private void configure_add_button () {
			view.add_button.clicked.connect (() => {
				var pid = view.pid_entry.text.to_int ();
				if (pid != 0) {
					view.pid_entry.text = "";
					var session = create_session (pid);
					session.inject ();
				}
			});
		}

		private void configure_session_view () {
			view.session_view.key_press_event.connect ((event) => {
				if (event.keyval == KEYVAL_DELETE) {
					var selection = view.session_view.get_selection ();

					Gtk.TreeModel model;
					Gtk.TreeIter iter;
					if (selection.get_selected (out model, out iter)) {
						AgentSession session;
						model.get (iter, 0, out session);
						session.terminate ();
					}
				}

				return false;
			});
		}

		private AgentSession create_session (uint pid) {
			var session = new AgentSession (pid, winjector, agent_desc);

			session.notify["state"].connect (() => {
				Gtk.TreeIter iter;
				if (session_store.get_iter_first (out iter)) {
					do {
						AgentSession s;
						session_store.get (iter, 0, out s);
						if (s == session) {
							var path = session_store.get_path (iter);
							session_store.row_changed (path, iter);

							if (session.state == AgentSession.State.TERMINATED)
								schedule_removal_of (path);

							break;
						}
					} while (session_store.iter_next (ref iter));
				}
			});

			Gtk.TreeIter iter;
			session_store.append (out iter);
			session_store.set (iter, 0, session);

			return session;
		}

		private void schedule_removal_of (Gtk.TreePath path) {
			Timeout.add (1000, () => {
				Gtk.TreeIter iter;
				if (session_store.get_iter (out iter, path))
					session_store.remove (iter);
				return false;
			});
		}

		private void pid_entry_completion_data_callback (Gtk.CellLayout layout, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			ProcessInfo pi;
			model.get (iter, 1, out pi);

			if (renderer is Gtk.CellRendererPixbuf)
				(renderer as Gtk.CellRendererPixbuf).pixbuf = pi.icon;
			else
				(renderer as Gtk.CellRendererText).text = pi.pid.to_string ();
		}

		private void session_column_data_callback (Gtk.TreeViewColumn col, Gtk.CellRenderer renderer, Gtk.TreeModel model, Gtk.TreeIter iter) {
			AgentSession session;
			model.get (iter, 0, out session);

			Gtk.CellRendererText text_renderer = (Gtk.CellRendererText) renderer;
			if (col.title == "PID")
				text_renderer.text = session.pid.to_string ();
			else
				text_renderer.text = session.state_to_string ();
		}

		private static extern void * get_winagent_32_data ();
		private static extern uint get_winagent_32_size ();

		private static extern void * get_winagent_64_data ();
		private static extern uint get_winagent_64_size ();
	}

	private class AgentSession : Object {
		public enum State {
			UNINITIALIZED,
			INJECTING,
			INJECTED,
			ERROR,
			TERMINATED
		}

		public uint pid {
			get;
			private set;
		}

		public State state {
			get;
			private set;
		}

		private string error_message;

		private Service.Winjector winjector;
		private Service.AgentDescriptor agent_desc;

		public WinIpc.Proxy proxy {
			get;
			private set;
		}

		public AgentSession (uint pid, Service.Winjector winjector, Service.AgentDescriptor agent_desc) {
			this.pid = pid;
			this.state = State.UNINITIALIZED;
			this.winjector = winjector;
			this.agent_desc = agent_desc;
		}

		public async void inject () {
			try {
				this.state = State.INJECTING;
				proxy = yield winjector.inject (pid, agent_desc, null);
				proxy.add_notify_handler ("FuncEvent", "(i(ssu)(ssu))", on_func_event);
				this.state = State.INJECTED;
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

			state = State.TERMINATED;
		}

		private void error (string message) {
			this.error_message = message;
			this.state = State.ERROR;
		}

		private void on_func_event (Variant? arg) {
			/*
			Gtk.TreeIter iter;
			event_store.append (out iter);
			event_store.set (iter, 0, arg.print (false));
			*/
			print ("on_func_event\n");
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

	public class ProcessList : Object {
		public Gtk.TreeModel model {
			get { return store; }
		}
		private Gtk.ListStore store;

		private ArrayList<UpdateRequest> pending_requests = new ArrayList<UpdateRequest> ();
		private Timer last_update_timer = new Timer ();

		public ProcessList () {
			store = new Gtk.ListStore (2, typeof (string), typeof (ProcessInfo));
			update ();
		}

		public async void update () {
			bool is_first_request = pending_requests.is_empty;

			var request = new UpdateRequest (() => update.callback ());
			if (is_first_request) {
				try {
					Thread.create (do_enumerate_processes, false);
				} catch (ThreadError e) {
					error (e.message);
				}
			}
			pending_requests.add (request);
			yield;

			if (is_first_request) {
				store.clear ();

				foreach (var process in request.result) {
					Gtk.TreeIter iter;
					store.append (out iter);
					store.set (iter, 0, process.name, 1, process);
				}
			}

			last_update_timer.start ();
		}

		public double time_since_last_update () {
			return last_update_timer.elapsed ();
		}

		private void * do_enumerate_processes () {
			var timer = new Timer ();
			var processes = enumerate_processes ();
			print ("update took %d ms\n", (int) (timer.elapsed () * 1000.0));

			Idle.add (() => {
				var requests = pending_requests;
				pending_requests = new ArrayList<UpdateRequest> ();

				foreach (var request in requests)
					request.complete (processes);

				return false;
			});

			return null;
		}

		private class UpdateRequest {
			public delegate void CompletionHandler ();
			private CompletionHandler handler;

			public ProcessInfo[] result {
				get;
				private set;
			}

			public UpdateRequest (CompletionHandler handler) {
				this.handler = handler;
			}

			public void complete (ProcessInfo[] processes) {
				this.result = processes;
				handler ();
			}
		}

		private static extern ProcessInfo[] enumerate_processes ();
	}

	public class ProcessInfo : Object {
		public uint pid {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public Gdk.Pixbuf? icon {
			get;
			private set;
		}

		public ProcessInfo (uint pid, string name, Gdk.Pixbuf? icon) {
			this.pid = pid;
			this.name = name;
			this.icon = icon;
		}
	}
}

