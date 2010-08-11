using Gee;

public class Zed.Service.ProcessList : Object {
	public Gtk.TreeModel model {
		get { return store; }
	}
	private Gtk.ListStore store;

	private ArrayList<UpdateRequest> pending_requests = new ArrayList<UpdateRequest> ();
	private HashMap<uint, ProcessInfo> process_info_by_pid = new HashMap<uint, ProcessInfo> ();
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
			process_info_by_pid.clear ();

			foreach (var process in request.result) {
				Gtk.TreeIter iter;
				store.append (out iter);
				store.set (iter, 0, process.name, 1, process);

				process_info_by_pid[process.pid] = process;
			}
		}

		last_update_timer.start ();
	}

	public async ProcessInfo info_from_pid (uint pid) {
		var info = process_info_by_pid[pid];

		if (info == null) {
			yield update ();
			info = process_info_by_pid[pid];
		}

		if (info == null)
			info = new ProcessInfo (pid, "[Unknown Process]");

		return info;
	}

	public double time_since_last_update () {
		return last_update_timer.elapsed ();
	}

	private void * do_enumerate_processes () {
		var processes = enumerate_processes ();

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

