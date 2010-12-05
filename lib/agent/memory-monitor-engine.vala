namespace Zed.Agent {
	public class MemoryMonitorEngine : Object {
		public signal void memory_read_detected (uint64 from, uint64 address, string module_name);

		private Gee.HashMap<string, Session> session_by_module_name = new Gee.HashMap<string, Session> ();

		public void set_enabled (string module_name, bool enable) throws IOError {
			if (enable) {
				if (session_by_module_name.has_key (module_name))
					throw new IOError.FAILED ("memory monitoring is already enabled for " + module_name);
				var session = new Session (module_name);
				session.memory_read_detected.connect ((from, address, module_name) => memory_read_detected (from, address, module_name));
				session.open ();
				session_by_module_name[module_name] = session;
			} else {
				Session session;
				if (!session_by_module_name.unset (module_name, out session))
					throw new IOError.FAILED ("memory monitoring is not enabled for " + module_name);
				session.close ();
			}
		}

		public class Session : Object {
			public signal void memory_read_detected (uint64 from, uint64 address, string module_name);

			public string module_name {
				get;
				construct;
			}

			private Gee.ArrayList<Gum.MemoryAccessMonitor> monitors = new Gee.ArrayList<Gum.MemoryAccessMonitor> ();
			private Gee.HashMap<void *, void *> unique_readers = new Gee.HashMap<void *, void *> ();

			public Session (string module_name) {
				Object (module_name: module_name);
			}

			~Session () {
				close ();
			}

			public void open () throws IOError {
				Gum.Module.enumerate_ranges (module_name, Gum.PageProtection.EXECUTE, (range, prot) => {
					var monitor = new Gum.MemoryAccessMonitor ();
					monitor.enable (range, on_memory_access);
					monitors.add (monitor);
					return true;
				});

				if (monitors.is_empty)
					throw new IOError.FAILED ("module does not contain any executable ranges");
			}

			public void close () {
				foreach (var monitor in monitors)
					monitor.disable ();
				monitors.clear ();
				unique_readers.clear ();
			}

			private void on_memory_access (Gum.MemoryAccessMonitor monitor, Gum.MemoryAccessDetails details) {
				if (details.operation != Gum.MemoryOperation.READ)
					return;
				Idle.add (() => {
					if (!unique_readers.has_key (details.from)) {
						unique_readers[details.from] = details.address;
						memory_read_detected ((uint64) details.from, (uint64) details.address, module_name);
					}
					return false;
				});
			}
		}
	}
}
