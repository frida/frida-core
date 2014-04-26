#if LINUX
using Gee;

namespace Frida {
	public class Linjector : Object {
		public signal void uninjected (uint id);

		private ResourceStore resource_store;

		/* these should be private, but must be accessible to glue code */
		private MainContext main_context;
		public Gee.HashMap<uint, void *> instance_by_id = new Gee.HashMap<uint, void *> ();
		public uint last_id = 1;

		construct {
			main_context = MainContext.get_thread_default ();
		}

		~Linjector () {
			foreach (var instance in instance_by_id.values)
				_free_instance (instance);
		}

		public async uint inject (uint pid, AgentDescriptor desc, string data_string) throws IOError {
			if (resource_store == null) {
				resource_store = new ResourceStore ();
			}
			var filename = resource_store.ensure_copy_of (desc);

			var id = _do_inject (pid, filename, data_string);

			var fifo = _get_fifo_for_instance (instance_by_id[id]);
			var buf = new uint8[1];
			var cancellable = new Cancellable ();
			var cancelled = new IOError.CANCELLED ("");
			var timeout_source = new TimeoutSource (2000);
			timeout_source.set_callback (() => {
				cancellable.cancel ();
				return false;
			});
			timeout_source.attach (MainContext.get_thread_default ());
			ssize_t size;
			try {
				size = yield fifo.read_async (buf, Priority.DEFAULT, cancellable);
			} catch (Error e) {
				if (e is IOError && e.code == cancelled.code)
					throw new IOError.TIMED_OUT ("timed out");
				else
					throw new IOError.FAILED (e.message);
			}
			timeout_source.destroy ();
			if (size == 0) {
				var source = new IdleSource ();
				source.set_callback (() => {
					_on_uninject (id);
					return false;
				});
				source.attach (main_context);
			} else {
				_monitor_instance (id);
			}

			return id;
		}

		private async void _monitor_instance (uint id) {
			var fifo = _get_fifo_for_instance (instance_by_id[id]);
			while (true) {
				var buf = new uint8[1];
				try {
					var size = yield fifo.read_async (buf);
					if (size == 0) {
						_on_uninject (id);
						return;
					}
				} catch (IOError e) {
					_on_uninject (id);
					return;
				}
			}
		}

		private void _on_uninject (uint id) {
			void * instance;
			bool found = instance_by_id.unset (id, out instance);
			assert (found);
			_free_instance (instance);
			uninjected (id);
		}

		public bool any_still_injected () {
			return !instance_by_id.is_empty;
		}

		public bool is_still_injected (uint id) {
			return instance_by_id.has_key (id);
		}

		public extern InputStream _get_fifo_for_instance (void * instance);
		public extern void _free_instance (void * instance);
		public extern uint _do_inject (uint pid, string so_path, string data_string) throws IOError;

		private class ResourceStore {
			public TemporaryDirectory tempdir {
				get;
				private set;
			}

			private HashMap<string, TemporaryFile> agents = new HashMap<string, TemporaryFile> ();

			public ResourceStore () throws IOError {
				tempdir = new TemporaryDirectory ();
			}

			~ResourceStore () {
				foreach (var tempfile in agents.values)
					tempfile.destroy ();
				tempdir.destroy ();
			}

			public string ensure_copy_of (AgentDescriptor desc) throws IOError {
				var temp_agent = agents[desc.name];
				if (temp_agent == null) {
					temp_agent = new TemporaryFile.from_stream (desc.name, desc.sofile, tempdir);
					agents[desc.name] = temp_agent;
				}
				return temp_agent.path;
			}
		}
	}

	public class AgentDescriptor : Object {
		public string name {
			get;
			construct;
		}

		public InputStream sofile {
			get {
				reset_stream (_sofile);
				return _sofile;
			}

			construct {
				_sofile = value;
			}
		}
		private InputStream _sofile;

		public AgentDescriptor (string name, InputStream sofile) {
			Object (name: name, sofile: sofile);

			assert (sofile is Seekable);
		}

		private void reset_stream (InputStream stream) {
			try {
				(stream as Seekable).seek (0, SeekType.SET);
			} catch (Error e) {
				assert_not_reached ();
			}
		}
	}
}
#endif
