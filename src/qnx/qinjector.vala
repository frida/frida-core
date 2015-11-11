#if QNX
using Gee;

namespace Frida {
	public class Qinjector : Object {
		public signal void uninjected (uint id);

		public string temp_directory {
			owned get {
				return resource_store.tempdir.path;
			}
		}

		public ResourceStore resource_store {
			get {
				if (_resource_store == null) {
					try {
						_resource_store = new ResourceStore ();
					} catch (Error e) {
						assert_not_reached ();
					}
				}
				return _resource_store;
			}
		}
		private ResourceStore _resource_store;

		/* these should be private, but must be accessible to glue code */
		private MainContext main_context;
		public Gee.HashMap<uint, void *> instance_by_id = new Gee.HashMap<uint, void *> ();
		public uint last_id = 1;

		construct {
			main_context = MainContext.get_thread_default ();
		}

		~Qinjector () {
			foreach (var instance in instance_by_id.values)
				_free_instance (instance);
		}

		public async uint inject (uint pid, AgentDescriptor desc, string data_string) throws Error {
			var filename = resource_store.ensure_copy_of (desc);

			var id = _do_inject (pid, filename, data_string, resource_store.tempdir.path);

			var fifo = _get_fifo_for_instance (instance_by_id[id]);
			var buf = new uint8[1];
			var cancellable = new Cancellable ();
			var timeout_source = new TimeoutSource (2000);
			timeout_source.set_callback (() => {
				cancellable.cancel ();
				return false;
			});
			timeout_source.attach (main_context);
			ssize_t size = 0;
			while (size == 0) {
				try {
					size = yield fifo.read_async (buf, Priority.DEFAULT, cancellable);
				} catch (IOError e) {
					if (e is IOError.CANCELLED)
						throw new Error.TIMED_OUT ("Unexpectedly timed out while waiting for FIFO to establish");
					else
						throw new Error.NOT_SUPPORTED ("Unexpected error while waiting for FIFO to establish (child process crashed?)");
				}
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
				_monitor_instance.begin (id);
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
						/*
						 * Give it some time to execute its final instructions before we free the memory being executed
						 * Should consider to instead signal the remote thread id and poll /proc until it's gone.
						 */
						var timeout_source = new TimeoutSource (50);
						timeout_source.set_callback (() => {
							_on_uninject (id);
							return false;
						});
						timeout_source.attach (main_context);
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
		public extern uint _do_inject (uint pid, string so_path, string data_string, string temp_path) throws Error;

		public class ResourceStore {
			public TemporaryDirectory tempdir {
				get;
				private set;
			}

			private HashMap<string, TemporaryFile> agents = new HashMap<string, TemporaryFile> ();

			public ResourceStore () throws Error {
				tempdir = new TemporaryDirectory ();
				FileUtils.chmod (tempdir.path, 0755);
			}

			~ResourceStore () {
				foreach (var tempfile in agents.values)
					tempfile.destroy ();
				tempdir.destroy ();
			}

			public string ensure_copy_of (AgentDescriptor desc) throws Error {
				var temp_agent = agents[desc.name];
				if (temp_agent == null) {
					temp_agent = new TemporaryFile.from_stream (desc.name, desc.sofile, tempdir);
					FileUtils.chmod (temp_agent.path, 0755);
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
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}
}
#endif
