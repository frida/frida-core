namespace Frida {
	public class Qinjector : Object, Injector {
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
		public uint next_instance_id = 1;

		private Gee.HashMap<uint, TemporaryFile> blob_file_by_id = new Gee.HashMap<uint, TemporaryFile> ();
		private uint next_blob_id = 1;

		private Cancellable io_cancellable = new Cancellable ();

		construct {
			main_context = MainContext.get_thread_default ();
		}

		~Qinjector () {
			foreach (var instance in instance_by_id.values)
				_free_instance (instance);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			var id = _do_inject (pid, path, entrypoint, data, resource_store.tempdir.path);

			var fifo = _get_fifo_for_instance (instance_by_id[id]);

			var read_cancellable = new Cancellable ();

			var timeout_source = new TimeoutSource (2000);
			timeout_source.set_callback (() => {
				read_cancellable.cancel ();
				return false;
			});
			timeout_source.attach (main_context);

			var cancel_source = new CancellableSource (cancellable);
			cancel_source.set_callback (() => {
				read_cancellable.cancel ();
				return false;
			});
			cancel_source.attach (main_context);

			ssize_t size = 0;
			try {
				var buf = new uint8[1];
				while (size == 0) {
					try {
						size = yield fifo.read_async (buf, Priority.DEFAULT, read_cancellable);
					} catch (IOError e) {
						if (e is IOError.CANCELLED) {
							throw new Error.TIMED_OUT (
								"Unexpectedly timed out while waiting for FIFO to establish");
						} else {
							throw new Error.NOT_SUPPORTED (
								"Unexpected error while waiting for FIFO to establish " +
								"(child process crashed?)");
						}
					}
				}
			} finally {
				cancel_source.destroy ();
				timeout_source.destroy ();
			}

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

		public async uint inject_library_blob (uint pid, Bytes blob, string entrypoint, string data, Cancellable? cancellable)
				throws Error, IOError {
			var name = "blob%u.so".printf (next_blob_id++);
			var file = new TemporaryFile.from_stream (name, new MemoryInputStream.from_bytes (blob), resource_store.tempdir);
			var path = file.path;
			FileUtils.chmod (path, 0755);

			var id = yield inject_library_file (pid, path, entrypoint, data, cancellable);

			blob_file_by_id[id] = file;

			return id;
		}

		public async uint inject_library_resource (uint pid, AgentDescriptor descriptor, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			var path = resource_store.ensure_copy_of (descriptor);
			return yield inject_library_file (pid, path, entrypoint, data, cancellable);
		}

		public async uint demonitor_and_clone_state (uint id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		public async void recreate_thread (uint pid, uint id, Cancellable? cancellable) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Not yet supported on this OS");
		}

		private async void _monitor_instance (uint id) {
			var fifo = _get_fifo_for_instance (instance_by_id[id]);
			while (true) {
				var buf = new uint8[1];
				try {
					var size = yield fifo.read_async (buf, Priority.DEFAULT, io_cancellable);
					if (size == 0) {
						/*
						 * Give it some time to execute its final instructions before we free the memory being
						 * executed. Should consider to instead signal the remote thread id and poll /proc until
						 * it's gone.
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

			blob_file_by_id.unset (id);

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
		public extern uint _do_inject (uint pid, string path, string entrypoint, string data, string temp_path) throws Error;

		public class ResourceStore {
			public TemporaryDirectory tempdir {
				get;
				private set;
			}

			private Gee.HashMap<string, TemporaryFile> agents = new Gee.HashMap<string, TemporaryFile> ();

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
				((Seekable) stream).seek (0, SeekType.SET);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}
	}
}
