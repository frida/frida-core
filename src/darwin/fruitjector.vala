#if DARWIN
using Gee;

namespace Frida {
	public class Fruitjector : Object {
		public signal void uninjected (uint id);

		private ResourceStore normal_resource_store;
		private HelperFactory normal_helper_factory = new HelperFactory (PrivilegeLevel.NORMAL);

		private ResourceStore elevated_resource_store;
		private HelperFactory elevated_helper_factory = new HelperFactory (PrivilegeLevel.ELEVATED);

		public async void close () {
			yield normal_helper_factory.close ();
			yield elevated_helper_factory.close ();

			normal_resource_store = null;
			elevated_resource_store = null;
		}

		public async void inject (uint pid, AgentDescriptor desc, string data_string) throws IOError {
			if (normal_resource_store == null) {
				normal_resource_store = new ResourceStore ();
				normal_helper_factory.resource_store = normal_resource_store;
			}

			var filename = normal_resource_store.ensure_copy_of (desc);

			bool injected = false;

			var normal_helper = yield normal_helper_factory.obtain ();
			try {
				yield normal_helper.inject (pid, filename, data_string);
				injected = true;
			} catch (IOError inject_error) {
				var permission_error = new IOError.PERMISSION_DENIED ("");
				if (inject_error.code != permission_error.code)
					throw inject_error;
			}

			if (!injected) {
				if (elevated_resource_store == null) {
					elevated_resource_store = new ResourceStore ();
					elevated_helper_factory.resource_store = elevated_resource_store;
				}

				filename = elevated_resource_store.ensure_copy_of (desc);

				var elevated_helper = yield elevated_helper_factory.obtain ();
				yield elevated_helper.inject (pid, filename, data_string);
			}
		}

		private class HelperInstance {
			private TemporaryFile helper;
			private PipeTransport transport;
			private Pipe pipe;
			private DBusConnection connection;
			private FruitjectorHelper proxy;
			private void * process;

			private const uint ESTABLISH_TIMEOUT_MSEC = 30 * 1000;

			public HelperInstance (TemporaryFile helper, PipeTransport transport, Pipe pipe, void * process) {
				this.helper = helper;
				this.transport = transport;
				this.pipe = pipe;
				this.process = process;
			}

			public async void open () throws IOError {
				try {
					connection = yield DBusConnection.new_for_stream (pipe, null, DBusConnectionFlags.NONE);
				} catch (Error e) {
					throw new IOError.FAILED (e.message);
				}
				proxy = yield connection.get_proxy (null, FruitjectorObjectPath.HELPER);
			}

			public async void close () {
				try {
					yield proxy.stop ();
				} catch (IOError e) {
				}
			}

			public async void inject (uint pid, string filename_template, string data_string) throws IOError {
				yield proxy.inject (pid, filename_template, data_string);
			}
		}

		protected enum PrivilegeLevel {
			NORMAL,
			ELEVATED
		}

		private class HelperFactory {
			private PrivilegeLevel level;
			private MainContext main_context;
			private HelperInstance helper;
			private ArrayList<ObtainRequest> obtain_requests = new ArrayList<ObtainRequest> ();

			public ResourceStore resource_store {
				get;
				set;
			}

			public HelperFactory (PrivilegeLevel level) {
				this.level = level;
				this.main_context = MainContext.get_thread_default ();
			}

			public async void close () {
				if (helper != null) {
					yield helper.close ();
					helper = null;
				}

				resource_store = null;
			}

			public async HelperInstance obtain () throws IOError {
				if (helper != null)
					return helper;

				if (obtain_requests.size == 0) {
					try {
						Thread.create<bool> (obtain_worker, false);
					} catch (ThreadError e) {
						error (e.message);
					}
				}

				var request = new ObtainRequest (() => obtain.callback ());
				obtain_requests.add (request);
				yield;

				return request.get_result ();
			}

			private bool obtain_worker () {
				HelperInstance instance = null;
				IOError error = null;

				try {
					var transport = new PipeTransport.with_pid (0);
					var pipe = new Pipe (transport.local_address);
					void * process = spawn (resource_store.helper.path, transport.remote_address, level);
					instance = new HelperInstance (resource_store.helper, transport, pipe, process);
				} catch (IOError e) {
					error = e;
				}

				var source = new IdleSource ();
				source.set_callback (() => {
					complete_obtain (instance, error);
					return false;
				});
				source.attach (main_context);

				return error == null;
			}

			private async void complete_obtain (HelperInstance? instance, IOError? error) {
				HelperInstance completed_instance = instance;
				IOError completed_error = error;

				if (instance != null) {
					try {
						yield instance.open ();
					} catch (IOError e) {
						completed_instance = null;
						completed_error = e;
					}
				}

				this.helper = completed_instance;

				foreach (var request in obtain_requests)
					request.complete (completed_instance, completed_error);
				obtain_requests.clear ();
			}

			private class ObtainRequest {
				public delegate void CompletionHandler ();
				private CompletionHandler handler;

				private HelperInstance helper;
				private IOError error;

				public ObtainRequest (owned CompletionHandler handler) {
					this.handler = (owned) handler;
				}

				public void complete (HelperInstance? helper, IOError? error) {
					this.helper = helper;
					this.error = error;
					handler ();
				}

				public HelperInstance get_result () throws IOError {
					if (helper == null)
						throw error;
					return helper;
				}
			}

			private static extern void * spawn (string path, string parameters, PrivilegeLevel level) throws IOError;
		}

		private class ResourceStore {
			private TemporaryDirectory tempdir = new TemporaryDirectory ();

			public TemporaryFile helper {
				get;
				private set;
			}

			private HashMap<string, TemporaryFile> agents = new HashMap<string, TemporaryFile> ();

			public ResourceStore () throws IOError {
				var blob = Frida.Data.Fruitjector.get_fruitjector_helper_blob ();
				helper = new TemporaryFile.from_stream ("frida-fruitjector-helper",
					new MemoryInputStream.from_data (blob.data, null),
					tempdir);
			}

			~ResourceStore () {
				foreach (var tempfile in agents.values)
					tempfile.destroy ();
				tempdir.destroy ();
			}

			public string ensure_copy_of (AgentDescriptor desc) throws IOError {
				var temp_agent = agents[desc.name];
				if (temp_agent == null) {
					temp_agent = new TemporaryFile.from_stream (desc, tempdir);
					agents[desc.name] = temp_agent;
				}
				return temp_agent.filename_template;
			}
		}
	}

	public class AgentDescriptor : Object {
		public string name {
			get;
			construct;
		}

		public InputStream dylib {
			get {
				reset_stream (_dylib);
				return _dylib;
			}

			construct {
				_dylib = value;
			}
		}
		private InputStream _dylib;

		public AgentDescriptor (string name, InputStream dylib) {
			Object (name: name, dylib: dylib);

			assert (dylib is Seekable);
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
