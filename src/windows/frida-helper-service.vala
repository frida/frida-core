namespace Frida {
	public int main (string[] args) {
		HelperMode mode = HelperMode.SERVICE;

		if (args.length > 1) {
			var mode_str = args[1].up ();
			switch (mode_str) {
				case "MANAGER":	    mode = HelperMode.MANAGER;	  break;
				case "STANDALONE":  mode = HelperMode.STANDALONE; break;
				case "SERVICE":	    mode = HelperMode.SERVICE;	  break;
				default:					  return 1;
			}
		}

		if (mode == HelperMode.MANAGER) {
			if (args.length != 4)
				return 1;
			PrivilegeLevel level;
			var level_str = args[2].up ();
			switch (level_str) {
				case "NORMAL":   level = PrivilegeLevel.NORMAL;   break;
				case "ELEVATED": level = PrivilegeLevel.ELEVATED; break;
				default:					  return 1;
			}
			var parent_address = args[3];

			var manager = new HelperManager (parent_address, level);
			return manager.run ();
		}

		HelperService service;
		if (mode == HelperMode.STANDALONE)
			service = new StandaloneHelperService ();
		else
			service = new ManagedHelperService ();
		service.run ();

		return 0;
	}

	private enum HelperMode {
		MANAGER,
		STANDALONE,
		SERVICE
	}

	private class HelperManager : Object, WindowsRemoteHelper {
		public string parent_address {
			get;
			construct;
		}

		public PrivilegeLevel level {
			get;
			construct;
		}

		private MainLoop loop = new MainLoop ();
		private int run_result = 0;

		private DBusConnection connection;
		private uint registration_id;
		private ServiceConnection helper32;
		private ServiceConnection? helper64;
		private void * context;

		public HelperManager (string parent_address, PrivilegeLevel level) {
			Object (parent_address: parent_address, level: level);
		}

		public int run () {
			Idle.add (() => {
				start.begin ();
				return false;
			});

			loop.run ();

			return run_result;
		}

		private async void shutdown () {
			if (connection != null) {
				if (registration_id != 0)
					connection.unregister_object (registration_id);
				connection.on_closed.disconnect (on_connection_closed);
				try {
					yield connection.close ();
				} catch (GLib.Error connection_error) {
				}
				connection = null;
			}

			if (context != null)
				stop_services (context);
			loop.quit ();
		}

		private async void start () {
			try {
				helper32 = new ServiceConnection (HelperService.derive_svcname_for_suffix ("32"));
				if (WindowsSystem.is_x64 ())
					helper64 = new ServiceConnection (HelperService.derive_svcname_for_suffix ("64"));

				context = start_services (HelperService.derive_basename (), level);

				yield helper32.open ();
				helper32.proxy.uninjected.connect (on_uninjected);

				if (helper64 != null) {
					yield helper64.open ();
					helper64.proxy.uninjected.connect (on_uninjected);
				}

				var stream_request = Pipe.open (parent_address, null);
				var stream = yield stream_request.wait_async (null);

				connection = yield new DBusConnection (stream, null, DELAY_MESSAGE_PROCESSING);
				connection.on_closed.connect (on_connection_closed);

				WindowsRemoteHelper helper = this;
				registration_id = connection.register_object (ObjectPath.HELPER, helper);

				connection.start_message_processing ();
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				run_result = 1;
				shutdown.begin ();
			}
		}

		public async void stop (Cancellable? cancellable) throws Error, IOError {
			if (helper64 != null) {
				try {
					yield helper64.proxy.stop (cancellable);
				} catch (GLib.Error e) {
					if (e is IOError.CANCELLED)
						throw (IOError) e;
				}
			}
			try {
				yield helper32.proxy.stop (cancellable);
			} catch (GLib.Error e) {
				if (e is IOError.CANCELLED)
					throw (IOError) e;
			}

			Timeout.add (20, () => {
				shutdown.begin ();
				return false;
			});
		}

		public async bool can_handle_target (uint pid, Cancellable? cancellable) throws Error, IOError {
			return true;
		}

		public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data,
				string[] dependencies, uint id, Cancellable? cancellable) throws Error, IOError {
			try {
				if (helper64 != null && yield helper64.proxy.can_handle_target (pid, cancellable)) {
					yield helper64.proxy.inject_library_file (pid, path_template, entrypoint, data, dependencies, id,
						cancellable);
				} else {
					yield helper32.proxy.inject_library_file (pid, path_template, entrypoint, data, dependencies, id,
						cancellable);
				}
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			stop.begin (null);
		}

		private void on_uninjected (uint id) {
			uninjected (id);
		}

		private class ServiceConnection {
			public WindowsRemoteHelper proxy {
				get;
				private set;
			}

			private string name;
			private Future<IOStream> stream_request;
			private DBusConnection connection;

			public ServiceConnection (string name) {
				this.name = name;
				this.stream_request = Pipe.open ("pipe:role=server,name=" + name, null);
			}

			public async void open () throws Error {
				try {
					var stream = yield this.stream_request.wait_async (null);

					connection = yield new DBusConnection (stream, null, NONE);
				} catch (GLib.Error e) {
					throw new Error.PERMISSION_DENIED ("%s", e.message);
				}

				try {
					proxy = yield connection.get_proxy (null, ObjectPath.HELPER, DO_NOT_LOAD_PROPERTIES);
				} catch (IOError e) {
					throw new Error.PROTOCOL ("%s", e.message);
				}
			}
		}

		private extern static void * start_services (string service_basename, PrivilegeLevel level);
		private extern static void stop_services (void * context);
	}

	private abstract class HelperService : Object, WindowsRemoteHelper {
		public PrivilegeLevel level {
			get;
			construct;
		}

		private DBusConnection connection;
		private uint registration_id;

		private WindowsHelperBackend backend;

		construct {
			backend = new WindowsHelperBackend (level);
			backend.uninjected.connect (on_backend_uninjected);

			Idle.add (() => {
				start.begin ();
				return false;
			});
		}

		public abstract void run ();

		protected abstract void shutdown ();

		private async void start () {
			try {
				var stream_request = Pipe.open ("pipe:role=client,name=" + derive_svcname_for_self (), null);
				var stream = yield stream_request.wait_async (null);

				connection = yield new DBusConnection (stream, null, DELAY_MESSAGE_PROCESSING);
				connection.on_closed.connect (on_connection_closed);

				WindowsRemoteHelper helper = this;
				registration_id = connection.register_object (ObjectPath.HELPER, helper);

				connection.start_message_processing ();
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				shutdown ();
			}
		}

		public async void stop (Cancellable? cancellable) throws Error, IOError {
			Timeout.add (20, () => {
				do_stop.begin ();
				return false;
			});
		}

		private async void do_stop () {
			connection.unregister_object (registration_id);
			connection.on_closed.disconnect (on_connection_closed);
			try {
				yield connection.close ();
			} catch (GLib.Error connection_error) {
			}

			try {
				yield backend.close (null);
			} catch (IOError e) {
				assert_not_reached ();
			}

			shutdown ();
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			do_stop.begin ();
		}

		public async bool can_handle_target (uint pid, Cancellable? cancellable) throws Error, IOError {
			uint local_arch = sizeof (void *) == 8 ? 64 : 32;
			uint remote_arch = WindowsProcess.is_x64 (pid) ? 64 : 32;
			return local_arch == remote_arch;
		}

		public async void inject_library_file (uint pid, PathTemplate path_template, string entrypoint, string data,
				string[] dependencies, uint id, Cancellable? cancellable) throws Error, IOError {
			yield backend.inject_library_file (pid, path_template, entrypoint, data, dependencies, id, cancellable);
		}

		private void on_backend_uninjected (uint id) {
			uninjected (id);
		}

		public extern static string derive_basename ();
		public extern static string derive_svcname_for_self ();
		public extern static string derive_svcname_for_suffix (string suffix);
	}

	private class StandaloneHelperService : HelperService {
		private MainLoop loop;

		public StandaloneHelperService () {
			Object (level: PrivilegeLevel.NORMAL);
		}

		public override void run () {
			loop = new MainLoop ();
			loop.run ();
		}

		public override void shutdown () {
			Idle.add (() => {
				loop.quit ();
				return false;
			});
		}
	}

	private class ManagedHelperService : HelperService {
		public ManagedHelperService () {
			Object (level: PrivilegeLevel.ELEVATED);
		}

		public override void run () {
			enter_dispatcher_and_main_loop ();
		}

		public override void shutdown () {
		}

		private extern static void enter_dispatcher_and_main_loop ();
	}
}
