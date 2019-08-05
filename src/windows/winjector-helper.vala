using Frida;

namespace Winjector {
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

			var manager = new Winjector.Manager (parent_address, level);
			return manager.run ();
		}

		Service service;
		if (mode == HelperMode.STANDALONE)
			service = new StandaloneService ();
		else
			service = new ManagedService ();
		service.run ();

		return 0;
	}

	public enum HelperMode {
		MANAGER,
		STANDALONE,
		SERVICE
	}

	public enum PrivilegeLevel {
		NORMAL,
		ELEVATED
	}

	public class Manager : Object, WinjectorHelper {
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
		private HelperService helper32;
		private HelperService helper64;
		private void * context;

		public Manager (string parent_address, PrivilegeLevel level) {
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
				helper32 = new HelperService (Service.derive_svcname_for_suffix ("32"));
				if (System.is_x64 ())
					helper64 = new HelperService (Service.derive_svcname_for_suffix ("64"));

				context = start_services (Service.derive_basename (), level);

				yield helper32.start ();
				helper32.proxy.uninjected.connect (on_uninjected);

				if (System.is_x64 ()) {
					yield helper64.start ();
					helper64.proxy.uninjected.connect (on_uninjected);
				}

				var stream_request = Pipe.open (parent_address, null);
				var stream = yield stream_request.wait_async (null);

				connection = yield new DBusConnection (stream, null, DELAY_MESSAGE_PROCESSING);
				connection.on_closed.connect (on_connection_closed);

				WinjectorHelper helper = this;
				registration_id = connection.register_object (WinjectorObjectPath.HELPER, helper);

				connection.start_message_processing ();
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				run_result = 1;
				shutdown.begin ();
			}
		}

		public async void stop (Cancellable? cancellable) throws Frida.Error, IOError {
			if (System.is_x64 ()) {
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

		public async uint inject_library_file (uint pid, string path_template, string entrypoint, string data,
				Cancellable? cancellable) throws Frida.Error, IOError {
			try {
				if (Process.is_x64 (pid)) {
					return yield helper64.proxy.inject_library_file (pid, path_template.printf (64), entrypoint, data,
						cancellable);
				} else {
					return yield helper32.proxy.inject_library_file (pid, path_template.printf (32), entrypoint, data,
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

		private class HelperService {
			public WinjectorHelper proxy {
				get;
				private set;
			}

			private string name;
			private Future<IOStream> stream_request;
			private DBusConnection connection;

			public HelperService (string name) {
				this.name = name;
				this.stream_request = Pipe.open ("pipe:role=server,name=" + name, null);
			}

			public async void start () throws Frida.Error {
				try {
					var stream = yield this.stream_request.wait_async (null);

					connection = yield new DBusConnection (stream, null, NONE);
				} catch (GLib.Error e) {
					throw new Frida.Error.PERMISSION_DENIED ("%s", e.message);
				}

				try {
					proxy = yield connection.get_proxy (null, WinjectorObjectPath.HELPER);
				} catch (IOError e) {
					throw new Frida.Error.PROTOCOL ("%s", e.message);
				}
			}
		}

		private extern static void * start_services (string service_basename, PrivilegeLevel level);
		private extern static void stop_services (void * context);
	}

	public abstract class Service : Object, WinjectorHelper {
		private DBusConnection connection;
		private uint registration_id;

		private uint next_id = 0;
		private uint pending = 0;

		protected Service () {
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

				WinjectorHelper helper = this;
				registration_id = connection.register_object (WinjectorObjectPath.HELPER, helper);

				connection.start_message_processing ();
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				shutdown ();
			}
		}

		public async void stop (Cancellable? cancellable) throws Frida.Error, IOError {
			Timeout.add (20, () => {
				do_stop.begin ();
				return false;
			});
		}

		private async void do_stop () throws Frida.Error {
			connection.unregister_object (registration_id);
			connection.on_closed.disconnect (on_connection_closed);
			try {
				yield connection.close ();
			} catch (GLib.Error connection_error) {
			}

			if (pending == 0)
				shutdown ();
		}

		public async uint inject_library_file (uint pid, string path, string entrypoint, string data, Cancellable? cancellable)
				throws Frida.Error {
			if (next_id == 0 || next_id >= int.MAX) {
				/* Avoid ID collisions when running one helper for 32-bit and one for 64-bit targets */
				next_id = (sizeof (void *) == 4) ? 1 : 2;
			}
			var id = next_id;
			next_id += 2;

			void * instance, waitable_thread_handle;
			Process.inject_library_file (pid, path, entrypoint, data, out instance, out waitable_thread_handle);
			if (waitable_thread_handle != null) {
				pending++;
				var source = WaitHandleSource.create (waitable_thread_handle, true);
				source.set_callback (() => {
					bool is_resident;
					Process.free_inject_instance (instance, out is_resident);

					uninjected (id);

					pending--;
					if (connection.is_closed () && pending == 0)
						shutdown ();

					return false;
				});
				source.attach (MainContext.default ());
			}

			return id;
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			if (pending == 0)
				shutdown ();
		}

		public extern static string derive_basename ();
		public extern static string derive_filename_for_suffix (string suffix);
		public extern static string derive_svcname_for_self ();
		public extern static string derive_svcname_for_suffix (string suffix);
	}

	public class StandaloneService : Service {
		private MainLoop loop;

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

	public class ManagedService : Service {
		public override void run () {
			enter_dispatcher_and_main_loop ();
		}

		public override void shutdown () {
		}

		private extern static void enter_dispatcher_and_main_loop ();
	}

	namespace System {
		public extern static bool is_x64 ();
	}

	namespace Process {
		public extern static bool is_x64 (uint32 pid);
		public extern static void inject_library_file (uint32 pid, string path, string entrypoint, string data, out void * inject_instance, out void * waitable_thread_handle) throws Frida.Error;
		public extern static void free_inject_instance (void * inject_instance, out bool is_resident);
	}

	namespace WaitHandleSource {
		public static Source create (void * handle, bool owns_handle) {
			return wait_handle_source_new (handle, owns_handle);
		}
	}

	private extern Source wait_handle_source_new (void * handle, bool owns_handle);
}
