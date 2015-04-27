#if WINDOWS
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
				connection.closed.disconnect (on_connection_closed);
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
				if (System.is_x64 ())
					yield helper64.start ();

				connection = yield DBusConnection.new (new Pipe (parent_address), null, DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				connection.closed.connect (on_connection_closed);
				WinjectorHelper helper = this;
				registration_id = connection.register_object (WinjectorObjectPath.HELPER, helper);
				connection.start_message_processing ();
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				run_result = 1;
				shutdown.begin ();
			}
		}

		public async void stop () throws Frida.Error {
			if (System.is_x64 ())
				yield helper64.proxy.stop ();
			yield helper32.proxy.stop ();

			Timeout.add (20, () => {
				shutdown.begin ();
				return false;
			});
		}

		public async void inject (uint pid, string filename_template, string data_string) throws Frida.Error {
			try {
				if (Process.is_x64 (pid))
					yield helper64.proxy.inject (pid, filename_template.printf (64), data_string);
				else
					yield helper32.proxy.inject (pid, filename_template.printf (32), data_string);
			} catch (Frida.Error e) {
				DBusError.strip_remote_error (e);
				throw e;
			}
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			stop.begin ();
		}

		private class HelperService {
			public WinjectorHelper proxy {
				get;
				private set;
			}

			private string name;
			private Pipe pipe;
			private DBusConnection connection;

			public HelperService (string name) throws Frida.Error {
				this.name = name;
				try {
					this.pipe = new Pipe ("pipe:role=server,name=" + name);
				} catch (IOError e) {
					throw new Frida.Error.ADDRESS_IN_USE (e.message);
				}
			}

			public async void start () throws Frida.Error {
				try {
					connection = yield DBusConnection.new (pipe, null, DBusConnectionFlags.NONE);
				} catch (GLib.Error e) {
					throw new Frida.Error.PERMISSION_DENIED (e.message);
				}

				try {
					proxy = yield connection.get_proxy (null, WinjectorObjectPath.HELPER);
				} catch (IOError e) {
					throw new Frida.Error.PROTOCOL (e.message);
				}
			}
		}

		private static extern void * start_services (string service_basename, PrivilegeLevel level);
		private static extern void stop_services (void * context);
	}

	public abstract class Service : Object, WinjectorHelper {
		private DBusConnection connection;
		private uint registration_id;

		private Gee.HashMap<uint32, void *> thread_handle_by_pid = new Gee.HashMap<uint32, void *> ();

		public Service () {
			Idle.add (() => {
				start.begin ();
				return false;
			});
		}

		public abstract void run ();

		protected abstract void shutdown ();

		private async void start () {
			try {
				connection = yield DBusConnection.new (new Pipe ("pipe:role=client,name=" + derive_svcname_for_self ()), null, DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				WinjectorHelper helper = this;
				registration_id = connection.register_object (WinjectorObjectPath.HELPER, helper);
				connection.start_message_processing ();
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				shutdown ();
			}
		}

		public async void stop () throws Frida.Error {
			Timeout.add (20, () => {
				do_stop.begin ();
				return false;
			});
		}

		private async void do_stop () throws Frida.Error {
			connection.unregister_object (registration_id);
			try {
				yield connection.close ();
			} catch (GLib.Error connection_error) {
			}
			connection = null;

			shutdown ();
		}

		public async void inject (uint pid, string filename, string data_string) throws Frida.Error {
			for (int i = 0; thread_handle_by_pid.has_key (pid) && i != 40; i++) {
				Timeout.add (50, () => {
					inject.callback ();
					return false;
				});
				yield;
			}

			if (thread_handle_by_pid.has_key (pid))
				throw new Frida.Error.TIMED_OUT ("Unexpectedly timed out while waiting for existing agent to unload");

			var waitable_thread_handle = Process.inject (pid, filename, data_string);
			if (waitable_thread_handle != null) {
				thread_handle_by_pid[pid] = waitable_thread_handle;

				var source = WaitHandleSource.create (waitable_thread_handle, true);
				source.set_callback (() => {
					thread_handle_by_pid.unset (pid);
					return false;
				});
				source.attach (MainContext.default ());
			}
		}

		public static extern string derive_basename ();
		public static extern string derive_filename_for_suffix (string suffix);
		public static extern string derive_svcname_for_self ();
		public static extern string derive_svcname_for_suffix (string suffix);
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

		private static extern void enter_dispatcher_and_main_loop ();
	}

	namespace System {
		public static extern bool is_x64 ();
	}

	namespace Process {
		public static extern bool is_x64 (uint32 process_id);
		public static extern void * inject (uint32 process_id, string dll_path, string ipc_server_address) throws Frida.Error;
	}

	namespace WaitHandleSource {
		public static Source create (void * handle, bool owns_handle) {
			return wait_handle_source_new (handle, owns_handle);
		}
	}

	private extern Source wait_handle_source_new (void * handle, bool owns_handle);
}
#endif
