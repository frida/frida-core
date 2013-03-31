using Zed;

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
			if (args.length != 3)
				return 1;
			var parent_address = args[2];

			var manager = new Winjector.Manager (parent_address);
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

	public class Manager : Object, WinjectorHelper {
		public string parent_address {
			get;
			construct;
		}

		private MainLoop loop = new MainLoop ();
		private int run_result = 0;
		private bool stopping = false;

		private DBusConnection connection;
		private uint registration_id;
		private HelperService helper32;
		private HelperService helper64;
		private void * context;

		public Manager (string parent_address) {
			Object (parent_address: parent_address);
		}

		public int run () {
			Idle.add (() => {
				start ();
				return false;
			});

			loop.run ();

			return run_result;
		}

		private async void start () {
			try {
				helper32 = new HelperService (Service.derive_svcname_for_suffix ("32"));
				if (System.is_x64 ())
					helper64 = new HelperService (Service.derive_svcname_for_suffix ("64"));

				context = start_services (Service.derive_basename ());

				yield helper32.start ();
				if (System.is_x64 ())
					yield helper64.start ();

				connection = yield DBusConnection.new_for_stream (new Pipe (parent_address), null, DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				connection.closed.connect (on_connection_closed);
				WinjectorHelper helper = this;
				registration_id = connection.register_object (WinjectorObjectPath.HELPER, helper);
				connection.start_message_processing ();
			} catch (Error e) {
				stderr.printf ("start failed: %s\n", e.message);
				run_result = 1;
				loop.quit ();
			}
		}

		public async void stop () throws IOError {
			if (stopping)
				throw new IOError.FAILED ("already stopping");
			stopping = true;

			if (System.is_x64 ())
				yield helper64.proxy.stop ();
			yield helper32.proxy.stop ();

			// HACK: give child processes some time to shut down
			Timeout.add (100, () => {
				if (context != null)
					stop_services (context);
				loop.quit ();
				return false;
			});
		}

		public async void inject (uint pid, string filename_template, string data_string) throws IOError {
			if (Process.is_x64 (pid))
				yield helper64.proxy.inject (pid, filename_template.printf (64), data_string);
			else
				yield helper32.proxy.inject (pid, filename_template.printf (32), data_string);
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			stop ();
		}

		private class HelperService {
			public WinjectorHelper proxy {
				get;
				private set;
			}

			private string name;
			private Pipe pipe;
			private DBusConnection connection;

			public HelperService (string name) throws IOError {
				this.name = name;
				this.pipe = new Pipe ("pipe:role=server,name=" + name);
			}

			public async void start () throws IOError {
				try {
					connection = yield DBusConnection.new_for_stream (pipe, null, DBusConnectionFlags.NONE);
				} catch (Error e) {
					throw new IOError.FAILED (e.message);
				}
				proxy = connection.get_proxy_sync (null, WinjectorObjectPath.HELPER);
			}
		}

		private static extern void * start_services (string service_basename);
		private static extern void stop_services (void * context);
	}

	public abstract class Service : Object, WinjectorHelper {
		private DBusConnection connection;
		private uint registration_id;

		private Gee.HashMap<uint32, void *> thread_handle_by_pid = new Gee.HashMap<uint32, void *> ();

		public Service () {
			Idle.add (() => {
				start ();
				return false;
			});
		}

		public abstract void run ();

		protected abstract void shutdown ();

		private async void start () {
			try {
				connection = yield DBusConnection.new_for_stream (new Pipe ("pipe:role=client,name=" + derive_svcname_for_self ()), null, DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				WinjectorHelper helper = this;
				registration_id = connection.register_object (WinjectorObjectPath.HELPER, helper);
				connection.start_message_processing ();
			} catch (Error e) {
				stderr.printf ("start failed: %s\n", e.message);
				shutdown ();
			}
		}

		public async void stop () throws IOError {
			Timeout.add (20, () => {
				shutdown ();
				return false;
			});
		}

		public async void inject (uint pid, string filename, string data_string) throws IOError {
			for (int i = 0; thread_handle_by_pid.has_key (pid) && i != 40; i++) {
				Timeout.add (50, () => {
					inject.callback ();
					return false;
				});
				yield;
			}

			if (thread_handle_by_pid.has_key (pid))
				throw new IOError.TIMED_OUT ("timed out while waiting for existing agent to unload");

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
		public static extern void * inject (uint32 process_id, string dll_path, string ipc_server_address) throws IOError;
	}

	namespace WaitHandleSource {
		public static Source create (void * handle, bool owns_handle) {
			return wait_handle_source_new (handle, owns_handle);
		}
	}

	private extern Source wait_handle_source_new (void * handle, bool owns_handle);
}
