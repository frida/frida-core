#if DARWIN
namespace Frida {
	public int main (string[] args) {
		Posix.setsid ();

		Gum.init ();

		var parent_address = args[1];
		var worker = new Thread<int> ("frida-helper-main-loop", () => {
			var service = new HelperService (parent_address);

			var exit_code = service.run ();
			_stop_run_loop ();

			return exit_code;
		});
		_start_run_loop ();
		var exit_code = worker.join ();

		return exit_code;
	}

	public extern void _start_run_loop ();
	public extern void _stop_run_loop ();

	public class HelperService : Object, Helper {
		public signal void child_dead (uint pid);
		public signal void child_ready (uint pid);

		public string parent_address {
			get;
			construct;
		}

		private MainLoop loop = new MainLoop ();
		private int run_result = 0;

		private DBusConnection connection;
		private uint helper_registration_id = 0;
		private uint system_session_registration_id = 0;
		private AgentContainer system_session;
		private Gee.HashMap<uint, OutputStream> stdin_streams = new Gee.HashMap<uint, OutputStream> ();
		private Gee.HashMap<PipeProxy, uint> pipe_proxies = new Gee.HashMap<PipeProxy, uint> ();
		private uint last_pipe_proxy_id = 1;

		/* these should be private, but must be accessible to glue code */
		public void * context;
		public Gee.HashMap<uint, void *> spawn_instance_by_pid = new Gee.HashMap<uint, void *> ();
		public Gee.HashMap<uint, void *> inject_instance_by_id = new Gee.HashMap<uint, void *> ();
		public uint last_id = 1;

		public HelperService (string parent_address) {
			Object (parent_address: parent_address);
			_create_context ();
		}

		~HelperService () {
			foreach (var instance in spawn_instance_by_pid.values)
				_free_spawn_instance (instance);
			foreach (var instance in inject_instance_by_id.values)
				_free_inject_instance (instance);
			_destroy_context ();
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
				foreach (var registration_id in pipe_proxies.values)
					connection.unregister_object (registration_id);
				pipe_proxies.clear ();

				if (system_session != null) {
					assert (system_session_registration_id != 0);
					connection.unregister_object (system_session_registration_id);
					yield system_session.destroy ();
					system_session = null;
				}

				if (helper_registration_id != 0)
					connection.unregister_object (helper_registration_id);

				connection.closed.disconnect (on_connection_closed);
				try {
					yield connection.close ();
				} catch (GLib.Error connection_error) {
				}
				connection = null;
			}

			loop.quit ();
		}

		private async void start () {
			try {
				connection = yield DBusConnection.new_for_address (parent_address, DBusConnectionFlags.AUTHENTICATION_CLIENT | DBusConnectionFlags.DELAY_MESSAGE_PROCESSING);
				connection.closed.connect (on_connection_closed);

				Helper helper = this;
				helper_registration_id = connection.register_object (Frida.ObjectPath.HELPER, helper);

				connection.start_message_processing ();
			} catch (GLib.Error e) {
				printerr ("Unable to start: %s\n", e.message);
				run_result = 1;
				shutdown.begin ();
			}
		}

		public async void stop () throws Error {
			Timeout.add (20, () => {
				shutdown.begin ();
				return false;
			});
		}

		public async string create_system_session (string agent_filename) throws GLib.Error {
			assert (system_session == null);

			system_session = yield AgentContainer.create (agent_filename);
			AgentSession system_agent_session = system_session;
			system_session_registration_id = connection.register_object (Frida.ObjectPath.SYSTEM_SESSION, system_agent_session);

			return Frida.ObjectPath.SYSTEM_SESSION;
		}

		public async uint spawn (string path, string[] argv, string[] envp) throws Error {
			string error = null;

			StdioPipes pipes;
			uint child_pid = _do_spawn (path, argv, envp, out pipes);
			var death_handler = child_dead.connect ((pid) => {
				if (pid == child_pid) {
					error = "Unexpected error while spawning child process '%s' (child process crashed)".printf (path);
					spawn.callback ();
				}
			});
			var ready_handler = child_ready.connect ((pid) => {
				if (pid == child_pid) {
					spawn.callback ();
				}
			});
			yield;
			disconnect (death_handler);
			disconnect (ready_handler);

			if (error != null)
				throw new Error.NOT_SUPPORTED (error);

			stdin_streams[child_pid] = new UnixOutputStream (pipes.input, false);
			pipes.weak_ref (() => {
				stdin_streams.unset (child_pid);
			});
			process_next_output_from.begin (new UnixInputStream (pipes.output, false), child_pid, 1, pipes);
			process_next_output_from.begin (new UnixInputStream (pipes.error, false), child_pid, 2, pipes);

			return child_pid;
		}

		private async void process_next_output_from (InputStream stream, uint pid, int fd, Object resource) {
			try {
				var buf = new uint8[4096];
				var n = yield stream.read_async (buf);
				var data = buf[0:n];
				output (pid, fd, data);
				if (n > 0)
					process_next_output_from.begin (stream, pid, fd, resource);
			} catch (GLib.Error e) {
				output (pid, fd, new uint8[0] {});
			}
		}

		public async void launch (string identifier, string url) throws Error {
			_do_launch (identifier, (url.length > 0) ? url : null);
		}

		public async void input (uint pid, uint8[] data) throws GLib.Error {
			var stream = stdin_streams[pid];
			if (stream == null)
				throw new Error.INVALID_ARGUMENT ("Invalid pid");
			var data_copy = data; /* FIXME: workaround for Vala compiler bug */
			yield stream.write_all_async (data_copy, Priority.DEFAULT, null, null);
		}

		public async void resume (uint pid) throws Error {
			void * instance;
			bool instance_found = spawn_instance_by_pid.unset (pid, out instance);
			if (!instance_found)
				throw new Error.INVALID_ARGUMENT ("Invalid pid");
			_resume_spawn_instance (instance);
			_free_spawn_instance (instance);
		}

		public async uint inject (uint pid, string filename, string data_string) throws Error {
			return _do_inject (pid, filename, data_string);
		}

		public async PipeEndpoints make_pipe_endpoints (uint local_pid, uint remote_pid) throws GLib.Error {
			bool need_proxy;
			var endpoints = _do_make_pipe_endpoints (local_pid, remote_pid, out need_proxy);
			if (need_proxy) {
				var pipe = new Pipe (endpoints.local_address);
				var proxy = new PipeProxy (pipe);

				var id = last_pipe_proxy_id++;
				var proxy_object_path = Frida.ObjectPath.from_tunneled_stream_id (id);
				TunneledStream ts = proxy;
				var registration_id = connection.register_object (proxy_object_path, ts);
				pipe_proxies[proxy] = registration_id;
				proxy.closed.connect (() => {
					connection.unregister_object (registration_id);
					pipe_proxies.unset (proxy);
				});

				return PipeEndpoints (proxy_object_path, endpoints.remote_address);
			}
			return endpoints;
		}

		private void on_connection_closed (bool remote_peer_vanished, GLib.Error? error) {
			shutdown.begin ();
		}

		public void _on_spawn_instance_dead (uint pid) {
			Idle.add (() => {
				void * instance;
				bool instance_found = spawn_instance_by_pid.unset (pid, out instance);
				assert (instance_found);
				_free_spawn_instance (instance);
				child_dead (pid);
				return false;
			});
		}

		public void _on_spawn_instance_ready (uint pid) {
			Idle.add (() => {
				child_ready (pid);
				return false;
			});
		}

		public void _on_inject_instance_dead (uint id) {
			Idle.add (() => {
				void * instance;
				bool instance_id_found = inject_instance_by_id.unset (id, out instance);
				assert (instance_id_found);
				_free_inject_instance (instance);
				uninjected (id);
				return false;
			});
		}

		public extern void _create_context ();
		public extern void _destroy_context ();

		public extern uint _do_spawn (string path, string[] argv, string[] envp, out StdioPipes pipes) throws Error;
		public extern void _do_launch (string identifier, string? url) throws Error;
		public extern void _resume_spawn_instance (void * instance);
		public extern void _free_spawn_instance (void * instance);

		public extern uint _do_inject (uint pid, string dylib_path, string data_string) throws Error;
		public extern void _free_inject_instance (void * instance);

		public static extern PipeEndpoints _do_make_pipe_endpoints (uint local_pid, uint remote_pid, out bool need_proxy) throws Error;
	}

	public class StdioPipes : Object {
		public int input {
			get;
			construct;
		}

		public int output {
			get;
			construct;
		}

		public int error {
			get;
			construct;
		}

		public StdioPipes (int input, int output, int error) {
			Object (input: input, output: output, error: error);
		}

		construct {
			try {
				Unix.set_fd_nonblocking (input, true);
				Unix.set_fd_nonblocking (output, true);
				Unix.set_fd_nonblocking (error, true);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		~StdioPipes () {
			Posix.close (input);
			Posix.close (output);
			Posix.close (error);
		}
	}

	private class PipeProxy : Object, TunneledStream {
		public signal void closed ();

		public Pipe pipe {
			get;
			construct;
		}
		private InputStream input;
		private OutputStream output;

		public PipeProxy (Pipe pipe) {
			Object (pipe: pipe);
		}

		construct {
			input = pipe.input_stream;
			output = pipe.output_stream;
		}

		public async void close () throws GLib.Error {
			try {
				yield pipe.close_async ();
			} catch (GLib.Error e) {
			}
			closed ();
		}

		public async uint8[] read () throws GLib.Error {
			try {
				var buf = new uint8[4096];
				var n = yield input.read_async (buf);
				return buf[0:n];
			} catch (GLib.Error e) {
				close.begin ();
				throw e;
			}
		}

		public async void write (uint8[] data) throws GLib.Error {
			try {
				var data_copy = data; /* FIXME: workaround for Vala compiler bug */
				yield output.write_all_async (data_copy, Priority.DEFAULT, null, null);
			} catch (GLib.Error e) {
				close.begin ();
				throw e;
			}
		}
	}
}
#endif
