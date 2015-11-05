#if DARWIN
namespace Frida {
	public int main (string[] args) {
		Posix.setsid ();

		var parent_address = args[1];
		var service = new HelperService (parent_address);
		return service.run ();
	}

	public class HelperService : Object, Helper {
		public signal void child_dead (uint pid);
		public signal void child_ready (uint pid);

		public string parent_address {
			get;
			construct;
		}

		private SystemSession system_session = new SystemSession ();

		private MainLoop loop = new MainLoop ();
		private int run_result = 0;

		private DBusConnection connection;
		private uint helper_registration_id = 0;
		private uint system_session_registration_id = 0;

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
				if (system_session_registration_id != 0)
					connection.unregister_object (system_session_registration_id);
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

				AgentSession ss = system_session;
				system_session_registration_id = connection.register_object (Frida.ObjectPath.KERNEL_SESSION, ss);

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

		public async uint spawn (string path, string[] argv, string[] envp) throws Error {
			string error = null;

			uint child_pid = _do_spawn (path, argv, envp);
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

			return child_pid;
		}

		public async void launch (string identifier, string url) throws Error {
			_do_launch (identifier, (url.length > 0) ? url : null);
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

		public async PipeEndpoints make_pipe_endpoints (uint local_pid, uint remote_pid) throws Error {
			return _do_make_pipe_endpoints (local_pid, remote_pid);
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

		public extern uint _do_spawn (string path, string[] argv, string[] envp) throws Error;
		public extern void _do_launch (string identifier, string? url) throws Error;
		public extern void _resume_spawn_instance (void * instance);
		public extern void _free_spawn_instance (void * instance);

		public extern uint _do_inject (uint pid, string dylib_path, string data_string) throws Error;
		public extern void _free_inject_instance (void * instance);

		public static extern PipeEndpoints _do_make_pipe_endpoints (uint local_pid, uint remote_pid) throws Error;
	}

	private class SystemSession : Object, AgentSession {
		private Gum.ScriptBackend script_backend = Gum.ScriptBackend.obtain ();

		private Gee.HashMap<uint, Gum.Script> script_by_id = new Gee.HashMap<uint, Gum.Script> ();
		private uint last_script_id = 0;

		public async void close () throws Error {
		}

		public async void ping () throws Error {
		}

		public async AgentScriptId create_script (string name, string source) throws Error {
			var sid = AgentScriptId (++last_script_id);

			string script_name;
			if (name != "")
				script_name = name;
			else
				script_name = "script%u".printf (sid.handle);

			Gum.Script script;
			try {
				script = yield script_backend.create (script_name, source);
			} catch (IOError create_error) {
				throw new Error.INVALID_ARGUMENT (create_error.message);
			}
			script.set_message_handler ((script, message, data) => {
				var data_param = (data != null) ? data.get_data () : new uint8[] {};
				this.message_from_script (sid, message, data_param);
			});

			script_by_id[sid.handle] = script;

			return sid;
		}

		public async void destroy_script (AgentScriptId sid) throws Error {
			Gum.Script script;
			if (!script_by_id.unset (sid.handle, out script))
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			yield script.unload ();
		}

		public async void load_script (AgentScriptId sid) throws Error {
			var script = script_by_id[sid.handle];
			if (script == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			yield script.load ();
		}

		public async void post_message_to_script (AgentScriptId sid, string message) throws Error {
			var script = script_by_id[sid.handle];
			if (script == null)
				throw new Error.INVALID_ARGUMENT ("Invalid script ID");
			script.post_message (message);
		}

		public async void enable_debugger () throws Error {
			script_backend.set_debug_message_handler (on_debug_message);
		}

		public async void disable_debugger () throws Error {
			script_backend.set_debug_message_handler (null);
		}

		public async void post_message_to_debugger (string message) throws Error {
			script_backend.post_debug_message (message);
		}

		private void on_debug_message (string message) {
			message_from_debugger (message);
		}
	}
}
#endif
