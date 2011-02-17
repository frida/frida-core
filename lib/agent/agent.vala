namespace Zed.Agent {
	public class AgentServer : Object, AgentSession {
		public string listen_address {
			get;
			construct;
		}

		private MainLoop main_loop = new MainLoop ();
		private DBusServer server;
		private bool closing = false;
		private Gee.ArrayList<DBusConnection> connections = new Gee.ArrayList<DBusConnection> ();
		private Gee.HashMap<DBusConnection, uint> registration_id_by_connection = new Gee.HashMap<DBusConnection, uint> ();
#if WINDOWS
		private MemoryMonitorEngine memory_monitor_engine = new MemoryMonitorEngine ();
#endif
		private ScriptEngine script_engine = new ScriptEngine ();
		private GMainWatchdog gmain_watchdog = new GMainWatchdog ();
		private GLogProbe glog_probe = new GLogProbe ();

		public AgentServer (string listen_address) {
			Object (listen_address: listen_address);
		}

		construct {
#if WINDOWS
			memory_monitor_engine.memory_read_detected.connect ((from, address, module_name) => this.memory_read_detected (from, address, module_name));
#endif
			script_engine.message_from_script.connect ((script_id, msg) => this.message_from_script (script_id, msg));
			glog_probe.message.connect ((timestamp, domain, level, message) => this.glog_message (timestamp, domain, level, message));
		}

		public async void close () throws IOError {
			if (closing)
				throw new IOError.FAILED ("close already in progress");
			closing = true;

			server.stop ();
			server = null;

			if (script_engine != null) {
				script_engine.shutdown ();
				script_engine = null;
			}

			Timeout.add (100, () => {
				close_connections_and_schedule_shutdown ();
				return false;
			});
		}

		private async void close_connections_and_schedule_shutdown () {
			foreach (var connection in connections.to_array ()) {
				unregister (connection);

				try {
					yield connection.close ();
				} catch (IOError first_close_error) {
				}

				/* FIXME: close again to make sure things are shut down, needs further investigation */
				try {
					yield connection.close ();
				} catch (IOError second_close_error) {
				}
			}
			connections.clear ();

			Timeout.add (100, () => {
				main_loop.quit ();
				return false;
			});
		}

		public async uint64 resolve_module_base (string module_name) throws IOError {
			return (uint64) Gum.Module.find_base_address (module_name);
		}

		public async uint64 resolve_module_export (string module_name, string symbol_name) throws IOError {
			return (uint64) Gum.Module.find_export_by_name (module_name, symbol_name);
		}

		public async AgentModuleInfo[] query_modules () throws IOError {
			var module_list = new Gee.ArrayList<AgentModuleInfo?> ();
			Gum.Process.enumerate_modules ((name, address, path) => {
				module_list.add (AgentModuleInfo (name, path, 42, (uint64) address));
				return true;
			});

			var modules = new AgentModuleInfo[0];
			foreach (var module in module_list)
				modules += module;

			return modules;
		}

		public async AgentFunctionInfo[] query_module_functions (string module_name) throws IOError {
			var function_list = new Gee.ArrayList<AgentFunctionInfo?> ();
			Gum.Module.enumerate_exports (module_name, (name, address) => {
				function_list.add (AgentFunctionInfo (name, (uint64) address));
				return true;
			});

			var functions = new AgentFunctionInfo[0];
			foreach (var function in function_list)
				functions += function;

			return functions;
		}

		public async uint64[] scan_memory_for_pattern (MemoryProtection required_protection, string pattern) throws IOError {
			var match_pattern = new Gum.MatchPattern.from_string (pattern);
			if (match_pattern == null)
				throw new IOError.FAILED ("invalid match pattern");

			var match_list = new Gee.ArrayList<void *> ();
			Gum.Process.enumerate_ranges ((Gum.PageProtection) required_protection, (range, prot) => {
				Gum.Memory.scan (range, match_pattern, (address, size) => {
					match_list.add (address);
					return true;
				});

				return true;
			});

			var matches = new uint64[0];
			foreach (var match in match_list)
				matches += (uint64) match;

			return matches;
		}

		public async uint64[] scan_module_for_code_pattern (string module_name, string pattern) throws IOError {
			var match_pattern = new Gum.MatchPattern.from_string (pattern);
			if (match_pattern == null)
				throw new IOError.FAILED ("invalid match pattern");

			var match_list = new Gee.ArrayList<void *> ();
			Gum.Module.enumerate_ranges (module_name, Gum.PageProtection.EXECUTE, (range, prot) => {
				Gum.Memory.scan (range, match_pattern, (address, size) => {
					match_list.add (address);
					return true;
				});

				return true;
			});

			var matches = new uint64[0];
			foreach (var match in match_list)
				matches += (uint64) match;

			return matches;
		}

		public async uint8[] read_memory (uint64 address, uint size) throws IOError {
			var bytes = Gum.Memory.read ((void *) address, size);
			if (bytes.length == 0)
				throw new IOError.FAILED ("specified memory region is not readable");
			return bytes;
		}

		public async void write_memory (uint64 address, uint8[] bytes) throws IOError {
			if (bytes.length == 0)
				throw new IOError.FAILED ("zero-length write not allowed");
			if (!Gum.Memory.write ((void *) address, bytes))
				throw new IOError.FAILED ("specified memory region is not writable");
		}

		public async void start_investigation (AgentTriggerInfo start_trigger, AgentTriggerInfo stop_trigger) throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async void stop_investigation () throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async AgentScriptInfo compile_script (string script_text) throws IOError {
			var instance = script_engine.compile_script (script_text);
			var script = instance.script;
			return AgentScriptInfo (instance.sid, (uint64) script.get_code_address (), script.get_code_size ());
		}

		public async void destroy_script (AgentScriptId sid) throws IOError {
			script_engine.destroy_script (sid);
		}

		public async void attach_script_to (AgentScriptId sid, uint64 address) throws IOError {
			script_engine.attach_script_to (sid, address);
		}

		public async void redirect_script_messages_to (AgentScriptId sid, string folder, uint keep_last_n) throws IOError {
			script_engine.redirect_script_messages_to (sid, folder, keep_last_n);
		}

		public async void set_monitor_enabled (string module_name, bool enable) throws IOError {
#if WINDOWS
			memory_monitor_engine.set_enabled (module_name, enable);
#else
			throw new IOError.FAILED ("only supported on Windows for now");
#endif
		}

		public async void begin_instance_trace () throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async void end_instance_trace () throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async AgentInstanceInfo[] peek_instances () throws IOError {
			throw new IOError.FAILED ("not implemented");
		}

		public async void add_glog_pattern (string pattern, uint levels) throws IOError {
			glog_probe.add (pattern, levels);
		}

		public async void clear_glog_patterns () throws IOError {
			glog_probe.clear ();
		}

		public async void enable_gmain_watchdog (double max_duration) throws IOError {
			gmain_watchdog.enable (max_duration);
		}

		public async void disable_gmain_watchdog () throws IOError {
			gmain_watchdog.disable ();
		}

		public void run () throws Error {
			server = new DBusServer.sync (listen_address, DBusServerFlags.AUTHENTICATION_ALLOW_ANONYMOUS, DBus.generate_guid ());
			server.new_connection.connect ((connection) => {
				connection.closed.connect (on_connection_closed);

				try {
					Zed.AgentSession session = this;
					var registration_id = connection.register_object (Zed.ObjectPath.AGENT_SESSION, session);
					registration_id_by_connection[connection] = registration_id;
				} catch (IOError e) {
					printerr ("failed to register object: %s\n", e.message);
					close ();
					return false;
				}

				connections.add (connection);
				return true;
			});

			server.start ();

			main_loop = new MainLoop ();
			main_loop.run ();
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			unregister (connection);

			connections.remove (connection);
			if (connections.is_empty)
				close ();
		}

		private async void unregister (DBusConnection connection) {
			uint registration_id;
			if (registration_id_by_connection.unset (connection, out registration_id))
				connection.unregister_object (registration_id);
		}
	}

	public void main (string listen_address) {
		Environment.init ();
		run_server_listening_on (listen_address);
		Environment.deinit ();
	}

	private void run_server_listening_on (string listen_address) {
		var interceptor = Gum.Interceptor.obtain ();
		interceptor.ignore_current_thread ();

		var server = new AgentServer (listen_address);

		try {
			server.run ();
		} catch (Error e) {
			printerr ("error: %s\n", e.message);
		}

		interceptor.unignore_current_thread ();
	}

	namespace Environment {
		public extern void init ();
		public extern void deinit ();
	}

}
