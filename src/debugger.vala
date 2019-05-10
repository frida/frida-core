namespace Frida {
	private class Debugger : Object {
		public uint port {
			get;
			construct;
		}

		public AgentSession agent_session {
			get;
			construct;
		}

		private DebugServer server;

		public Debugger (uint16 port, AgentSession agent_session) {
			Object (port: port, agent_session: agent_session);
		}

		public async void enable () throws Error {
			try {
				yield agent_session.enable_debugger ();
			} catch (GLib.Error e) {
				throw Marshal.from_dbus (e);
			}

			try {
				server = new DebugServer (port, agent_session);
				server.start ();
			} catch (Error e) {
				agent_session.disable_debugger.begin ();
				throw e;
			}
		}

		public void disable () {
			server.stop ();
			server = null;

			agent_session.disable_debugger.begin ();
		}
	}

	private class DebugServer : Object {
		public Gum.InspectorServer server {
			get;
			construct;
		}

		public AgentSession agent_session {
			get;
			construct;
		}

		public DebugServer (uint port, AgentSession agent_session) {
			Object (
				server: (port != 0) ? new Gum.InspectorServer.with_port (port) : new Gum.InspectorServer (),
				agent_session: agent_session
			);
		}

		public void start () throws Error {
			try {
				server.start ();
			} catch (GLib.IOError e) {
				throw new Error.ADDRESS_IN_USE (e.message);
			}

			server.message.connect (on_message_from_frontend);
			agent_session.message_from_debugger.connect (on_message_from_backend);
		}

		public void stop () {
			agent_session.message_from_debugger.disconnect (on_message_from_backend);
			server.message.disconnect (on_message_from_frontend);

			server.stop ();
		}

		private void on_message_from_frontend (string message) {
			agent_session.post_message_to_debugger.begin (message);
		}

		private void on_message_from_backend (string message) {
			server.post_message (message);
		}
	}
}
