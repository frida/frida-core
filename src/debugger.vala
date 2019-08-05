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

		public async void enable (Cancellable? cancellable) throws Error, IOError {
			try {
				yield agent_session.enable_debugger (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}

			try {
				server = new DebugServer (port, agent_session);
				server.start ();
			} catch (Error e) {
				try {
					yield agent_session.disable_debugger (cancellable);
				} catch (GLib.Error e) {
				}
				throw e;
			}
		}

		public async void disable (Cancellable? cancellable) throws Error, IOError {
			server.stop ();
			server = null;

			try {
				yield agent_session.disable_debugger (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
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

		private Cancellable io_cancellable = new Cancellable ();

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
				throw new Error.ADDRESS_IN_USE ("%s", e.message);
			}

			server.message.connect (on_message_from_frontend);
			agent_session.message_from_debugger.connect (on_message_from_backend);
		}

		public void stop () {
			agent_session.message_from_debugger.disconnect (on_message_from_backend);
			server.message.disconnect (on_message_from_frontend);

			server.stop ();

			io_cancellable.cancel ();
		}

		private void on_message_from_frontend (string message) {
			agent_session.post_message_to_debugger.begin (message, io_cancellable);
		}

		private void on_message_from_backend (string message) {
			server.post_message (message);
		}
	}
}
