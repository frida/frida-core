namespace Frida {
	private class Debugger : Object {
		public uint port {
			get;
			construct;
		}

		public AgentSession agent_session {
			get {
				return active_session;
			}
			construct {
				active_session = value;
			}
		}

		private AgentSession active_session;
		private AgentSession? obsolete_session;

		private Gum.InspectorServer? server;

		private Cancellable io_cancellable = new Cancellable ();

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
				server = (port != 0)
					? new Gum.InspectorServer.with_port (port)
					: new Gum.InspectorServer ();
				server.start ();

				server.message.connect (on_message_from_frontend);
			} catch (GLib.Error e) {
				try {
					yield agent_session.disable_debugger (cancellable);
				} catch (GLib.Error e) {
				}

				throw new Error.ADDRESS_IN_USE ("%s", e.message);
			}
		}

		public async void disable (Cancellable? cancellable) throws Error, IOError {
			server.message.disconnect (on_message_from_frontend);

			server.stop ();
			server = null;

			io_cancellable.cancel ();

			try {
				yield agent_session.disable_debugger (cancellable);
			} catch (GLib.Error e) {
				throw_dbus_error (e);
			}
		}

		private void on_message_from_frontend (string message) {
			agent_session.post_message_to_debugger.begin (message, io_cancellable);
		}

		public void handle_message_from_backend (string message) {
			server.post_message (message);
		}

		public void begin_migration (AgentSession new_session) {
			assert (obsolete_session == null);
			obsolete_session = active_session;

			active_session = new_session;
		}

		public void commit_migration (AgentSession new_session) {
			assert (new_session == active_session);
			assert (obsolete_session != null);

			obsolete_session = null;
		}

#if HAVE_NICE
		public void cancel_migration (AgentSession new_session) {
			assert (new_session == active_session);
			assert (obsolete_session != null);

			active_session = obsolete_session;
			obsolete_session = null;
		}
#endif
	}
}
