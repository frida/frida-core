namespace Zed {
	public class WindowsHostSessionBackend : Object, HostSessionBackend {
		private WindowsHostSessionProvider local_provider;

		public async void start () {
			assert (local_provider == null);
			local_provider = new WindowsHostSessionProvider ();
			provider_available (local_provider);
		}

		public async void stop () {
			assert (local_provider != null);
			provider_unavailable (local_provider);
			yield local_provider.close ();
			local_provider = null;
		}
	}

	public class WindowsHostSessionProvider : Object, HostSessionProvider {
		public string name {
			get { return "Local System"; }
		}

		public ImageData? icon {
			get { return _icon; }
		}
		private ImageData? _icon;

		public HostSessionProviderKind kind {
			get { return HostSessionProviderKind.LOCAL_SYSTEM; }
		}

		private WindowsHostSession host_session;

		construct {
			try {
				_icon = _extract_icon ();
			} catch (IOError e) {
			}
		}

		public async void close () {
			if (host_session != null)
				yield host_session.close ();
			host_session = null;
		}

		public async HostSession create () throws IOError {
			if (host_session != null)
				throw new IOError.FAILED ("may only create one HostSession");
			host_session = new WindowsHostSession ();
			host_session.agent_session_closed.connect ((id, error) => this.agent_session_closed (id, error));
			return host_session;
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			if (host_session == null)
				throw new IOError.FAILED ("no such id");
			return yield host_session.obtain_agent_session (id);
		}

		public static extern ImageData? _extract_icon () throws IOError;
	}

	public class WindowsHostSession : Object, HostSession {
		public signal void agent_session_closed (AgentSessionId id, Error? error);

		private ProcessEnumerator process_enumerator = new ProcessEnumerator ();

		private Winjector winjector = new Winjector ();
		private AgentDescriptor agent_desc;

		private const string LISTEN_ADDRESS_TEMPLATE = "tcp:host=127.0.0.1,port=%u";
		private uint last_agent_port = 27043;
		private Gee.ArrayList<Entry> entries = new Gee.ArrayList<Entry> ();

		construct {
			var blob32 = Zed.Data.Agent.get_zed_agent_32_dll_blob ();
			var blob64 = Zed.Data.Agent.get_zed_agent_64_dll_blob ();
			agent_desc = new AgentDescriptor ("zed-agent-%u.dll",
				new MemoryInputStream.from_data (blob32.data, null),
				new MemoryInputStream.from_data (blob64.data, null));
		}

		public async void close () {
			foreach (var entry in entries)
				yield entry.close ();
			entries.clear ();

			/* HACK: give processes 100 ms to unload DLLs */
			var source = new TimeoutSource (100);
			source.set_callback (() => {
				close.callback ();
				return false;
			});
			source.attach (MainContext.get_thread_default ());
			yield;

			agent_desc = null;

			yield winjector.close ();
			winjector = null;
		}

		public async HostProcessInfo[] enumerate_processes () throws IOError {
			var processes = yield process_enumerator.enumerate_processes ();
			return processes;
		}

		public async AgentSessionId attach_to (uint pid) throws IOError {
			try {
				var port = last_agent_port++;
				var listen_address = LISTEN_ADDRESS_TEMPLATE.printf (port);
				yield winjector.inject (pid, agent_desc, listen_address, null);
				return AgentSessionId (port);
			} catch (WinjectorError e) {
				throw new IOError.FAILED (e.message);
			}
		}

		public async AgentSession obtain_agent_session (AgentSessionId id) throws IOError {
			var address = LISTEN_ADDRESS_TEMPLATE.printf (id.handle);

			DBusConnection connection = null;

			for (int i = 1; connection == null; i++) {
				try {
					connection = yield DBusConnection.new_for_address (address, DBusConnectionFlags.AUTHENTICATION_CLIENT);
				} catch (Error connect_error) {
					if (i != 40) {
						var source = new TimeoutSource (50);
						source.set_callback (() => {
							obtain_agent_session.callback ();
							return false;
						});
						source.attach (MainContext.get_thread_default ());
						yield;
					} else {
						break;
					}
				}
			}

			if (connection == null)
				throw new IOError.TIMED_OUT ("timed out");

			AgentSession session = connection.get_proxy_sync (null, ObjectPath.AGENT_SESSION);

			var entry = new Entry (id, connection, session);
			entries.add (entry);

			connection.closed.connect (on_connection_closed);

			return session;
		}

		private void on_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			bool closed_by_us = (!remote_peer_vanished && error == null);
			if (closed_by_us)
				return;

			Entry entry_to_remove = null;
			foreach (var entry in entries) {
				if (entry.connection == connection) {
					entry_to_remove = entry;
					break;
				}
			}

			assert (entry_to_remove != null);
			entries.remove (entry_to_remove);

			agent_session_closed (entry_to_remove.id, error);
		}

		private class Entry : Object {
			public AgentSessionId id {
				get;
				private set;
			}

			public DBusConnection connection {
				get;
				private set;
			}

			public Object proxy {
				get;
				private set;
			}

			public Entry (AgentSessionId id, DBusConnection connection, Object proxy) {
				this.id = id;
				this.connection = connection;
				this.proxy = proxy;
			}

			public async void close () {
				proxy = null;

				try {
					yield connection.close ();
				} catch (Error conn_error) {
				}
				connection = null;
			}
		}
	}
}
