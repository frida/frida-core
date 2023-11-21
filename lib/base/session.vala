namespace Frida {
	[DBus (name = "re.frida.HostSession16")]
	public interface HostSession : Object {
		public abstract async void ping (uint interval_seconds, Cancellable? cancellable) throws GLib.Error;

		public abstract async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws GLib.Error;
		public abstract async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;

		public abstract async void enable_spawn_gating (Cancellable? cancellable) throws GLib.Error;
		public abstract async void disable_spawn_gating (Cancellable? cancellable) throws GLib.Error;
		public abstract async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws GLib.Error;
		public abstract async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws GLib.Error;
		public abstract async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws GLib.Error;
		public abstract async void input (uint pid, uint8[] data, Cancellable? cancellable) throws GLib.Error;
		public abstract async void resume (uint pid, Cancellable? cancellable) throws GLib.Error;
		public abstract async void kill (uint pid, Cancellable? cancellable) throws GLib.Error;
		public abstract async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async void reattach (AgentSessionId id, Cancellable? cancellable) throws GLib.Error;
		public abstract async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
			Cancellable? cancellable) throws GLib.Error;

		public signal void spawn_added (HostSpawnInfo info);
		public signal void spawn_removed (HostSpawnInfo info);
		public signal void child_added (HostChildInfo info);
		public signal void child_removed (HostChildInfo info);
		public signal void process_crashed (CrashInfo crash);
		public signal void output (uint pid, int fd, uint8[] data);
		public signal void agent_session_detached (AgentSessionId id, SessionDetachReason reason, CrashInfo crash);
		public signal void uninjected (InjectorPayloadId id);
	}

	[DBus (name = "re.frida.AgentSessionProvider16")]
	public interface AgentSessionProvider : Object {
		public abstract async void open (AgentSessionId id, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
#if !WINDOWS
		public abstract async void migrate (AgentSessionId id, GLib.Socket to_socket, Cancellable? cancellable) throws GLib.Error;
#endif
		public abstract async void unload (Cancellable? cancellable) throws GLib.Error;

		public signal void opened (AgentSessionId id);
		public signal void closed (AgentSessionId id);
		public signal void eternalized ();
		public signal void child_gating_changed (uint subscriber_count);
	}

	[DBus (name = "re.frida.AgentSession16")]
	public interface AgentSession : Object {
		public abstract async void close (Cancellable? cancellable) throws GLib.Error;

		public abstract async void interrupt (Cancellable? cancellable) throws GLib.Error;
		public abstract async void resume (uint rx_batch_id, Cancellable? cancellable, out uint tx_batch_id) throws GLib.Error;

		public abstract async void enable_child_gating (Cancellable? cancellable) throws GLib.Error;
		public abstract async void disable_child_gating (Cancellable? cancellable) throws GLib.Error;

		public abstract async AgentScriptId create_script (string source, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async AgentScriptId create_script_from_bytes (uint8[] bytes, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async uint8[] compile_script (string source, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async uint8[] snapshot_script (string embed_script, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void eternalize_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;

		public abstract async void enable_debugger (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void disable_debugger (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;

		public abstract async void post_messages (AgentMessage[] messages, uint batch_id,
			Cancellable? cancellable) throws GLib.Error;

		public abstract async PortalMembershipId join_portal (string address, HashTable<string, Variant> options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async void leave_portal (PortalMembershipId membership_id, Cancellable? cancellable) throws GLib.Error;

		public abstract async void offer_peer_connection (string offer_sdp, HashTable<string, Variant> peer_options,
			Cancellable? cancellable, out string answer_sdp) throws GLib.Error;
		public abstract async void add_candidates (string[] candidate_sdps, Cancellable? cancellable) throws GLib.Error;
		public abstract async void notify_candidate_gathering_done (Cancellable? cancellable) throws GLib.Error;
		public abstract async void begin_migration (Cancellable? cancellable) throws GLib.Error;
		public abstract async void commit_migration (Cancellable? cancellable) throws GLib.Error;
		public signal void new_candidates (string[] candidate_sdps);
		public signal void candidate_gathering_done ();
	}

	[DBus (name = "re.frida.AgentController16")]
	public interface AgentController : Object {
#if !WINDOWS
		public abstract async HostChildId prepare_to_fork (uint parent_pid, Cancellable? cancellable, out uint parent_injectee_id,
			out uint child_injectee_id, out GLib.Socket child_socket) throws GLib.Error;
#endif

		public abstract async HostChildId prepare_to_specialize (uint pid, string identifier, Cancellable? cancellable,
			out uint specialized_injectee_id, out string specialized_pipe_address) throws GLib.Error;

		public abstract async void recreate_agent_thread (uint pid, uint injectee_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void wait_for_permission_to_resume (HostChildId id, HostChildInfo info,
			Cancellable? cancellable) throws GLib.Error;

		public abstract async void prepare_to_exec (HostChildInfo info, Cancellable? cancellable) throws GLib.Error;
		public abstract async void cancel_exec (uint pid, Cancellable? cancellable) throws GLib.Error;

		public abstract async void acknowledge_spawn (HostChildInfo info, SpawnStartState start_state,
			Cancellable? cancellable) throws GLib.Error;
	}

	[DBus (name = "re.frida.AgentMessageSink16")]
	public interface AgentMessageSink : Object {
		public abstract async void post_messages (AgentMessage[] messages, uint batch_id,
			Cancellable? cancellable) throws GLib.Error;
	}

	public struct AgentMessage {
		public AgentMessageKind kind;

		public AgentScriptId script_id;

		public string text;

		public bool has_data;
		public uint8[] data;

		public AgentMessage (AgentMessageKind kind, AgentScriptId script_id, string text, bool has_data, uint8[] data) {
			this.kind = kind;
			this.script_id = script_id;
			this.text = text;
			this.has_data = has_data;
			this.data = data;
		}
	}

	public enum AgentMessageKind {
		SCRIPT = 1,
		DEBUGGER
	}

	public class AgentMessageTransmitter : Object {
		public signal void closed ();
		public signal void new_candidates (string[] candidate_sdps);
		public signal void candidate_gathering_done ();

		public weak AgentSession agent_session {
			get;
			construct;
		}

		public uint persist_timeout {
			get;
			construct;
		}

		public AgentMessageSink? message_sink {
			get;
			set;
		}

		public MainContext frida_context {
			get;
			construct;
		}

		public MainContext dbus_context {
			get;
			construct;
		}

		private Promise<bool>? close_request;

		private State state = LIVE;

		private TimeoutSource? expiry_timer;

		private uint last_rx_batch_id = 0;
		private Gee.LinkedList<PendingMessage> pending_messages = new Gee.LinkedList<PendingMessage> ();
		private int next_serial = 1;
		private uint pending_deliveries = 0;
		private Cancellable delivery_cancellable = new Cancellable ();

#if HAVE_NICE
		private Nice.Agent? nice_agent;
		private uint nice_stream_id;
		private uint nice_component_id;
		private SctpConnection? nice_iostream;
		private DBusConnection? nice_connection;
		private uint nice_registration_id;
#endif
		private AgentMessageSink? nice_message_sink;
		private Cancellable nice_cancellable = new Cancellable ();

		private enum State {
			LIVE,
			INTERRUPTED
		}

		public AgentMessageTransmitter (AgentSession agent_session, uint persist_timeout, MainContext frida_context,
				MainContext dbus_context) {
			Object (
				agent_session: agent_session,
				persist_timeout: persist_timeout,
				frida_context: frida_context,
				dbus_context: dbus_context
			);
		}

		construct {
			assert (frida_context != null);
			assert (dbus_context != null);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			while (close_request != null) {
				try {
					yield close_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			close_request = new Promise<bool> ();

			nice_cancellable.cancel ();

			delivery_cancellable.cancel ();

			yield teardown_peer_connection_and_emit_closed ();

			message_sink = null;

			close_request.resolve (true);
		}

		public void check_okay_to_receive () throws Error {
			if (state == INTERRUPTED)
				throw new Error.INVALID_OPERATION ("Cannot receive messages while interrupted");
		}

		public void interrupt () throws Error {
			if (persist_timeout == 0 || expiry_timer != null)
				throw new Error.INVALID_OPERATION ("Invalid operation");

			state = INTERRUPTED;
			delivery_cancellable.cancel ();

			expiry_timer = new TimeoutSource.seconds (persist_timeout);
			expiry_timer.set_callback (() => {
				close.begin (null);
				return false;
			});
			expiry_timer.attach (frida_context);
		}

		public void resume (uint rx_batch_id, out uint tx_batch_id) throws Error {
			if (persist_timeout == 0 || expiry_timer == null)
				throw new Error.INVALID_OPERATION ("Invalid operation");

			if (rx_batch_id != 0) {
				PendingMessage? m;
				while ((m = pending_messages.peek ()) != null && m.delivery_attempts > 0 && m.serial <= rx_batch_id) {
					pending_messages.poll ();
				}
			}

			expiry_timer.destroy ();
			expiry_timer = null;

			delivery_cancellable = new Cancellable ();
			state = LIVE;

			schedule_on_frida_thread (() => {
				maybe_deliver_pending_messages ();
				return false;
			});

			tx_batch_id = last_rx_batch_id;
		}

		public void notify_rx_batch_id (uint batch_id) throws Error {
			if (state == INTERRUPTED)
				throw new Error.INVALID_OPERATION ("Cannot receive messages while interrupted");

			last_rx_batch_id = batch_id;
		}

#if HAVE_NICE
		public async void offer_peer_connection (string offer_sdp, HashTable<string, Variant> peer_options,
				Cancellable? cancellable, out string answer_sdp) throws Error, IOError {
			var offer = PeerSessionDescription.parse (offer_sdp);

			var agent = new Nice.Agent.full (dbus_context, Nice.Compatibility.RFC5245, ICE_TRICKLE);
			agent.set_software ("Frida");
			agent.controlling_mode = false;
			agent.ice_tcp = false;

			uint stream_id = agent.add_stream (1);
			if (stream_id == 0)
				throw new Error.NOT_SUPPORTED ("Unable to add stream");
			uint component_id = 1;
			agent.set_stream_name (stream_id, "application");
			agent.set_remote_credentials (stream_id, offer.ice_ufrag, offer.ice_pwd);

			yield PeerConnection.configure_agent (agent, stream_id, component_id, PeerOptions._deserialize (peer_options),
				cancellable);

			uint8[] cert_der;
			string cert_pem, key_pem;
			yield generate_certificate (out cert_der, out cert_pem, out key_pem);

			TlsCertificate certificate;
			try {
				certificate = new TlsCertificate.from_pem (cert_pem + key_pem, -1);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			var answer = new PeerSessionDescription ();
			answer.session_id = PeerSessionId.generate ();
			agent.get_local_credentials (stream_id, out answer.ice_ufrag, out answer.ice_pwd);
			answer.ice_trickle = offer.ice_trickle;
			answer.fingerprint = PeerConnection.compute_certificate_fingerprint (cert_der);
			answer.setup = (offer.setup != ACTIVE) ? PeerSetup.ACTIVE : PeerSetup.ACTPASS;
			answer.sctp_port = offer.sctp_port;
			answer.max_message_size = offer.max_message_size;

			answer_sdp = answer.to_sdp ();

			if (nice_agent != null)
				throw new Error.INVALID_OPERATION ("Peer connection already exists");

			nice_agent = agent;
			nice_stream_id = stream_id;
			nice_component_id = component_id;

			schedule_on_dbus_thread (() => {
				open_peer_connection.begin (certificate, offer, cancellable);
				return false;
			});
		}

		private async void teardown_peer_connection_and_emit_closed () {
			schedule_on_frida_thread (() => {
				if (nice_agent != null)
					close_nice_resources_and_emit_closed.begin ();
				else
					closed ();
				return Source.REMOVE;
			});
		}

		private async void close_nice_resources_and_emit_closed () {
			yield close_nice_resources (true);

			closed ();
		}

		private async void close_nice_resources (bool connection_still_alive) {
			Nice.Agent? agent = nice_agent;
			DBusConnection? conn = nice_connection;

			discard_nice_resources ();

			if (conn != null && connection_still_alive) {
				try {
					yield conn.flush ();
					yield conn.close ();
				} catch (GLib.Error e) {
				}
			}

			if (agent != null) {
				schedule_on_dbus_thread (() => {
					agent.close_async.begin ();

					schedule_on_frida_thread (() => {
						close_nice_resources.callback ();
						return false;
					});

					return false;
				});
				yield;
			}
		}

		private void discard_nice_resources () {
			nice_cancellable.cancel ();
			nice_cancellable = new Cancellable ();

			nice_message_sink = null;

			if (nice_registration_id != 0) {
				nice_connection.unregister_object (nice_registration_id);
				nice_registration_id = 0;
			}

			if (nice_connection != null) {
				nice_connection.on_closed.disconnect (on_nice_connection_closed);
				nice_connection = null;
			}

			nice_iostream = null;

			nice_component_id = 0;
			nice_stream_id = 0;

			nice_agent = null;
		}

		private async void open_peer_connection (TlsCertificate certificate, PeerSessionDescription offer,
				Cancellable? cancellable) {
			Nice.Agent agent = nice_agent;
			DtlsConnection? tc = null;
			ulong candidate_handler = 0;
			ulong gathering_handler = 0;
			ulong accept_handler = 0;
			try {
				agent.component_state_changed.connect (on_component_state_changed);

				var pending_candidates = new Gee.ArrayList<string> ();
				candidate_handler = agent.new_candidate_full.connect (candidate => {
					string candidate_sdp = agent.generate_local_candidate_sdp (candidate);
					pending_candidates.add (candidate_sdp);
					if (pending_candidates.size == 1) {
						schedule_on_dbus_thread (() => {
							var stolen_candidates = pending_candidates;
							pending_candidates = new Gee.ArrayList<string> ();

							schedule_on_frida_thread (() => {
								int n = stolen_candidates.size;
								var sdps = new string[n + 1];
								for (int i = 0; i != n; i++)
									sdps[i] = stolen_candidates[i];

								new_candidates (sdps[0:n]);

								return false;
							});

							return false;
						});
					}
				});

				gathering_handler = agent.candidate_gathering_done.connect (stream_id => {
					schedule_on_dbus_thread (() => {
						schedule_on_frida_thread (() => {
							candidate_gathering_done ();
							return false;
						});
						return false;
					});
				});

				if (!agent.gather_candidates (nice_stream_id))
					throw new Error.NOT_SUPPORTED ("Unable to gather local candidates");

				var socket = new PeerSocket (agent, nice_stream_id, nice_component_id);

				if (offer.setup == ACTIVE) {
					tc = DtlsServerConnection.new (socket, certificate);
				} else {
					tc = DtlsClientConnection.new (socket, null);
					tc.set_certificate (certificate);
				}
				tc.set_database (null);
				accept_handler = tc.accept_certificate.connect ((peer_cert, errors) => {
					return PeerConnection.compute_certificate_fingerprint (peer_cert.certificate.data) == offer.fingerprint;
				});
				yield tc.handshake_async (Priority.DEFAULT, nice_cancellable);

				nice_iostream = new SctpConnection (tc, offer.setup, offer.sctp_port, offer.max_message_size);

				schedule_on_frida_thread (() => {
					complete_peer_connection.begin ();
					return false;
				});
			} catch (GLib.Error e) {
				schedule_on_frida_thread (() => {
					close_nice_resources.begin (false);
					return false;
				});
			} finally {
				if (accept_handler != 0)
					tc.disconnect (accept_handler);
				if (gathering_handler != 0)
					agent.disconnect (gathering_handler);
				if (candidate_handler != 0)
					agent.disconnect (candidate_handler);
			}
		}

		private async void complete_peer_connection () {
			try {
				nice_connection = yield new DBusConnection (nice_iostream, null, DELAY_MESSAGE_PROCESSING, null,
					nice_cancellable);
				nice_connection.on_closed.connect (on_nice_connection_closed);

				try {
					nice_registration_id = nice_connection.register_object (ObjectPath.AGENT_SESSION, agent_session);
				} catch (IOError io_error) {
					assert_not_reached ();
				}

				nice_connection.start_message_processing ();

				nice_message_sink = yield nice_connection.get_proxy (null, ObjectPath.AGENT_MESSAGE_SINK,
					DO_NOT_LOAD_PROPERTIES, null);
			} catch (GLib.Error e) {
				close_nice_resources.begin (false);
			}
		}

		private void on_component_state_changed (uint stream_id, uint component_id, Nice.ComponentState state) {
			switch (state) {
				case FAILED:
					nice_cancellable.cancel ();
					break;
				default:
					break;
			}
		}

		public void add_candidates (string[] candidate_sdps) throws Error {
			Nice.Agent? agent = nice_agent;
			if (agent == null)
				throw new Error.INVALID_OPERATION ("No peer connection in progress");

			string[] candidate_sdps_copy = candidate_sdps;
			schedule_on_dbus_thread (() => {
				var candidates = new SList<Nice.Candidate> ();
				foreach (unowned string sdp in candidate_sdps_copy) {
					var candidate = agent.parse_remote_candidate_sdp (nice_stream_id, sdp);
					if (candidate != null)
						candidates.append (candidate);
				}

				agent.set_remote_candidates (nice_stream_id, nice_component_id, candidates);

				return false;
			});
		}

		public void notify_candidate_gathering_done () throws Error {
			Nice.Agent? agent = nice_agent;
			if (agent == null)
				throw new Error.INVALID_OPERATION ("No peer connection in progress");

			schedule_on_dbus_thread (() => {
				agent.peer_candidate_gathering_done (nice_stream_id);

				return false;
			});
		}

		private void on_nice_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			handle_nice_connection_closure.begin ();
		}

		private async void handle_nice_connection_closure () {
			yield close_nice_resources (false);

			if (persist_timeout != 0) {
				try {
					interrupt ();
				} catch (Error e) {
				}
			} else {
				close.begin (null);
			}
		}
#else
		public async void offer_peer_connection (string offer_sdp, HashTable<string, Variant> peer_options,
				Cancellable? cancellable, out string answer_sdp) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Peer-to-peer support not available due to build configuration");
		}

		private async void teardown_peer_connection_and_emit_closed () {
			schedule_on_frida_thread (() => {
				closed ();
				return Source.REMOVE;
			});
		}

		public void add_candidates (string[] candidate_sdps) throws Error {
		}

		public void notify_candidate_gathering_done () throws Error {
		}
#endif

		public void begin_migration () {
			state = INTERRUPTED;
		}

		public void commit_migration () {
			if (expiry_timer != null)
				return;

			state = LIVE;

			maybe_deliver_pending_messages ();
		}

		public void post_message_from_script (AgentScriptId script_id, string json, Bytes? data) {
			pending_messages.offer (new PendingMessage (next_serial++, AgentMessageKind.SCRIPT, script_id, json, data));
			maybe_deliver_pending_messages ();
		}

		public void post_message_from_debugger (AgentScriptId script_id, string message) {
			pending_messages.offer (new PendingMessage (next_serial++, AgentMessageKind.DEBUGGER, script_id, message));
			maybe_deliver_pending_messages ();
		}

		private void maybe_deliver_pending_messages () {
			if (state != LIVE)
				return;

			AgentMessageSink? sink = (nice_message_sink != null) ? nice_message_sink : message_sink;
			if (sink == null)
				return;

			if (pending_messages.is_empty)
				return;

			var batch = new Gee.ArrayList<PendingMessage> ();
			void * items = null;
			int n_items = 0;
			size_t total_size = 0;
			size_t max_size = 4 * 1024 * 1024;
			PendingMessage? m;
			while ((m = pending_messages.peek ()) != null) {
				size_t message_size = m.estimate_size_in_bytes ();
				if (total_size + message_size > max_size && !batch.is_empty)
					break;
				pending_messages.poll ();
				batch.add (m);

				n_items++;
				items = realloc (items, n_items * sizeof (AgentMessage));

				AgentMessage * am = (AgentMessage *) items + n_items - 1;

				am->kind = m.kind;
				am->script_id = m.script_id;

				*((void **) &am->text) = m.text;

				unowned Bytes? data = m.data;
				am->has_data = data != null;
				*((void **) &am->data) = am->has_data ? data.get_data () : null;
				am->data.length = am->has_data ? data.length : 0;

				total_size += message_size;
			}

			if (persist_timeout == 0)
				emit_batch (sink, batch, items);
			else
				deliver_batch.begin (sink, batch, items);
		}

		private void emit_batch (AgentMessageSink sink, Gee.ArrayList<PendingMessage> messages, void * items) {
			unowned AgentMessage[] items_arr = (AgentMessage[]) items;
			items_arr.length = messages.size;

			sink.post_messages.begin (items_arr, 0, delivery_cancellable);

			free (items);
		}

		private async void deliver_batch (AgentMessageSink sink, Gee.ArrayList<PendingMessage> messages, void * items) {
			bool success = false;
			pending_deliveries++;
			try {
				int n = messages.size;

				foreach (var message in messages)
					message.delivery_attempts++;

				unowned AgentMessage[] items_arr = (AgentMessage[]) items;
				items_arr.length = n;

				uint batch_id = messages[n - 1].serial;

				yield sink.post_messages (items_arr, batch_id, delivery_cancellable);

				success = true;
			} catch (GLib.Error e) {
				pending_messages.add_all (messages);
				pending_messages.sort ((a, b) => a.serial - b.serial);
			} finally {
				pending_deliveries--;
				if (pending_deliveries == 0 && success)
					next_serial = 1;

				free (items);
			}
		}

		protected void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (frida_context);
		}

		protected void schedule_on_dbus_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (dbus_context);
		}

		private class PendingMessage {
			public int serial;
			public AgentMessageKind kind;
			public AgentScriptId script_id;
			public string text;
			public Bytes? data;
			public uint delivery_attempts;

			public PendingMessage (int serial, AgentMessageKind kind, AgentScriptId script_id, string text,
					Bytes? data = null) {
				this.serial = serial;
				this.kind = kind;
				this.script_id = script_id;
				this.text = text;
				this.data = data;
			}

			public size_t estimate_size_in_bytes () {
				return sizeof (AgentMessage) + text.length + 1 + ((data != null) ? data.length : 0);
			}
		}
	}

	[DBus (name = "re.frida.TransportBroker16")]
	public interface TransportBroker : Object {
		public abstract async void open_tcp_transport (AgentSessionId id, Cancellable? cancellable, out uint16 port,
			out string token) throws GLib.Error;
	}

	[DBus (name = "re.frida.PortalSession16")]
	public interface PortalSession : Object {
		public abstract async void join (HostApplicationInfo app, SpawnStartState current_state,
			AgentSessionId[] interrupted_sessions, HashTable<string, Variant> options, Cancellable? cancellable,
			out SpawnStartState next_state) throws GLib.Error;
		public signal void resume ();
		public signal void kill ();
	}

	[DBus (name = "re.frida.BusSession16")]
	public interface BusSession : Object {
		public abstract async void attach (Cancellable? cancellable) throws GLib.Error;
		public abstract async void post (string json, bool has_data, uint8[] data, Cancellable? cancellable) throws GLib.Error;
		public signal void message (string json, bool has_data, uint8[] data);
	}

	[DBus (name = "re.frida.AuthenticationService16")]
	public interface AuthenticationService : Object {
		public abstract async string authenticate (string token, Cancellable? cancellable) throws GLib.Error;
	}

	public class StaticAuthenticationService : Object, AuthenticationService {
		public string token_hash {
			get;
			construct;
		}

		public StaticAuthenticationService (string token) {
			Object (token_hash: Checksum.compute_for_string (SHA256, token));
		}

		public async string authenticate (string token, Cancellable? cancellable) throws Error, IOError {
			string input_hash = Checksum.compute_for_string (SHA256, token);

			uint accumulator = 0;
			for (uint i = 0; i != input_hash.length; i++) {
				accumulator |= input_hash[i] ^ token_hash[i];
			}

			if (accumulator != 0)
				throw new Error.INVALID_ARGUMENT ("Incorrect token");

			return "{}";
		}
	}

	public class NullAuthenticationService : Object, AuthenticationService {
		public async string authenticate (string token, Cancellable? cancellable) throws Error, IOError {
			throw new Error.INVALID_OPERATION ("Authentication not expected");
		}
	}

	public class UnauthorizedHostSession : Object, HostSession {
		public async void ping (uint interval_seconds, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostApplicationInfo get_frontmost_application (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostApplicationInfo[] enumerate_applications (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostProcessInfo[] enumerate_processes (HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void enable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void disable_spawn_gating (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void input (uint pid, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void resume (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void kill (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async AgentSessionId attach (uint pid, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void reattach (AgentSessionId id, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async InjectorPayloadId inject_library_file (uint pid, string path, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async InjectorPayloadId inject_library_blob (uint pid, uint8[] blob, string entrypoint, string data,
				Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}
	}

	public class UnauthorizedPortalSession : Object, PortalSession {
		public async void join (HostApplicationInfo app, SpawnStartState current_state,
				AgentSessionId[] interrupted_sessions, HashTable<string, Variant> options,
				Cancellable? cancellable, out SpawnStartState next_state) throws Error, IOError {
			throw_not_authorized ();
		}
	}

	public class UnauthorizedBusSession : Object, BusSession {
		public async void attach (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async void post (string json, bool has_data, uint8[] data, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}
	}

	[NoReturn]
	private void throw_not_authorized () throws Error {
		throw new Error.PERMISSION_DENIED ("Not authorized, authentication required");
	}

	public enum Realm {
		NATIVE,
		EMULATED;

		public static Realm from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<Realm> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Realm> (this);
		}
	}

	public enum SpawnStartState {
		RUNNING,
		SUSPENDED;

		public static SpawnStartState from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<SpawnStartState> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<SpawnStartState> (this);
		}
	}

	public enum UnloadPolicy {
		IMMEDIATE,
		RESIDENT,
		DEFERRED;

		public static UnloadPolicy from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<UnloadPolicy> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<UnloadPolicy> (this);
		}
	}

	public struct InjectorPayloadId {
		public uint handle;

		public InjectorPayloadId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (InjectorPayloadId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (InjectorPayloadId? a, InjectorPayloadId? b) {
			return a.handle == b.handle;
		}
	}

	public struct MappedLibraryBlob {
		public uint64 address;
		public uint size;
		public uint allocated_size;

		public MappedLibraryBlob (uint64 address, uint size, uint allocated_size) {
			this.address = address;
			this.size = size;
			this.allocated_size = allocated_size;
		}
	}

#if DARWIN
	public struct DarwinInjectorState {
		public Gum.MemoryRange? mapped_range;
	}
#endif

#if LINUX
	public struct LinuxInjectorState {
		public int frida_ctrlfd;
		public int agent_ctrlfd;
	}
#endif

#if LINUX || FREEBSD
	public struct PosixInjectorState {
		public int fifo_fd;
	}
#endif

	public enum SessionDetachReason {
		APPLICATION_REQUESTED = 1,
		PROCESS_REPLACED,
		PROCESS_TERMINATED,
		CONNECTION_TERMINATED,
		DEVICE_LOST;

		public static SessionDetachReason from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<SessionDetachReason> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<SessionDetachReason> (this);
		}
	}

	[DBus (name = "re.frida.Error")]
	public errordomain Error {
		SERVER_NOT_RUNNING,
		EXECUTABLE_NOT_FOUND,
		EXECUTABLE_NOT_SUPPORTED,
		PROCESS_NOT_FOUND,
		PROCESS_NOT_RESPONDING,
		INVALID_ARGUMENT,
		INVALID_OPERATION,
		PERMISSION_DENIED,
		ADDRESS_IN_USE,
		TIMED_OUT,
		NOT_SUPPORTED,
		PROTOCOL,
		TRANSPORT
	}

	[NoReturn]
	public static void throw_api_error (GLib.Error e) throws Frida.Error, IOError {
		if (e is Frida.Error)
			throw (Frida.Error) e;

		if (e is IOError.CANCELLED)
			throw (IOError) e;

		assert_not_reached ();
	}

	[NoReturn]
	public static void throw_dbus_error (GLib.Error e) throws Frida.Error, IOError {
		DBusError.strip_remote_error (e);

		if (e is Frida.Error)
			throw (Frida.Error) e;

		if (e is IOError.CANCELLED)
			throw (IOError) e;

		if (e is DBusError.UNKNOWN_METHOD) {
			throw new Frida.Error.PROTOCOL ("Unable to communicate with remote frida-server; " +
				"please ensure that major versions match and that the remote Frida has the " +
				"feature you are trying to use");
		}

		throw new Frida.Error.TRANSPORT ("%s", e.message);
	}

	public struct HostApplicationInfo {
		public string identifier;
		public string name;
		public uint pid;
		public HashTable<string, Variant> parameters;

		public HostApplicationInfo (string identifier, string name, uint pid, owned HashTable<string, Variant> parameters) {
			this.identifier = identifier;
			this.name = name;
			this.pid = pid;
			this.parameters = parameters;
		}

		public HostApplicationInfo.empty () {
			this.identifier = "";
			this.name = "";
			this.pid = 0;
			this.parameters = make_parameters_dict ();
		}
	}

	public struct HostProcessInfo {
		public uint pid;
		public string name;
		public HashTable<string, Variant> parameters;

		public HostProcessInfo (uint pid, string name, owned HashTable<string, Variant> parameters) {
			this.pid = pid;
			this.name = name;
			this.parameters = parameters;
		}
	}

	public class FrontmostQueryOptions : Object {
		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (scope != MINIMAL)
				dict["scope"] = new Variant.string (scope.to_nick ());

			return dict;
		}

		public static FrontmostQueryOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new FrontmostQueryOptions ();

			Variant? scope = dict["scope"];
			if (scope != null) {
				if (!scope.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'scope' option must be a string");
				options.scope = Scope.from_nick (scope.get_string ());
			}

			return options;
		}
	}

	public class ApplicationQueryOptions : Object {
		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}

		private Gee.List<string> identifiers = new Gee.ArrayList<string> ();

		public void select_identifier (string identifier) {
			identifiers.add (identifier);
		}

		public bool has_selected_identifiers () {
			return !identifiers.is_empty;
		}

		public void enumerate_selected_identifiers (Func<string> func) {
			foreach (var identifier in identifiers)
				func (identifier);
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (!identifiers.is_empty)
				dict["identifiers"] = identifiers.to_array ();

			if (scope != MINIMAL)
				dict["scope"] = new Variant.string (scope.to_nick ());

			return dict;
		}

		public static ApplicationQueryOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new ApplicationQueryOptions ();

			Variant? identifiers = dict["identifiers"];
			if (identifiers != null) {
				if (!identifiers.is_of_type (VariantType.STRING_ARRAY))
					throw new Error.INVALID_ARGUMENT ("The 'identifiers' option must be a string array");
				var iter = identifiers.iterator ();
				Variant? val;
				while ((val = iter.next_value ()) != null)
					options.select_identifier (val.get_string ());
			}

			Variant? scope = dict["scope"];
			if (scope != null) {
				if (!scope.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'scope' option must be a string");
				options.scope = Scope.from_nick (scope.get_string ());
			}

			return options;
		}
	}

	public class ProcessQueryOptions : Object {
		public Scope scope {
			get;
			set;
			default = MINIMAL;
		}

		private Gee.List<uint> pids = new Gee.ArrayList<uint> ();

		public void select_pid (uint pid) {
			pids.add (pid);
		}

		public bool has_selected_pids () {
			return !pids.is_empty;
		}

		public void enumerate_selected_pids (Func<uint> func) {
			foreach (var pid in pids)
				func (pid);
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (!pids.is_empty)
				dict["pids"] = pids.to_array ();

			if (scope != MINIMAL)
				dict["scope"] = new Variant.string (scope.to_nick ());

			return dict;
		}

		public static ProcessQueryOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new ProcessQueryOptions ();

			Variant? pids = dict["pids"];
			if (pids != null) {
				if (!pids.is_of_type (new VariantType.array (VariantType.UINT32)))
					throw new Error.INVALID_ARGUMENT ("The 'pids' option must be a uint32 array");
				var iter = pids.iterator ();
				Variant? val;
				while ((val = iter.next_value ()) != null)
					options.select_pid (val.get_uint32 ());
			}

			Variant? scope = dict["scope"];
			if (scope != null) {
				if (!scope.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'scope' option must be a string");
				options.scope = Scope.from_nick (scope.get_string ());
			}

			return options;
		}
	}

	public enum Scope {
		MINIMAL,
		METADATA,
		FULL;

		public static Scope from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<Scope> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Scope> (this);
		}
	}

	public struct HostSpawnOptions {
		public bool has_argv;
		public string[] argv;

		public bool has_envp;
		public string[] envp;

		public bool has_env;
		public string[] env;

		public string cwd;

		public Stdio stdio;

		public HashTable<string, Variant> aux;

		public HostSpawnOptions () {
			this.argv = {};
			this.envp = {};
			this.env = {};
			this.cwd = "";
			this.stdio = INHERIT;
			this.aux = make_parameters_dict ();
		}

		public string[] compute_argv (string path) {
			return has_argv ? argv : new string[] { path };
		}

		public string[] compute_envp () {
			var base_env = has_envp ? envp : Environ.get ();
			if (!has_env)
				return base_env;

			var names = new Gee.ArrayList<string> ();
			var values = new Gee.HashMap<string, string> ();
			parse_envp (base_env, names, values);

			var overridden_names = new Gee.ArrayList<string> ();
			var overridden_values = new Gee.HashMap<string, string> ();
			parse_envp (env, overridden_names, overridden_values);

			foreach (var name in overridden_names) {
				if (!values.has_key (name))
					names.add (name);
				values[name] = overridden_values[name];
			}

			var result = new string[names.size];
			var i = 0;
			foreach (var name in names) {
				result[i] = name.concat ("=", values[name]);
				i++;
			}
			return result;
		}

		private static void parse_envp (string[] envp, Gee.ArrayList<string> names, Gee.HashMap<string, string> values) {
			foreach (var pair in envp) {
				var tokens = pair.split ("=", 2);
				if (tokens.length == 1)
					continue;
				var name = tokens[0];
				var val = tokens[1];
				names.add (name);
				values[name] = val;
			}
		}
	}

	public class SessionOptions : Object {
		public Realm realm {
			get;
			set;
			default = NATIVE;
		}

		public uint persist_timeout {
			get;
			set;
			default = 0;
		}

		public string? emulated_agent_path {
			get;
			set;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (realm != NATIVE)
				dict["realm"] = new Variant.string (realm.to_nick ());

			if (persist_timeout != 0)
				dict["persist-timeout"] = new Variant.uint32 (persist_timeout);

			if (emulated_agent_path != null)
				dict["emulated-agent-path"] = new Variant.string (emulated_agent_path);

			return dict;
		}

		public static SessionOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new SessionOptions ();

			Variant? realm = dict["realm"];
			if (realm != null) {
				if (!realm.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'realm' option must be a string");
				options.realm = Realm.from_nick (realm.get_string ());
			}

			Variant? persist_timeout = dict["persist-timeout"];
			if (persist_timeout != null) {
				if (!persist_timeout.is_of_type (VariantType.UINT32))
					throw new Error.INVALID_ARGUMENT ("The 'persist-timeout' option must be a uint32");
				options.persist_timeout = persist_timeout.get_uint32 ();
			}

			Variant? path = dict["emulated-agent-path"];
			if (path != null) {
				if (!path.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'emulated-agent-path' option must be a string");
				options.emulated_agent_path = path.get_string ();
			}

			return options;
		}
	}

	public enum Stdio {
		INHERIT,
		PIPE;

		public static Stdio from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<Stdio> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<Stdio> (this);
		}
	}

	public struct HostSpawnInfo {
		public uint pid;
		public string identifier;

		public HostSpawnInfo (uint pid, string identifier) {
			this.pid = pid;
			this.identifier = identifier;
		}
	}

	public struct HostChildId {
		public uint handle;

		public HostChildId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (HostChildId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (HostChildId? a, HostChildId? b) {
			return a.handle == b.handle;
		}
	}

	public struct HostChildInfo {
		public uint pid;
		public uint parent_pid;

		public ChildOrigin origin;

		public string identifier;
		public string path;

		public bool has_argv;
		public string[] argv;

		public bool has_envp;
		public string[] envp;

		public HostChildInfo (uint pid, uint parent_pid, ChildOrigin origin) {
			this.pid = pid;
			this.parent_pid = parent_pid;
			this.origin = origin;
			this.identifier = "";
			this.path = "";
			this.argv = {};
			this.envp = {};
		}
	}

	public enum ChildOrigin {
		FORK,
		EXEC,
		SPAWN;

		public static ChildOrigin from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<ChildOrigin> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<ChildOrigin> (this);
		}
	}

	public struct CrashInfo {
		public uint pid;
		public string process_name;

		public string summary;
		public string report;

		public HashTable<string, Variant> parameters;

		public CrashInfo (uint pid, string process_name, string summary, string report,
				HashTable<string, Variant>? parameters = null) {
			this.pid = pid;
			this.process_name = process_name;

			this.summary = summary;
			this.report = report;

			this.parameters = (parameters != null) ? parameters : make_parameters_dict ();
		}

		public CrashInfo.empty () {
			this.pid = 0;
			this.process_name = "";
			this.summary = "";
			this.report = "";
			this.parameters = make_parameters_dict ();
		}
	}

	public struct AgentSessionId {
		public string handle;

		public AgentSessionId (string handle) {
			this.handle = handle;
		}

		public AgentSessionId.generate () {
			this.handle = Uuid.string_random ().replace ("-", "");
		}

		public static uint hash (AgentSessionId? id) {
			return id.handle.hash ();
		}

		public static bool equal (AgentSessionId? a, AgentSessionId? b) {
			return a.handle == b.handle;
		}
	}

	public struct AgentScriptId {
		public uint handle;

		public AgentScriptId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (AgentScriptId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (AgentScriptId? a, AgentScriptId? b) {
			return a.handle == b.handle;
		}
	}

	public class ScriptOptions : Object {
		public string? name {
			get;
			set;
		}

		public Bytes? snapshot {
			get;
			set;
		}

		public SnapshotTransport snapshot_transport {
			get;
			set;
			default = INLINE;
		}

		public ScriptRuntime runtime {
			get;
			set;
			default = DEFAULT;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (name != null)
				dict["name"] = new Variant.string (name);

			if (snapshot != null) {
				if (snapshot_transport == SHARED_MEMORY) {
					unowned uint8[]? data = snapshot.get_data ();
					dict["snapshot-memory-range"] = new Variant ("(tu)", (uint64) data, (uint) data.length);
				} else {
					dict["snapshot"] = Variant.new_from_data (new VariantType ("ay"), snapshot.get_data (), true, snapshot);
				}
			}

			if (runtime != DEFAULT)
				dict["runtime"] = new Variant.string (runtime.to_nick ());

			return dict;
		}

		public static ScriptOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new ScriptOptions ();

			Variant? name = dict["name"];
			if (name != null) {
				if (!name.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'name' option must be a string");
				options.name = name.get_string ();
			}

			Variant? snapshot = dict["snapshot"];
			if (snapshot != null) {
				if (!snapshot.is_of_type (new VariantType ("ay")))
					throw new Error.INVALID_ARGUMENT ("The 'snapshot' option must be a byte array");
				options.snapshot = snapshot.get_data_as_bytes ();
			} else {
				Variant? range = dict["snapshot-memory-range"];
				if (range != null) {
					if (!range.is_of_type (new VariantType ("(tu)")))
						throw new Error.INVALID_ARGUMENT ("The 'snapshot-memory-range' option must be a tuple");

					uint64 base_address;
					uint size;
					range.get ("(tu)", out base_address, out size);
					unowned uint8[]? data = ((uint8[]) (void *) base_address)[:size];

					options.snapshot = new Bytes.static (data);
				}
			}

			Variant? runtime = dict["runtime"];
			if (runtime != null) {
				if (!runtime.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'runtime' option must be a string");
				options.runtime = ScriptRuntime.from_nick (runtime.get_string ());
			}

			return options;
		}
	}

	public enum SnapshotTransport {
		INLINE,
		SHARED_MEMORY
	}

	public class SnapshotOptions : Object {
		public string? warmup_script {
			get;
			set;
		}

		public ScriptRuntime runtime {
			get;
			set;
			default = DEFAULT;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (warmup_script != null)
				dict["warmup-script"] = new Variant.string (warmup_script);

			if (runtime != DEFAULT)
				dict["runtime"] = new Variant.string (runtime.to_nick ());

			return dict;
		}

		public static SnapshotOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new SnapshotOptions ();

			Variant? warmup_script = dict["warmup-script"];
			if (warmup_script != null) {
				if (!warmup_script.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'warmup-script' option must be a string");
				options.warmup_script = warmup_script.get_string ();
			}

			Variant? runtime = dict["runtime"];
			if (runtime != null) {
				if (!runtime.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'runtime' option must be a string");
				options.runtime = ScriptRuntime.from_nick (runtime.get_string ());
			}

			return options;
		}
	}

	public enum ScriptRuntime {
		DEFAULT,
		QJS,
		V8;

		public static ScriptRuntime from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<ScriptRuntime> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<ScriptRuntime> (this);
		}
	}

	public struct PortalMembershipId {
		public uint handle;

		public PortalMembershipId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (PortalMembershipId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (PortalMembershipId? a, PortalMembershipId? b) {
			return a.handle == b.handle;
		}
	}

	public class PortalOptions : Object {
		public TlsCertificate? certificate {
			get;
			set;
		}

		public string? token {
			get;
			set;
		}

		public string[]? acl {
			get;
			set;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (certificate != null)
				dict["certificate"] = new Variant.string (certificate.certificate_pem);

			if (token != null)
				dict["token"] = new Variant.string (token);

			if (acl != null)
				dict["acl"] = new Variant.strv (acl);

			return dict;
		}

		public static PortalOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new PortalOptions ();

			Variant? cert_pem = dict["certificate"];
			if (cert_pem != null) {
				if (!cert_pem.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'certificate' option must be a string");
				try {
					options.certificate = new TlsCertificate.from_pem (cert_pem.get_string (), -1);
				} catch (GLib.Error e) {
					throw new Error.INVALID_ARGUMENT ("%s", e.message);
				}
			}

			Variant? token = dict["token"];
			if (token != null) {
				if (!token.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'token' option must be a string");
				options.token = token.get_string ();
			}

			Variant? acl = dict["acl"];
			if (acl != null) {
				if (!acl.is_of_type (VariantType.STRING_ARRAY))
					throw new Error.INVALID_ARGUMENT ("The 'acl' option must be a string array");
				options.acl = acl.get_strv ();
			}

			return options;
		}
	}

	public class PeerOptions : Object {
		public string? stun_server {
			get;
			set;
		}

		private Gee.List<Relay> relays = new Gee.ArrayList<Relay> ();

		public void clear_relays () {
			relays.clear ();
		}

		public void add_relay (Relay relay) {
			relays.add (relay);
		}

		public void enumerate_relays (Func<Relay> func) {
			foreach (var relay in relays)
				func (relay);
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_parameters_dict ();

			if (stun_server != null)
				dict["stun-server"] = new Variant.string (stun_server);

			if (!relays.is_empty) {
				var builder = new VariantBuilder (new VariantType.array (Relay.get_variant_type ()));
				foreach (var relay in relays)
					builder.add_value (relay.to_variant ());
				dict["relays"] = builder.end ();
			}

			return dict;
		}

		public static PeerOptions _deserialize (HashTable<string, Variant> dict) throws Error {
			var options = new PeerOptions ();

			Variant? stun_server = dict["stun-server"];
			if (stun_server != null) {
				if (!stun_server.is_of_type (VariantType.STRING))
					throw new Error.INVALID_ARGUMENT ("The 'stun-server' option must be a string");
				options.stun_server = stun_server.get_string ();
			}

			Variant? relays_val = dict["relays"];
			if (relays_val != null) {
				if (!relays_val.is_of_type (new VariantType.array (Relay.get_variant_type ())))
					throw new Error.INVALID_ARGUMENT ("The 'relays' option must be an array of tuples");
				var iter = relays_val.iterator ();
				Variant? val;
				while ((val = iter.next_value ()) != null)
					options.add_relay (Relay.from_variant (val));
			}

			return options;
		}
	}

	public class Relay : Object {
		public string address {
			get;
			construct;
		}

		public string username {
			get;
			construct;
		}

		public string password {
			get;
			construct;
		}

		public RelayKind kind {
			get;
			construct;
		}

		public Relay (string address, string username, string password, RelayKind kind) {
			Object (
				address: address,
				username: username,
				password: password,
				kind: kind
			);
		}

		internal static VariantType get_variant_type () {
			return new VariantType ("(sssu)");
		}

		internal Variant to_variant () {
			return new Variant ("(sssu)", address, username, password, (uint) kind);
		}

		internal static Relay from_variant (Variant val) {
			string address, username, password;
			uint kind;
			val.get ("(sssu)", out address, out username, out password, out kind);

			return new Relay (address, username, password, (RelayKind) kind);
		}
	}

	public enum RelayKind {
		TURN_UDP,
		TURN_TCP,
		TURN_TLS
	}

	public HashTable<string, Variant> make_parameters_dict () {
		return new HashTable<string, Variant> (str_hash, str_equal);
	}

	public HashTable<string, Variant> compute_system_parameters () {
		var parameters = new HashTable<string, Variant> (str_hash, str_equal);

		var os = new HashTable<string, Variant> (str_hash, str_equal);
		string id;
#if WINDOWS
		id = "windows";
#elif MACOS
		id = "macos";
#elif LINUX && !ANDROID
		id = "linux";
#elif IOS
		id = "ios";
#elif WATCHOS
		id = "watchos";
#elif TVOS
		id = "tvos";
#elif ANDROID
		id = "android";
#elif FREEBSD
		id = "freebsd";
#elif QNX
		id = "qnx";
#else
		id = FIXME;
#endif
		os["id"] = id;
#if WINDOWS
		os["name"] = "Windows";
		os["version"] = _query_windows_version ();
#elif DARWIN
		try {
			string plist;
			FileUtils.get_contents ("/System/Library/CoreServices/SystemVersion.plist", out plist);

			MatchInfo info;
			if (/<key>ProductName<\/key>.*?<string>(.+?)<\/string>/s.match (plist, 0, out info)) {
				os["name"] = info.fetch (1);
			}
			if (/<key>ProductVersion<\/key>.*?<string>(.+?)<\/string>/s.match (plist, 0, out info)) {
				os["version"] = info.fetch (1);
			}
		} catch (FileError e) {
		}
#elif LINUX && !ANDROID
		try {
			string details;
			FileUtils.get_contents ("/etc/os-release", out details);

			MatchInfo info;
			if (/^ID=(.+)$/m.match (details, 0, out info)) {
				os["id"] = Shell.unquote (info.fetch (1));
			}
			if (/^NAME=(.+)$/m.match (details, 0, out info)) {
				os["name"] = Shell.unquote (info.fetch (1));
			}
			if (/^VERSION_ID=(.+)$/m.match (details, 0, out info)) {
				os["version"] = Shell.unquote (info.fetch (1));
			}
		} catch (GLib.Error e) {
		}
#elif ANDROID
		os["name"] = "Android";
		os["version"] = _query_android_system_property ("ro.build.version.release");
#elif QNX
		os["name"] = "QNX";
#endif
		parameters["os"] = os;

		string platform;
#if WINDOWS
		platform = "windows";
#elif DARWIN
		platform = "darwin";
#elif LINUX
		platform = "linux";
#elif FREEBSD
		platform = "freebsd";
#elif QNX
		platform = "qnx";
#else
		platform = FIXME;
#endif
		parameters["platform"] = platform;

		string arch;
#if X86
		arch = "ia32";
#elif X86_64
		arch = "x64";
#elif ARM
		arch = "arm";
#elif ARM64
		arch = "arm64";
#elif MIPS
		arch = "mips";
#else
		arch = FIXME;
#endif
		parameters["arch"] = arch;

		parameters["access"] = "full";

#if WINDOWS
		parameters["name"] = _query_windows_computer_name ();
#elif IOS
		import_mg_property (parameters, "name", "UserAssignedDeviceName");
		import_mg_property (parameters, "udid", "UniqueDeviceID");

		add_interfaces (parameters);
#elif ANDROID
		parameters["api-level"] = int64.parse (_query_android_system_property ("ro.build.version.sdk"));
#else
		parameters["name"] = Environment.get_host_name ();
#endif

		return parameters;
	}

#if WINDOWS
	public extern string _query_windows_version ();
	public extern string _query_windows_computer_name ();
#elif IOS
	private void import_mg_property (HashTable<string, Variant> parameters, string key, string query) {
		string? val = try_resolve_mg_property (query);
		if (val != null)
			parameters[key] = val;
	}

	private void add_interfaces (HashTable<string, Variant> parameters) {
		var ifaces = new VariantBuilder (new VariantType.array (VariantType.VARDICT));

		maybe_add_network_interface (ifaces, "ethernet", "EthernetMacAddress");
		maybe_add_network_interface (ifaces, "wifi", "WifiAddress");
		maybe_add_network_interface (ifaces, "bluetooth", "BluetoothAddress");

		string? phone = try_resolve_mg_property ("PhoneNumber");
		if (phone != null) {
			ifaces.open (VariantType.VARDICT);
			ifaces.add ("{sv}", "type", new Variant.string ("cellular"));
			ifaces.add ("{sv}", "phone-number", new Variant.string (phone));
			ifaces.close ();
		}

		parameters["interfaces"] = ifaces.end ();
	}

	private void maybe_add_network_interface (VariantBuilder ifaces, string type, string query) {
		string? address = try_resolve_mg_property (query);
		if (address == null)
			return;
		ifaces.open (VariantType.VARDICT);
		ifaces.add ("{sv}", "type", new Variant.string (type));
		ifaces.add ("{sv}", "address", new Variant.string (address));
		ifaces.close ();
	}

	private string? try_resolve_mg_property (string query) {
		var answer = _query_mobile_gestalt (query);
		if (answer == null || !answer.is_of_type (VariantType.STRING))
			return null;

		string val = answer.get_string ();
		if (val.length == 0)
			return null;

		return val;
	}

	public extern Variant? _query_mobile_gestalt (string query);
#elif ANDROID
	public extern string _query_android_system_property (string name);
#endif

	namespace ServerGuid {
		public const string HOST_SESSION_SERVICE = "6769746875622e636f6d2f6672696461";
	}

	namespace ObjectPath {
		public const string HOST_SESSION = "/re/frida/HostSession";
		public const string AGENT_SESSION_PROVIDER = "/re/frida/AgentSessionProvider";
		public const string AGENT_SESSION = "/re/frida/AgentSession";
		public const string AGENT_CONTROLLER = "/re/frida/AgentController";
		public const string AGENT_MESSAGE_SINK = "/re/frida/AgentMessageSink";
		public const string CHILD_SESSION = "/re/frida/ChildSession";
		public const string TRANSPORT_BROKER = "/re/frida/TransportBroker";
		public const string PORTAL_SESSION = "/re/frida/PortalSession";
		public const string BUS_SESSION = "/re/frida/BusSession";
		public const string AUTHENTICATION_SERVICE = "/re/frida/AuthenticationService";

		public static string for_agent_session (AgentSessionId id) {
			return AGENT_SESSION + "/" + id.handle;
		}

		public static string for_agent_message_sink (AgentSessionId id) {
			return AGENT_MESSAGE_SINK + "/" + id.handle;
		}
	}

	namespace Marshal {
		public static T enum_from_nick<T> (string nick) throws Error {
			var klass = (EnumClass) typeof (T).class_ref ();
			var v = klass.get_value_by_nick (nick);
			if (v == null)
				throw new Error.INVALID_ARGUMENT ("Invalid %s", klass.get_type ().name ());
			return (T) v.value;
		}

		public static string enum_to_nick<T> (int val) {
			var klass = (EnumClass) typeof (T).class_ref ();
			return klass.get_value (val).value_nick;
		}
	}

	namespace Numeric {
		public uint int64_hash (int64? val) {
			uint64 v = (uint64) val.abs ();
			return (uint) ((v >> 32) ^ (v & 0xffffffffU));
		}

		public bool int64_equal (int64? val_a, int64? val_b) {
			int64 a = val_a;
			int64 b = val_b;
			return a == b;
		}

		public uint uint64_hash (uint64? val) {
			uint64 v = val;
			return (uint) ((v >> 32) ^ (v & 0xffffffffU));
		}

		public bool uint64_equal (uint64? val_a, uint64? val_b) {
			uint64 a = val_a;
			uint64 b = val_b;
			return a == b;
		}
	}
}
