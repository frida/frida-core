namespace Frida {
	public abstract class BaseAgentSession : Object, AgentSession {
		public signal void closed ();
		public signal void script_eternalized (Gum.Script script);

		public weak ProcessInvader invader {
			get;
			construct;
		}

		public AgentSessionId id {
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
		private Promise<bool> flush_complete = new Promise<bool> ();

		private State state = LIVE;

		private TimeoutSource? expiry_timer;

		private uint last_rx_batch_id = 0;
		private Gee.LinkedList<PendingMessage> pending_messages = new Gee.LinkedList<PendingMessage> ();
		private int next_serial = 1;
		private uint pending_deliveries = 0;
		private Cancellable delivery_cancellable = new Cancellable ();

		private bool child_gating_enabled = false;

		private ScriptEngine script_engine;

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

		construct {
			assert (invader != null);
			assert (frida_context != null);
			assert (dbus_context != null);

			script_engine = new ScriptEngine (invader);
			script_engine.message_from_script.connect (on_message_from_script);
			script_engine.message_from_debugger.connect (on_message_from_debugger);
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

			try {
				yield disable_child_gating (cancellable);
			} catch (GLib.Error e) {
				assert (e is IOError.CANCELLED);
				close_request.reject (e);
				throw (IOError) e;
			}

			yield script_engine.flush ();
			flush_complete.resolve (true);

			yield script_engine.close ();
			script_engine.message_from_script.disconnect (on_message_from_script);
			script_engine.message_from_debugger.disconnect (on_message_from_debugger);

			delivery_cancellable.cancel ();

			yield teardown_peer_connection_and_emit_closed ();

			message_sink = null;

			close_request.resolve (true);
		}

		public async void interrupt (Cancellable? cancellable) throws Error, IOError {
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

		public async void resume (uint rx_batch_id, Cancellable? cancellable, out uint tx_batch_id) throws Error, IOError {
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

		public async void flush () {
			if (close_request == null)
				close.begin (null);

			try {
				yield flush_complete.future.wait_async (null);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
		}

		public async void prepare_for_termination (TerminationReason reason) {
			yield script_engine.prepare_for_termination (reason);
		}

		public void unprepare_for_termination () {
			script_engine.unprepare_for_termination ();
		}

		public async void enable_child_gating (Cancellable? cancellable) throws Error, IOError {
			check_open ();

			if (child_gating_enabled)
				return;

			invader.acquire_child_gating ();

			child_gating_enabled = true;
		}

		public async void disable_child_gating (Cancellable? cancellable) throws Error, IOError {
			if (!child_gating_enabled)
				return;

			invader.release_child_gating ();

			child_gating_enabled = false;
		}

		public async AgentScriptId create_script (string source, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var instance = yield script_engine.create_script (source, null, ScriptOptions._deserialize (options));
			return instance.script_id;
		}

		public async AgentScriptId create_script_from_bytes (uint8[] bytes, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var instance = yield script_engine.create_script (null, new Bytes (bytes), ScriptOptions._deserialize (options));
			return instance.script_id;
		}

		public async uint8[] compile_script (string source, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var bytes = yield script_engine.compile_script (source, ScriptOptions._deserialize (options));
			return bytes.get_data ();
		}

		public async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			yield script_engine.destroy_script (script_id);
		}

		public async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			yield script_engine.load_script (script_id);
		}

		public async void eternalize_script (AgentScriptId script_id, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var script = script_engine.eternalize_script (script_id);
			script_eternalized (script);
		}

		public async void enable_debugger (Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.enable_debugger ();
		}

		public async void disable_debugger (Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.disable_debugger ();
		}

		public async void post_messages (AgentMessage[] messages, uint batch_id,
				Cancellable? cancellable) throws Error, IOError {
			if (state == INTERRUPTED)
				throw new Error.INVALID_OPERATION ("Cannot receive messages while interrupted");

			foreach (var m in messages) {
				switch (m.kind) {
					case SCRIPT:
						script_engine.post_to_script (m.script_id, m.text, m.has_data ? new Bytes (m.data) : null);
						break;
					case DEBUGGER:
						script_engine.post_to_debugger (m.text);
						break;
				}
			}

			last_rx_batch_id = batch_id;
		}

		public async PortalMembershipId join_portal (string address, HashTable<string, Variant> options,
				Cancellable? cancellable) throws Error, IOError {
			return yield invader.join_portal (address, PortalOptions._deserialize (options), cancellable);
		}

		public async void leave_portal (PortalMembershipId membership_id, Cancellable? cancellable) throws Error, IOError {
			yield invader.leave_portal (membership_id, cancellable);
		}

#if HAVE_NICE
		public async void offer_peer_connection (string offer_sdp, HashTable<string, Variant> peer_options,
				Cancellable? cancellable, out string answer_sdp) throws Error, IOError {
			var offer = PeerSessionDescription.parse (offer_sdp);

			var agent = new Nice.Agent.full (dbus_context, Nice.Compatibility.RFC5245, ICE_TRICKLE);
			agent.set_software ("Frida");
			agent.controlling_mode = false;

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
			if (nice_agent != null) {
				schedule_on_frida_thread (() => {
					close_nice_resources_and_emit_closed.begin ();
					return false;
				});
			} else {
				closed ();
			}
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
					nice_registration_id = nice_connection.register_object (ObjectPath.AGENT_SESSION,
						(AgentSession) this);
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

		public async void add_candidates (string[] candidate_sdps, Cancellable? cancellable) throws Error, IOError {
			Nice.Agent? agent = nice_agent;
			if (agent == null)
				throw new Error.INVALID_OPERATION ("No peer connection in progress");

			string[] candidate_sdps_copy = candidate_sdps;
			schedule_on_dbus_thread (() => {
				var candidates = new SList<Nice.Candidate> ();
				foreach (unowned string sdp in candidate_sdps_copy) {
					var candidate = agent.parse_remote_candidate_sdp (nice_stream_id, sdp);
					if (candidate == null)
						return false;
					candidates.append (candidate);
				}

				agent.set_remote_candidates (nice_stream_id, nice_component_id, candidates);

				return false;
			});
		}

		public async void notify_candidate_gathering_done (Cancellable? cancellable) throws Error, IOError {
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

			if (persist_timeout != 0)
				interrupt.begin (null);
			else
				close.begin (null);
		}
#else
		public async void offer_peer_connection (string offer_sdp, HashTable<string, Variant> peer_options,
				Cancellable? cancellable, out string answer_sdp) throws Error, IOError {
			throw new Error.NOT_SUPPORTED ("Peer-to-peer support not available due to build configuration");
		}

		private async void teardown_peer_connection_and_emit_closed () {
			closed ();
		}

		public async void add_candidates (string[] candidate_sdps, Cancellable? cancellable) throws Error, IOError {
		}

		public async void notify_candidate_gathering_done (Cancellable? cancellable) throws Error, IOError {
		}
#endif

		public async void begin_migration (Cancellable? cancellable) throws Error, IOError {
			state = INTERRUPTED;
		}

		public async void commit_migration (Cancellable? cancellable) throws Error, IOError {
			if (expiry_timer != null)
				return;

			state = LIVE;

			maybe_deliver_pending_messages ();
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Session is closing");
		}

		private void on_message_from_script (AgentScriptId script_id, string json, Bytes? data) {
			pending_messages.offer (
				new PendingMessage (next_serial++, AgentMessageKind.SCRIPT, script_id, json, data));
			maybe_deliver_pending_messages ();
		}

		private void on_message_from_debugger (string message) {
			pending_messages.offer (
				new PendingMessage (next_serial++, AgentMessageKind.DEBUGGER, AgentScriptId (0), message));
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
}
