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

		private Promise<bool>? delivery_request;
		private Cancellable delivery_cancellable = new Cancellable ();
		private Gee.Queue<AgentScriptMessage?> pending_script_messages = new Gee.ArrayQueue<AgentScriptMessage?> ();
		private Gee.Queue<AgentDebuggerMessage?> pending_debugger_messages = new Gee.ArrayQueue<AgentDebuggerMessage?> ();
		private uint next_serial = 1;

		private bool child_gating_enabled = false;

		private ScriptEngine script_engine;

#if HAVE_NICE
		private Nice.Agent? nice_agent;
		private uint nice_stream_id;
		private uint nice_component_id;
		private IOStream? nice_stream;
		private DBusConnection? nice_connection;
		private uint nice_registration_id;
		private AgentMessageSink nice_message_sink;
#endif
		private Cancellable? nice_cancellable;

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

			if (nice_cancellable != null)
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

			yield teardown_peer_connection_and_emit_closed ();

			close_request.resolve (true);
		}

		public async void interrupt (Cancellable? cancellable) throws Error, IOError {
			if (persist_timeout == 0 || expiry_timer != null)
				throw new Error.INVALID_OPERATION ("Invalid operation");

			state = INTERRUPTED;
			delivery_cancellable.cancel ();

			expiry_timer = new TimeoutSource (persist_timeout * 1000);
			expiry_timer.set_callback (() => {
				close.begin (null);
				return false;
			});
			expiry_timer.attach (frida_context);
		}

		public async void resume (Cancellable? cancellable) throws Error, IOError {
			if (persist_timeout == 0 || expiry_timer == null)
				throw new Error.INVALID_OPERATION ("Invalid operation");

			expiry_timer.destroy ();
			expiry_timer = null;

			delivery_cancellable = new Cancellable ();
			state = LIVE;

			maybe_deliver_pending_messages ();
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

		public async AgentScriptId create_script (string source, AgentScriptOptions options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var instance = yield script_engine.create_script (source, null, ScriptOptions._deserialize (options.data));
			return instance.script_id;
		}

		public async AgentScriptId create_script_from_bytes (uint8[] bytes, AgentScriptOptions options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var instance = yield script_engine.create_script (null, new Bytes (bytes),
				ScriptOptions._deserialize (options.data));
			return instance.script_id;
		}

		public async uint8[] compile_script (string source, AgentScriptOptions options,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			var bytes = yield script_engine.compile_script (source, ScriptOptions._deserialize (options.data));
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

		public async void post_to_script (AgentScriptId script_id, string message, bool has_data, uint8[] data,
				Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.post_to_script (script_id, message, has_data ? new Bytes (data) : null);
		}

		public async void enable_debugger (Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.enable_debugger ();
		}

		public async void disable_debugger (Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.disable_debugger ();
		}

		public async void post_message_to_debugger (string message, Cancellable? cancellable) throws Error, IOError {
			check_open ();

			script_engine.post_message_to_debugger (message);
		}

		public async PortalMembershipId join_portal (string address, AgentPortalOptions options,
				Cancellable? cancellable) throws Error, IOError {
			return yield invader.join_portal (parse_cluster_address (address), PortalOptions._deserialize (options.data),
				cancellable);
		}

		public async void leave_portal (PortalMembershipId membership_id, Cancellable? cancellable) throws Error, IOError {
			yield invader.leave_portal (membership_id, cancellable);
		}

#if HAVE_NICE
		public async void offer_peer_connection (string offer_sdp, AgentPeerOptions peer_options, string cert_pem,
				Cancellable? cancellable, out string answer_sdp) throws Error, IOError {
			var agent = new Nice.Agent.full (dbus_context, Nice.Compatibility.RFC5245, RELIABLE | ICE_TRICKLE);
			agent.controlling_mode = false;

			uint stream_id = agent.add_stream (1);
			if (stream_id == 0)
				throw new Error.NOT_SUPPORTED ("Unable to add stream");
			uint component_id = 1;
			agent.set_stream_name (stream_id, "application");

			var peer_opts = PeerOptions._deserialize (peer_options.data);

			string? stun_server = peer_opts.stun_server;
			if (stun_server != null) {
				InetSocketAddress? addr;
				try {
					var enumerator = NetworkAddress.parse (stun_server, 3478).enumerate ();
					addr = (InetSocketAddress) yield enumerator.next_async (cancellable);
				} catch (GLib.Error e) {
					throw new Error.INVALID_ARGUMENT ("Invalid STUN server address: %s", e.message);
				}
				if (addr == null)
					throw new Error.INVALID_ARGUMENT ("Invalid STUN server address");
				agent.stun_server = addr.get_address ().to_string ();
				agent.stun_server_port = addr.get_port ();
			}

			var relays = new Gee.ArrayList<Relay> ();
			peer_opts.enumerate_relays (relay => {
				relays.add (relay);
			});
			foreach (var relay in relays) {
				InetSocketAddress? addr;
				try {
					var enumerator = NetworkAddress.parse (relay.address, 3478).enumerate ();
					addr = (InetSocketAddress) yield enumerator.next_async (cancellable);
				} catch (GLib.Error e) {
					throw new Error.INVALID_ARGUMENT ("Invalid relay server address: %s", e.message);
				}
				if (addr == null)
					throw new Error.INVALID_ARGUMENT ("Invalid relay server address");
				agent.set_relay_info (stream_id, component_id, addr.get_address ().to_string (),
					addr.get_port (), relay.username, relay.password, relay_kind_to_libnice (relay.kind));
			}

			if (agent.parse_remote_sdp (offer_sdp) < 0)
				throw new Error.INVALID_ARGUMENT ("Invalid SDP");

			answer_sdp = agent.generate_local_sdp ();

			TlsCertificate certificate;
			try {
				certificate = new TlsCertificate.from_pem (cert_pem, -1);
			} catch (GLib.Error e) {
				throw new Error.INVALID_ARGUMENT ("%s", e.message);
			}

			if (nice_agent != null)
				throw new Error.INVALID_OPERATION ("Peer connection already exists");

			nice_agent = agent;
			nice_cancellable = new Cancellable ();
			nice_stream_id = stream_id;
			nice_component_id = component_id;

			schedule_on_dbus_thread (() => {
				open_peer_connection.begin (certificate, cancellable);
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
			yield close_nice_resources ();

			closed ();
		}

		private async void close_nice_resources () {
			if (nice_registration_id != 0) {
				nice_connection.unregister_object (nice_registration_id);
				nice_registration_id = 0;
			}

			DBusConnection? conn = nice_connection;
			if (conn != null) {
				conn.on_closed.disconnect (on_nice_connection_closed);
				nice_connection = null;
				try {
					yield conn.flush ();
				} catch (GLib.Error e) {
				}
				try {
					yield conn.close ();
				} catch (GLib.Error e) {
				}
			}

			nice_message_sink = null;

			schedule_on_dbus_thread (() => {
				nice_stream = null;

				if (nice_agent != null)
					nice_agent.close_async.begin ();

				schedule_on_frida_thread (() => {
					close_nice_resources.callback ();
					return false;
				});

				return false;
			});
			yield;

			nice_component_id = 0;
			nice_stream_id = 0;
			nice_cancellable = null;
			nice_agent = null;
		}

		private async void open_peer_connection (TlsCertificate certificate, Cancellable? cancellable) {
			Nice.Agent agent = nice_agent;
			TlsClientConnection? tc = null;
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

				nice_stream = agent.get_io_stream (nice_stream_id, nice_component_id);

				uint8 hello[1];
				yield nice_stream.input_stream.read_async (hello, Priority.DEFAULT, nice_cancellable);

				tc = TlsClientConnection.new (nice_stream, null);
				tc.set_database (null);
				accept_handler = tc.accept_certificate.connect ((peer_cert, errors) => {
					return peer_cert.verify (null, certificate) == 0;
				});
				yield tc.handshake_async (Priority.DEFAULT, nice_cancellable);
				nice_stream = tc;

				schedule_on_frida_thread (() => {
					complete_peer_connection.begin ();
					return false;
				});
			} catch (GLib.Error e) {
				schedule_on_frida_thread (() => {
					close_nice_resources.begin ();
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
				nice_connection = yield new DBusConnection (nice_stream, ServerGuid.AGENT_SESSION, DELAY_MESSAGE_PROCESSING,
					null, nice_cancellable);
				nice_connection.on_closed.connect (on_nice_connection_closed);

				try {
					nice_registration_id = nice_connection.register_object (ObjectPath.AGENT_SESSION,
						(AgentSession) this);
				} catch (IOError io_error) {
					assert_not_reached ();
				}

				nice_connection.start_message_processing ();

				nice_message_sink = yield nice_connection.get_proxy (null, ObjectPath.AGENT_MESSAGE_SINK,
					DBusProxyFlags.NONE, null);
			} catch (GLib.Error e) {
				close_nice_resources.begin ();
			}
		}

		private void on_component_state_changed (uint stream_id, uint component_id, Nice.ComponentState state) {
			switch (state) {
				case CONNECTED:
					write_hello.begin ();
					break;
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

		private async void write_hello () {
			try {
				uint8 hello[1] = { 42 };
				yield nice_stream.output_stream.write_async (hello, Priority.DEFAULT, nice_cancellable);
			} catch (GLib.Error e) {
				nice_cancellable.cancel ();
			}
		}

		private void on_nice_connection_closed (DBusConnection connection, bool remote_peer_vanished, GLib.Error? error) {
			close.begin (null);
		}

		private void schedule_on_frida_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (frida_context);
		}

		private void schedule_on_dbus_thread (owned SourceFunc function) {
			var source = new IdleSource ();
			source.set_callback ((owned) function);
			source.attach (dbus_context);
		}

		private static Nice.RelayType relay_kind_to_libnice (RelayKind kind) {
			switch (kind) {
				case TURN_UDP: return Nice.RelayType.TURN_UDP;
				case TURN_TCP: return Nice.RelayType.TURN_TCP;
				case TURN_TLS: return Nice.RelayType.TURN_TLS;
			}
			assert_not_reached ();
		}
#else
		public async void offer_peer_connection (string offer_sdp, AgentPeerOptions peer_options, string cert_pem,
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
			migrated ();

			state = LIVE;

			yield process_pending_message_deliveries (cancellable);
		}

		private void check_open () throws Error {
			if (close_request != null)
				throw new Error.INVALID_OPERATION ("Session is closing");
		}

		private void on_message_from_script (AgentScriptId script_id, string message, Bytes? data) {
			bool has_data = data != null;
			var data_param = has_data ? data.get_data () : new uint8[0];
			pending_script_messages.offer (AgentScriptMessage (next_serial++, script_id, message, has_data, data_param));
			maybe_deliver_pending_messages ();
		}

		private void on_message_from_debugger (string message) {
			pending_debugger_messages.offer (AgentDebuggerMessage (next_serial++, message));
			maybe_deliver_pending_messages ();
		}

		private void maybe_deliver_pending_messages () {
			if (state != LIVE)
				return;
			if (delivery_request != null)
				return;
			if (pending_script_messages.is_empty && pending_debugger_messages.is_empty)
				return;
			process_pending_message_deliveries.begin (delivery_cancellable);
		}

		private async void process_pending_message_deliveries (Cancellable? cancellable) throws IOError {
			while (delivery_request != null) {
				try {
					yield delivery_request.future.wait_async (cancellable);
					return;
				} catch (GLib.Error e) {
					assert (e is IOError.CANCELLED);
					cancellable.set_error_if_cancelled ();
				}
			}
			delivery_request = new Promise<bool> ();

			try {
				AgentScriptMessage? script_msg = null;
				AgentDebuggerMessage? debugger_msg = null;

				do {
					AgentMessageSink? sink = message_sink;
					if (sink == null)
						break;

					// TODO: Batch and deliver in parallel.

					script_msg = pending_script_messages.peek ();
					if (script_msg != null) {
						yield sink.post_script_messages ({ script_msg }, delivery_cancellable);
						pending_script_messages.poll ();
					}

					debugger_msg = pending_debugger_messages.peek ();
					if (debugger_msg != null) {
						yield sink.post_debugger_messages ({ debugger_msg }, delivery_cancellable);
						pending_debugger_messages.poll ();
					}
				} while (state == LIVE && (script_msg != null || debugger_msg != null));
			} catch (GLib.Error e) {
			} finally {
				delivery_request.resolve (true);
				delivery_request = null;
			}
		}
	}
}
