[CCode (gir_namespace = "FridaFruity", gir_version = "1.0")]
namespace Frida.Fruity {
	using OpenSSL;
	using OpenSSL.Envelope;

	public sealed class DiscoveryService : Object, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}

		private XpcConnection connection;

		private Promise<Variant> handshake_promise = new Promise<Variant> ();
		private Variant handshake_body;

		private Cancellable io_cancellable = new Cancellable ();

		public static async DiscoveryService open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var service = new DiscoveryService (stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private DiscoveryService (IOStream stream) {
			Object (stream: stream);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			connection = new XpcConnection (stream);
			connection.close.connect (on_close);
			connection.message.connect (on_message);
			connection.activate ();

			handshake_body = yield handshake_promise.future.wait_async (cancellable);

			return true;
		}

		public void close () {
			io_cancellable.cancel ();
			connection.cancel ();
		}

		public string query_udid () throws Error {
			var reader = new VariantReader (handshake_body);
			reader
				.read_member ("Properties")
				.read_member ("UniqueDeviceID");
			return reader.get_string_value ();
		}

		public ServiceInfo get_service (string identifier) throws Error {
			var reader = new VariantReader (handshake_body);
			reader.read_member ("Services");
			try {
				reader.read_member (identifier);
			} catch (Error e) {
				throw new Error.NOT_SUPPORTED ("Service '%s' not found", identifier);
			}

			var port = (uint16) uint.parse (reader.read_member ("Port").get_string_value ());

			return new ServiceInfo () {
				port = port,
			};
		}

		private void on_close (Error? error) {
			if (!handshake_promise.future.ready) {
				handshake_promise.reject (
					(error != null)
						? error
						: new Error.TRANSPORT ("XpcConnection closed while waiting for Handshake message"));
			}
		}

		private void on_message (XpcMessage msg) {
			if (msg.body == null)
				return;

			var reader = new VariantReader (msg.body);
			try {
				reader.read_member ("MessageType");
				unowned string message_type = reader.get_string_value ();

				if (message_type == "Handshake") {
					handshake_promise.resolve (msg.body);

					connection.post.begin (
						new XpcBodyBuilder ()
							.begin_dictionary ()
								.set_member_name ("MessageType")
								.add_string_value ("Handshake")
								.set_member_name ("MessagingProtocolVersion")
								.add_uint64_value (5)
								.set_member_name ("Services")
								.begin_dictionary ()
								.end_dictionary ()
								.set_member_name ("Properties")
								.begin_dictionary ()
									.set_member_name ("RemoteXPCVersionFlags")
									.add_uint64_value (0x100000000000006)
								.end_dictionary ()
								.set_member_name ("UUID")
								.add_uuid_value (make_random_v4_uuid ())
							.end_dictionary ()
							.build (),
						io_cancellable);
				}
			} catch (Error e) {
			}
		}
	}

	public sealed class ServiceInfo {
		public uint16 port;
	}

	public sealed class PairingService : Object, AsyncInitable {
		public const string DNS_SD_NAME = "_remotepairing._tcp.local";

		public PairingTransport transport {
			get;
			construct;
		}

		public PairingStore store {
			get;
			construct;
		}

		public DeviceOptions device_options {
			get;
			private set;
		}

		public DeviceInfo? device_info {
			get;
			private set;
		}

		public PairingPeer? established_peer {
			get;
			private set;
		}

		private Gee.Map<uint64?, Promise<ObjectReader>> requests =
			new Gee.HashMap<uint64?, Promise<ObjectReader>> (Numeric.uint64_hash, Numeric.uint64_equal);
		private uint64 next_control_sequence_number = 0;
		private uint64 next_encrypted_sequence_number = 0;

		private ChaCha20Poly1305? client_cipher;
		private ChaCha20Poly1305? server_cipher;

		public static async PairingService open (PairingTransport transport, PairingStore store, Cancellable? cancellable = null)
				throws Error, IOError {
			var service = new PairingService (transport, store);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private PairingService (PairingTransport transport, PairingStore store) {
			Object (transport: transport, store: store);
		}

		construct {
			transport.close.connect (on_close);
			transport.message.connect (on_message);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			yield transport.open (cancellable);

			yield attempt_pair_verify (cancellable);

			PairingPeer? peer = yield verify_manual_pairing (cancellable);
			if (peer == null) {
				if (!device_options.allows_pair_setup)
					throw new Error.NOT_SUPPORTED ("Device not paired and pairing not allowed on current transport");
				peer = yield setup_manual_pairing (cancellable);
			}

			if (peer.remote_unlock_host_key == null) {
				bool peer_modified = false;
				try {
					peer.remote_unlock_host_key = yield create_remote_unlock_key (cancellable);
					peer_modified = true;
				} catch (Error e) {
					if (e is Error.INVALID_OPERATION) {
						store.forget_peer (peer);
						throw e;
					}
					if (!(e is Error.NOT_SUPPORTED))
						throw e;
				}
				if (peer_modified) {
					try {
						store.save_peer (peer);
					} catch (Error e) {
					}
				}
			}

			established_peer = peer;

			return true;
		}

		public void close () {
			transport.cancel ();
		}

		public async TunnelConnection open_tunnel (InetAddress device_address, NetworkStack netstack,
				Cancellable? cancellable = null) throws Error, IOError {
			string? protocol = Environment.get_variable ("FRIDA_FRUITY_TUNNEL_PROTOCOL");
			if (protocol == null)
				protocol = "tcp";

			Key local_keypair;
			uint8[] key;
			if (protocol == "quic") {
				local_keypair = make_keypair (RSA);
				key = key_to_der (local_keypair);
			} else {
				local_keypair = make_keypair (ED25519);
				key = get_raw_private_key (local_keypair).get_data ();
			}

			string request = Json.to_string (
				new Json.Builder ()
				.begin_object ()
					.set_member_name ("request")
					.begin_object ()
						.set_member_name ("_0")
						.begin_object ()
							.set_member_name ("createListener")
							.begin_object ()
								.set_member_name ("transportProtocolType")
								.add_string_value (protocol)
								.set_member_name ("key")
								.add_string_value (Base64.encode (key))
							.end_object ()
						.end_object ()
					.end_object ()
				.end_object ()
				.get_root (), false);

			string response = yield request_encrypted (request, cancellable);

			Json.Reader reader;
			try {
				reader = new Json.Reader (Json.from_string (response));
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("Invalid response JSON");
			}

			reader.read_member ("response");
			reader.read_member ("_1");
			reader.read_member ("createListener");

			if (!reader.read_member ("devicePublicKey"))
				throw new Error.NOT_SUPPORTED ("Unsupported tunnel service");
			string? device_pubkey = reader.get_string_value ();
			reader.end_member ();

			reader.read_member ("port");
			uint16 port = (uint16) reader.get_int_value ();
			reader.end_member ();

			GLib.Error? error = reader.get_error ();
			if (error != null)
				throw new Error.PROTOCOL ("Invalid response: %s", error.message);

			Key remote_pubkey = key_from_der (Base64.decode (device_pubkey));

			var tunnel_endpoint = (InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: device_address,
				port: port,
				scope_id: netstack.scope_id
			);

			if (protocol == "quic") {
				return yield QuicTunnelConnection.open (
					tunnel_endpoint,
					netstack,
					new TunnelKey ((owned) local_keypair),
					new TunnelKey ((owned) remote_pubkey),
					cancellable);
			} else {
				return yield TcpTunnelConnection.open (
					tunnel_endpoint,
					netstack,
					new TunnelKey ((owned) local_keypair),
					new TunnelKey ((owned) remote_pubkey),
					cancellable);
			}
		}

		private async void attempt_pair_verify (Cancellable? cancellable) throws Error, IOError {
			Bytes payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("request")
					.begin_dictionary ()
						.set_member_name ("_0")
						.begin_dictionary ()
							.set_member_name ("handshake")
							.begin_dictionary ()
								.set_member_name ("_0")
								.begin_dictionary ()
									.set_member_name ("wireProtocolVersion")
									.add_int64_value (19)
									.set_member_name ("hostOptions")
									.begin_dictionary ()
										.set_member_name ("attemptPairVerify")
										.add_bool_value (true)
									.end_dictionary ()
								.end_dictionary ()
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ();

			ObjectReader response = yield request_plain (payload, cancellable);

			response
				.read_member ("response")
				.read_member ("_1")
				.read_member ("handshake")
				.read_member ("_0");

			response.read_member ("deviceOptions");

			bool allows_pair_setup = response.read_member ("allowsPairSetup").get_bool_value ();
			response.end_member ();

			bool allows_pinless_pairing = response.read_member ("allowsPinlessPairing").get_bool_value ();
			response.end_member ();

			bool allows_promptless_automation_pairing_upgrade =
				response.read_member ("allowsPromptlessAutomationPairingUpgrade").get_bool_value ();
			response.end_member ();

			bool allows_sharing_sensitive_info = response.read_member ("allowsSharingSensitiveInfo").get_bool_value ();
			response.end_member ();

			bool allows_incoming_tunnel_connections =
				response.read_member ("allowsIncomingTunnelConnections").get_bool_value ();
			response.end_member ();

			device_options = new DeviceOptions () {
				allows_pair_setup = allows_pair_setup,
				allows_pinless_pairing = allows_pinless_pairing,
				allows_promptless_automation_pairing_upgrade = allows_promptless_automation_pairing_upgrade,
				allows_sharing_sensitive_info = allows_sharing_sensitive_info,
				allows_incoming_tunnel_connections = allows_incoming_tunnel_connections,
			};

			if (response.has_member ("peerDeviceInfo")) {
				response.read_member ("peerDeviceInfo");

				string name = response.read_member ("name").get_string_value ();
				response.end_member ();

				string model = response.read_member ("model").get_string_value ();
				response.end_member ();

				string udid = response.read_member ("udid").get_string_value ();
				response.end_member ();

				uint64 ecid = response.read_member ("ecid").get_uint64_value ();
				response.end_member ();

				Plist kvs;
				try {
					kvs = new Plist.from_binary (response.read_member ("deviceKVSData").get_data_value ().get_data ());
					response.end_member ();
				} catch (PlistError e) {
					throw new Error.PROTOCOL ("%s", e.message);
				}

				device_info = new DeviceInfo () {
					name = name,
					model = model,
					udid = udid,
					ecid = ecid,
					kvs = kvs,
				};
			}
		}

		private async PairingPeer? verify_manual_pairing (Cancellable? cancellable) throws Error, IOError {
			Key host_keypair = make_keypair (X25519);
			uint8[] raw_host_pubkey = get_raw_public_key (host_keypair).get_data ();

			Bytes start_params = new PairingParamsBuilder ()
				.add_state (1)
				.add_public_key (host_keypair)
				.build ();

			Bytes start_payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("verifyManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (true)
					.set_member_name ("data")
					.add_data_value (start_params)
				.end_dictionary ()
				.build ();

			var start_response = yield request_pairing_data (start_payload, cancellable);
			if (start_response.has_member ("error")) {
				yield notify_pair_verify_failed (cancellable);
				return null;
			}
			uint8[] raw_device_pubkey = start_response.read_member ("public-key").get_data_value ().get_data ();
			start_response.end_member ();
			var device_pubkey = new Key.from_raw_public_key (X25519, null, raw_device_pubkey);

			Bytes shared_key = derive_shared_key (host_keypair, device_pubkey);

			Bytes operation_key = derive_chacha_key (shared_key,
				"Pair-Verify-Encrypt-Info",
				"Pair-Verify-Encrypt-Salt");

			var cipher = new ChaCha20Poly1305 (operation_key);

			var start_inner_response = new VariantReader (PairingParamsParser.parse (cipher.decrypt (
				new Bytes.static ("\x00\x00\x00\x00PV-Msg02".data[:12]),
				start_response.read_member ("encrypted-data").get_data_value ())));
			string peer_identifier = start_inner_response
				.read_member ("identifier")
				.get_uuid_value ();
			PairingPeer? peer = store.find_peer_by_identifier (peer_identifier);
			if (peer == null) {
				yield notify_pair_verify_failed (cancellable);
				return null;
			}
			// TODO: Verify signature using peer's public key.

			unowned string host_identifier = store.self_identity.identifier;

			var message = new ByteArray.sized (100);
			message.append (raw_host_pubkey);
			message.append (host_identifier.data);
			message.append (raw_device_pubkey);
			Bytes signature = compute_message_signature (ByteArray.free_to_bytes ((owned) message), store.self_identity.key);

			Bytes inner_params = new PairingParamsBuilder ()
				.add_identifier (host_identifier)
				.add_signature (signature)
				.build ();

			Bytes outer_params = new PairingParamsBuilder ()
				.add_state (3)
				.add_encrypted_data (
					cipher.encrypt (
						new Bytes.static ("\x00\x00\x00\x00PV-Msg03".data[:12]),
						inner_params))
				.build ();

			Bytes finish_payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("verifyManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (false)
					.set_member_name ("data")
					.add_data_value (outer_params)
				.end_dictionary ()
				.build ();

			ObjectReader finish_response = yield request_pairing_data (finish_payload, cancellable);
			if (finish_response.has_member ("error")) {
				yield notify_pair_verify_failed (cancellable);
				return null;
			}

			setup_main_encryption_keys (shared_key);

			return peer;
		}

		private async void notify_pair_verify_failed (Cancellable? cancellable) throws Error, IOError {
			yield post_plain (transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("event")
					.begin_dictionary ()
						.set_member_name ("_0")
						.begin_dictionary ()
							.set_member_name ("pairVerifyFailed")
							.begin_dictionary ()
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build (), cancellable);
		}

		private async PairingPeer setup_manual_pairing (Cancellable? cancellable) throws Error, IOError {
			Bytes start_params = new PairingParamsBuilder ()
				.add_method (0)
				.add_state (1)
				.build ();

			Bytes start_payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("setupManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (true)
					.set_member_name ("sendingHost")
					.add_string_value (Environment.get_host_name ())
					.set_member_name ("data")
					.add_data_value (start_params)
				.end_dictionary ()
				.build ();

			var start_response = yield request_pairing_data (start_payload, cancellable);
			if (start_response.has_member ("retry-delay")) {
				uint16 retry_delay = start_response.read_member ("retry-delay").get_uint16_value ();
				throw new Error.INVALID_OPERATION ("Rate limit exceeded, try again in %u seconds", retry_delay);
			}

			Bytes remote_pubkey = start_response.read_member ("public-key").get_data_value ();
			start_response.end_member ();

			Bytes salt = start_response.read_member ("salt").get_data_value ();
			start_response.end_member ();

			var srp_session = new SRPClientSession ("Pair-Setup", "000000");
			srp_session.process (remote_pubkey, salt);
			Bytes shared_key = srp_session.key;

			Bytes verify_params = new PairingParamsBuilder ()
				.add_state (3)
				.add_raw_public_key (srp_session.public_key)
				.add_proof (srp_session.key_proof)
				.build ();

			Bytes verify_payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("setupManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (false)
					.set_member_name ("sendingHost")
					.add_string_value (Environment.get_host_name ())
					.set_member_name ("data")
					.add_data_value (verify_params)
				.end_dictionary ()
				.build ();

			var verify_response = yield request_pairing_data (verify_payload, cancellable);
			Bytes remote_proof = verify_response.read_member ("proof").get_data_value ();

			srp_session.verify_proof (remote_proof);

			Bytes operation_key = derive_chacha_key (shared_key,
				"Pair-Setup-Encrypt-Info",
				"Pair-Setup-Encrypt-Salt");

			var cipher = new ChaCha20Poly1305 (operation_key);

			Bytes signing_key = derive_chacha_key (shared_key,
				"Pair-Setup-Controller-Sign-Info",
				"Pair-Setup-Controller-Sign-Salt");

			unowned PairingIdentity self_identity = store.self_identity;
			Bytes self_identity_pubkey = get_raw_public_key (self_identity.key);

			var message = new ByteArray.sized (100);
			message.append (signing_key.get_data ());
			message.append (self_identity.identifier.data);
			message.append (self_identity_pubkey.get_data ());
			Bytes signature = compute_message_signature (ByteArray.free_to_bytes ((owned) message), self_identity.key);

			Bytes self_info = new OpackBuilder ()
				.begin_dictionary ()
					.set_member_name ("name")
					.add_string_value (Environment.get_host_name ())
					.set_member_name ("accountID")
					.add_string_value (self_identity.identifier)
					.set_member_name ("remotepairing_serial_number")
					.add_string_value ("AAAAAAAAAAAA")
					.set_member_name ("altIRK")
					.add_data_value (self_identity.irk)
					.set_member_name ("model")
					.add_string_value ("computer-model")
					.set_member_name ("mac")
					.add_data_value (new Bytes ({ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 }))
					.set_member_name ("btAddr")
					.add_string_value ("11:22:33:44:55:66")
				.end_dictionary ()
				.build ();

			Bytes inner_params = new PairingParamsBuilder ()
				.add_identifier (self_identity.identifier)
				.add_raw_public_key (self_identity_pubkey)
				.add_signature (signature)
				.add_info (self_info)
				.build ();

			Bytes outer_params = new PairingParamsBuilder ()
				.add_state (5)
				.add_encrypted_data (
					cipher.encrypt (
						new Bytes.static ("\x00\x00\x00\x00PS-Msg05".data[:12]),
						inner_params))
				.build ();

			Bytes finish_payload = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("kind")
					.add_string_value ("setupManualPairing")
					.set_member_name ("startNewSession")
					.add_bool_value (false)
					.set_member_name ("sendingHost")
					.add_string_value (Environment.get_host_name ())
					.set_member_name ("data")
					.add_data_value (outer_params)
				.end_dictionary ()
				.build ();

			var outer_finish_response = yield request_pairing_data (finish_payload, cancellable);
			var inner_finish_response = new VariantReader (PairingParamsParser.parse (
				cipher.decrypt (new Bytes.static ("\x00\x00\x00\x00PS-Msg06".data[:12]),
					outer_finish_response.read_member ("encrypted-data").get_data_value ())));

			string peer_identifier = inner_finish_response.read_member ("identifier").get_string_value ();
			inner_finish_response.end_member ();
			Bytes peer_pubkey = inner_finish_response.read_member ("public-key").get_data_value ();
			inner_finish_response.end_member ();
			Bytes peer_info = inner_finish_response.read_member ("info").get_data_value ();
			inner_finish_response.end_member ();

			PairingPeer peer = store.add_peer (peer_identifier, peer_pubkey, peer_info);

			setup_main_encryption_keys (shared_key);

			return peer;
		}

		private async Bytes? create_remote_unlock_key (Cancellable? cancellable) throws Error, IOError {
			string request = Json.to_string (
				new Json.Builder ()
				.begin_object ()
					.set_member_name ("request")
					.begin_object ()
						.set_member_name ("_0")
						.begin_object ()
							.set_member_name ("createRemoteUnlockKey")
							.begin_object ()
							.end_object ()
						.end_object ()
					.end_object ()
				.end_object ()
				.get_root (), false);

			string response = yield request_encrypted (request, cancellable);

			Json.Reader reader;
			try {
				reader = new Json.Reader (Json.from_string (response));
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("Invalid createRemoteUnlockKey response JSON");
			}

			reader.read_member ("response");
			reader.read_member ("_1");

			if (reader.read_member ("errorExtended")) {
				reader.read_member ("_0");

				reader.read_member ("domain");
				unowned string? domain = reader.get_string_value ();
				reader.end_member ();

				reader.read_member ("code");
				int64 code = reader.get_int_value ();
				reader.end_member ();

				reader.read_member ("userInfo");
				reader.read_member ("NSLocalizedDescription");
				unowned string? description = reader.get_string_value ();

				if (domain == null || description == null)
					throw new Error.PROTOCOL ("Invalid createRemoteUnlockKey error response");

				if (domain == "com.apple.CoreDevice.ControlChannelConnectionError" && code == 2)
					throw new Error.INVALID_OPERATION ("%s", description);

				throw new Error.NOT_SUPPORTED ("%s", description);
			}
			reader.end_member ();

			reader.read_member ("createRemoteUnlockKey");
			reader.read_member ("hostKey");
			unowned string? key = reader.get_string_value ();
			if (key == null)
				throw new Error.PROTOCOL ("Malformed createRemoteUnlockKey response");
			return new Bytes (Base64.decode (key));
		}

		private void setup_main_encryption_keys (Bytes shared_key) {
			client_cipher = new ChaCha20Poly1305 (derive_chacha_key (shared_key, "ClientEncrypt-main"));
			server_cipher = new ChaCha20Poly1305 (derive_chacha_key (shared_key, "ServerEncrypt-main"));
		}

		private async ObjectReader request_pairing_data (Bytes payload, Cancellable? cancellable) throws Error, IOError {
			Bytes wrapper = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("event")
					.begin_dictionary ()
						.set_member_name ("_0")
						.begin_dictionary ()
							.set_member_name ("pairingData")
							.begin_dictionary ()
								.set_member_name ("_0")
								.add_raw_value (payload)
							.end_dictionary ()
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ();

			ObjectReader response = yield request_plain (wrapper, cancellable);

			response
				.read_member ("event")
				.read_member ("_0");

			if (response.has_member ("pairingRejectedWithError")) {
				string description = response
					.read_member ("pairingRejectedWithError")
					.read_member ("wrappedError")
					.read_member ("userInfo")
					.read_member ("NSLocalizedDescription")
					.get_string_value ();
				throw new Error.PROTOCOL ("%s", description);
			}

			Bytes raw_data = response
				.read_member ("pairingData")
				.read_member ("_0")
				.read_member ("data")
				.get_data_value ();
			Variant data = PairingParamsParser.parse (raw_data);
			return new VariantReader (data);
		}

		private async ObjectReader request_plain (Bytes payload, Cancellable? cancellable) throws Error, IOError {
			uint64 seqno = next_control_sequence_number++;
			var promise = new Promise<ObjectReader> ();
			requests[seqno] = promise;

			try {
				yield post_plain_with_sequence_number (seqno, payload, cancellable);
			} catch (GLib.Error e) {
				if (requests.unset (seqno))
					promise.reject (e);
			}

			ObjectReader response = yield promise.future.wait_async (cancellable);

			return response
				.read_member ("plain")
				.read_member ("_0");
		}

		private async void post_plain (Bytes payload, Cancellable? cancellable) throws Error, IOError {
			uint64 seqno = next_control_sequence_number++;
			yield post_plain_with_sequence_number (seqno, payload, cancellable);
		}

		private async void post_plain_with_sequence_number (uint64 seqno, Bytes payload, Cancellable? cancellable)
				throws Error, IOError {
			transport.post (transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("sequenceNumber")
					.add_uint64_value (seqno)
					.set_member_name ("originatedBy")
					.add_string_value ("host")
					.set_member_name ("message")
					.begin_dictionary ()
						.set_member_name ("plain")
						.begin_dictionary ()
							.set_member_name ("_0")
							.add_raw_value (payload)
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ());
		}

		private async string request_encrypted (string json, Cancellable? cancellable) throws Error, IOError {
			uint64 seqno = next_control_sequence_number++;
			var promise = new Promise<ObjectReader> ();
			requests[seqno] = promise;

			Bytes iv = new BufferBuilder (LITTLE_ENDIAN)
				.append_uint64 (next_encrypted_sequence_number++)
				.append_uint32 (0)
				.build ();

			Bytes raw_request = transport.make_object_builder ()
				.begin_dictionary ()
					.set_member_name ("sequenceNumber")
					.add_uint64_value (seqno)
					.set_member_name ("originatedBy")
					.add_string_value ("host")
					.set_member_name ("message")
					.begin_dictionary ()
						.set_member_name ("streamEncrypted")
						.begin_dictionary ()
							.set_member_name ("_0")
							.add_data_value (client_cipher.encrypt (iv, new Bytes.static (json.data)))
						.end_dictionary ()
					.end_dictionary ()
				.end_dictionary ()
				.build ();

			transport.post (raw_request);

			ObjectReader response = yield promise.future.wait_async (cancellable);

			Bytes encrypted_response = response
				.read_member ("streamEncrypted")
				.read_member ("_0")
				.get_data_value ();

			Bytes decrypted_response = server_cipher.decrypt (iv, encrypted_response);

			unowned string s = (string) decrypted_response.get_data ();
			if (!s.validate ((ssize_t) decrypted_response.get_size ()))
				throw new Error.PROTOCOL ("Invalid UTF-8");

			return s;
		}

		private void on_close (Error? error) {
			var e = (error != null)
				? error
				: new Error.TRANSPORT ("Connection closed while waiting for response");
			foreach (Promise<ObjectReader> promise in requests.values)
				promise.reject (e);
			requests.clear ();
		}

		private void on_message (ObjectReader reader) {
			try {
				string origin = reader.read_member ("originatedBy").get_string_value ();
				if (origin != "device")
					return;
				reader.end_member ();

				uint64 seqno = reader.read_member ("sequenceNumber").get_uint64_value ();
				reader.end_member ();

				reader.read_member ("message");

				Promise<ObjectReader> promise;
				if (!requests.unset (seqno, out promise))
					return;

				promise.resolve (reader);
			} catch (Error e) {
			}
		}

		private static uint8[] key_to_der (Key key) {
			var sink = new BasicIO (BasicIOMethod.memory ());
			key.to_der (sink);
			unowned uint8[] der_data = get_basic_io_content (sink);
			uint8[] der_data_owned = der_data;
			return der_data_owned;
		}

		private static Key key_from_der (uint8[] der) throws Error {
			var source = new BasicIO.from_static_memory_buffer (der);
			Key? key = new Key.from_der (source);
			if (key == null)
				throw new Error.PROTOCOL ("Invalid key");
			return key;
		}

		private static unowned uint8[] get_basic_io_content (BasicIO bio) {
			unowned uint8[] data;
			long n = bio.get_mem_data (out data);
			data.length = (int) n;
			return data;
		}

		private static Bytes derive_shared_key (Key local_keypair, Key remote_pubkey) {
			var ctx = new KeyContext.for_key (local_keypair);
			ctx.derive_init ();
			ctx.derive_set_peer (remote_pubkey);

			size_t size = 0;
			ctx.derive (null, ref size);

			var shared_key = new uint8[size];
			ctx.derive (shared_key, ref size);

			return new Bytes.take ((owned) shared_key);
		}

		private static Bytes derive_chacha_key (Bytes shared_key, string info, string? salt = null) {
			var kdf = KeyDerivationFunction.fetch (null, KeyDerivationAlgorithm.HKDF);

			var kdf_ctx = new KeyDerivationContext (kdf);

			size_t return_size = OpenSSL.ParamReturnSize.UNMODIFIED;

			OpenSSL.Param kdf_params[] = {
				{ KeyDerivationParameter.DIGEST, UTF8_STRING, OpenSSL.ShortName.sha512.data, return_size },
				{ KeyDerivationParameter.KEY, OCTET_STRING, shared_key.get_data (), return_size },
				{ KeyDerivationParameter.INFO, OCTET_STRING, info.data, return_size },
				{ (salt != null) ? KeyDerivationParameter.SALT : null, OCTET_STRING, (salt != null) ? salt.data : null,
					return_size },
				{ null, INTEGER, null, return_size },
			};

			var derived_key = new uint8[32];
			kdf_ctx.derive (derived_key, kdf_params);

			return new Bytes.take ((owned) derived_key);
		}

		private static Bytes compute_message_signature (Bytes message, Key key) {
			var ctx = new MessageDigestContext ();
			ctx.digest_sign_init (null, null, null, key);

			unowned uint8[] data = message.get_data ();

			size_t size = 0;
			ctx.digest_sign (null, ref size, data);

			var signature = new uint8[size];
			ctx.digest_sign (signature, ref size, data);

			return new Bytes.take ((owned) signature);
		}

		private class ChaCha20Poly1305 {
			private Bytes key;

			private Cipher cipher = Cipher.fetch (null, OpenSSL.ShortName.chacha20_poly1305);
			private CipherContext? cached_ctx;

			private const size_t TAG_SIZE = 16;

			public ChaCha20Poly1305 (Bytes key) {
				this.key = key;
			}

			public Bytes encrypt (Bytes iv, Bytes message) {
				size_t cleartext_size = message.get_size ();
				var buf = new uint8[cleartext_size + TAG_SIZE];

				unowned CipherContext ctx = get_context ();
				cached_ctx.encrypt_init (cipher, key.get_data (), iv.get_data ());

				int size = buf.length;
				ctx.encrypt_update (buf, ref size, message.get_data ());

				int extra_size = buf.length - size;
				ctx.encrypt_final (buf[size:], ref extra_size);
				assert (extra_size == 0);

				ctx.ctrl (AEAD_GET_TAG, (int) TAG_SIZE, (void *) buf[size:]);

				return new Bytes.take ((owned) buf);
			}

			public Bytes decrypt (Bytes iv, Bytes message) throws Error {
				size_t message_size = message.get_size ();
				if (message_size < 1 + TAG_SIZE)
					throw new Error.PROTOCOL ("Encrypted message is too short");
				unowned uint8[] message_data = message.get_data ();

				var buf = new uint8[message_size];

				unowned CipherContext ctx = get_context ();
				cached_ctx.decrypt_init (cipher, key.get_data (), iv.get_data ());

				int size = (int) message_size;
				int res = ctx.decrypt_update (buf, ref size, message_data);
				if (res != 1)
					throw new Error.PROTOCOL ("Failed to decrypt: %d", res);

				int extra_size = buf.length - size;
				res = ctx.decrypt_final (buf[size:], ref extra_size);
				if (res != 1)
					throw new Error.PROTOCOL ("Failed to decrypt: %d", res);
				assert (extra_size == 0);

				size_t cleartext_size = message_size - TAG_SIZE;
				buf[cleartext_size] = 0;
				buf.length = (int) cleartext_size;

				return new Bytes.take ((owned) buf);
			}

			private unowned CipherContext get_context () {
				if (cached_ctx == null)
					cached_ctx = new CipherContext ();
				else
					cached_ctx.reset ();
				return cached_ctx;
			}
		}

		private class SRPClientSession {
			public Bytes public_key {
				owned get {
					var buf = new uint8[local_pubkey.num_bytes ()];
					local_pubkey.to_big_endian (buf);
					return new Bytes.take ((owned) buf);
				}
			}

			public Bytes key {
				get {
					return _key;
				}
			}

			public Bytes key_proof {
				get {
					return _key_proof;
				}
			}

			private string username;
			private string password;

			private BigNumber prime = BigNumber.get_rfc3526_prime_3072 ();
			private BigNumber generator;
			private BigNumber multiplier;

			private BigNumber local_privkey;
			private BigNumber local_pubkey;

			private BigNumber? remote_pubkey;
			private Bytes? salt;

			private BigNumber? password_hash;
			private BigNumber? password_verifier;

			private BigNumber? common_secret;
			private BigNumber? premaster_secret;
			private Bytes? _key;
			private Bytes? _key_proof;
			private Bytes? _key_proof_hash;

			private BigNumberContext bn_ctx = new BigNumberContext.secure ();

			public SRPClientSession (string username, string password) {
				this.username = username;
				this.password = password;

				uint8 raw_gen = 5;
				generator = new BigNumber.from_native ((uint8[]) &raw_gen);
				multiplier = new HashBuilder ()
					.add_number_padded (prime)
					.add_number_padded (generator)
					.build_number ();

				uint8 raw_local_privkey[128];
				Rng.generate (raw_local_privkey);
				local_privkey = new BigNumber.from_big_endian (raw_local_privkey);

				local_pubkey = new BigNumber ();
				BigNumber.mod_exp (local_pubkey, generator, local_privkey, prime, bn_ctx);
			}

			public void process (Bytes raw_remote_pubkey, Bytes salt) throws Error {
				remote_pubkey = new BigNumber.from_big_endian (raw_remote_pubkey.get_data ());
				var rem = new BigNumber ();
				BigNumber.mod (rem, remote_pubkey, prime, bn_ctx);
				if (rem.is_zero ())
					throw new Error.INVALID_ARGUMENT ("Malformed remote public key");

				this.salt = salt;

				password_hash = compute_password_hash (salt);
				password_verifier = compute_password_verifier (password_hash);

				common_secret = compute_common_secret (remote_pubkey);
				premaster_secret = compute_premaster_secret (common_secret, remote_pubkey, password_hash,
					password_verifier);
				_key = compute_session_key (premaster_secret);
				_key_proof = compute_session_key_proof (_key, remote_pubkey, salt);
				_key_proof_hash = compute_session_key_proof_hash (_key_proof, _key);
			}

			public void verify_proof (Bytes proof) throws Error {
				size_t size = proof.get_size ();
				if (size != _key_proof_hash.get_size ())
					throw new Error.INVALID_ARGUMENT ("Invalid proof size");

				if (Crypto.memcmp (proof.get_data (), _key_proof_hash.get_data (), size) != 0)
					throw new Error.INVALID_ARGUMENT ("Invalid proof");
			}

			private BigNumber compute_password_hash (Bytes salt) {
				return new HashBuilder ()
					.add_bytes (salt)
					.add_bytes (new HashBuilder ()
						.add_string (username)
						.add_string (":")
						.add_string (password)
						.build_digest ())
					.build_number ();
			}

			private BigNumber compute_password_verifier (BigNumber password_hash) {
				var verifier = new BigNumber ();
				BigNumber.mod_exp (verifier, generator, password_hash, prime, bn_ctx);
				return verifier;
			}

			private BigNumber compute_common_secret (BigNumber remote_pubkey) {
				return new HashBuilder ()
					.add_number_padded (local_pubkey)
					.add_number_padded (remote_pubkey)
					.build_number ();
			}

			private BigNumber compute_premaster_secret (BigNumber common_secret, BigNumber remote_pubkey,
					BigNumber password_hash, BigNumber password_verifier) {
				var val = new BigNumber ();

				BigNumber.mul (val, multiplier, password_verifier, bn_ctx);
				var baze = new BigNumber ();
				BigNumber.sub (baze, remote_pubkey, val);

				var exp = new BigNumber ();
				BigNumber.mul (val, common_secret, password_hash, bn_ctx);
				BigNumber.add (exp, local_privkey, val);

				BigNumber.mod_exp (val, baze, exp, prime, bn_ctx);

				return val;
			}

			private static Bytes compute_session_key (BigNumber premaster_secret) {
				return new HashBuilder ()
					.add_number (premaster_secret)
					.build_digest ();
			}

			private Bytes compute_session_key_proof (Bytes session_key, BigNumber remote_pubkey, Bytes salt) {
				Bytes prime_hash = new HashBuilder ().add_number (prime).build_digest ();
				Bytes generator_hash = new HashBuilder ().add_number (generator).build_digest ();
				uint8 prime_and_generator_xored[64];
				unowned uint8[] left = prime_hash.get_data ();
				unowned uint8[] right = generator_hash.get_data ();
				for (var i = 0; i != prime_and_generator_xored.length; i++)
					prime_and_generator_xored[i] = left[i] ^ right[i];

				return new HashBuilder ()
					.add_data (prime_and_generator_xored)
					.add_bytes (new HashBuilder ().add_string (username).build_digest ())
					.add_bytes (salt)
					.add_number (local_pubkey)
					.add_number (remote_pubkey)
					.add_bytes (session_key)
					.build_digest ();
			}

			private Bytes compute_session_key_proof_hash (Bytes key_proof, Bytes key) {
				return new HashBuilder ()
					.add_number (local_pubkey)
					.add_bytes (key_proof)
					.add_bytes (key)
					.build_digest ();
			}

			private class HashBuilder {
				private Checksum checksum = new Checksum (SHA512);

				public unowned HashBuilder add_number (BigNumber val) {
					var buf = new uint8[val.num_bytes ()];
					val.to_big_endian (buf);
					return add_data (buf);
				}

				public unowned HashBuilder add_number_padded (BigNumber val) {
					uint8 buf[384];
					val.to_big_endian_padded (buf);
					return add_data (buf);
				}

				public unowned HashBuilder add_string (string val) {
					return add_data (val.data);
				}

				public unowned HashBuilder add_bytes (Bytes val) {
					return add_data (val.get_data ());
				}

				public unowned HashBuilder add_data (uint8[] val) {
					checksum.update (val, val.length);
					return this;
				}

				public Bytes build_digest () {
					var buf = new uint8[64];
					size_t len = buf.length;
					checksum.get_digest (buf, ref len);
					return new Bytes.take ((owned) buf);
				}

				public BigNumber build_number () {
					uint8 buf[64];
					size_t len = buf.length;
					checksum.get_digest (buf, ref len);
					return new BigNumber.from_big_endian (buf);
				}
			}
		}
	}

	public interface PairingTransport : Object {
		public signal void close (Error? error);
		public signal void message (ObjectReader reader);

		public abstract async void open (Cancellable? cancellable) throws Error, IOError;
		public abstract void cancel ();

		public abstract ObjectBuilder make_object_builder ();
		public abstract void post (Bytes message);
	}

	public sealed class XpcPairingTransport : Object, PairingTransport {
		public IOStream stream {
			get;
			construct;
		}

		private XpcConnection connection;

		private Cancellable io_cancellable = new Cancellable ();

		public XpcPairingTransport (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			connection = new XpcConnection (stream);
			connection.close.connect (on_close);
			connection.message.connect (on_message);
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			connection.activate ();

			yield connection.wait_until_ready (cancellable);
		}

		public void cancel () {
			io_cancellable.cancel ();

			connection.cancel ();
		}

		public ObjectBuilder make_object_builder () {
			return new XpcObjectBuilder ();
		}

		public void post (Bytes msg) {
			connection.post.begin (
				new XpcBodyBuilder ()
					.begin_dictionary ()
						.set_member_name ("mangledTypeName")
						.add_string_value ("RemotePairing.ControlChannelMessageEnvelope")
						.set_member_name ("value")
						.add_raw_value (msg)
					.end_dictionary ()
					.build (),
				io_cancellable);
		}

		private void on_close (Error? error) {
			close (error);
		}

		private void on_message (XpcMessage msg) {
			if (msg.body == null)
				return;

			var reader = new VariantReader (msg.body);
			try {
				string type_name = reader.read_member ("mangledTypeName").get_string_value ();
				if (type_name != "RemotePairingDevice.ControlChannelMessageEnvelope")
					return;
				reader.end_member ();

				reader.read_member ("value");

				message (reader);
			} catch (Error e) {
			}
		}
	}

	public sealed class PlainPairingTransport : Object, PairingTransport {
		public IOStream stream {
			get;
			construct;
		}

		private BufferedInputStream input;
		private OutputStream output;

		private ByteArray pending_output = new ByteArray ();
		private bool writing = false;

		private Cancellable io_cancellable = new Cancellable ();

		public PlainPairingTransport (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			input = (BufferedInputStream) Object.new (typeof (BufferedInputStream),
				"base-stream", stream.get_input_stream (),
				"close-base-stream", false,
				"buffer-size", 128 * 1024);
			output = stream.get_output_stream ();
		}

		public async void open (Cancellable? cancellable) throws Error, IOError {
			process_incoming_messages.begin ();
		}

		public void cancel () {
			io_cancellable.cancel ();
		}

		public ObjectBuilder make_object_builder () {
			return new JsonObjectBuilder ();
		}

		public void post (Bytes msg) {
			Bytes raw_msg = new BufferBuilder (BIG_ENDIAN)
				.append_string ("RPPairing", StringTerminator.NONE)
				.append_uint16 ((uint16) msg.get_size ())
				.append_bytes (msg)
				.build ();
			pending_output.append (raw_msg.get_data ());

			if (!writing) {
				writing = true;

				var source = new IdleSource ();
				source.set_callback (() => {
					process_pending_output.begin ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}
		}

		private async void process_incoming_messages () {
			try {
				while (true) {
					size_t header_size = 11;
					if (input.get_available () < header_size)
						yield fill_until_n_bytes_available (header_size);

					uint8 raw_magic[9];
					input.peek (raw_magic);
					string magic = ((string) raw_magic).make_valid (raw_magic.length);
					if (magic != "RPPairing")
						throw new Error.PROTOCOL ("Invalid message magic: '%s'", magic);

					uint16 body_size = 0;
					unowned uint8[] size_buf = ((uint8[]) &body_size)[:2];
					input.peek (size_buf, raw_magic.length);
					body_size = uint16.from_big_endian (body_size);
					if (body_size < 2)
						throw new Error.PROTOCOL ("Invalid message size");

					size_t full_size = header_size + body_size;
					if (input.get_available () < full_size)
						yield fill_until_n_bytes_available (full_size);

					var raw_json = new uint8[body_size + 1];
					input.peek (raw_json[:body_size], header_size);

					unowned string json = (string) raw_json;
					if (!json.validate ())
						throw new Error.PROTOCOL ("Invalid UTF-8");

					var reader = new JsonObjectReader (json);

					message (reader);

					input.skip (full_size, io_cancellable);
				}
			} catch (GLib.Error e) {
			}

			close (null);
		}

		private async void process_pending_output () {
			while (pending_output.len > 0) {
				uint8[] batch = pending_output.steal ();

				size_t bytes_written;
				try {
					yield output.write_all_async (batch, Priority.DEFAULT, io_cancellable, out bytes_written);
				} catch (GLib.Error e) {
					break;
				}
			}

			writing = false;
		}

		private async void fill_until_n_bytes_available (size_t minimum) throws Error, IOError {
			size_t available = input.get_available ();
			while (available < minimum) {
				if (input.get_buffer_size () < minimum)
					input.set_buffer_size (minimum);

				ssize_t n;
				try {
					n = yield input.fill_async ((ssize_t) (input.get_buffer_size () - available), Priority.DEFAULT,
						io_cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Connection closed");
				}

				if (n == 0)
					throw new Error.TRANSPORT ("Connection closed");

				available += n;
			}
		}
	}

	public sealed class PairingStore {
		public PairingIdentity self_identity {
			get {
				return _self_identity;
			}
		}

		public Gee.Iterable<PairingPeer> peers {
			get {
				return _peers;
			}
		}

		private PairingIdentity _self_identity;
		private Gee.List<PairingPeer> _peers;

		public PairingStore () {
			_self_identity = try_load_identity ();
			if (_self_identity == null) {
				_self_identity = PairingIdentity.make ();
				try {
					save_identity (_self_identity);
				} catch (GLib.Error e) {
				}
			}

			_peers = load_peers ();
		}

		public PairingPeer add_peer (string identifier, Bytes public_key, Bytes info) throws Error {
			var r = new VariantReader (OpackParser.parse (info));

			Bytes irk = r.read_member ("altIRK").get_data_value ();
			r.end_member ();

			unowned string name = r.read_member ("name").get_string_value ();
			r.end_member ();

			unowned string model = r.read_member ("model").get_string_value ();
			r.end_member ();

			unowned string udid = r.read_member ("remotepairing_udid").get_string_value ();
			r.end_member ();

			var peer = new PairingPeer () {
				identifier = identifier,
				public_key = public_key,
				irk = irk,
				name = name,
				model = model,
				udid = udid,
				info = info,
				remote_unlock_host_key = null,
			};
			_peers.add (peer);

			try {
				save_peer (peer);
			} catch (Error e) {
			}

			return peer;
		}

		public PairingPeer? find_peer_by_identifier (string identifier) {
			return peers.first_match (p => p.identifier == identifier);
		}

		public PairingPeer? find_peer_matching_service (PairingServiceDetails service) {
			var mac = OpenSSL.Envelope.MessageAuthCode.fetch (null, OpenSSL.ShortName.siphash);

			size_t hash_size = 8;
			size_t return_size = OpenSSL.ParamReturnSize.UNMODIFIED;
			OpenSSL.Param mac_params[] = {
				{ OpenSSL.Envelope.MessageAuthParameter.SIZE, UNSIGNED_INTEGER,
					(uint8[]) &hash_size, return_size },
				{ null, INTEGER, null, return_size },
			};

			foreach (var peer in _peers) {
				var ctx = new OpenSSL.Envelope.MessageAuthCodeContext (mac);
				ctx.init (peer.irk.get_data (), mac_params);
				ctx.update (service.identifier.data);
				uint8 output[8];
				size_t outlen = 0;
				ctx.final (output, out outlen);

				uint8 tag[6];
				for (uint i = 0; i != 6; i++)
					tag[i] = output[5 - i];

				if (Memory.cmp (tag, service.auth_tag.get_data (), service.auth_tag.get_size ()) == 0)
					return peer;
			}

			return null;
		}

		private static PairingIdentity? try_load_identity () {
			try {
				var plist = new Plist.from_data (query_self_identity_location ().load_bytes ().get_data ());
				return new PairingIdentity () {
					identifier = plist.get_string ("identifier"),
					key = new Key.from_raw_private_key (ED25519, null, plist.get_bytes ("privateKey").get_data ()),
					irk = plist.get_bytes ("irk"),
				};
			} catch (GLib.Error e) {
				return null;
			}
		}

		private static void save_identity (PairingIdentity identity) throws Error {
			var plist = new Plist ();
			plist.set_string ("identifier", identity.identifier);
			plist.set_bytes ("publicKey", get_raw_public_key (identity.key));
			plist.set_bytes ("privateKey", get_raw_private_key (identity.key));
			plist.set_bytes ("irk", identity.irk);
			save_plist (plist, query_self_identity_location ());
		}

		private static Gee.List<PairingPeer> load_peers () {
			var peers = new Gee.ArrayList<PairingPeer> ();

			try {
				var enumerator = query_peers_location ().enumerate_children (FileAttribute.STANDARD_NAME, FileQueryInfoFlags.NONE);
				File? child;
				while (enumerator.iterate (null, out child) && child != null) {
					var plist = new Plist.from_data (child.load_bytes ().get_data ());

					var info = plist.get_bytes ("info");
					var r = new VariantReader (OpackParser.parse (info));
					unowned string udid = r.read_member ("remotepairing_udid").get_string_value ();

					Bytes? remote_unlock_host_key = null;
					if (plist.has ("remoteUnlockHostKey"))
						remote_unlock_host_key = plist.get_bytes ("remoteUnlockHostKey");

					peers.add (new PairingPeer () {
						identifier = plist.get_string ("identifier"),
						public_key = plist.get_bytes ("publicKey"),
						irk = plist.get_bytes ("irk"),
						name = plist.get_string ("name"),
						model = plist.get_string ("model"),
						udid = udid,
						info = info,
						remote_unlock_host_key = remote_unlock_host_key,
					});
				}
			} catch (GLib.Error e) {
			}

			return peers;
		}

		public void save_peer (PairingPeer peer) throws Error {
			var plist = new Plist ();
			plist.set_string ("identifier", peer.identifier);
			plist.set_bytes ("publicKey", peer.public_key);
			plist.set_bytes ("irk", peer.irk);
			plist.set_string ("name", peer.name);
			plist.set_string ("model", peer.model);
			plist.set_bytes ("info", peer.info);
			if (peer.remote_unlock_host_key != null)
				plist.set_bytes ("remoteUnlockHostKey", peer.remote_unlock_host_key);

			save_plist (plist, query_peer_location (peer));
		}

		public void forget_peer (PairingPeer peer) {
			try {
				query_peer_location (peer).delete ();
			} catch (GLib.Error e) {
			}

			_peers.remove (peer);
		}

		private static File query_self_identity_location () {
			return query_base_location ().get_child ("self-identity.plist");
		}

		private static File query_peer_location (PairingPeer peer) {
			return query_peers_location ().get_child (peer.identifier + ".plist");
		}

		private static File query_peers_location () {
			return query_base_location ().get_child ("peers");
		}

		private static File query_base_location () {
			return File.new_build_filename (Environment.get_user_config_dir (), "frida");
		}

		private static void save_plist (Plist plist, File location) throws Error {
			try {
				location.get_parent ().make_directory_with_parents ();
			} catch (GLib.Error e) {
			}
			try {
				location.replace_contents (plist.to_binary (), null, false, PRIVATE | REPLACE_DESTINATION, null);
			} catch (GLib.Error e) {
				throw new Error.NOT_SUPPORTED ("%s", e.message);
			}
		}
	}

	public sealed class PairingIdentity {
		public string identifier;
		public Key key;
		public Bytes irk;

		public static PairingIdentity make () {
			uint8 raw_irk[16];
			Rng.generate (raw_irk);

			return new PairingIdentity () {
				identifier = make_host_identifier (),
				key = make_keypair (ED25519),
				irk = new Bytes (raw_irk),
			};
		}
	}

	public sealed class PairingPeer {
		public string identifier;
		public Bytes public_key;
		public Bytes irk;
		public string name;
		public string model;
		public string udid;
		public Bytes info;
		public Bytes? remote_unlock_host_key;
	}

	public sealed class PairingServiceMetadata {
		public string identifier;
		public Bytes auth_tag;

		public static PairingServiceMetadata from_txt_record (Gee.Iterable<string> record) throws Error {
			string? identifier = null;
			Bytes? auth_tag = null;
			foreach (string item in record) {
				string[] tokens = item.split ("=", 2);
				if (tokens.length != 2)
					continue;

				unowned string key = tokens[0];
				unowned string val = tokens[1];
				if (key == "identifier")
					identifier = val;
				else if (key == "authTag")
					auth_tag = new Bytes (Base64.decode (val));
			}
			if (identifier == null || auth_tag == null)
				throw new Error.PROTOCOL ("Missing TXT metadata");

			return new PairingServiceMetadata () {
				identifier = identifier,
				auth_tag = auth_tag,
			};
		}
	}

	public sealed class DeviceOptions {
		public bool allows_pair_setup;
		public bool allows_pinless_pairing;
		public bool allows_promptless_automation_pairing_upgrade;
		public bool allows_sharing_sensitive_info;
		public bool allows_incoming_tunnel_connections;
	}

	public sealed class DeviceInfo {
		public string name;
		public string model;
		public string udid;
		public uint64 ecid;
		public Plist kvs;
	}

	private sealed class PairingParamsBuilder {
		private BufferBuilder builder = new BufferBuilder (LITTLE_ENDIAN);

		public unowned PairingParamsBuilder add_method (uint8 method) {
			begin_param (METHOD, 1)
				.append_uint8 (method);

			return this;
		}

		public unowned PairingParamsBuilder add_identifier (string identifier) {
			begin_param (IDENTIFIER, identifier.data.length)
				.append_data (identifier.data);

			return this;
		}

		public unowned PairingParamsBuilder add_public_key (Key key) {
			return add_raw_public_key (get_raw_public_key (key));
		}

		public unowned PairingParamsBuilder add_raw_public_key (Bytes key) {
			return add_blob (PUBLIC_KEY, key);
		}

		public unowned PairingParamsBuilder add_proof (Bytes proof) {
			return add_blob (PROOF, proof);
		}

		public unowned PairingParamsBuilder add_encrypted_data (Bytes bytes) {
			return add_blob (ENCRYPTED_DATA, bytes);
		}

		public unowned PairingParamsBuilder add_state (uint8 state) {
			begin_param (STATE, 1)
				.append_uint8 (state);

			return this;
		}

		public unowned PairingParamsBuilder add_signature (Bytes signature) {
			return add_blob (SIGNATURE, signature);
		}

		public unowned PairingParamsBuilder add_info (Bytes info) {
			return add_blob (INFO, info);
		}

		private unowned PairingParamsBuilder add_blob (PairingParamType type, Bytes blob) {
			unowned uint8[] data = blob.get_data ();

			uint cursor = 0;
			do {
				uint n = uint.min (data.length - cursor, uint8.MAX);
				begin_param (type, n)
					.append_data (data[cursor:cursor + n]);
				cursor += n;
			} while (cursor != data.length);

			return this;
		}

		private unowned BufferBuilder begin_param (PairingParamType type, size_t size) {
			return builder
				.append_uint8 (type)
				.append_uint8 ((uint8) size);
		}

		public Bytes build () {
			return builder.build ();
		}
	}

	private sealed class PairingParamsParser {
		private BufferReader reader;
		private EnumClass param_type_class;

		public static Variant parse (Bytes pairing_params) throws Error {
			var parser = new PairingParamsParser (pairing_params);
			return parser.read_params ();
		}

		private PairingParamsParser (Bytes bytes) {
			reader = new BufferReader (new Buffer (bytes, LITTLE_ENDIAN));
			param_type_class = (EnumClass) typeof (PairingParamType).class_ref ();
		}

		private Variant read_params () throws Error {
			var byte_array = new VariantType.array (VariantType.BYTE);

			var parameters = new Gee.HashMap<string, Variant> ();
			while (reader.available != 0) {
				var raw_type = reader.read_uint8 ();
				unowned EnumValue? type_enum_val = param_type_class.get_value (raw_type);
				if (type_enum_val == null)
					throw new Error.INVALID_ARGUMENT ("Unsupported pairing parameter type (0x%x)", raw_type);
				var type = (PairingParamType) raw_type;
				unowned string key = type_enum_val.value_nick;

				var val_size = reader.read_uint8 ();
				Variant val;
				switch (type) {
					case IDENTIFIER:
						val = new Variant.string (reader.read_fixed_string (val_size));
						break;
					case STATE:
					case ERROR:
						if (val_size != 1)
							throw new Error.INVALID_ARGUMENT ("Invalid value for '%s': size=%u", key, val_size);
						val = new Variant.byte (reader.read_uint8 ());
						break;
					case RETRY_DELAY: {
						uint16 delay;
						switch (val_size) {
							case 1:
								delay = reader.read_uint8 ();
								break;
							case 2:
								delay = reader.read_uint16 ();
								break;
							default:
								throw new Error.INVALID_ARGUMENT ("Invalid value for 'retry-delay'");
						}
						val = new Variant.uint16 (delay);
						break;
					}
					default: {
						Bytes val_bytes = reader.read_bytes (val_size);
						var val_bytes_copy = new Bytes (val_bytes.get_data ());
						val = Variant.new_from_data (byte_array, val_bytes_copy.get_data (), true, val_bytes_copy);
						break;
					}
				}

				Variant? existing_val = parameters[key];
				if (existing_val != null) {
					if (!existing_val.is_of_type (byte_array))
						throw new Error.INVALID_ARGUMENT ("Unable to merge '%s' keys: unsupported type", key);
					Bytes part1 = existing_val.get_data_as_bytes ();
					Bytes part2 = val.get_data_as_bytes ();
					var combined = new ByteArray.sized ((uint) (part1.get_size () + part2.get_size ()));
					combined.append (part1.get_data ());
					combined.append (part2.get_data ());
					val = Variant.new_from_data (byte_array, combined.data, true, (owned) combined);
				}

				parameters[key] = val;
			}

			var builder = new VariantBuilder (VariantType.VARDICT);
			foreach (var e in parameters.entries)
				builder.add ("{sv}", e.key, e.value);
			return builder.end ();
		}
	}

	private enum PairingParamType {
		METHOD,
		IDENTIFIER,
		SALT,
		PUBLIC_KEY,
		PROOF,
		ENCRYPTED_DATA,
		STATE,
		ERROR,
		RETRY_DELAY /* = 8 */,
		SIGNATURE = 10,
		INFO = 17,
	}

	public interface TunnelConnection : Object {
		public signal void closed ();

		public abstract NetworkStack tunnel_netstack {
			get;
		}

		public abstract InetAddress remote_address {
			get;
		}

		public abstract uint16 remote_rsd_port {
			get;
		}

		public abstract async void close (Cancellable? cancellable) throws IOError;

		protected static Bytes make_handshake_request (size_t mtu) {
			string body = Json.to_string (
				new Json.Builder ()
				.begin_object ()
					.set_member_name ("type")
					.add_string_value ("clientHandshakeRequest")
					.set_member_name ("mtu")
					.add_int_value (mtu)
				.end_object ()
				.get_root (), false);
			return make_request (body.data);
		}

		protected static Bytes make_request (uint8[] body) {
			return new BufferBuilder (BIG_ENDIAN)
				.append_string ("CDTunnel", StringTerminator.NONE)
				.append_uint16 ((uint16) body.length)
				.append_data (body)
				.build ();
		}
	}

	public sealed class TunnelParameters {
		public InetAddress address;
		public uint16 mtu;
		public InetAddress server_address;
		public uint16 server_rsd_port;

		public static TunnelParameters from_json (JsonObjectReader reader) throws Error {
			reader.read_member ("clientParameters");

			reader.read_member ("address");
			string address = reader.get_string_value ();
			reader.end_member ();

			reader.read_member ("mtu");
			uint16 mtu = reader.get_uint16_value ();
			reader.end_member ();

			reader.end_member ();

			reader.read_member ("serverAddress");
			string server_address = reader.get_string_value ();
			reader.end_member ();

			reader.read_member ("serverRSDPort");
			uint16 server_rsd_port = reader.get_uint16_value ();
			reader.end_member ();

			return new TunnelParameters () {
				address = new InetAddress.from_string (address),
				mtu = (uint16) mtu,
				server_address = new InetAddress.from_string (server_address),
				server_rsd_port = server_rsd_port,
			};
		}
	}

	public sealed class TcpTunnelConnection : Object, TunnelConnection, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}

		public NetworkStack tunnel_netstack {
			get {
				return _tunnel_netstack;
			}
		}

		public InetAddress remote_address {
			get {
				return tunnel_params.server_address;
			}
		}

		public uint16 remote_rsd_port {
			get {
				return tunnel_params.server_rsd_port;
			}
		}

		private Promise<bool> close_request = new Promise<bool> ();

		private TunnelParameters tunnel_params;
		private VirtualNetworkStack _tunnel_netstack;

		private BufferedInputStream input;
		private OutputStream output;

		private ByteArray pending_output = new ByteArray ();
		private bool writing = false;

		private Cancellable io_cancellable = new Cancellable ();

		private const size_t PREFERRED_MTU = 16000;
		private const string PSK_IDENTITY = "com.apple.CoreDevice.TunnelService.Identity";

		public static async TcpTunnelConnection open (InetSocketAddress address, NetworkStack netstack, TunnelKey local_keypair,
				TunnelKey remote_pubkey, Cancellable? cancellable = null) throws Error, IOError {
			var stream = yield netstack.open_tcp_connection (address, cancellable);

			TlsClientConnection tls_connection;
			try {
				tls_connection = TlsClientConnection.new (stream, null);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			tls_connection.set_data ("tcp-tunnel-keypair", local_keypair);
			tls_connection.set_database (null);

			unowned SSL ssl = get_ssl_handle_from_connection (tls_connection);
			ssl.set_cipher_list ("PSK-AES128-GCM-SHA256:PSK-AES256-GCM-SHA384:PSK-AES256-CBC-SHA384:PSK-AES128-CBC-SHA256");
			ssl.set_psk_client_callback ((ssl, hint, identity, psk) => {
				unowned TlsClientConnection conn = (TlsClientConnection) get_connection_from_ssl_handle (ssl);
				unowned TunnelKey tk = conn.get_data ("tcp-tunnel-keypair");

				Memory.copy (identity, PSK_IDENTITY.data, PSK_IDENTITY.data.length);

				var key = get_raw_private_key (tk.handle).get_data ();
				Memory.copy (psk, key, key.length);

				return key.length;
			});

			try {
				yield tls_connection.handshake_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}

			var connection = new TcpTunnelConnection (tls_connection);

			try {
				yield connection.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return connection;
		}

		public static async TcpTunnelConnection open_stream (IOStream stream, Cancellable? cancellable = null)
				throws Error, IOError {
			var connection = new TcpTunnelConnection (stream);

			try {
				yield connection.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return connection;
		}

		private TcpTunnelConnection (IOStream stream) {
			Object (stream: stream);
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			input = (BufferedInputStream) Object.new (typeof (BufferedInputStream),
				"base-stream", stream.get_input_stream (),
				"close-base-stream", false,
				"buffer-size", 128 * 1024);
			output = stream.get_output_stream ();

			post (make_handshake_request (PREFERRED_MTU));

			tunnel_params = TunnelParameters.from_json (yield read_message (cancellable));

			_tunnel_netstack = new VirtualNetworkStack (null, tunnel_params.address, tunnel_params.mtu);
			_tunnel_netstack.outgoing_datagram.connect (post);

			process_incoming_messages.begin ();

			return true;
		}

		public async void close (Cancellable? cancellable) throws IOError {
			io_cancellable.cancel ();

			try {
				yield close_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private async void process_incoming_messages () {
			try {
				while (true) {
					var datagram = yield read_datagram (io_cancellable);

					_tunnel_netstack.handle_incoming_datagram (datagram);
				}
			} catch (GLib.Error e) {
			}

			io_cancellable.cancel ();

			var source = new IdleSource ();
			source.set_callback (process_incoming_messages.callback);
			source.attach (MainContext.get_thread_default ());
			yield;

			try {
				yield stream.close_async ();
			} catch (GLib.Error e) {
			}

			if (_tunnel_netstack != null)
				_tunnel_netstack.stop ();

			close_request.resolve (true);

			closed ();
		}

		private void post (Bytes bytes) {
			pending_output.append (bytes.get_data ());

			if (!writing) {
				writing = true;

				var source = new IdleSource ();
				source.set_callback (() => {
					process_pending_output.begin ();
					return false;
				});
				source.attach (MainContext.get_thread_default ());
			}
		}

		private async void process_pending_output () {
			while (pending_output.len > 0) {
				uint8[] batch = pending_output.steal ();

				size_t bytes_written;
				try {
					yield output.write_all_async (batch, Priority.DEFAULT, io_cancellable, out bytes_written);
				} catch (GLib.Error e) {
					break;
				}
			}

			writing = false;
		}

		private async JsonObjectReader read_message (Cancellable? cancellable) throws Error, IOError {
			size_t header_size = 10;
			if (input.get_available () < header_size)
				yield fill_until_n_bytes_available (header_size, cancellable);

			uint8 raw_magic[8];
			input.peek (raw_magic);
			string magic = ((string) raw_magic).make_valid (raw_magic.length);
			if (magic != "CDTunnel")
				throw new Error.PROTOCOL ("Invalid message magic: '%s'", magic);

			uint16 body_size = 0;
			unowned uint8[] size_buf = ((uint8[]) &body_size)[:2];
			input.peek (size_buf, raw_magic.length);
			body_size = uint16.from_big_endian (body_size);

			size_t full_size = header_size + body_size;
			if (input.get_available () < full_size)
				yield fill_until_n_bytes_available (full_size, cancellable);

			var body = new uint8[body_size + 1];
			input.peek (body[:body_size], header_size);
			body.length = body_size;

			input.skip (full_size, cancellable);

			unowned string json = (string) body;
			if (!json.validate ())
				throw new Error.PROTOCOL ("Invalid UTF-8");

			return new JsonObjectReader (json);
		}

		private async Bytes read_datagram (Cancellable? cancellable) throws Error, IOError {
			size_t header_size = 40;
			if (input.get_available () < header_size)
				yield fill_until_n_bytes_available (header_size, cancellable);

			uint16 payload_size = 0;
			unowned uint8[] size_buf = ((uint8[]) &payload_size)[:2];
			input.peek (size_buf, 4);
			payload_size = uint16.from_big_endian (payload_size);

			size_t full_size = header_size + payload_size;
			if (input.get_available () < full_size)
				yield fill_until_n_bytes_available (full_size, cancellable);

			var datagram = new uint8[full_size];
			input.read (datagram, cancellable);

			return new Bytes.take ((owned) datagram);
		}

		private async void fill_until_n_bytes_available (size_t minimum, Cancellable? cancellable) throws Error, IOError {
			size_t available = input.get_available ();
			while (available < minimum) {
				if (input.get_buffer_size () < minimum)
					input.set_buffer_size (minimum);

				ssize_t n;
				try {
					n = yield input.fill_async ((ssize_t) (input.get_buffer_size () - available), Priority.DEFAULT,
						cancellable);
				} catch (GLib.Error e) {
					throw new Error.TRANSPORT ("Connection closed");
				}

				if (n == 0)
					throw new Error.TRANSPORT ("Connection closed");

				available += n;
			}
		}

		[CCode (cname = "g_tls_connection_openssl_get_ssl")]
		private extern static unowned SSL get_ssl_handle_from_connection (void * connection);

		[CCode (cname = "g_tls_connection_openssl_get_connection_from_ssl")]
		private extern static void * get_connection_from_ssl_handle (SSL ssl);
	}

	public sealed class QuicTunnelConnection : Object, TunnelConnection, AsyncInitable {
		public InetSocketAddress address {
			get;
			construct;
		}

		public NetworkStack netstack {
			get;
			construct;
		}

		public NetworkStack tunnel_netstack {
			get {
				return _tunnel_netstack;
			}
		}

		public TunnelKey local_keypair {
			get;
			construct;
		}

		public TunnelKey remote_pubkey {
			get;
			construct;
		}

		public InetAddress remote_address {
			get {
				return tunnel_params.server_address;
			}
		}

		public uint16 remote_rsd_port {
			get {
				return tunnel_params.server_rsd_port;
			}
		}

		private State state = ACTIVE;
		private Promise<bool> establish_request = new Promise<bool> ();
		private Promise<bool> close_request = new Promise<bool> ();

		private Stream? control_stream;
		private TunnelParameters tunnel_params;
		private VirtualNetworkStack? _tunnel_netstack;

		private Gee.Map<int64?, Stream> streams = new Gee.HashMap<int64?, Stream> (Numeric.int64_hash, Numeric.int64_equal);
		private Gee.Queue<Bytes> tx_datagrams = new Gee.ArrayQueue<Bytes> ();

		private DatagramBasedSource? rx_source;
		private uint8[] rx_buf = new uint8[MAX_UDP_PAYLOAD_SIZE];
		private uint8[] tx_buf = new uint8[MAX_UDP_PAYLOAD_SIZE];
		private Source? write_idle;
		private Source? expiry_timer;

		private UdpSocket? socket;
		private uint8[] raw_local_address;
		private NGTcp2.Connection? connection;
		private NGTcp2.Crypto.ConnectionRef connection_ref;
		private OpenSSL.SSLContext ssl_ctx;
		private OpenSSL.SSL ssl;

		private MainContext main_context;

		private Cancellable io_cancellable = new Cancellable ();

		private enum State {
			ACTIVE,
			CLOSE_SCHEDULED,
			CLOSE_WRITTEN,
		}

		private const string ALPN = "\x1bRemotePairingTunnelProtocol";

		private const size_t NETWORK_MTU = 1500;

		private const size_t ETHERNET_HEADER_SIZE = 14;
		private const size_t IPV6_HEADER_SIZE = 40;
		private const size_t UDP_HEADER_SIZE = 8;
		private const size_t QUIC_HEADER_MAX_SIZE = 38;

		private const size_t MAX_UDP_PAYLOAD_SIZE = NETWORK_MTU - ETHERNET_HEADER_SIZE - IPV6_HEADER_SIZE - UDP_HEADER_SIZE;
		private const size_t PREFERRED_MTU = MAX_UDP_PAYLOAD_SIZE - QUIC_HEADER_MAX_SIZE;

		private const size_t MAX_QUIC_DATAGRAM_SIZE = 14000;
		private const NGTcp2.Duration KEEP_ALIVE_TIMEOUT = 15ULL * NGTcp2.SECONDS;

		public static async QuicTunnelConnection open (InetSocketAddress address, NetworkStack netstack, TunnelKey local_keypair,
				TunnelKey remote_pubkey, Cancellable? cancellable = null) throws Error, IOError {
			var connection = new QuicTunnelConnection (address, netstack, local_keypair, remote_pubkey);

			try {
				yield connection.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return connection;
		}

		private QuicTunnelConnection (InetSocketAddress address, NetworkStack netstack, TunnelKey local_keypair,
				TunnelKey remote_pubkey) {
			Object (
				address: address,
				netstack: netstack,
				local_keypair: local_keypair,
				remote_pubkey: remote_pubkey
			);
		}

		construct {
			connection_ref.get_conn = conn_ref => {
				QuicTunnelConnection * self = conn_ref.user_data;
				return self->connection;
			};
			connection_ref.user_data = this;

			ssl_ctx = new OpenSSL.SSLContext (OpenSSL.SSLMethod.tls_client ());
			NGTcp2.Crypto.Quictls.configure_client_context (ssl_ctx);
			ssl_ctx.use_certificate (make_certificate (local_keypair.handle));
			ssl_ctx.use_private_key (local_keypair.handle);

			ssl = new OpenSSL.SSL (ssl_ctx);
			ssl.set_app_data (&connection_ref);
			ssl.set_connect_state ();
			ssl.set_alpn_protos (ALPN.data);
			ssl.set_quic_transport_version (OpenSSL.TLSExtensionType.quic_transport_parameters);

			main_context = MainContext.ref_thread_default ();
		}

		public override void dispose () {
			perform_teardown ();

			base.dispose ();
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			socket = netstack.create_udp_socket ();
			socket.bind ((InetSocketAddress) Object.new (typeof (InetSocketAddress),
				address: netstack.listener_ip,
				scope_id: netstack.scope_id
			));
			socket.socket_connect (address, cancellable);

			raw_local_address = address_to_native (socket.get_local_address ());
			uint8[] raw_remote_address = address_to_native (address);

			var dcid = make_connection_id (NGTcp2.MIN_INITIAL_DCIDLEN);
			var scid = make_connection_id (NGTcp2.MIN_INITIAL_DCIDLEN);

			var path = NGTcp2.Path () {
				local = NGTcp2.Address () { addr = raw_local_address },
				remote = NGTcp2.Address () { addr = raw_remote_address },
			};

			var callbacks = NGTcp2.Callbacks () {
				get_new_connection_id = on_get_new_connection_id,
				extend_max_local_streams_bidi = (conn, max_streams, user_data) => {
					QuicTunnelConnection * self = user_data;
					return self->on_extend_max_local_streams_bidi (max_streams);
				},
				stream_close = (conn, flags, stream_id, app_error_code, user_data, stream_user_data) => {
					QuicTunnelConnection * self = user_data;
					return self->on_stream_close (flags, stream_id, app_error_code);
				},
				recv_stream_data = (conn, flags, stream_id, offset, data, user_data, stream_user_data) => {
					QuicTunnelConnection * self = user_data;
					return self->on_recv_stream_data (flags, stream_id, offset, data);
				},
				recv_datagram = (conn, flags, data, user_data) => {
					QuicTunnelConnection * self = user_data;
					return self->on_recv_datagram (flags, data);
				},
				rand = on_rand,
				client_initial = NGTcp2.Crypto.client_initial_cb,
				recv_crypto_data = NGTcp2.Crypto.recv_crypto_data_cb,
				encrypt = NGTcp2.Crypto.encrypt_cb,
				decrypt = NGTcp2.Crypto.decrypt_cb,
				hp_mask = NGTcp2.Crypto.hp_mask_cb,
				recv_retry = NGTcp2.Crypto.recv_retry_cb,
				update_key = NGTcp2.Crypto.update_key_cb,
				delete_crypto_aead_ctx = NGTcp2.Crypto.delete_crypto_aead_ctx_cb,
				delete_crypto_cipher_ctx = NGTcp2.Crypto.delete_crypto_cipher_ctx_cb,
				get_path_challenge_data = NGTcp2.Crypto.get_path_challenge_data_cb,
				version_negotiation = NGTcp2.Crypto.version_negotiation_cb,
			};

			var settings = NGTcp2.Settings.make_default ();
			settings.initial_ts = make_timestamp ();
			settings.max_tx_udp_payload_size = MAX_UDP_PAYLOAD_SIZE;
			settings.no_tx_udp_payload_size_shaping = true;
			settings.handshake_timeout = 5ULL * NGTcp2.SECONDS;

			var transport_params = NGTcp2.TransportParams.make_default ();
			transport_params.max_datagram_frame_size = MAX_QUIC_DATAGRAM_SIZE;
			transport_params.max_idle_timeout = 30ULL * NGTcp2.SECONDS;
			transport_params.initial_max_data = 1048576;
			transport_params.initial_max_stream_data_bidi_local = 1048576;

			NGTcp2.Connection.make_client (out connection, dcid, scid, path, NGTcp2.ProtocolVersion.V1, callbacks,
				settings, transport_params, null, this);
			connection.set_tls_native_handle (ssl);
			connection.set_keep_alive_timeout (KEEP_ALIVE_TIMEOUT);

			rx_source = socket.datagram_based.create_source (IOCondition.IN, io_cancellable);
			rx_source.set_callback (on_socket_readable);
			rx_source.attach (main_context);

			process_pending_writes ();

			yield establish_request.future.wait_async (cancellable);

			return true;
		}

		private void on_control_stream_opened () {
			var zeroed_padding_packet = new uint8[PREFERRED_MTU];
			send_datagram (new Bytes.take ((owned) zeroed_padding_packet));

			control_stream.send (make_handshake_request (PREFERRED_MTU).get_data ());
		}

		private void on_control_stream_response (string json) throws Error {
			tunnel_params = TunnelParameters.from_json (new JsonObjectReader (json));

			_tunnel_netstack = new VirtualNetworkStack (null, tunnel_params.address, tunnel_params.mtu);
			_tunnel_netstack.outgoing_datagram.connect (send_datagram);

			establish_request.resolve (true);
		}

		public async void close (Cancellable? cancellable) throws IOError {
			if (connection == null)
				return;

			state = CLOSE_SCHEDULED;
			process_pending_writes ();

			try {
				yield close_request.future.wait_async (cancellable);
			} catch (Error e) {
				assert_not_reached ();
			}
		}

		private void perform_teardown () {
			if (close_request.future.ready)
				return;

			connection = null;
			socket = null;

			io_cancellable.cancel ();

			if (rx_source != null) {
				rx_source.destroy ();
				rx_source = null;
			}

			if (write_idle != null) {
				write_idle.destroy ();
				write_idle = null;
			}

			if (expiry_timer != null) {
				expiry_timer.destroy ();
				expiry_timer = null;
			}

			if (_tunnel_netstack != null)
				_tunnel_netstack.stop ();

			close_request.resolve (true);

			closed ();
		}

		private void on_stream_data_available (Stream stream, uint8[] data, out size_t consumed) {
			if (stream != control_stream || establish_request.future.ready) {
				consumed = data.length;
				return;
			}

			consumed = 0;

			if (data.length < 12)
				return;

			var buf = new Buffer (new Bytes.static (data), BIG_ENDIAN);

			try {
				string magic = buf.read_fixed_string (0, 8);
				if (magic != "CDTunnel")
					throw new Error.PROTOCOL ("Invalid magic");

				size_t body_size = buf.read_uint16 (8);
				size_t body_available = data.length - 10;
				if (body_available < body_size)
					return;

				var raw_json = new uint8[body_size + 1];
				Memory.copy (raw_json, data + 10, body_size);

				unowned string json = (string) raw_json;
				if (!json.validate ())
					throw new Error.PROTOCOL ("Invalid UTF-8");

				on_control_stream_response (json);

				consumed = 10 + body_size;
			} catch (Error e) {
				if (!establish_request.future.ready)
					establish_request.reject (e);
			}
		}

		private void send_datagram (Bytes datagram) {
			tx_datagrams.offer (datagram);
			process_pending_writes ();
		}

		private bool on_socket_readable (DatagramBased datagram_based, IOCondition condition) {
			try {
				InetSocketAddress remote_address;
				size_t n = Udp.recv (rx_buf, socket.datagram_based, io_cancellable, out remote_address);

				uint8[] raw_remote_address = address_to_native (remote_address);

				var path = NGTcp2.Path () {
					local = NGTcp2.Address () { addr = raw_local_address },
					remote = NGTcp2.Address () { addr = raw_remote_address },
				};

				unowned uint8[] data = rx_buf[:n];

				var res = connection.read_packet (path, null, data, make_timestamp ());
				if (res == NGTcp2.ErrorCode.DRAINING)
					perform_teardown ();
			} catch (GLib.Error e) {
				return Source.REMOVE;
			} finally {
				process_pending_writes ();
			}

			return Source.CONTINUE;
		}

		private void process_pending_writes () {
			if (connection == null || write_idle != null)
				return;

			var source = new IdleSource ();
			source.set_callback (() => {
				write_idle = null;
				do_process_pending_writes ();
				return Source.REMOVE;
			});
			source.attach (main_context);
			write_idle = source;
		}

		private void do_process_pending_writes () {
			var ts = make_timestamp ();

			var pi = NGTcp2.PacketInfo ();
			Gee.Iterator<Stream> stream_iter = streams.values.iterator ();
			while (true) {
				ssize_t n = -1;

				if (state == CLOSE_SCHEDULED) {
					var error = NGTcp2.ConnectionError.application (0);
					n = connection.write_connection_close (null, &pi, tx_buf, error, ts);
					state = CLOSE_WRITTEN;
				} else {
					Bytes? datagram = tx_datagrams.peek ();
					if (datagram != null) {
						int accepted = -1;
						n = connection.write_datagram (null, null, tx_buf, &accepted, NGTcp2.WriteDatagramFlags.MORE, 0,
							datagram.get_data (), ts);
						if (accepted > 0)
							tx_datagrams.poll ();
					} else {
						Stream? stream = null;
						unowned uint8[]? data = null;
						NGTcp2.WriteStreamFlags stream_flags = MORE;

						while (stream == null && stream_iter.next ()) {
							Stream s = stream_iter.get ();
							uint64 len = s.tx_buf.len;
							uint64 limit = 0;

							if (len != 0 && (limit = connection.get_max_stream_data_left (s.id)) != 0) {
								stream = s;
								data = s.tx_buf.data[:(int) uint64.min (len, limit)];
								break;
							}
						}

						ssize_t datalen = 0;
						n = connection.write_stream (null, &pi, tx_buf, &datalen, stream_flags,
							(stream != null) ? stream.id : -1, data, ts);
						if (datalen > 0)
							stream.tx_buf.remove_range (0, (uint) datalen);
					}
				}

				if (n == 0)
					break;
				if (n == NGTcp2.ErrorCode.WRITE_MORE)
					continue;
				if (n == NGTcp2.ErrorCode.CLOSING) {
					perform_teardown ();
					break;
				}
				if (n < 0)
					break;

				try {
					Udp.send (tx_buf[:n], socket.datagram_based, io_cancellable);
				} catch (GLib.Error e) {
					continue;
				}
			}

			if (expiry_timer != null) {
				expiry_timer.destroy ();
				expiry_timer = null;
			}

			if (close_request.future.ready)
				return;

			NGTcp2.Timestamp expiry = connection.get_expiry ();
			if (expiry == uint64.MAX)
				return;

			NGTcp2.Timestamp now = make_timestamp ();

			uint delta_msec;
			if (expiry > now) {
				uint64 delta_nsec = expiry - now;
				delta_msec = (uint) (delta_nsec / 1000000ULL);
			} else {
				delta_msec = 1;
			}

			var source = new TimeoutSource (delta_msec);
			source.set_callback (on_expiry);
			source.attach (main_context);
			expiry_timer = source;
		}

		private bool on_expiry () {
			int res = connection.handle_expiry (make_timestamp ());
			if (res != 0) {
				perform_teardown ();
				return Source.REMOVE;
			}

			process_pending_writes ();

			return Source.REMOVE;
		}

		private static int on_get_new_connection_id (NGTcp2.Connection conn, out NGTcp2.ConnectionID cid, uint8[] token,
				size_t cidlen, void * user_data) {
			cid = make_connection_id (cidlen);

			OpenSSL.Rng.generate (token[:NGTcp2.STATELESS_RESET_TOKENLEN]);

			return 0;
		}

		private int on_extend_max_local_streams_bidi (uint64 max_streams) {
			if (control_stream == null) {
				control_stream = open_bidi_stream ();

				var source = new IdleSource ();
				source.set_callback (() => {
					on_control_stream_opened ();
					return Source.REMOVE;
				});
				source.attach (main_context);
			}

			return 0;
		}

		private int on_stream_close (uint32 flags, int64 stream_id, uint64 app_error_code) {
			if (!establish_request.future.ready) {
				establish_request.reject (new Error.TRANSPORT ("Connection closed early with QUIC app error code %" +
					uint64.FORMAT_MODIFIER + "u", app_error_code));
			}

			perform_teardown ();

			return 0;
		}

		private int on_recv_stream_data (uint32 flags, int64 stream_id, uint64 offset, uint8[] data) {
			Stream? stream = streams[stream_id];
			if (stream != null)
				stream.on_recv (data);

			return 0;
		}

		private int on_recv_datagram (uint32 flags, uint8[] data) {
			try {
				_tunnel_netstack.handle_incoming_datagram (new Bytes (data));
			} catch (Error e) {
			}

			return 0;
		}

		private static void on_rand (uint8[] dest, NGTcp2.RNGContext rand_ctx) {
			OpenSSL.Rng.generate (dest);
		}

		private static uint8[] address_to_native (SocketAddress address) {
			var size = address.get_native_size ();
			var buf = new uint8[size];
			try {
				address.to_native (buf, size);
			} catch (GLib.Error e) {
				assert_not_reached ();
			}
			return buf;
		}

		private static NGTcp2.ConnectionID make_connection_id (size_t len) {
			var cid = NGTcp2.ConnectionID () {
				datalen = len,
			};

			NGTcp2.ConnectionID * mutable_cid = &cid;
			OpenSSL.Rng.generate (mutable_cid->data[:len]);

			return cid;
		}

		private static NGTcp2.Timestamp make_timestamp () {
			return get_monotonic_time () * NGTcp2.MICROSECONDS;
		}

		private static X509 make_certificate (Key keypair) {
			var cert = new X509 ();
			cert.get_serial_number ().set_uint64 (1);
			cert.get_not_before ().adjust (0);
			cert.get_not_after ().adjust (5260000);

			unowned X509.Name name = cert.get_subject_name ();
			cert.set_issuer_name (name);
			cert.set_pubkey (keypair);

			var mc = new MessageDigestContext ();
			mc.digest_sign_init (null, null, null, keypair);
			cert.sign_ctx (mc);

			return cert;
		}

		private Stream open_bidi_stream () {
			int64 id;
			connection.open_bidi_stream (out id, null);

			var stream = new Stream (this, id);
			streams[id] = stream;

			return stream;
		}

		private class Stream {
			public int64 id;

			private weak QuicTunnelConnection parent;

			public ByteArray rx_buf = new ByteArray.sized (256);
			public ByteArray tx_buf = new ByteArray.sized (128);

			public Stream (QuicTunnelConnection parent, int64 id) {
				this.parent = parent;
				this.id = id;
			}

			public void send (uint8[] data) {
				tx_buf.append (data);
				parent.process_pending_writes ();
			}

			public void on_recv (uint8[] data) {
				rx_buf.append (data);

				size_t consumed;
				parent.on_stream_data_available (this, rx_buf.data, out consumed);

				if (consumed != 0)
					rx_buf.remove_range (0, (uint) consumed);
			}
		}
	}

	public sealed class TunnelKey {
		public Key handle;

		public TunnelKey (owned Key handle) {
			this.handle = (owned) handle;
		}
	}

	public sealed class AppService : TrustedService {
		public static async AppService open (IOStream stream, Cancellable? cancellable = null) throws Error, IOError {
			var service = new AppService (stream);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private AppService (IOStream stream) {
			Object (stream: stream);
		}

		public async Gee.List<ApplicationInfo> enumerate_applications (Cancellable? cancellable = null) throws Error, IOError {
			Bytes input = new XpcObjectBuilder ()
				.begin_dictionary ()
					.set_member_name ("includeDefaultApps")
					.add_bool_value (true)
					.set_member_name ("includeRemovableApps")
					.add_bool_value (true)
					.set_member_name ("includeInternalApps")
					.add_bool_value (true)
					.set_member_name ("includeHiddenApps")
					.add_bool_value (true)
					.set_member_name ("includeAppClips")
					.add_bool_value (true)
				.end_dictionary ()
				.build ();
			var response = yield invoke ("com.apple.coredevice.feature.listapps", input, cancellable);

			var applications = new Gee.ArrayList<ApplicationInfo> ();
			uint n = response.count_elements ();
			for (uint i = 0; i != n; i++) {
				response.read_element (i);

				string bundle_identifier = response
					.read_member ("bundleIdentifier")
					.get_string_value ();
				response.end_member ();

				string? bundle_version = null;
				if (response.has_member ("bundleVersion")) {
					bundle_version = response
						.read_member ("bundleVersion")
						.get_string_value ();
					response.end_member ();
				}

				string name = response
					.read_member ("name")
					.get_string_value ();
				response.end_member ();

				string? version = null;
				if (response.has_member ("version")) {
					version = response
						.read_member ("version")
						.get_string_value ();
					response.end_member ();
				}

				string path = response
					.read_member ("path")
					.get_string_value ();
				response.end_member ();

				bool is_first_party = response
					.read_member ("isFirstParty")
					.get_bool_value ();
				response.end_member ();

				bool is_developer_app = response
					.read_member ("isDeveloperApp")
					.get_bool_value ();
				response.end_member ();

				bool is_removable = response
					.read_member ("isRemovable")
					.get_bool_value ();
				response.end_member ();

				bool is_internal = response
					.read_member ("isInternal")
					.get_bool_value ();
				response.end_member ();

				bool is_hidden = response
					.read_member ("isHidden")
					.get_bool_value ();
				response.end_member ();

				bool is_app_clip = response
					.read_member ("isAppClip")
					.get_bool_value ();
				response.end_member ();

				applications.add (new ApplicationInfo () {
					bundle_identifier = bundle_identifier,
					bundle_version = bundle_version,
					name = name,
					version = version,
					path = path,
					is_first_party = is_first_party,
					is_developer_app = is_developer_app,
					is_removable = is_removable,
					is_internal = is_internal,
					is_hidden = is_hidden,
					is_app_clip = is_app_clip,
				});

				response.end_element ();
			}

			return applications;
		}

		public async Gee.List<ProcessInfo> enumerate_processes (Cancellable? cancellable = null) throws Error, IOError {
			var response = yield invoke ("com.apple.coredevice.feature.listprocesses", null, cancellable);

			var processes = new Gee.ArrayList<ProcessInfo> ();
			uint n = response
				.read_member ("processTokens")
				.count_elements ();
			for (uint i = 0; i != n; i++) {
				response.read_element (i);

				int64 pid = response
					.read_member ("processIdentifier")
					.get_int64_value ();
				response.end_member ();

				string url = response
					.read_member ("executableURL")
					.read_member ("relative")
					.get_string_value ();
				response
					.end_member ()
					.end_member ();

				if (!url.has_prefix ("file://"))
					throw new Error.PROTOCOL ("Unsupported URL: %s", url);

				string path = url[7:];

				processes.add (new ProcessInfo () {
					pid = (uint) pid,
					path = path,
				});

				response.end_element ();
			}

			return processes;
		}

		public sealed class ApplicationInfo {
			public string bundle_identifier;
			public string? bundle_version;
			public string name;
			public string? version;
			public string path;
			public bool is_first_party;
			public bool is_developer_app;
			public bool is_removable;
			public bool is_internal;
			public bool is_hidden;
			public bool is_app_clip;
		}

		public sealed class ProcessInfo {
			public uint pid;
			public string path;
		}
	}

	public abstract class TrustedService : Object, AsyncInitable {
		public IOStream stream {
			get;
			construct;
		}

		private XpcConnection connection;

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			connection = new XpcConnection (stream);
			connection.activate ();

			return true;
		}

		public void close () {
			connection.cancel ();
		}

		protected async VariantReader invoke (string feature_identifier, Bytes? input = null, Cancellable? cancellable)
				throws Error, IOError {
			var request = new XpcBodyBuilder ()
				.begin_dictionary ()
					.set_member_name ("CoreDevice.featureIdentifier")
					.add_string_value (feature_identifier)
					.set_member_name ("CoreDevice.action")
					.begin_dictionary ()
					.end_dictionary ()
					.set_member_name ("CoreDevice.input");

			if (input != null)
				request.add_raw_value (input);
			else
				request.add_null_value ();

			add_standard_request_values (request);
			request.end_dictionary ();

			XpcMessage raw_response = yield connection.request (request.build (), cancellable);

			var response = new VariantReader (raw_response.body);
			response.read_member ("CoreDevice.output");
			return response;
		}

		public static void add_standard_request_values (ObjectBuilder builder) {
			builder
				.set_member_name ("CoreDevice.invocationIdentifier")
				.add_string_value (Uuid.string_random ().up ())
				.set_member_name ("CoreDevice.CoreDeviceDDIProtocolVersion")
				.add_int64_value (0)
				.set_member_name ("CoreDevice.coreDeviceVersion")
				.begin_dictionary ()
					.set_member_name ("originalComponentsCount")
					.add_int64_value (2)
					.set_member_name ("components")
					.begin_array ()
						.add_uint64_value (348)
						.add_uint64_value (1)
						.add_uint64_value (0)
						.add_uint64_value (0)
						.add_uint64_value (0)
					.end_array ()
					.set_member_name ("stringValue")
					.add_string_value ("348.1")
				.end_dictionary ()
				.set_member_name ("CoreDevice.deviceIdentifier")
				.add_string_value (make_host_identifier ());
		}
	}

	public sealed class XpcConnection : Object {
		public signal void close (Error? error);
		public signal void message (XpcMessage msg);

		public IOStream stream {
			get;
			construct;
		}

		public State state {
			get;
			private set;
			default = INACTIVE;
		}

		private Error? pending_error;

		private Promise<bool> ready = new Promise<bool> ();
		private XpcMessage? root_helo;
		private XpcMessage? reply_helo;
		private Gee.Map<uint64?, PendingResponse> pending_responses =
			new Gee.HashMap<uint64?, PendingResponse> (Numeric.uint64_hash, Numeric.uint64_equal);

		private NGHttp2.Session session;
		private Stream root_stream;
		private Stream reply_stream;
		private uint next_message_id = 1;

		private bool is_processing_messages;

		private ByteArray? send_queue;
		private Source? send_source;

		private Cancellable io_cancellable = new Cancellable ();

		public enum State {
			INACTIVE,
			ACTIVE,
			CLOSED,
		}

		public XpcConnection (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			NGHttp2.SessionCallbacks callbacks;
			NGHttp2.SessionCallbacks.make (out callbacks);

			callbacks.set_send_callback ((session, data, flags, user_data) => {
				XpcConnection * self = user_data;
				return self->on_send (data, flags);
			});
			callbacks.set_on_frame_send_callback ((session, frame, user_data) => {
				XpcConnection * self = user_data;
				return self->on_frame_send (frame);
			});
			callbacks.set_on_frame_not_send_callback ((session, frame, lib_error_code, user_data) => {
				XpcConnection * self = user_data;
				return self->on_frame_not_send (frame, lib_error_code);
			});
			callbacks.set_on_data_chunk_recv_callback ((session, flags, stream_id, data, user_data) => {
				XpcConnection * self = user_data;
				return self->on_data_chunk_recv (flags, stream_id, data);
			});
			callbacks.set_on_frame_recv_callback ((session, frame, user_data) => {
				XpcConnection * self = user_data;
				return self->on_frame_recv (frame);
			});
			callbacks.set_on_stream_close_callback ((session, stream_id, error_code, user_data) => {
				XpcConnection * self = user_data;
				return self->on_stream_close (stream_id, error_code);
			});

			NGHttp2.Option option;
			NGHttp2.Option.make (out option);
			option.set_no_auto_window_update (true);
			option.set_peer_max_concurrent_streams (100);
			option.set_no_http_messaging (true);
			// option.set_no_http_semantics (true);
			option.set_no_closed_streams (true);

			NGHttp2.Session.make_client (out session, callbacks, this, option);
		}

		public void activate () {
			do_activate.begin ();
		}

		private async void do_activate () {
			try {
				is_processing_messages = true;
				process_incoming_messages.begin ();

				session.submit_settings (NGHttp2.Flag.NONE, {
					{ MAX_CONCURRENT_STREAMS, 100 },
					{ INITIAL_WINDOW_SIZE, 1048576 },
				});

				session.set_local_window_size (NGHttp2.Flag.NONE, 0, 1048576);

				root_stream = make_stream ();

				Bytes header_request = new XpcMessageBuilder (HEADER)
					.add_body (new XpcBodyBuilder ()
						.begin_dictionary ()
						.end_dictionary ()
						.build ()
					)
					.build ();
				yield root_stream.submit_data (header_request, io_cancellable);

				Bytes ping_request = new XpcMessageBuilder (PING)
					.build ();
				yield root_stream.submit_data (ping_request, io_cancellable);

				reply_stream = make_stream ();

				Bytes open_reply_channel_request = new XpcMessageBuilder (HEADER)
					.add_flags (HEADER_OPENS_REPLY_CHANNEL)
					.build ();
				yield reply_stream.submit_data (open_reply_channel_request, io_cancellable);
			} catch (GLib.Error e) {
				if (e is Error && pending_error == null)
					pending_error = (Error) e;
				cancel ();
			}
		}

		public void cancel () {
			io_cancellable.cancel ();
		}

		public async PeerInfo wait_until_ready (Cancellable? cancellable = null) throws Error, IOError {
			yield ready.future.wait_async (cancellable);

			return new PeerInfo () {
				metadata = root_helo.body,
			};
		}

		public async XpcMessage request (Bytes body, Cancellable? cancellable = null) throws Error, IOError {
			uint64 request_id = make_message_id ();

			Bytes raw_request = new XpcMessageBuilder (MSG)
				.add_flags (WANTS_REPLY)
				.add_id (request_id)
				.add_body (body)
				.build ();

			bool waiting = false;

			var pending = new PendingResponse (() => {
				if (waiting)
					request.callback ();
				return Source.REMOVE;
			});
			pending_responses[request_id] = pending;

			try {
				yield root_stream.submit_data (raw_request, cancellable);
			} catch (Error e) {
				if (pending_responses.unset (request_id))
					pending.complete_with_error (e);
			}

			if (!pending.completed) {
				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (() => {
					if (pending_responses.unset (request_id))
						pending.complete_with_error (new IOError.CANCELLED ("Operation was cancelled"));
					return false;
				});
				cancel_source.attach (MainContext.get_thread_default ());

				waiting = true;
				yield;
				waiting = false;

				cancel_source.destroy ();
			}

			cancellable.set_error_if_cancelled ();

			if (pending.error != null)
				throw_api_error (pending.error);

			return pending.result;
		}

		private class PendingResponse {
			private SourceFunc? handler;

			public bool completed {
				get {
					return result != null || error != null;
				}
			}

			public XpcMessage? result {
				get;
				private set;
			}

			public GLib.Error? error {
				get;
				private set;
			}

			public PendingResponse (owned SourceFunc handler) {
				this.handler = (owned) handler;
			}

			public void complete_with_result (XpcMessage result) {
				if (completed)
					return;
				this.result = result;
				handler ();
				handler = null;
			}

			public void complete_with_error (GLib.Error error) {
				if (completed)
					return;
				this.error = error;
				handler ();
				handler = null;
			}
		}

		public async void post (Bytes body, Cancellable? cancellable = null) throws Error, IOError {
			Bytes raw_request = new XpcMessageBuilder (MSG)
				.add_id (make_message_id ())
				.add_body (body)
				.build ();

			yield root_stream.submit_data (raw_request, cancellable);
		}

		private void on_header (XpcMessage msg, Stream sender) {
			if (sender == root_stream) {
				if (root_helo == null)
					root_helo = msg;
			} else if (sender == reply_stream) {
				if (reply_helo == null)
					reply_helo = msg;
			}

			if (!ready.future.ready && root_helo != null && reply_helo != null)
				ready.resolve (true);
		}

		private void on_reply (XpcMessage msg, Stream sender) {
			if (sender != reply_stream)
				return;

			PendingResponse response;
			if (!pending_responses.unset (msg.id, out response))
				return;

			if (msg.body != null)
				response.complete_with_result (msg);
			else
				response.complete_with_error (new Error.NOT_SUPPORTED ("Request not supported"));
		}

		private void maybe_send_pending () {
			while (session.want_write ()) {
				bool would_block = send_source != null && send_queue == null;
				if (would_block)
					break;

				session.send ();
			}
		}

		private async void process_incoming_messages () {
			InputStream input = stream.get_input_stream ();

			var buffer = new uint8[4096];

			while (is_processing_messages) {
				try {
					ssize_t n = yield input.read_async (buffer, Priority.DEFAULT, io_cancellable);
					if (n == 0) {
						is_processing_messages = false;
						continue;
					}

					ssize_t result = session.mem_recv (buffer[:n]);
					if (result < 0)
						throw new Error.PROTOCOL ("%s", NGHttp2.strerror (result));

					session.consume_connection (n);
				} catch (GLib.Error e) {
					if (e is Error && pending_error == null)
						pending_error = (Error) e;
					is_processing_messages = false;
				}
			}

			Error error = (pending_error != null)
				? pending_error
				: new Error.TRANSPORT ("Connection closed");

			foreach (var r in pending_responses.values.to_array ())
				r.complete_with_error (error);
			pending_responses.clear ();

			if (!ready.future.ready)
				ready.reject (error);

			state = CLOSED;

			close (pending_error);
			pending_error = null;
		}

		private ssize_t on_send (uint8[] data, int flags) {
			if (send_source == null) {
				send_queue = new ByteArray.sized (1024);

				var source = new IdleSource ();
				source.set_callback (() => {
					do_send.begin ();
					return Source.REMOVE;
				});
				source.attach (MainContext.get_thread_default ());
				send_source = source;
			}

			if (send_queue == null)
				return NGHttp2.ErrorCode.WOULDBLOCK;

			send_queue.append (data);
			return data.length;
		}

		private async void do_send () {
			uint8[] buffer = send_queue.steal ();
			send_queue = null;

			try {
				size_t bytes_written;
				yield stream.get_output_stream ().write_all_async (buffer, Priority.DEFAULT, io_cancellable,
					out bytes_written);
			} catch (GLib.Error e) {
			}

			send_source = null;

			maybe_send_pending ();
		}

		private int on_frame_send (NGHttp2.Frame frame) {
			if (frame.hd.type == DATA)
				find_stream_by_id (frame.hd.stream_id).on_data_frame_send ();
			return 0;
		}

		private int on_frame_not_send (NGHttp2.Frame frame, NGHttp2.ErrorCode lib_error_code) {
			if (frame.hd.type == DATA)
				find_stream_by_id (frame.hd.stream_id).on_data_frame_not_send (lib_error_code);
			return 0;
		}

		private int on_data_chunk_recv (uint8 flags, int32 stream_id, uint8[] data) {
			return find_stream_by_id (stream_id).on_data_frame_recv_chunk (data);
		}

		private int on_frame_recv (NGHttp2.Frame frame) {
			if (frame.hd.type == DATA)
				return find_stream_by_id (frame.hd.stream_id).on_data_frame_recv_end (frame);
			return 0;
		}

		private int on_stream_close (int32 stream_id, uint32 error_code) {
			io_cancellable.cancel ();
			return 0;
		}

		private Stream make_stream () {
			int stream_id = session.submit_headers (NGHttp2.Flag.NONE, -1, null, {}, null);
			maybe_send_pending ();

			return new Stream (this, stream_id);
		}

		private Stream? find_stream_by_id (int32 id) {
			if (root_stream.id == id)
				return root_stream;
			if (reply_stream.id == id)
				return reply_stream;
			return null;
		}

		private uint make_message_id () {
			uint id = next_message_id;
			next_message_id += 2;
			return id;
		}

		private class Stream {
			public int32 id;

			private weak XpcConnection parent;

			private Gee.Deque<SubmitOperation> submissions = new Gee.ArrayQueue<SubmitOperation> ();
			private SubmitOperation? current_submission = null;
			private ByteArray incoming_message = new ByteArray ();

			public Stream (XpcConnection parent, int32 id) {
				this.parent = parent;
				this.id = id;
			}

			public async void submit_data (Bytes bytes, Cancellable? cancellable) throws Error, IOError {
				bool waiting = false;

				var op = new SubmitOperation (bytes, () => {
					if (waiting)
						submit_data.callback ();
					return Source.REMOVE;
				});

				var cancel_source = new CancellableSource (cancellable);
				cancel_source.set_callback (() => {
					op.state = CANCELLED;
					op.callback ();
					return Source.REMOVE;
				});
				cancel_source.attach (MainContext.get_thread_default ());

				submissions.offer_tail (op);
				maybe_submit_data ();

				if (op.state < SubmitOperation.State.SUBMITTED) {
					waiting = true;
					yield;
					waiting = false;
				}

				cancel_source.destroy ();

				if (op.state == CANCELLED && current_submission != op)
					submissions.remove (op);

				cancellable.set_error_if_cancelled ();

				if (op.state == ERROR)
					throw new Error.TRANSPORT ("%s", NGHttp2.strerror (op.error_code));
			}

			private void maybe_submit_data () {
				if (current_submission != null)
					return;

				SubmitOperation? op = submissions.peek_head ();
				if (op == null)
					return;
				current_submission = op;

				var data_prd = NGHttp2.DataProvider ();
				data_prd.source.ptr = op;
				data_prd.read_callback = on_data_provider_read;
				int result = parent.session.submit_data (NGHttp2.DataFlag.NO_END_STREAM, id, data_prd);
				if (result < 0) {
					while (true) {
						op = submissions.poll_head ();
						if (op == null)
							break;
						op.state = ERROR;
						op.error_code = (NGHttp2.ErrorCode) result;
						op.callback ();
					}
					current_submission = null;
					return;
				}

				parent.maybe_send_pending ();
			}

			private static ssize_t on_data_provider_read (NGHttp2.Session session, int32 stream_id, uint8[] buf,
					ref uint32 data_flags, NGHttp2.DataSource source, void * user_data) {
				var op = (SubmitOperation) source.ptr;

				unowned uint8[] data = op.bytes.get_data ();

				uint remaining = data.length - op.cursor;
				uint n = uint.min (remaining, buf.length);
				Memory.copy (buf, (uint8 *) data + op.cursor, n);

				op.cursor += n;

				if (op.cursor == data.length)
					data_flags |= NGHttp2.DataFlag.EOF;

				return n;
			}

			public void on_data_frame_send () {
				submissions.poll_head ().complete (SUBMITTED);
				current_submission = null;

				maybe_submit_data ();
			}

			public void on_data_frame_not_send (NGHttp2.ErrorCode lib_error_code) {
				submissions.poll_head ().complete (ERROR, lib_error_code);
				current_submission = null;

				maybe_submit_data ();
			}

			private class SubmitOperation {
				public Bytes bytes;
				public SourceFunc callback;

				public State state = PENDING;
				public NGHttp2.ErrorCode error_code;
				public uint cursor = 0;

				public enum State {
					PENDING,
					SUBMITTING,
					SUBMITTED,
					ERROR,
					CANCELLED,
				}

				public SubmitOperation (Bytes bytes, owned SourceFunc callback) {
					this.bytes = bytes;
					this.callback = (owned) callback;
				}

				public void complete (State new_state, NGHttp2.ErrorCode err = -1) {
					if (state != PENDING)
						return;
					state = new_state;
					error_code = err;
					callback ();
				}
			}

			public int on_data_frame_recv_chunk (uint8[] data) {
				incoming_message.append (data);
				return 0;
			}

			public int on_data_frame_recv_end (NGHttp2.Frame frame) {
				XpcMessage? msg;
				size_t size;
				try {
					msg = XpcMessage.try_parse (incoming_message.data, out size);
				} catch (Error e) {
					return -1;
				}
				if (msg == null)
					return 0;
				incoming_message.remove_range (0, (uint) size);

				switch (msg.type) {
					case HEADER:
						parent.on_header (msg, this);
						break;
					case MSG:
						if ((msg.flags & MessageFlags.IS_REPLY) != 0)
							parent.on_reply (msg, this);
						else if ((msg.flags & (MessageFlags.WANTS_REPLY | MessageFlags.IS_REPLY)) == 0)
							parent.message (msg);
						break;
					case PING:
						break;
				}

				return 0;
			}
		}
	}

	public sealed class PeerInfo {
		public Variant? metadata;
	}

	public sealed class XpcMessageBuilder : Object {
		private MessageType message_type;
		private MessageFlags message_flags = NONE;
		private uint64 message_id = 0;
		private Bytes? body = null;

		public XpcMessageBuilder (MessageType message_type) {
			this.message_type = message_type;
		}

		public unowned XpcMessageBuilder add_flags (MessageFlags flags) {
			message_flags = flags;
			return this;
		}

		public unowned XpcMessageBuilder add_id (uint64 id) {
			message_id = id;
			return this;
		}

		public unowned XpcMessageBuilder add_body (Bytes b) {
			body = b;
			return this;
		}

		public Bytes build () {
			var builder = new BufferBuilder (LITTLE_ENDIAN)
				.append_uint32 (XpcMessage.MAGIC)
				.append_uint8 (XpcMessage.PROTOCOL_VERSION)
				.append_uint8 (message_type)
				.append_uint16 (message_flags)
				.append_uint64 ((body != null) ? body.length : 0)
				.append_uint64 (message_id);

			if (body != null)
				builder.append_bytes (body);

			return builder.build ();
		}
	}

	public sealed class XpcMessage {
		public MessageType type;
		public MessageFlags flags;
		public uint64 id;
		public Variant? body;

		public const uint32 MAGIC = 0x29b00b92;
		public const uint8 PROTOCOL_VERSION = 1;
		public const size_t HEADER_SIZE = 24;
		public const size_t MAX_SIZE = (128 * 1024 * 1024) - 1;

		public static XpcMessage parse (uint8[] data) throws Error {
			size_t size;
			var msg = try_parse (data, out size);
			if (msg == null)
				throw new Error.INVALID_ARGUMENT ("XpcMessage is truncated");
			return msg;
		}

		public static XpcMessage? try_parse (uint8[] data, out size_t size) throws Error {
			if (data.length < HEADER_SIZE) {
				size = HEADER_SIZE;
				return null;
			}

			var buf = new Buffer (new Bytes.static (data), LITTLE_ENDIAN);

			var magic = buf.read_uint32 (0);
			if (magic != MAGIC)
				throw new Error.INVALID_ARGUMENT ("Invalid message: bad magic (0x%08x)", magic);

			var protocol_version = buf.read_uint8 (4);
			if (protocol_version != PROTOCOL_VERSION)
				throw new Error.INVALID_ARGUMENT ("Invalid message: unsupported protocol version (%u)", protocol_version);

			var raw_message_type = buf.read_uint8 (5);
			var message_type_class = (EnumClass) typeof (MessageType).class_ref ();
			if (message_type_class.get_value (raw_message_type) == null)
				throw new Error.INVALID_ARGUMENT ("Invalid message: unsupported message type (0x%x)", raw_message_type);
			var message_type = (MessageType) raw_message_type;

			MessageFlags message_flags = (MessageFlags) buf.read_uint16 (6);

			Variant? body = null;
			uint64 message_size = buf.read_uint64 (8);
			size = HEADER_SIZE + (size_t) message_size;
			if (message_size != 0) {
				if (message_size > MAX_SIZE) {
					throw new Error.INVALID_ARGUMENT ("Invalid message: too large (%" + int64.FORMAT_MODIFIER + "u)",
						message_size);
				}
				if (data.length - HEADER_SIZE < message_size)
					return null;
				body = XpcBodyParser.parse (data[HEADER_SIZE:HEADER_SIZE + message_size]);
			}

			uint64 message_id = buf.read_uint64 (16);

			return new XpcMessage (message_type, message_flags, message_id, body);
		}

		private XpcMessage (MessageType type, MessageFlags flags, uint64 id, Variant? body) {
			this.type = type;
			this.flags = flags;
			this.id = id;
			this.body = body;
		}
	}

	public enum MessageType {
		HEADER,
		MSG,
		PING;

		public static MessageType from_nick (string nick) throws Error {
			return Marshal.enum_from_nick<MessageType> (nick);
		}

		public string to_nick () {
			return Marshal.enum_to_nick<MessageType> (this);
		}
	}

	[Flags]
	public enum MessageFlags {
		NONE				= 0,
		WANTS_REPLY			= (1 << 0),
		IS_REPLY			= (1 << 1),
		HEADER_OPENS_STREAM_TX		= (1 << 4),
		HEADER_OPENS_STREAM_RX		= (1 << 5),
		HEADER_OPENS_REPLY_CHANNEL	= (1 << 6);

		public string print () {
			uint remainder = this;
			if (remainder == 0)
				return "NONE";

			var result = new StringBuilder.sized (128);

			var klass = (FlagsClass) typeof (MessageFlags).class_ref ();
			foreach (FlagsValue fv in klass.values) {
				if ((remainder & fv.value) != 0) {
					if (result.len != 0)
						result.append (" | ");
					result.append (fv.value_nick.up ().replace ("-", "_"));
					remainder &= ~fv.value;
				}
			}

			if (remainder != 0) {
				if (result.len != 0)
					result.append (" | ");
				result.append_printf ("0x%04x", remainder);
			}

			return result.str;
		}
	}

	public sealed class XpcBodyBuilder : XpcObjectBuilder {
		public XpcBodyBuilder () {
			base ();

			builder
				.append_uint32 (SerializedXpcObject.MAGIC)
				.append_uint32 (SerializedXpcObject.VERSION);
		}
	}

	public class XpcObjectBuilder : Object, ObjectBuilder {
		protected BufferBuilder builder = new BufferBuilder (LITTLE_ENDIAN);
		private Gee.Deque<Scope> scopes = new Gee.ArrayQueue<Scope> ();

		public XpcObjectBuilder () {
			push_scope (new Scope (ROOT));
		}

		public unowned ObjectBuilder begin_dictionary () {
			begin_object (DICTIONARY);

			size_t size_offset = builder.offset;
			builder.append_uint32 (0);

			size_t num_entries_offset = builder.offset;
			builder.append_uint32 (0);

			push_scope (new DictionaryScope (size_offset, num_entries_offset));

			return this;
		}

		public unowned ObjectBuilder set_member_name (string name) {
			builder
				.append_string (name)
				.align (4);

			return this;
		}

		public unowned ObjectBuilder end_dictionary () {
			DictionaryScope scope = pop_scope ();

			uint32 size = (uint32) (builder.offset - scope.num_entries_offset);
			builder.write_uint32 (scope.size_offset, size);

			builder.write_uint32 (scope.num_entries_offset, scope.num_objects);

			return this;
		}

		public unowned ObjectBuilder begin_array () {
			begin_object (ARRAY);

			size_t size_offset = builder.offset;
			builder.append_uint32 (0);

			size_t num_elements_offset = builder.offset;
			builder.append_uint32 (0);

			push_scope (new ArrayScope (size_offset, num_elements_offset));

			return this;
		}

		public unowned ObjectBuilder end_array () {
			ArrayScope scope = pop_scope ();

			uint32 size = (uint32) (builder.offset - scope.num_elements_offset);
			builder.write_uint32 (scope.size_offset, size);

			builder.write_uint32 (scope.num_elements_offset, scope.num_objects);

			return this;
		}

		public unowned ObjectBuilder add_null_value () {
			begin_object (NULL);
			return this;
		}

		public unowned ObjectBuilder add_bool_value (bool val) {
			begin_object (BOOL).append_uint32 ((uint32) val);
			return this;
		}

		public unowned ObjectBuilder add_int64_value (int64 val) {
			begin_object (INT64).append_int64 (val);
			return this;
		}

		public unowned ObjectBuilder add_uint64_value (uint64 val) {
			begin_object (UINT64).append_uint64 (val);
			return this;
		}

		public unowned ObjectBuilder add_data_value (Bytes val) {
			begin_object (DATA)
				.append_uint32 (val.length)
				.append_bytes (val)
				.align (4);
			return this;
		}

		public unowned ObjectBuilder add_string_value (string val) {
			begin_object (STRING)
				.append_uint32 (val.length + 1)
				.append_string (val)
				.align (4);
			return this;
		}

		public unowned ObjectBuilder add_uuid_value (uint8[] val) {
			assert (val.length == 16);
			begin_object (UUID).append_data (val);
			return this;
		}

		public unowned ObjectBuilder add_raw_value (Bytes val) {
			peek_scope ().num_objects++;
			builder.append_bytes (val);
			return this;
		}

		private unowned BufferBuilder begin_object (ObjectType type) {
			peek_scope ().num_objects++;
			return builder.append_uint32 (type);
		}

		public Bytes build () {
			return builder.build ();
		}

		private void push_scope (Scope scope) {
			scopes.offer_tail (scope);
		}

		private Scope peek_scope () {
			return scopes.peek_tail ();
		}

		private T pop_scope<T> () {
			return (T) scopes.poll_tail ();
		}

		private class Scope {
			public Kind kind;
			public uint32 num_objects = 0;

			public enum Kind {
				ROOT,
				DICTIONARY,
				ARRAY,
			}

			public Scope (Kind kind) {
				this.kind = kind;
			}
		}

		private class DictionaryScope : Scope {
			public size_t size_offset;
			public size_t num_entries_offset;

			public DictionaryScope (size_t size_offset, size_t num_entries_offset) {
				base (DICTIONARY);
				this.size_offset = size_offset;
				this.num_entries_offset = num_entries_offset;
			}
		}

		private class ArrayScope : Scope {
			public size_t size_offset;
			public size_t num_elements_offset;

			public ArrayScope (size_t size_offset, size_t num_elements_offset) {
				base (DICTIONARY);
				this.size_offset = size_offset;
				this.num_elements_offset = num_elements_offset;
			}
		}
	}

	private enum ObjectType {
		NULL		= 0x1000,
		BOOL		= 0x2000,
		INT64		= 0x3000,
		UINT64		= 0x4000,
		DATA		= 0x8000,
		STRING		= 0x9000,
		UUID		= 0xa000,
		ARRAY		= 0xe000,
		DICTIONARY	= 0xf000,
	}

	private sealed class XpcBodyParser {
		public static Variant parse (uint8[] data) throws Error {
			if (data.length < 12)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: truncated");

			var buf = new Buffer (new Bytes.static (data), LITTLE_ENDIAN);

			var magic = buf.read_uint32 (0);
			if (magic != SerializedXpcObject.MAGIC)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: bad magic (0x%08x)", magic);

			var version = buf.read_uint8 (4);
			if (version != SerializedXpcObject.VERSION)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: unsupported version (%u)", version);

			var parser = new XpcObjectParser (buf, 8);
			return parser.read_object ();
		}
	}

	private sealed class XpcObjectParser {
		private Buffer buf;
		private size_t cursor;
		private EnumClass object_type_class;

		public XpcObjectParser (Buffer buf, uint cursor) {
			this.buf = buf;
			this.cursor = cursor;
			this.object_type_class = (EnumClass) typeof (ObjectType).class_ref ();
		}

		public Variant read_object () throws Error {
			var raw_type = read_raw_uint32 ();
			if (object_type_class.get_value ((int) raw_type) == null)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: unsupported type (0x%x)", raw_type);
			var type = (ObjectType) raw_type;

			switch (type) {
				case NULL:
					return new Variant.maybe (VariantType.VARIANT, null);
				case BOOL:
					return new Variant.boolean (read_raw_uint32 () != 0);
				case INT64:
					return new Variant.int64 (read_raw_int64 ());
				case UINT64:
					return new Variant.uint64 (read_raw_uint64 ());
				case DATA:
					return read_data ();
				case STRING:
					return read_string ();
				case UUID:
					return read_uuid ();
				case ARRAY:
					return read_array ();
				case DICTIONARY:
					return read_dictionary ();
				default:
					assert_not_reached ();
			}
		}

		private Variant read_data () throws Error {
			var size = read_raw_uint32 ();

			var bytes = read_raw_bytes (size);
			align (4);

			return Variant.new_from_data (new VariantType.array (VariantType.BYTE), bytes.get_data (), true, bytes);
		}

		private Variant read_string () throws Error {
			var size = read_raw_uint32 ();

			var str = buf.read_string (cursor);
			cursor += size;
			align (4);

			return new Variant.string (str);
		}

		private Variant read_uuid () throws Error {
			uint8[] uuid = read_raw_bytes (16).get_data ();
			return new Variant.string ("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X".printf (
				uuid[0], uuid[1], uuid[2], uuid[3],
				uuid[4], uuid[5],
				uuid[6], uuid[7],
				uuid[8], uuid[9],
				uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]));
		}

		private Variant read_array () throws Error {
			var builder = new VariantBuilder (new VariantType.array (VariantType.VARIANT));

			var size = read_raw_uint32 ();
			size_t num_elements_offset = cursor;
			var num_elements = read_raw_uint32 ();

			for (uint32 i = 0; i != num_elements; i++)
				builder.add ("v", read_object ());

			cursor = num_elements_offset;
			skip (size);

			return builder.end ();
		}

		private Variant read_dictionary () throws Error {
			var builder = new VariantBuilder (VariantType.VARDICT);

			var size = read_raw_uint32 ();
			size_t num_entries_offset = cursor;
			var num_entries = read_raw_uint32 ();

			for (uint32 i = 0; i != num_entries; i++) {
				string key = buf.read_string (cursor);
				skip (key.length + 1);
				align (4);

				Variant val = read_object ();

				builder.add ("{sv}", key, val);
			}

			cursor = num_entries_offset;
			skip (size);

			return builder.end ();
		}

		private uint32 read_raw_uint32 () throws Error {
			check_available (sizeof (uint32));
			var result = buf.read_uint32 (cursor);
			cursor += sizeof (uint32);
			return result;
		}

		private int64 read_raw_int64 () throws Error {
			check_available (sizeof (int64));
			var result = buf.read_int64 (cursor);
			cursor += sizeof (int64);
			return result;
		}

		private uint64 read_raw_uint64 () throws Error {
			check_available (sizeof (uint64));
			var result = buf.read_uint64 (cursor);
			cursor += sizeof (uint64);
			return result;
		}

		private Bytes read_raw_bytes (size_t n) throws Error {
			check_available (n);
			Bytes result = buf.bytes[cursor:cursor + n];
			cursor += n;
			return result;
		}

		private void skip (size_t n) throws Error {
			check_available (n);
			cursor += n;
		}

		private void align (size_t n) throws Error {
			size_t remainder = cursor % n;
			if (remainder != 0)
				skip (n - remainder);
		}

		private void check_available (size_t required) throws Error {
			size_t available = buf.bytes.get_size () - cursor;
			if (available < required)
				throw new Error.INVALID_ARGUMENT ("Invalid xpc_object: truncated");
		}
	}

	namespace SerializedXpcObject {
		public const uint32 MAGIC = 0x42133742;
		public const uint32 VERSION = 5;
	}

	private Key make_keypair (KeyType type) {
		var ctx = new KeyContext.for_key_type (type);
		ctx.keygen_init ();

		Key? keypair = null;
		ctx.keygen (ref keypair);

		return keypair;
	}

	private Bytes get_raw_public_key (Key key) {
		size_t size = 0;
		key.get_raw_public_key (null, ref size);

		var result = new uint8[size];
		key.get_raw_public_key (result, ref size);

		return new Bytes.take ((owned) result);
	}

	private Bytes get_raw_private_key (Key key) {
		size_t size = 0;
		key.get_raw_private_key (null, ref size);

		var result = new uint8[size];
		key.get_raw_private_key (result, ref size);

		return new Bytes.take ((owned) result);
	}

	private string make_host_identifier () {
		var checksum = new Checksum (MD5);

		const uint8 uuid_version = 3;
		const uint8 dns_namespace[] = { 0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30, 0xc8 };
		checksum.update (dns_namespace, dns_namespace.length);

		unowned uint8[] host_name = Environment.get_host_name ().data;
		checksum.update (host_name, host_name.length);

		uint8 uuid[16];
		size_t len = uuid.length;
		checksum.get_digest (uuid, ref len);

		uuid[6] = (uuid_version << 4) | (uuid[6] & 0xf);
		uuid[8] = 0x80 | (uuid[8] & 0x3f);

		var result = new StringBuilder.sized (36);
		for (var i = 0; i != uuid.length; i++) {
			result.append_printf ("%02X", uuid[i]);
			switch (i) {
				case 3:
				case 5:
				case 7:
				case 9:
					result.append_c ('-');
					break;
			}
		}

		return result.str;
	}

	private uint8[] make_random_v4_uuid () {
		uint8 uuid[16];
		OpenSSL.Rng.generate (uuid);

		const uint8 uuid_version = 4;
		uuid[6] = (uuid_version << 4) | (uuid[6] & 0xf);
		uuid[8] = 0x80 | (uuid[8] & 0x3f);

		return uuid;
	}
}
