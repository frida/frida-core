namespace Frida {
	[DBus (name = "re.frida.HostSession14")]
	public interface HostSession : Object {
		public abstract async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws GLib.Error;
		public abstract async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws GLib.Error;
		public abstract async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws GLib.Error;

		public abstract async void enable_spawn_gating (Cancellable? cancellable) throws GLib.Error;
		public abstract async void disable_spawn_gating (Cancellable? cancellable) throws GLib.Error;
		public abstract async HostSpawnInfo[] enumerate_pending_spawn (Cancellable? cancellable) throws GLib.Error;
		public abstract async HostChildInfo[] enumerate_pending_children (Cancellable? cancellable) throws GLib.Error;
		public abstract async uint spawn (string program, HostSpawnOptions options, Cancellable? cancellable) throws GLib.Error;
		public abstract async void input (uint pid, uint8[] data, Cancellable? cancellable) throws GLib.Error;
		public abstract async void resume (uint pid, Cancellable? cancellable) throws GLib.Error;
		public abstract async void kill (uint pid, Cancellable? cancellable) throws GLib.Error;
		public abstract async AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws GLib.Error;
		public abstract async AgentSessionId attach_in_realm (uint pid, Realm realm, Cancellable? cancellable) throws GLib.Error;
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
		public signal void agent_session_destroyed (AgentSessionId id, SessionDetachReason reason);
		public signal void agent_session_crashed (AgentSessionId id, CrashInfo crash);
		public signal void uninjected (InjectorPayloadId id);
	}

	[DBus (name = "re.frida.AgentSessionProvider14")]
	public interface AgentSessionProvider : Object {
		public abstract async void open (AgentSessionId id, Realm realm, Cancellable? cancellable) throws GLib.Error;
#if !WINDOWS
		public abstract async void migrate (AgentSessionId id, GLib.Socket to_socket, Cancellable? cancellable) throws GLib.Error;
#endif
		public abstract async void unload (Cancellable? cancellable) throws GLib.Error;

		public signal void opened (AgentSessionId id);
		public signal void closed (AgentSessionId id);
		public signal void eternalized ();
		public signal void child_gating_changed (uint subscriber_count);
	}

	[DBus (name = "re.frida.AgentSession14")]
	public interface AgentSession : Object {
		public abstract async void close (Cancellable? cancellable) throws GLib.Error;

		public abstract async void enable_child_gating (Cancellable? cancellable) throws GLib.Error;
		public abstract async void disable_child_gating (Cancellable? cancellable) throws GLib.Error;

		public abstract async AgentScriptId create_script (string name, string source, Cancellable? cancellable) throws GLib.Error;
		public abstract async AgentScriptId create_script_with_options (string source, AgentScriptOptions options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async AgentScriptId create_script_from_bytes (uint8[] bytes, Cancellable? cancellable) throws GLib.Error;
		public abstract async AgentScriptId create_script_from_bytes_with_options (uint8[] bytes, AgentScriptOptions options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async uint8[] compile_script (string name, string source, Cancellable? cancellable) throws GLib.Error;
		public abstract async uint8[] compile_script_with_options (string source, AgentScriptOptions options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void eternalize_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void post_to_script (AgentScriptId script_id, string message, bool has_data, uint8[] data,
			Cancellable? cancellable) throws GLib.Error;
		public signal void message_from_script (AgentScriptId script_id, string message, bool has_data, uint8[] data);

		public abstract async void enable_debugger (Cancellable? cancellable) throws GLib.Error;
		public abstract async void disable_debugger (Cancellable? cancellable) throws GLib.Error;
		public abstract async void post_message_to_debugger (string message, Cancellable? cancellable) throws GLib.Error;
		public signal void message_from_debugger (string message);

		public abstract async void enable_jit (Cancellable? cancellable) throws GLib.Error;

		public abstract async PortalMembershipId join_portal (string address, AgentPortalOptions options,
			Cancellable? cancellable) throws GLib.Error;
		public abstract async void leave_portal (PortalMembershipId membership_id, Cancellable? cancellable) throws GLib.Error;

		public abstract async void offer_peer_connection (string offer_sdp, AgentPeerOptions peer_options, string cert_pem,
			Cancellable? cancellable, out string answer_sdp) throws GLib.Error;
		public abstract async void add_candidates (string[] candidate_sdps, Cancellable? cancellable) throws GLib.Error;
		public abstract async void notify_candidate_gathering_done (Cancellable? cancellable) throws GLib.Error;
		public abstract async void begin_migration (Cancellable? cancellable) throws GLib.Error;
		public abstract async void commit_migration (Cancellable? cancellable) throws GLib.Error;
		public signal void new_candidates (string[] candidate_sdps);
		public signal void candidate_gathering_done ();
		public signal void migrated ();
	}

	[DBus (name = "re.frida.AgentController14")]
	public interface AgentController : Object {
#if !WINDOWS
		public abstract async HostChildId prepare_to_fork (uint parent_pid, Cancellable? cancellable, out uint parent_injectee_id,
			out uint child_injectee_id, out GLib.Socket child_socket) throws GLib.Error;
#endif
		public abstract async void recreate_agent_thread (uint pid, uint injectee_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void wait_for_permission_to_resume (HostChildId id, HostChildInfo info,
			Cancellable? cancellable) throws GLib.Error;

		public abstract async void prepare_to_exec (HostChildInfo info, Cancellable? cancellable) throws GLib.Error;
		public abstract async void cancel_exec (uint pid, Cancellable? cancellable) throws GLib.Error;

		public abstract async void acknowledge_spawn (HostChildInfo info, SpawnStartState start_state,
			Cancellable? cancellable) throws GLib.Error;
	}

	[DBus (name = "re.frida.TransportBroker14")]
	public interface TransportBroker : Object {
		public abstract async void open_tcp_transport (AgentSessionId id, Cancellable? cancellable, out uint16 port,
			out string token) throws GLib.Error;
	}

	[DBus (name = "re.frida.PortalSession14")]
	public interface PortalSession : Object {
		public abstract async void join (HostApplicationInfo app, SpawnStartState current_state, Cancellable? cancellable,
			out SpawnStartState next_state) throws GLib.Error;
		public signal void resume ();
		public signal void kill ();
	}

	[DBus (name = "re.frida.BusSession14")]
	public interface BusSession : Object {
		public abstract async void post (string message, bool has_data, uint8[] data, Cancellable? cancellable) throws GLib.Error;
		public signal void message (string message, bool has_data, uint8[] data);
	}

	[DBus (name = "re.frida.AuthenticationService14")]
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
		public async HostApplicationInfo get_frontmost_application (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostApplicationInfo[] enumerate_applications (Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async HostProcessInfo[] enumerate_processes (Cancellable? cancellable) throws Error, IOError {
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

		public async AgentSessionId attach_to (uint pid, Cancellable? cancellable) throws Error, IOError {
			throw_not_authorized ();
		}

		public async AgentSessionId attach_in_realm (uint pid, Realm realm, Cancellable? cancellable) throws Error, IOError {
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
		public async void join (HostApplicationInfo app, SpawnStartState current_state, Cancellable? cancellable,
				out SpawnStartState next_state) throws Error, IOError {
			throw_not_authorized ();
		}
	}

	public class UnauthorizedBusSession : Object, BusSession {
		public async void post (string message, bool has_data, uint8[] data, Cancellable? cancellable) throws Error, IOError {
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

		public string to_nick () {
			return Marshal.enum_to_nick<Realm> (this);
		}
	}

	public enum SpawnStartState {
		RUNNING,
		SUSPENDED;

		public string to_nick () {
			return Marshal.enum_to_nick<SpawnStartState> (this);
		}
	}

	public enum UnloadPolicy {
		IMMEDIATE,
		RESIDENT,
		DEFERRED;

		public string to_nick () {
			return Marshal.enum_to_nick<UnloadPolicy> (this);
		}
	}

	public struct InjectorPayloadId {
		public uint handle {
			get;
			private set;
		}

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
		public uint64 address {
			get;
			private set;
		}

		public uint size {
			get;
			private set;
		}

		public uint allocated_size {
			get;
			private set;
		}

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
		public int fifo_fd;
	}
#endif

	public enum SessionDetachReason {
		APPLICATION_REQUESTED = 1,
		PROCESS_REPLACED,
		PROCESS_TERMINATED,
		SERVER_TERMINATED,
		DEVICE_LOST;

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
		public string identifier {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public uint pid {
			get;
			private set;
		}

		public ImageData small_icon {
			get;
			private set;
		}

		public ImageData large_icon {
			get;
			private set;
		}

		public HostApplicationInfo (string identifier, string name, uint pid, ImageData small_icon, ImageData large_icon) {
			this.identifier = identifier;
			this.name = name;
			this.pid = pid;
			this.small_icon = small_icon;
			this.large_icon = large_icon;
		}

		public HostApplicationInfo.empty () {
			this.identifier = "";
			this.name = "";
			this.pid = 0;
			this.small_icon = ImageData.empty ();
			this.large_icon = ImageData.empty ();
		}
	}

	public struct HostProcessInfo {
		public uint pid {
			get;
			private set;
		}

		public string name {
			get;
			private set;
		}

		public ImageData small_icon {
			get;
			private set;
		}

		public ImageData large_icon {
			get;
			private set;
		}

		public HostProcessInfo (uint pid, string name, ImageData small_icon, ImageData large_icon) {
			this.pid = pid;
			this.name = name;
			this.small_icon = small_icon;
			this.large_icon = large_icon;
		}
	}

	public class Image : Object {
		public ImageData data;

		public Image (ImageData data) {
			this.data = data;
		}

		public static Image? from_data (ImageData? data) {
			if (data == null)
				return null;
			return new Image (data);
		}
	}

	public struct ImageData {
		public int width {
			get;
			private set;
		}

		public int height {
			get;
			private set;
		}

		public int rowstride {
			get;
			private set;
		}

		public string pixels {
			get;
			private set;
		}

		public ImageData (int width, int height, int rowstride, string pixels) {
			this.width = width;
			this.height = height;
			this.rowstride = rowstride;
			this.pixels = pixels;
		}

		public ImageData.empty () {
			this.width = 0;
			this.height = 0;
			this.rowstride = 0;
			this.pixels = "";
		}
	}

	public struct HostSpawnOptions {
		public bool has_argv {
			get;
			set;
		}

		public string[] argv {
			get;
			set;
		}

		public bool has_envp {
			get;
			set;
		}

		public string[] envp {
			get;
			set;
		}

		public bool has_env {
			get;
			set;
		}

		public string[] env {
			get;
			set;
		}

		public string cwd {
			get;
			set;
		}

		public Stdio stdio {
			get;
			set;
		}

		public uint8[] aux {
			get;
			set;
		}

		public HostSpawnOptions () {
			this.argv = {};
			this.envp = {};
			this.env = {};
			this.cwd = "";
			this.stdio = INHERIT;
			this.aux = {};
		}

		public VariantDict load_aux () {
			return new VariantDict (new Variant.from_bytes (VariantType.VARDICT, new Bytes (aux), false));
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

	public enum Stdio {
		INHERIT,
		PIPE;

		public string to_nick () {
			return Marshal.enum_to_nick<Stdio> (this);
		}
	}

	public struct HostSpawnInfo {
		public uint pid {
			get;
			private set;
		}

		public string identifier {
			get;
			private set;
		}

		public HostSpawnInfo (uint pid, string identifier) {
			this.pid = pid;
			this.identifier = identifier;
		}
	}

	public struct HostChildId {
		public uint handle {
			get;
			private set;
		}

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
		public uint pid {
			get;
			private set;
		}

		public uint parent_pid {
			get;
			private set;
		}

		public ChildOrigin origin {
			get;
			private set;
		}

		public string identifier {
			get;
			set;
		}

		public string path {
			get;
			set;
		}

		public bool has_argv {
			get;
			set;
		}

		public string[] argv {
			get;
			set;
		}

		public bool has_envp {
			get;
			set;
		}

		public string[] envp {
			get;
			set;
		}

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

		public string to_nick () {
			return Marshal.enum_to_nick<ChildOrigin> (this);
		}
	}

	public struct CrashInfo {
		public uint pid {
			get;
			set;
		}

		public string process_name {
			get;
			set;
		}

		public string summary {
			get;
			set;
		}

		public string report {
			get;
			set;
		}

		public uint8[] parameters {
			get;
			set;
		}

		public CrashInfo (uint pid, string process_name, string summary, string report, Variant? parameters = null) {
			this.pid = pid;
			this.process_name = process_name;

			this.summary = summary;
			this.report = report;

			if (parameters != null)
				this.parameters = parameters.get_data_as_bytes ().get_data ();
			else
				this.parameters = {};
		}
	}

	public struct AgentSessionId {
		public uint handle {
			get;
			private set;
		}

		public AgentSessionId (uint handle) {
			this.handle = handle;
		}

		public static uint hash (AgentSessionId? id) {
			return direct_hash ((void *) id.handle);
		}

		public static bool equal (AgentSessionId? a, AgentSessionId? b) {
			return a.handle == b.handle;
		}
	}

	public struct AgentScriptId {
		public uint handle {
			get;
			private set;
		}

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

	public struct AgentScriptOptions {
		public uint8[] data {
			get;
			set;
		}

		public AgentScriptOptions () {
			this.data = {};
		}
	}

	public class ScriptOptions : Object {
		public string? name {
			get;
			set;
		}

		public ScriptRuntime runtime {
			get;
			set;
			default = DEFAULT;
		}

		public Bytes _serialize () {
			var dict = new VariantDict ();

			if (name != null)
				dict.insert_value ("name", new Variant.string (name));

			if (runtime != DEFAULT)
				dict.insert_value ("runtime", new Variant.byte (runtime));

			return dict.end ().get_data_as_bytes ();
		}

		public static ScriptOptions _deserialize (uint8[] data) {
			var dict = new VariantDict (new Variant.from_bytes (VariantType.VARDICT, new Bytes (data), false));

			var options = new ScriptOptions ();

			string? name = null;
			dict.lookup ("name", "s", out name);
			options.name = name;

			uint8 raw_runtime = ScriptRuntime.DEFAULT;
			dict.lookup ("runtime", "y", out raw_runtime);
			options.runtime = (ScriptRuntime) raw_runtime;

			return options;
		}
	}

	public enum ScriptRuntime {
		DEFAULT,
		QJS,
		V8;

		public string to_nick () {
			return Marshal.enum_to_nick<ScriptRuntime> (this);
		}
	}

	public struct PortalMembershipId {
		public uint handle {
			get;
			private set;
		}

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

	public struct AgentPortalOptions {
		public uint8[] data {
			get;
			set;
		}

		public AgentPortalOptions () {
			this.data = {};
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

		public Bytes _serialize () {
			var dict = new VariantDict ();

			if (certificate != null)
				dict.insert_value ("certificate", new Variant.string (certificate.certificate_pem));

			if (token != null)
				dict.insert_value ("token", new Variant.string (token));

			return dict.end ().get_data_as_bytes ();
		}

		public static PortalOptions _deserialize (uint8[] data) {
			var dict = new VariantDict (new Variant.from_bytes (VariantType.VARDICT, new Bytes (data), false));

			var options = new PortalOptions ();

			string? cert_pem = null;
			dict.lookup ("certificate", "s", out cert_pem);
			if (cert_pem != null) {
				try {
					options.certificate = new TlsCertificate.from_pem (cert_pem, -1);
				} catch (GLib.Error e) {
				}
			}

			string? token = null;
			dict.lookup ("token", "s", out token);
			options.token = token;

			return options;
		}
	}

	public struct AgentPeerOptions {
		public uint8[] data {
			get;
			set;
		}

		public AgentPeerOptions () {
			this.data = {};
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

		public Bytes _serialize () {
			var dict = new VariantDict ();

			if (stun_server != null)
				dict.insert_value ("stun-server", new Variant.string (stun_server));

			if (!relays.is_empty) {
				var builder = new VariantBuilder (new VariantType.array (Relay.get_variant_type ()));
				foreach (var relay in relays)
					builder.add_value (relay.to_variant ());
				dict.insert_value ("relays", builder.end ());
			}

			return dict.end ().get_data_as_bytes ();
		}

		public static PeerOptions _deserialize (uint8[] data) {
			var dict = new VariantDict (new Variant.from_bytes (VariantType.VARDICT, new Bytes (data), false));

			var options = new PeerOptions ();

			string? stun_server = null;
			dict.lookup ("stun-server", "s", out stun_server);
			options.stun_server = stun_server;

			Variant? relays_val = dict.lookup_value ("relays", new VariantType.array (Relay.get_variant_type ()));
			if (relays_val != null) {
				var iter = relays_val.iterator ();
				Variant? val;
				while ((val = iter.next_value ()) != null) {
					options.add_relay (Relay.from_variant (val));
				}
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

	namespace ServerGuid {
		public const string HOST_SESSION_SERVICE = "6769746875622e636f6d2f6672696461";
		public const string AGENT_SESSION = "6167656e742d732e66726964612e7265";
	}

	namespace ObjectPath {
		public const string HOST_SESSION = "/re/frida/HostSession";
		public const string AGENT_SESSION_PROVIDER = "/re/frida/AgentSessionProvider";
		public const string AGENT_SESSION = "/re/frida/AgentSession";
		public const string AGENT_CONTROLLER = "/re/frida/AgentController";
		public const string CHILD_SESSION = "/re/frida/ChildSession";
		public const string TRANSPORT_BROKER = "/re/frida/TransportBroker";
		public const string PORTAL_SESSION = "/re/frida/PortalSession";
		public const string BUS_SESSION = "/re/frida/BusSession";
		public const string AUTHENTICATION_SERVICE = "/re/frida/AuthenticationService";

		public static string from_agent_session_id (AgentSessionId id) {
			return "%s/%u".printf (AGENT_SESSION, id.handle);
		}
	}

	namespace Marshal {
		public static string enum_to_nick<T> (int val) {
			var klass = (EnumClass) typeof (T).class_ref ();
			return klass.get_value (val).value_nick;
		}
	}
}
