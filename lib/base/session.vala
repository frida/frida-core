namespace Frida {
	[DBus (name = "re.frida.HostSession15")]
	public interface HostSession : Object {
		public abstract async void ping (uint interval_seconds, Cancellable? cancellable) throws GLib.Error;

		public abstract async HashTable<string, Variant> query_system_parameters (Cancellable? cancellable) throws GLib.Error;
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

	[DBus (name = "re.frida.AgentSessionProvider15")]
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

	[DBus (name = "re.frida.AgentSession15")]
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
		public abstract async void destroy_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void load_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;
		public abstract async void eternalize_script (AgentScriptId script_id, Cancellable? cancellable) throws GLib.Error;

		public abstract async void enable_debugger (Cancellable? cancellable) throws GLib.Error;
		public abstract async void disable_debugger (Cancellable? cancellable) throws GLib.Error;

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

	[DBus (name = "re.frida.AgentController15")]
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

	[DBus (name = "re.frida.AgentMessageSink15")]
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

	[DBus (name = "re.frida.TransportBroker15")]
	public interface TransportBroker : Object {
		public abstract async void open_tcp_transport (AgentSessionId id, Cancellable? cancellable, out uint16 port,
			out string token) throws GLib.Error;
	}

	[DBus (name = "re.frida.PortalSession15")]
	public interface PortalSession : Object {
		public abstract async void join (HostApplicationInfo app, SpawnStartState current_state,
			AgentSessionId[] interrupted_sessions, HashTable<string, Variant> options, Cancellable? cancellable,
			out SpawnStartState next_state) throws GLib.Error;
		public signal void resume ();
		public signal void kill ();
	}

	[DBus (name = "re.frida.BusSession15")]
	public interface BusSession : Object {
		public abstract async void attach (Cancellable? cancellable) throws GLib.Error;
		public abstract async void post (string json, bool has_data, uint8[] data, Cancellable? cancellable) throws GLib.Error;
		public signal void message (string json, bool has_data, uint8[] data);
	}

	[DBus (name = "re.frida.AuthenticationService15")]
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
		public ImageData small_icon;
		public ImageData large_icon;

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
		public uint pid;
		public string name;
		public ImageData small_icon;
		public ImageData large_icon;

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
		public int width;
		public int height;
		public int rowstride;
		public string pixels;

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
			this.aux = make_options_dict ();
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

		public HashTable<string, Variant> _serialize () {
			var dict = make_options_dict ();

			if (realm != NATIVE)
				dict["realm"] = new Variant.string (realm.to_nick ());

			if (persist_timeout != 0)
				dict["persist-timeout"] = new Variant.uint32 (persist_timeout);

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

			this.parameters = (parameters != null) ? parameters : make_options_dict ();
		}

		public CrashInfo.empty () {
			this.pid = 0;
			this.process_name = "";
			this.summary = "";
			this.report = "";
			this.parameters = make_options_dict ();
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

		public ScriptRuntime runtime {
			get;
			set;
			default = DEFAULT;
		}

		public HashTable<string, Variant> _serialize () {
			var dict = make_options_dict ();

			if (name != null)
				dict["name"] = new Variant.string (name);

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
			var dict = make_options_dict ();

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
			var dict = make_options_dict ();

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

	public HashTable<string, Variant> make_options_dict () {
		return new HashTable<string, Variant> (str_hash, str_equal);
	}

	public HashTable<string, Variant> compute_system_parameters () {
		var parameters = new HashTable<string, Variant> (str_hash, str_equal);

		string platform;
#if WINDOWS
		platform = "windows";
#elif DARWIN
		platform = "darwin";
#elif LINUX
		platform = "linux";
#elif QNX
		platform = "qnx";
#else
		platform = FIXME;
#endif
		parameters["platform"] = platform;

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
#elif ANDROID
		id = "android";
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

#if WINDOWS
		parameters["name"] = _query_windows_computer_name ();
#elif IOS
		import_mg_property (parameters, "name", "UserAssignedDeviceName");
		import_mg_property (parameters, "udid", "UniqueDeviceID");

		import_mg_property (parameters, "phone-number", "PhoneNumber");
		import_mg_property (parameters, "ethernet-address", "EthernetMacAddress");
		import_mg_property (parameters, "wifi-address", "WifiAddress");
		import_mg_property (parameters, "bluetooth-address", "BluetoothAddress");
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
	private void import_mg_property (HashTable<string, Variant> target, string key, string query) {
		var answer = _query_mobile_gestalt (query);
		if (answer == null)
			return;
		if (answer.is_of_type (VariantType.STRING) && answer.get_string ().length == 0)
			return;
		target[key] = answer;
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
			return (Realm) v.value;
		}

		public static string enum_to_nick<T> (int val) {
			var klass = (EnumClass) typeof (T).class_ref ();
			return klass.get_value (val).value_nick;
		}
	}
}
