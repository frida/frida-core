namespace Frida.CompilerTest {
	public static void add_tests () {
		GLib.Test.add_func ("/Compiler/Performance/build-simple-agent", () => {
			var h = new Harness ((h) => Performance.build_simple_agent.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Compiler/Performance/watch-simple-agent", () => {
			var h = new Harness ((h) => Performance.watch_simple_agent.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Compiler/LanguageServer/complete-simple-agent", () => {
			var h = new Harness ((h) => LanguageServerTests.complete_simple_agent.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Compiler/Patterns/build-agent-with-patterns", () => {
			var h = new Harness ((h) => PatternTests.build_agent_with_patterns.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Compiler/Patterns/complete-pattern-fields", () => {
			var h = new Harness ((h) => PatternTests.complete_pattern_fields.begin (h as Harness));
			h.run ();
		});

		GLib.Test.add_func ("/Compiler/Patterns/compile-and-decode", () => {
			var h = new Harness ((h) => PatternTests.compile_and_decode.begin (h as Harness));
			h.run ();
		});
	}

	namespace PatternTests {
		private const string PLAYER_PATTERN = """
#pragma abi native

struct Vec3 {
	float x;
	float y;
	float z;
};

struct Player {
	u32 hitpoints;
	u16 armor;
	Vec3 position;
	Player *next;
};
""";

		private static async void build_agent_with_patterns (Harness h) {
			if (skip_slow_test ()) {
				stdout.printf ("<skipping, run in slow mode> ");
				h.done ();
				return;
			}

			try {
				string project_dir = DirUtils.make_tmp ("compiler-test.XXXXXX");
				string agent_ts_path = Path.build_filename (project_dir, "agent.ts");
				FileUtils.set_contents (agent_ts_path, """
import { Player } from "./player.pat";

const player = Player.at(Process.mainModule.base);
const hitpoints: number = player.hitpoints;
console.log(hitpoints, player.position.x, player.next);
""");
				string player_pat_path = Path.build_filename (project_dir, "player.pat");
				FileUtils.set_contents (player_pat_path, PLAYER_PATTERN);

				var compiler = new Compiler ();
				compiler.diagnostics.connect (d => printerr ("DIAGNOSTICS: %s\n", d.print (false)));
				var code = yield compiler.build (agent_ts_path);
				assert ("hitpoints" in code);
				assert ("readU32()" in code);

				string declarations_path = Path.build_filename (project_dir, "player.pat.d.ts");
				string declarations;
				FileUtils.get_contents (declarations_path, out declarations);
				assert ("export declare class Player" in declarations);

				FileUtils.unlink (declarations_path);
				FileUtils.unlink (player_pat_path);
				FileUtils.unlink (agent_ts_path);
				DirUtils.remove (project_dir);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void compile_and_decode (Harness h) {
			try {
				string project_dir = DirUtils.make_tmp ("compiler-test.XXXXXX");
				string player_pat_path = write_pattern (project_dir, "player.pat", PLAYER_PATTERN);
				write_pattern (project_dir, "game.hexpat", "import player;\n\nstruct Game {\n\tPlayer hero;\n};\n");
				write_pattern (project_dir, "placed.hexpat", PLAYER_PATTERN + "Player player @ 0x10;\n");
				write_pattern (project_dir, "broken.pat", "struct A { auto a @ 0; };\n");
				write_pattern (project_dir, "importing-broken.hexpat", "import broken;\n");
				write_pattern (project_dir, "configurable.hexpat",
					"u32 scale in = 1;\nstruct Sample { u8 raw; u32 scaled = raw * scale [[export]]; };\nSample sample @ 0;\n");
				write_pattern (project_dir, "formatted.hexpat", PLAYER_PATTERN + """
fn describe(u32 hp) { return std::format("{} hp", hp); }
struct Labelled { u32 hitpoints [[format("describe"), color("00FF00")]]; };
""");
				write_pattern (project_dir, "visualizing.hexpat", """
struct Image {
	u8 magic[2];
	u8 width;
	u8 visualizer[3] @ addressof(this) [[sealed, hex::visualize("image", this), no_unique_address]];
	u8 samples[2] [[hex::inline_visualize("line_plot", this, width)]];
};
""");
				write_pattern (project_dir, "printing.hexpat", """
fn describe(ref auto pattern) { std::print("width {}", pattern.width); };
struct Image { u8 magic[2]; u8 width; };
""");

				var compiler = new PatternCompiler ();
				var options = make_pattern_options (project_dir);

				var module = yield compiler.compile (player_pat_path, make_pattern_options ());
				assert (module.diagnostics.size () == 0);
				assert (module.types.size () == 2);
				assert (module.root_type == null);
				var player_type = module.types.get (1);
				assert (player_type.name == "Player" && player_type.file == "player.pat" && player_type.line == 9 && player_type.character == 0);

				var game = yield compiler.compile ("game.hexpat", options);
				assert (game.diagnostics.size () == 0);
				assert (game.lookup ("Game").file == "game.hexpat" && game.lookup ("Game").size == 32);
				assert (game.lookup ("Player").file == "player.pat");

				string previous_dir = Environment.get_current_dir ();
				Environment.set_current_dir (Path.get_dirname (project_dir));
				var rooted = yield compiler.compile ("player.pat", make_pattern_options (Path.get_basename (project_dir)));
				Environment.set_current_dir (previous_dir);
				assert (rooted.lookup ("Player").file == "player.pat");

				var placed = yield compiler.compile ("placed.hexpat", options);
				assert (placed.root_type == "Placed");
				assert (placed.lookup ("Placed").file == "placed.hexpat");
				assert (placed.lookup ("Placed").fields.get (0).name == "player");
				var player = module.lookup ("Player");
				assert (player.kind == STRUCT);
				assert (player.size == 32);
				assert (player.fields.size () == 4);
				var next = player.fields.get (3);
				assert (next.name == "next");
				assert (next.offset == 24);
				assert (next.type_ref.kind == POINTER);
				assert (next.type_ref.target.name == "Player");

				var broken = yield compiler.compile ("broken.pat", options);
				assert (broken.types.size () == 0);
				assert (broken.diagnostics.size () == 1);
				assert (broken.diagnostics.get (0).file == "broken.pat");
				assert (broken.diagnostics.get (0).message == "auto is not supported");
				assert (broken.diagnostics.get (0).character == 11);

				var importing_broken = yield compiler.compile ("importing-broken.hexpat", options);
				assert (importing_broken.diagnostics.get (0).file == "broken.pat");

				try {
					yield compiler.compile ("missing.hexpat", options);
					assert_not_reached ();
				} catch (Error e) {
					assert (e is Error.INVALID_ARGUMENT);
				}

				var configurable = yield compiler.compile ("configurable.hexpat", options);
				assert (configurable.inputs.size () == 1);
				assert (configurable.inputs.get (0).name == "scale");
				assert (configurable.inputs.get (0).type_ref.name == "u32");
				var decode_options = new PatternDecodeOptions ();
				decode_options.inputs["scale"] = new Variant.int64 (3);
				var scaled = yield configurable.decode ("Configurable", new Bytes ({ 7 }), 0, decode_options);
				assert (scaled.fields.get (0).fields.get (1).value.get_int64 () == 21);

				var data = new uint8[32];
				data[0] = 94;
				data[4] = 7;
				data[24] = 0x34;
				data[25] = 0x12;
				var value = yield module.decode ("Player", new Bytes (data), 0x1000);
				assert (value.type_name == "Player");
				assert (value.size == 32);
				assert (value.fields.get (0).name == "hitpoints");
				assert (value.fields.get (0).value.get_uint64 () == 94);
				assert (value.fields.get (2).fields.get (0).value.get_double () == 0.0);
				assert (value.fields.get (3).address == 0x1018);
				assert (value.fields.get (3).value.get_uint64 () == 0x1234);
				var serialized = value.to_variant ();
				assert (serialized.lookup_value ("fields", null).n_children () == 4);

				var formatted = yield compiler.compile ("formatted.hexpat", options);
				var labelled = yield formatted.decode ("Labelled", new Bytes (data), 0);
				assert (labelled.fields.get (0).formatted == "94 hp");
				assert (labelled.fields.get (0).color == "00FF00");

				var visualizing = yield compiler.compile ("visualizing.hexpat", options);
				var visualized = yield visualizing.decode ("Image", new Bytes ({ 0x89, 0x50, 7, 1, 2 }), 0x1000);
				var image = visualized.fields.get (2).visualizer;
				assert (image.name == "image" && image.presentation == DETACHED);
				var bytes = image.arguments.get (0);
				assert (bytes.kind == PATTERN && bytes.address == 0x1000 && bytes.size == 3);
				assert (bytes.pattern == visualized.fields.get (2).id && bytes.data.compare (new Bytes ({ 0x89, 0x50, 7 })) == 0);
				var plot = visualized.fields.get (3).visualizer;
				assert (plot.presentation == INLINE && plot.arguments.size () == 2);
				assert (plot.arguments.get (1).kind == VALUE && plot.arguments.get (1).value.get_int64 () == 7);
				assert (visualized.fields.get (2).to_variant ().lookup_value ("visualizer", null) != null);

				var printing = yield compiler.compile ("printing.hexpat", options);
				string output = yield printing.call_function ("Image", new Bytes ({ 0x89, 0x50, 7 }), 0x1000, 1, "describe");
				assert (output == "width 7");

				var truncated = yield module.decode ("Player", new Bytes (data[:20]), 0x1000);
				assert (truncated.truncated);
				assert (truncated.fields.get (3).value == null);

				try {
					yield module.decode ("Nope", new Bytes (data), 0);
					assert_not_reached ();
				} catch (Error e) {
					assert (e is Error.INVALID_ARGUMENT);
					assert ("unknown type Nope" in e.message);
				}

				remove_directory (project_dir);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}

		private static string write_pattern (string project_dir, string name, string contents) throws GLib.Error {
			string path = Path.build_filename (project_dir, name);
			FileUtils.set_contents (path, contents);
			return path;
		}

		private static PatternCompileOptions make_pattern_options (string? project_root = null) {
			var options = new PatternCompileOptions ();
			options.project_root = project_root;
			options.platform = "darwin";
			options.arch = "arm64";
			return options;
		}

		private static void remove_directory (string path) throws GLib.Error {
			var dir = Dir.open (path);
			string? name;
			while ((name = dir.read_name ()) != null)
				FileUtils.unlink (Path.build_filename (path, name));
			DirUtils.remove (path);
		}

		private static async void complete_pattern_fields (Harness h) {
			if (skip_slow_test ()) {
				stdout.printf ("<skipping, run in slow mode> ");
				h.done ();
				return;
			}

			try {
				string project_dir = DirUtils.make_tmp ("compiler-test.XXXXXX");
				string agent_ts_path = Path.build_filename (project_dir, "agent.ts");
				string agent_ts_source = "import { Player } from \"./player.pat\";\nconst p = Player.at(NULL);\np.\n";
				FileUtils.set_contents (agent_ts_path, agent_ts_source);
				string player_pat_path = Path.build_filename (project_dir, "player.pat");
				FileUtils.set_contents (player_pat_path, PLAYER_PATTERN);

				var server = new LanguageServer (project_dir);

				var client = new LanguageServerTests.Client (server);
				yield server.start ();

				yield client.request ("initialize", """{
					"processId": null,
					"rootUri": "%s",
					"capabilities": {}
				}""".printf (LanguageServerTests.file_uri (project_dir)));
				client.send_notification ("initialized", "{}");

				client.send_notification ("textDocument/didOpen", """{
					"textDocument": {
						"uri": "%s",
						"languageId": "typescript",
						"version": 1,
						"text": "%s"
					}
				}""".printf (LanguageServerTests.file_uri (agent_ts_path), agent_ts_source.escape ()));

				var completion = yield client.request ("textDocument/completion", """{
					"textDocument": { "uri": "%s" },
					"position": { "line": 2, "character": 2 }
				}""".printf (LanguageServerTests.file_uri (agent_ts_path)));
				assert ("\"hitpoints\"" in completion);

				yield client.request ("shutdown", null);
				client.send_notification ("exit", null);
				server.stop ();

				FileUtils.unlink (Path.build_filename (project_dir, "player.pat.d.ts"));
				FileUtils.unlink (player_pat_path);
				FileUtils.unlink (agent_ts_path);
				DirUtils.remove (project_dir);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}
	}

	namespace LanguageServerTests {
		private static async void complete_simple_agent (Harness h) {
			if (skip_slow_test ()) {
				stdout.printf ("<skipping, run in slow mode> ");
				h.done ();
				return;
			}

			try {
				string project_dir = DirUtils.make_tmp ("compiler-test.XXXXXX");
				string agent_ts_path = Path.build_filename (project_dir, "agent.ts");
				string agent_ts_source = "const m = Process.mainModule;\nm.\n";
				FileUtils.set_contents (agent_ts_path, agent_ts_source);

				var server = new LanguageServer (project_dir);

				var client = new Client (server);
				yield server.start ();

				yield client.request ("initialize", """{
					"processId": null,
					"rootUri": "%s",
					"capabilities": {}
				}""".printf (file_uri (project_dir)));
				client.send_notification ("initialized", "{}");

				client.send_notification ("textDocument/didOpen", """{
					"textDocument": {
						"uri": "%s",
						"languageId": "typescript",
						"version": 1,
						"text": "%s"
					}
				}""".printf (file_uri (agent_ts_path), agent_ts_source.escape ()));

				var completion = yield client.request ("textDocument/completion", """{
					"textDocument": { "uri": "%s" },
					"position": { "line": 1, "character": 2 }
				}""".printf (file_uri (agent_ts_path)));
				assert ("\"enumerateExports\"" in completion);

				yield client.request ("shutdown", null);
				client.send_notification ("exit", null);
				server.stop ();

				FileUtils.unlink (agent_ts_path);
				DirUtils.remove (project_dir);
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}

		internal static string file_uri (string path) throws ConvertError {
			return Filename.to_uri (path);
		}

		internal class Client : Object {
			private LanguageServer server;
			private int next_id = 1;
			private Gee.Map<int, PendingRequest> pending = new Gee.HashMap<int, PendingRequest> ();

			public Client (LanguageServer server) {
				this.server = server;
				server.message.connect (on_message);
			}

			public async string request (string method, string? params) throws Error {
				int id = next_id++;
				var pending_request = new PendingRequest (request.callback);
				pending[id] = pending_request;

				server.post ("""{"jsonrpc": "2.0", "id": %d, "method": "%s"%s}""".printf (id, method, params_member (params)));
				yield;

				return pending_request.result;
			}

			public void send_notification (string method, string? params) throws Error {
				server.post ("""{"jsonrpc": "2.0", "method": "%s"%s}""".printf (method, params_member (params)));
			}

			private static string params_member (string? params) {
				return (params != null) ? ", \"params\": " + params : "";
			}

			private void on_message (string json) {
				if (GLib.Test.verbose ())
					print ("<<< %s\n", json);

				Json.Reader reader;
				try {
					reader = make_json_reader (json);
				} catch (GLib.Error e) {
					assert_not_reached ();
				}

				bool is_response = !reader.read_member ("method");
				reader.end_member ();

				if (is_response)
					handle_response (reader, json);
				else
					handle_call (reader);
			}

			private void handle_response (Json.Reader reader, string json) {
				reader.read_member ("id");
				int id = (int) reader.get_int_value ();
				reader.end_member ();

				PendingRequest pending_request;
				pending.unset (id, out pending_request);

				pending_request.result = json;
				pending_request.callback ();
			}

			private void handle_call (Json.Reader reader) {
				bool is_request = reader.read_member ("id");
				if (is_request)
					reply_to_server_request (reader.get_string_value ());
				reader.end_member ();
			}

			private void reply_to_server_request (string id) {
				try {
					server.post ("""{"jsonrpc": "2.0", "id": "%s", "result": null}""".printf (id));
				} catch (Error e) {
					assert_not_reached ();
				}
			}

			private class PendingRequest {
				public SourceFunc callback;
				public string? result;

				public PendingRequest (owned SourceFunc callback) {
					this.callback = (owned) callback;
				}
			}
		}
	}

	namespace Performance {
		private static async void build_simple_agent (Harness h) {
			if (skip_slow_test ()) {
				stdout.printf ("<skipping, run in slow mode> ");
				h.done ();
				return;
			}

			try {
				var device_manager = new DeviceManager ();
				var compiler = new Compiler (device_manager);

				string project_dir = DirUtils.make_tmp ("compiler-test.XXXXXX");
				string agent_ts_path = Path.build_filename (project_dir, "agent.ts");
				FileUtils.set_contents (agent_ts_path, """
import { log } from "./logger.js";

const woot = Buffer.from("w00t").toString("base64");

log("Hello World: " + woot);
log(hexdump(Process.mainModule.base, { ansi: true }));
""");

				string logger_ts_path = Path.build_filename (project_dir, "logger.ts");
				FileUtils.set_contents (logger_ts_path, """
export function log(...items: any[]) {
    const message = items.join("\n");
    console.log(`[LOG] ${message}`);
}
""");

				compiler.diagnostics.connect (d => printerr ("DIAGNOSTICS: %s\n", d.print (false)));
				var timer = new Timer ();
				var code = yield compiler.build (agent_ts_path);
				uint elapsed_msec = (uint) (timer.elapsed () * 1000.0);

				if (GLib.Test.verbose ()) {
					print ("Output:\nvvv\n%s^^^\n", code);
					print ("Built in %u ms\n", elapsed_msec);
				}

				unowned string? test_log_path = Environment.get_variable ("FRIDA_TEST_LOG");
				if (test_log_path != null) {
					var test_log = FileStream.open (test_log_path, "w");
					assert (test_log != null);

					test_log.printf ("build-time,%u\n", elapsed_msec);

					Gum.Process.enumerate_modules (m => {
						if ("frida-agent" in m.path) {
							var r = m.range;
							test_log.printf (("agent-range,0x%" + uint64.FORMAT_MODIFIER + "x,0x%" +
									uint64.FORMAT_MODIFIER + "x\n"),
								r.base_address, r.base_address + r.size);
							return false;
						}

						return true;
					});

					test_log = null;
				}

				FileUtils.unlink (agent_ts_path);
				DirUtils.remove (project_dir);

				compiler = null;
				yield device_manager.close ();
			} catch (GLib.Error e) {
				printerr ("\nFAIL: %s\n\n", e.message);
				assert_not_reached ();
			}

			h.done ();
		}

		private static async void watch_simple_agent (Harness h) {
			if (skip_slow_test ()) {
				stdout.printf ("<skipping, run in slow mode> ");
				h.done ();
				return;
			}

			try {
				var device_manager = new DeviceManager ();
				var compiler = new Compiler (device_manager);

				string project_dir = DirUtils.make_tmp ("compiler-test.XXXXXX");
				string agent_ts_path = Path.build_filename (project_dir, "agent.ts");
				FileUtils.set_contents (agent_ts_path, "console.log(\"Hello World\");");

				string? bundle = null;
				bool waiting = false;
				compiler.output.connect (b => {
					bundle = b;
					if (waiting)
						watch_simple_agent.callback ();
				});

				var timer = new Timer ();
				yield compiler.watch (agent_ts_path);
				while (bundle == null) {
					waiting = true;
					yield;
					waiting = false;
				}
				uint elapsed_msec = (uint) (timer.elapsed () * 1000.0);

				if (GLib.Test.verbose ())
					print ("Watch built first bundle in %u ms\n", elapsed_msec);

				unowned string? test_log_path = Environment.get_variable ("FRIDA_TEST_LOG");
				if (test_log_path != null) {
					var test_log = FileStream.open (test_log_path, "w");
					assert (test_log != null);

					test_log.printf ("build-time,%u\n", elapsed_msec);

					Gum.Process.enumerate_modules (m => {
						if ("frida-agent" in m.path) {
							var r = m.range;
							test_log.printf (("agent-range,0x%" + uint64.FORMAT_MODIFIER + "x,0x%" +
									uint64.FORMAT_MODIFIER + "x\n"),
								r.base_address, r.base_address + r.size);
							return false;
						}

						return true;
					});

					test_log = null;
				}

				FileUtils.unlink (agent_ts_path);
				DirUtils.remove (project_dir);

				compiler = null;
				yield device_manager.close ();
			} catch (GLib.Error e) {
				assert_not_reached ();
			}

			h.done ();
		}

	}

	private static bool skip_slow_test () {
		if (GLib.Test.slow ())
			return false;

		if (Frida.Test.os () == Frida.Test.OS.IOS)
			return true;

		switch (Frida.Test.cpu ()) {
			case ARM_32:
			case ARM_64: {
				bool likely_running_in_an_emulator = ByteOrder.HOST == ByteOrder.BIG_ENDIAN;
				if (likely_running_in_an_emulator)
					return true;
				break;
			}
			default:
				break;
		}

		return false;
	}

	private sealed class Harness : Frida.Test.AsyncHarness {
		public Harness (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}
	}
}
