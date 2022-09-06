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
	}

	namespace Performance {
		private static async void build_simple_agent (Harness h) {
			try {
				var device_manager = new DeviceManager ();
				var compiler = new Compiler (device_manager);

				string project_dir = DirUtils.make_tmp ("compiler-test.XXXXXX");
				string agent_ts_path = Path.build_filename (project_dir, "agent.ts");
				FileUtils.set_contents (agent_ts_path, "console.log(\"Hello World\");");

				var timer = new Timer ();
				yield compiler.build (agent_ts_path);
				uint elapsed_msec = (uint) (timer.elapsed () * 1000.0);

				if (GLib.Test.verbose ())
					print ("Built in %u ms\n", elapsed_msec);

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

		private static async void watch_simple_agent (Harness h) {
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

	private class Harness : Frida.Test.AsyncHarness {
		public Harness (owned Frida.Test.AsyncHarness.TestSequenceFunc func) {
			base ((owned) func);
		}
	}
}
