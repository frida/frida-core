namespace Zed.Test {

	public static void main (string[] args) {
		Environment.init ();
		Gum.init ();
		GLib.Test.init (ref args);

		Zed.AgentTest.add_tests ();
		Zed.CodeServiceTest.add_tests ();
		Zed.WinIpcTest.add_tests ();
		Zed.WinjectorTest.add_tests ();
		Zed.HostSessionTest.add_tests ();

		GLib.Test.run ();

		GLib.IO.deinit ();
		Gum.deinit ();
		GLib.Type.deinit ();
		GLib.Thread.deinit ();
		GLib.Test.deinit ();
		GLib.mem_deinit ();
		Environment.deinit ();
	}

	namespace Environment {
		public extern void init ();
		public extern void deinit ();
	}

}
