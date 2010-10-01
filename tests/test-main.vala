namespace Zed.Test {

	public static void main (string[] args) {
		Environment.init (ref args);

		Zed.AgentTest.add_tests ();
		Zed.CodeServiceTest.add_tests ();
		Zed.WinIpcTest.add_tests ();
		Zed.WinjectorTest.add_tests ();
		Zed.HostSessionTest.add_tests ();

		GLib.Test.run ();

		Environment.deinit ();
	}

	namespace Environment {
		public extern void init ([CCode (array_length_pos = 0.9)] ref unowned string[] args);
		public extern void deinit ();
	}

}
