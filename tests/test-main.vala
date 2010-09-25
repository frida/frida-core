namespace Zed.Test {

	public static void main (string[] args) {
		Gum.init ();
		GLib.Test.init (ref args);

		Zed.AgentTest.add_tests ();
		Zed.CodeServiceTest.add_tests ();
		Zed.WinIpcTest.add_tests ();
		Zed.WinjectorTest.add_tests ();
		Zed.HostSessionTest.add_tests ();

		GLib.Test.run ();
	}

}
