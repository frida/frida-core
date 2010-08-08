namespace Zed.Test {

	public static void main (string[] args) {
		Gum.init ();
		GLib.Test.init (ref args);

		Zed.Test.CodeService.add_tests ();
		Zed.Test.WinIpc.add_tests ();
		Zed.Test.Winjector.add_tests ();
		Zed.Test.HostSession.add_tests ();

		GLib.Test.run ();
	}

}
