namespace Zed.Test {

	public static void main (string[] args) {
		GLib.Test.init (ref args);

		Zed.Test.WinIpc.add_tests ();
		Zed.Test.Winjector.add_tests ();

		GLib.Test.run ();
	}

}
