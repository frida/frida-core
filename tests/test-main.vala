namespace Zed.Test {

	public static void main (string[] args) {
		GLib.Test.init (ref args);

		winipc_add_tests ();
		winjector_add_tests ();

		GLib.Test.run ();
	}

}
