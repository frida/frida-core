namespace Zed.Test {

	public static void main (string[] args) {
		GLib.Test.init (ref args);

		winjector_add_tests ();

		GLib.Test.run ();
	}

}
