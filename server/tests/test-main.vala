namespace Zed.Test {

	public static void main (string[] args) {
		GLib.Test.init (ref args);

		Zed.FruitjectorTest.add_tests ();
		Zed.SystemTest.add_tests ();

		GLib.Test.run ();
	}

}
