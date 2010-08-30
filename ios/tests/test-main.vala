namespace Zid.Test {

	public static void main (string[] args) {
		GLib.Test.init (ref args);

		Zid.FruitjectorTest.add_tests ();
		Zid.SystemTest.add_tests ();

		GLib.Test.run ();
	}

}
