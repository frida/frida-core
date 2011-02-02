namespace Zed.Test {

	public static void main (string[] args) {
		Environment.init (ref args);

		Zed.SystemTest.add_tests ();

#if WINDOWS
		Zed.WinIpcTest.add_tests ();
		Zed.WinjectorTest.add_tests ();
#endif

#if IOS
		Zed.FruitjectorTest.add_tests ();
#endif

		Zed.CodeServiceTest.add_tests ();
#if !ANDROID
		Zed.AgentTest.add_tests ();
#endif
		Zed.HostSessionTest.add_tests ();

#if WINDOWS
		Zed.HexViewTest.add_tests ();
#endif

		GLib.Test.run ();

		Environment.deinit ();
	}

	namespace Environment {
		public extern void init ([CCode (array_length_pos = 0.9)] ref unowned string[] args);
		public extern void deinit ();
	}

}
