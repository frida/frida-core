namespace Frida.Test {

	public static void run (string[] args) {
		Environment.init (ref args);

		Frida.SystemTest.add_tests ();

#if WINDOWS
		Frida.WinjectorTest.add_tests ();
#elif LINUX
		Frida.LinjectorTest.add_tests ();
#elif DARWIN
		Frida.FruitjectorTest.add_tests ();
#endif

		Frida.AgentTest.add_tests ();
		Frida.HostSessionTest.add_tests ();

		GLib.Test.run ();

		Environment.deinit ();
	}

	namespace Environment {
		public extern void init ([CCode (array_length_pos = 0.9)] ref unowned string[] args);
		public extern void deinit ();
	}

}
