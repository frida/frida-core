namespace Zed.Test {

	public static void run (string[] args) {
		Environment.init (ref args);

#if HAVE_LOCAL_BACKENDS
		Zed.SystemTest.add_tests ();
#endif

#if HAVE_LOCAL_BACKENDS
#if WINDOWS
		Zed.WinjectorTest.add_tests ();
#elif LINUX
		Zed.LinjectorTest.add_tests ();
#elif DARWIN
		Zed.FruitjectorTest.add_tests ();
#endif
#endif

		Zed.AgentTest.add_tests ();
		Zed.HostSessionTest.add_tests ();

		GLib.Test.run ();

		Environment.deinit ();
	}

	namespace Environment {
		public extern void init ([CCode (array_length_pos = 0.9)] ref unowned string[] args);
		public extern void deinit ();
	}

}
