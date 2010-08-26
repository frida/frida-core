public class Zid.Fruitjector {
	public async void inject (int pid, string dylib_path) throws IOError {
		do_inject (pid, dylib_path);
	}

	public extern void do_inject (int pid, string dylib_path) throws IOError;
}
