namespace Frida {
	public int main (string[] args) {
		Posix.setsid ();

		Gum.init ();

		var parent_address = args[1];
		var service = new HelperService (parent_address);
		return service.run ();
	}
}
