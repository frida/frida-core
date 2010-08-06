namespace Zid {
	[DBus (name = "org.zid.Controller")]
	public interface Controller : Object {
		public abstract void say (string message) throws IOError;
	}

	namespace ObjectPath {
		public const string CONTROLLER = "/org/zid/Controller";
	}
}
