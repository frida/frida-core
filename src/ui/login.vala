namespace Zed {
	public class View.Login : Object {
		public Gtk.Widget widget {
			get {
				return table;
			}
		}

		private Gtk.Table table;

		public Login () {
			try {
				var builder = new Gtk.Builder ();
				builder.add_from_string (Zed.Data.Login.UI_XML, -1);
				table = builder.get_object ("table") as Gtk.Table;
			} catch (Error e) {
			}
		}
	}

	public class Presenter.Login : Object {
		public View.Login view {
			get;
			construct;
		}

		public Login (View.Login view) {
			Object (view: view);
		}
	}
}

