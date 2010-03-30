namespace Zed {
	public class View.Workspace : Object {
		public Gtk.Widget widget {
			get {
				return vbox;
			}
		}

		private Gtk.UIManager ui_manager;
		private Gtk.VBox vbox;

		public Workspace () {
			try {
				var builder = new Gtk.Builder ();
				builder.add_from_string (Zed.Data.Ui.WORKSPACE_XML, -1);

				ui_manager = builder.get_object ("uimanager1") as Gtk.UIManager;
				vbox = builder.get_object ("root_vbox") as Gtk.VBox;
			} catch (Error e) {
				warning (e.message);
			}
		}
	}

	public class Presenter.Workspace : Object {
		public View.Workspace view {
			get;
			construct;
		}

		public Workspace (View.Workspace view) {
			Object (view: view);
		}
	}
}
