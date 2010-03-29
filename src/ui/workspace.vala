namespace Zed {
	public class View.Workspace : Object {
		public Gtk.Widget widget {
			get {
				return label;
			}
		}

		private Gtk.Label label;

		public Workspace () {
			label = new Gtk.Label ("Work in progress");
			label.show ();
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
