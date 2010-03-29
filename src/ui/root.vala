namespace Zed {
	public class View.Root : Object {
		public Gtk.Widget widget {
			get {
				return window;
			}
		}

		public View.Login login {
			get;
			construct;
		}

		public View.Workspace workspace {
			get;
			construct;
		}

		private Gtk.Window window;

		private Gtk.Notebook notebook;

		private static const int DEFAULT_WIDTH = 640;
		private static const int DEFAULT_HEIGHT = 480;

		public Root (View.Login login, View.Workspace workspace) {
			Object (login: login, workspace: workspace);

			setup_window ();
			setup_notebook ();
		}

		private void setup_window () {
			window = new Gtk.Window (Gtk.WindowType.TOPLEVEL);
			window.title = "Frida";
			window.set_default_size (DEFAULT_WIDTH, DEFAULT_HEIGHT);
			window.position = Gtk.WindowPosition.CENTER;
		}

		private void setup_notebook () {
			notebook = new Gtk.Notebook ();
			notebook.show_border = false;
			notebook.show_tabs = false;
			notebook.show ();
			window.add (notebook);

			notebook.append_page(login.widget, null);
		}
	}

	public class Presenter.Root : Object {
		public View.Root view {
			get;
			construct;
		}

		public Presenter.Login login {
			get;
			construct;
		}

		public Presenter.Workspace workspace {
			get;
			construct;
		}

		public Root (View.Root view, Presenter.Login login, Presenter.Workspace workspace) {
			Object (view: view, login: login, workspace: workspace);
		}
	}
}
