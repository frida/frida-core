public class Zed.Application : Object {
	private Presenter.Root root;

	public Application () {
		setup_presenters ();
	}

	public void run () {
		root.view.widget.show ();
		Gtk.main ();
	}

	private void setup_presenters () {
		var login = new Zed.Presenter.Login (new Zed.View.Login ());
		var workspace = new Zed.Presenter.Workspace (new Zed.View.Workspace ());

		var root_view = new Zed.View.Root (login.view, workspace.view);
		root = new Zed.Presenter.Root (root_view, login, workspace);

		root_view.widget.destroy.connect (Gtk.main_quit);
	}
}

int main (string[] args) {
	Gtk.init (ref args);

	// Access types needed in XML
	typeof (Gtk.Alignment);
	typeof (Gtk.Button);
	typeof (Gtk.Entry);
	typeof (Gtk.Label);
	typeof (Gtk.Table);
	typeof (Gtk.Window);

	var app = new Zed.Application ();
	app.run ();

	return 0;
}
