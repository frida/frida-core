public class Zed.Application : Object {
	private Configuration configuration;

	private Service.XmppClient xmpp_client;
	private Service.MucService muc_service;

	private Presenter.Root root;

	public Application () {
		configuration = Configuration.get_default ();

		setup_services ();
		setup_presenters ();
	}

	public void run () {
		root.view.widget.show ();
		Gtk.main ();
	}

	private void setup_services () {
		xmpp_client = new Service.XmppClient ();
		muc_service = new Service.MucService (xmpp_client);
	}

	private void setup_presenters () {
		var login = new Zed.Presenter.Login (new Zed.View.Login (), xmpp_client, configuration);
		var workspace = new Zed.Presenter.Workspace (new Zed.View.Workspace (), muc_service);

		var root_view = new Zed.View.Root (login.view, workspace.view);
		root = new Zed.Presenter.Root (root_view, login, workspace);

		root_view.widget.destroy.connect (Gtk.main_quit);
	}
}

int main (string[] args) {
	Wocky.init ();
	Gtk.init (ref args);

	// Access types needed in XML
	typeof (Gtk.ActionGroup);
	typeof (Gtk.Alignment);
	typeof (Gtk.Button);
	typeof (Gtk.Entry);
	typeof (Gtk.Frame);
	typeof (Gtk.Label);
	typeof (Gtk.MenuBar);
	typeof (Gtk.ScrolledWindow);
	typeof (Gtk.Statusbar);
	typeof (Gtk.Table);
	typeof (Gtk.TreeView);
	typeof (Gtk.UIManager);
	typeof (Gtk.VBox);
	typeof (Gtk.HPaned);
	typeof (Gtk.VPaned);
	typeof (Gtk.Window);

	var app = new Zed.Application ();
	app.run ();

	return 0;
}
