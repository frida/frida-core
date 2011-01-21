public class Zed.Application : Object {
	private Mx.ResourceProvider resource_provider = new EmbeddedResourceProvider ();

	private Configuration configuration;

	private Service.StorageBackend storage_backend;
	private Service.HostSessionService host_session_service;
	private Service.XmppClient xmpp_client;
	private Service.MucService muc_service;

	private Presenter.Root root;

	construct {
		Mx.ResourceProvider.set_default (resource_provider);

		setup_services ();

		configuration = new Configuration (storage_backend);

		setup_presenters ();
	}

	~Application () {
		Mx.ResourceProvider.set_default (null);
	}

	public void run () {
		root.view.widget.show ();
		Gtk.main ();
	}

	private async void stop () {
		yield host_session_service.stop ();
		yield xmpp_client.close ();
		Gtk.main_quit ();
	}

	private void setup_services () {
		storage_backend = new Service.StorageBackend ();
		host_session_service = new Service.HostSessionService ();
		xmpp_client = new Service.XmppClient ();
		muc_service = new Service.MucService (xmpp_client);

#if WINDOWS
		host_session_service.add_backend (new Service.WindowsHostSessionBackend ());
		host_session_service.add_backend (new Service.FruityHostSessionBackend ());
#endif
		host_session_service.add_backend (new Service.TcpHostSessionBackend ());
	}

	private void setup_presenters () {
		var login = new Zed.Presenter.Login (new Zed.View.Login (), xmpp_client, configuration);
		var workspace = new Zed.Presenter.Workspace (new Zed.View.Workspace (), host_session_service, muc_service, storage_backend);

		var root_view = new Zed.View.Root (login.view, workspace.view);
		root = new Zed.Presenter.Root (root_view, login, workspace);

		root_view.widget.destroy.connect (() => stop ());
	}

	private class EmbeddedResourceProvider : Object, Mx.ResourceProvider {
		public string? get_string (string name) {
			assert (name == "default.css");
			return (string) Zed.Data.Mx.get_default_css_blob ().data;
		}

		public uint8 * get_image (string name, out uint width, out uint height) {
			var blob = Zed.Data.Mx.find_image_by_name (name);
			assert (blob != null);

			var stream = new MemoryInputStream.from_data (blob.data, blob.size, null);

			try {
				var pixbuf = new Gdk.Pixbuf.from_stream (stream, null);

				width = pixbuf.get_width ();
				height = pixbuf.get_height ();

				return Memory.dup (pixbuf.get_pixels (), pixbuf.get_height () * pixbuf.get_rowstride ());
			} catch (Error pixbuf_error) {
				assert_not_reached ();
			}
		}
	}
}

int main (string[] args) {
	Wocky.init ();
#if WINDOWS
	GtkClutter.init (ref args);
#else
	Gtk.init (ref args);
#endif

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
