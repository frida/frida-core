namespace Zed {
	public class View.Workspace : Object {
		public Gtk.Widget widget {
			get {
				return vbox;
			}
		}

		public Gtk.Frame upper_frame {
			get;
			private set;
		}

		public Gtk.Frame bottom_frame {
			get;
			private set;
		}

		public View.HostSession host_session {
			get;
			private set;
		}

		public View.Chat chat {
			get;
			private set;
		}

		private Gtk.UIManager ui_manager;
		private Gtk.VBox vbox;

		public Workspace () {
			try {
				var builder = new Gtk.Builder ();
				var blob = Zed.Data.Ui.get_workspace_ui_blob ();
				builder.add_from_string ((string) blob.data, blob.size);

				ui_manager = builder.get_object ("uimanager1") as Gtk.UIManager;
				vbox = builder.get_object ("root_vbox") as Gtk.VBox;
				upper_frame = builder.get_object ("top_frame") as Gtk.Frame;
				bottom_frame = builder.get_object ("bottom_frame") as Gtk.Frame;
			} catch (Error e) {
				error (e.message);
			}

			host_session = new View.HostSession ();
			upper_frame.add (host_session.widget);

			chat = new View.Chat ();
			bottom_frame.add (chat.widget);
		}
	}

	public class Presenter.Workspace : Object {
		public View.Workspace view {
			get;
			construct;
		}

		public Presenter.HostSession host_session {
			get;
			construct;
		}

		public Presenter.Chat chat {
			get;
			construct;
		}

		public Workspace (View.Workspace view, Service.HostSessionService host_session_service, Service.MucService muc_service, Service.StorageBackend storage_backend) {
			Object (view: view, host_session: new Presenter.HostSession (view.host_session, host_session_service, storage_backend), chat: new Presenter.Chat (view.chat, muc_service));
		}
	}
}
