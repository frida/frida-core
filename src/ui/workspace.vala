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

		public View.Spy spy {
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
				builder.add_from_string (Zed.Data.Ui.WORKSPACE_XML, -1);

				ui_manager = builder.get_object ("uimanager1") as Gtk.UIManager;
				vbox = builder.get_object ("root_vbox") as Gtk.VBox;
				upper_frame = builder.get_object ("top_frame") as Gtk.Frame;
				bottom_frame = builder.get_object ("bottom_frame") as Gtk.Frame;
			} catch (Error e) {
				error (e.message);
			}

			spy = new View.Spy ();
			upper_frame.add (spy.widget);

			chat = new View.Chat ();
			bottom_frame.add (chat.widget);
		}
	}

	public class Presenter.Workspace : Object {
		public View.Workspace view {
			get;
			construct;
		}

		public Presenter.Spy spy {
			get;
			construct;
		}

		public Presenter.Chat chat {
			get;
			construct;
		}

		public Workspace (View.Workspace view, Service.MucService muc_service) {
			Object (view: view, spy: new Presenter.Spy (view.spy), chat: new Presenter.Chat (view.chat, muc_service));
		}
	}
}
