namespace Zed {
	public class View.Workspace : Object {
		public Workspace () {
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
