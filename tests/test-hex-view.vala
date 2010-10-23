namespace Zed.HexViewTest {
	public static void add_tests () {
		if (!GLib.Test.thorough ())
			return;

		GLib.Test.add_func ("/HexView/Layout/basics", () => {
			var h = new Harness ((h) => Layout.basics (h as Harness));
			h.run ();
		});
	}

	namespace Layout {

		private static async void basics (Harness h) {
			//h.done ();
		}

	}

	/* SCRATCH BEGIN */

	public class HexView : Mx.Widget {
		protected override void paint () {
			Clutter.Geometry geo;
			get_allocation_geometry (out geo);

			Cogl.Color bgcolor = Cogl.Color ();
			bgcolor.set_from_4ub (128, 128, 128, 255);

			Cogl.path_round_rectangle (0, 0, geo.width, geo.height, 5, (float) Math.PI_4 / 4.0f);
			Cogl.set_source_color (bgcolor);
			Cogl.path_stroke ();
		}
	}

	/* SCRATCH END */

	private class Harness : Zed.Test.AsyncHarness {
		private Clutter.Stage stage = new Clutter.Stage ();

		public HexView view {
			get;
			private set;
		}

		public Harness (Zed.Test.AsyncHarness.TestSequenceFunc func) {
			base (func);
		}

		construct {
			stage.destroy.connect (() => done ());
			stage.color = Clutter.Color.from_string ("#3b5998ff");
			stage.user_resizable = true;

			view = new HexView ();
			view.set_position (10.0f, 10.0f);
			view.set_size (320.0f, 240.0f);
			stage.add_actor (view);

			stage.show_all ();
		}

		protected override MainContext provide_main_context () {
			return MainContext.default ();
		}

		protected override uint provide_timeout () {
			return 0;
		}
	}
}
