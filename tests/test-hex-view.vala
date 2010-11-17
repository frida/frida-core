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

/* SCRATCH BEGIN */

namespace Zed {

	public class HexView : Mx.Widget, Mx.Stylable {
		private Clutter.ActorBox heading = Clutter.ActorBox ();
		private Clutter.Text heading_text = new Clutter.Text.with_text ("Lucida Console 10", "00");

		private Clutter.ActorBox margin = Clutter.ActorBox ();
		private Clutter.Text margin_text = new Clutter.Text.with_text ("Lucida Console 10", "00000000");

		//private Clutter.ActorBox line = Clutter.ActorBox ();
		private Clutter.Text line_text = new Clutter.Text.with_text ("Lucida Console 10", "01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f");

		private Clutter.ActorBox body = Clutter.ActorBox ();

		private Cogl.Color bg_color;
		private Cogl.Color fg_color;
		private Cogl.Color address_bg_color;
		private Cogl.Color address_fg_color;

		construct {
			margin_text.set_parent (this);
			var color = Clutter.Color.from_string ("#ffffffff");
			margin_text.color = color;
			margin_text.show ();

			style_changed.connect ((flags) => load_style_properties ());
		}

		public override void get_preferred_width (float for_height, out float min_width_p, out float natural_width_p) {
			var box = Clutter.ActorBox ();
			box.x2 = 640;
			box.y2 = 480;
			compute_layout_boxes (box);

			float min_width = heading.get_width ();
			min_width_p = min_width;
			natural_width_p = min_width;
		}

		public override void get_preferred_height (float for_width, out float min_height_p, out float natural_height_p) {
			float min_width;
			get_preferred_width (-1.0f, out min_width, null);

			float min_height = min_width * 1.61f;
			min_height_p = min_height;
			natural_height_p = min_height;
		}

		protected override void map () {
			base.map ();

			margin_text.map ();
		}

		protected override void unmap () {
			margin_text.unmap ();

			base.unmap ();
		}

		protected override void allocate (Clutter.ActorBox box, Clutter.AllocationFlags flags) {
			base.allocate (box, flags);

			compute_layout_boxes (box);

			margin_text.allocate (margin, flags);
		}

		protected override void paint_background () {
		}

		protected override void paint () {
			Cogl.path_rectangle (heading.x1, heading.y1, heading.x2, heading.y2);

			Cogl.path_rectangle (margin.x1, margin.y1, margin.x2, margin.y2);
			Cogl.set_source_color (address_bg_color);
			Cogl.path_fill ();

			Cogl.path_rectangle (body.x1, body.y1, body.x2, body.y2);
			Cogl.set_source_color (bg_color);
			Cogl.path_fill ();

			Cogl.set_source_color (address_fg_color);
			Cogl.path_line (body.x1, body.y1, body.x2, body.y1);
			Cogl.path_stroke ();
			Cogl.path_line (body.x1, body.y1, body.x1, body.y2);
			Cogl.path_stroke ();

			margin_text.paint ();

			base.paint ();
		}

		private void compute_layout_boxes (Clutter.ActorBox box) {
			float width, height;

			heading.x1 = box.x1;
			heading.y1 = box.y1;
			line_text.get_preferred_width (-1.0f, null, out width);
			heading.x2 = heading.x1 + width;
			heading_text.get_preferred_height (-1.0f, null, out height);
			heading.y2 = heading.y1 + 2.0f + height + 6.0f;
			heading.clamp_to_pixel ();

			margin_text.get_preferred_width (-1.0f, null, out width);
			margin.x1 = box.x1;
			margin.y1 = heading.y2;
			margin.x2 = margin.x1 + 8.0f + width + 8.0f;
			margin.y2 = box.y2;
			margin.clamp_to_pixel ();

			body.x1 = margin.x2;
			body.y1 = heading.y2;
			body.x2 = body.x1 + heading.get_width () - margin.get_width ();
			body.y2 = margin.y2;
			body.clamp_to_pixel ();
		}

		private void load_style_properties () {
			/* FIXME: split into multiple widgets */
			fg_color = Cogl.Color ();
			fg_color.set_from_4ub (0, 0, 0, 255);
			bg_color = get_style_color ("background-color");

			address_fg_color = Cogl.Color ();
			address_fg_color.set_from_4ub (0, 0, 0, 255);
			address_bg_color = get_style_color ("color");
		}

		private Cogl.Color get_style_color (string name) {
			Clutter.Color? c = null;
			get (name, out c);

			Cogl.Color result = Cogl.Color ();
			result.set_from_4ub (c.red, c.green, c.blue, c.alpha);

			return result;
		}
	}

}

/* SCRATCH END */
