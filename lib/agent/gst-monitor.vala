namespace Zed.Agent {
	public class GstMonitor : Object, Gum.InvocationListener {
		public signal void pad_stats (GstPadStats[] stats);

		private Gum.Interceptor interceptor = Gum.Interceptor.obtain ();
		private bool is_enabled = false;

		private Gee.HashMap<void *, PadInfo> pad_info_by_address = new Gee.HashMap<void *, PadInfo> ();
		private PadInfo[] monitored_pads = new PadInfo[0];
		private uint timeout_id = 0;
		private Stopwatch stopwatch = null;

		~GstMonitor () {
			shutdown ();
		}

		public void shutdown () {
			if (is_enabled) {
				try {
					disable ();
				} catch (IOError e) {
					assert_not_reached ();
				}
			}
		}

		public void enable () throws IOError {
			if (is_enabled)
				throw new IOError.FAILED ("already enabled");

			string gst_module_name = null;
			Gum.Process.enumerate_modules ((name, address, path) => {
				if (name.down ().str ("gstreamer-0.10") != null) {
					gst_module_name = name;
					return false;
				}

				return true;
			});

			if (gst_module_name == null)
				throw new IOError.FAILED ("GStreamer library not loaded");

			var pad_push_address = Gum.Module.find_export_by_name (gst_module_name, "gst_pad_push");
			if (pad_push_address == null)
				throw new IOError.FAILED ("gst_pad_push not found");

			interceptor.attach_listener (pad_push_address, this);
			is_enabled = true;

			handle_tick ();
			timeout_id = Timeout.add (1000, handle_tick);
		}

		public void disable () throws IOError {
			if (!is_enabled)
				throw new IOError.FAILED ("already disabled");

			interceptor.detach_listener (this);

			pad_info_by_address.clear ();
			monitored_pads = new PadInfo[0];

			var source = MainContext.default ().find_source_by_id (timeout_id);
			if (source != null)
				source.destroy ();
			timeout_id = 0;

			stopwatch = null;

			is_enabled = false;
		}

		public void on_enter (Gum.InvocationContext context) {
			unowned GstObject pad = (GstObject) context.get_nth_argument (0);

			lock (pad_info_by_address) {
				var info = pad_info_by_address[pad];
				if (info == null) {
					info = new PadInfo (generate_name_from_pad (pad), should_ignore_pad (pad));
					pad_info_by_address[pad] = info;

					if (!info.ignored)
						monitored_pads += info;
				}

				if (!info.ignored)
					info.buffer_count++;
			}
		}

		public void on_leave (Gum.InvocationContext context) {
		}

		public bool handle_tick () {
			if (stopwatch == null) {
				lock (pad_info_by_address) {
					foreach (var info in monitored_pads)
						info.buffer_count = 0;
				}

				stopwatch = new Stopwatch ();

				return true;
			}

			var result = new GstPadStats[0];

			lock (pad_info_by_address) {
				double elapsed = stopwatch.elapsed ();

				foreach (var info in monitored_pads) {
					result += GstPadStats (info.name, (double) info.buffer_count / elapsed);
					info.buffer_count = 0;
				}
			}

			stopwatch.restart ();

			if (result.length > 0)
				pad_stats (result);

			return true;
		}

		private string? generate_name_from_pad (GstObject pad) {
			if (!pad_has_sensible_name (pad))
				return null;
			return pad.parent.name + "." + pad.name;
		}

		private bool should_ignore_pad (GstObject pad) {
			if (!pad_has_sensible_name (pad))
				return true;
			return false;
		}

		private bool pad_has_sensible_name (GstObject pad) {
			return (pad.name != null && pad.parent != null && pad.parent.name != null);
		}

		private class PadInfo : Object {
			public string? name {
				get;
				construct;
			}

			public bool ignored;

			public int buffer_count;

			public PadInfo (string name, bool ignored) {
				Object (name: name);

				this.ignored = ignored;
			}
		}
	}

	[Compact]
	public class GstObject {
		/* GTypeInstance */
		public void * g_class;

		/* GObject */
		public uint ref_count;
		public void * qdata;

		/* GstObject */
		public int refcount;

		public Mutex lock;
		public string name;
		public string name_prefix;
		public GstObject parent;
		public uint32 flags;

		public void * _gst_reserved;
	}
}
