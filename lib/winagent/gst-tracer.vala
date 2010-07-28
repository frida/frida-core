using Gee;

namespace Zed {
	public class GstTracer : Object, Gum.InvocationListener {
		private WinIpc.Proxy proxy;

		public GstTracer (WinIpc.Proxy proxy) {
			this.proxy = proxy;
		}

		public extern void attach ();
		public extern void detach ();

		private HashMap<void *, PadEntry> pads = new HashMap<void *, PadEntry> ();
		private uint last_id = 1;

		private ArrayList<PadEntry> pending_adds = new ArrayList<PadEntry> ();
		private Timer last_add_timer = new Timer ();

		private uint flush_timeout_id = 0;

		private bool on_flush_timeout () {
			lock (pads) {
				if (last_add_timer.elapsed () < 2.0)
					return true;

				var builder = new VariantBuilder (VariantType.ARRAY);
				uint count = 0;
				foreach (var entry in pending_adds) {
					builder.add ("(us)", entry.id, entry.path);
					count++;
					if (count == 10) /* FIXME: zed-winipc has a maximum message size of 4k */
						break;
				}
				pending_adds.clear ();
				proxy.emit ("GstPadsDiscovered", builder.end ());

				flush_timeout_id = 0;
			}

			return false;
		}

		private void on_pad_push (void * pad, void * buffer) {
			lock (pads) {
				var entry = pads[pad];
				if (entry == null) {
					last_add_timer.start ();

					entry = new PadEntry (last_id++, query_object_path (pad));
					pads[pad] = entry;
					pending_adds.add (entry);

					if (flush_timeout_id == 0) {
						flush_timeout_id = Timeout.add (1000, on_flush_timeout);
					}
				}
			}
		}

		public void on_enter (Gum.InvocationContext ctx) {
			GstFunction func = (GstFunction) ctx.instance_data;
			if (func == GstFunction.PAD_PUSH) {
				on_pad_push (ctx.get_nth_argument (0), ctx.get_nth_argument (1));
			} else if (func == GstFunction.OBJECT_FREE) {
			} else {
				assert_not_reached ();
			}
		}

		public void on_leave (Gum.InvocationContext ctx) {
		}

		private class PadEntry {
			public uint id {
				get;
				private set;
			}

			public string path {
				get;
				private set;
			}

			public PadEntry (uint id, string path) {
				this.id = id;
				this.path = path;
			}
		}

		private extern string query_object_path (void * instance);
	}

	public enum GstFunction {
		PAD_PUSH = 1,
		OBJECT_FREE
	}
}
