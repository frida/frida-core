namespace Zed.Agent {
	public class GstMonitor : Object, Gum.InvocationListener {
		public signal void pad_stats (GstPadStats[] stats);

		private Gum.Interceptor interceptor = Gum.Interceptor.obtain ();
		private bool is_enabled = false;

		[CCode (has_target = false)]
		private delegate void * TypeClassRefFunc (ulong type);
		[CCode (has_target = false)]
		private delegate void TypeClassUnrefFunc (void * g_class);
		[CCode (has_target = false)]
		private delegate ulong GetTypeFunc ();
		private TypeClassRefFunc type_class_ref;
		private TypeClassUnrefFunc type_class_unref;

		[CCode (has_target = false)]
		private delegate void ObjectUnrefFunc (GstObject object);
		[CCode (has_target = false)]
		private delegate uint64 ElementGetBaseTimeFunc (GstObject element);
		[CCode (has_target = false)]
		private delegate GstObject * ElementGetClockFunc (GstObject element);
		[CCode (has_target = false)]
		private delegate uint64 BaseSinkGetLatencyFunc (GstObject base_sink);
		[CCode (has_target = false)]
		private delegate uint64 BaseSinkGetRenderDelayFunc (GstObject base_sink);
		[CCode (has_target = false)]
		private delegate uint64 ClockGetTimeFunc (GstObject clock);
		private ObjectUnrefFunc object_unref;
		private ElementGetBaseTimeFunc element_get_base_time;
		private ElementGetClockFunc element_get_clock;
		private ClockGetTimeFunc clock_get_time;
		private BaseSinkGetLatencyFunc base_sink_get_latency;
		private BaseSinkGetRenderDelayFunc base_sink_get_render_delay;

		private GstBaseSinkClass * base_audio_sink_klass;
		private GstBaseSinkClass * video_sink_klass;
		private GstBaseSinkClass * clutter_video_sink_klass;

		private Gee.HashMap<void *, SinkInfo> sink_info_by_address = new Gee.HashMap<void *, SinkInfo> ();
		private SinkInfo[] monitored_sinks = new SinkInfo[0];
		private uint timeout_id = 0;
		private Stopwatch session_watch = null;
		private Stopwatch period_watch = null;

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

			string gobj_module_name = null;
			string core_module_name = null;
			string base_module_name = null;
			string audio_module_name = null;
			string video_module_name = null;
			string clutter_gst_module_name = null;
			Gum.Process.enumerate_modules ((name, address, path) => {
				var name_lc = name.down ();
				if (name_lc.str ("gobject-2.0") != null)
					gobj_module_name = name;
				else if (name_lc.str ("gstreamer-0.10") != null)
					core_module_name = name;
				else if (name_lc.str ("gstbase-0.10") != null)
					base_module_name = name;
				else if (name_lc.str ("gstaudio-0.10") != null)
					audio_module_name = name;
				else if (name_lc.str ("gstvideo-0.10") != null)
					video_module_name = name;
				else if (name_lc.str ("clutter-gst") != null)
					clutter_gst_module_name = name;

				return true;
			});

			if (gobj_module_name == null || core_module_name == null || base_module_name == null)
				throw new IOError.FAILED ("GStreamer library not loaded");

			type_class_ref = (TypeClassRefFunc) Gum.Module.find_export_by_name (gobj_module_name, "g_type_class_ref");
			type_class_unref = (TypeClassUnrefFunc) Gum.Module.find_export_by_name (gobj_module_name, "g_type_class_unref");
			if (type_class_ref == null || type_class_unref == null)
				throw new IOError.FAILED ("g_type_class_{ref,unref} not found");

			object_unref = (ObjectUnrefFunc) Gum.Module.find_export_by_name (core_module_name, "gst_object_unref");
			element_get_base_time = (ElementGetBaseTimeFunc) Gum.Module.find_export_by_name (core_module_name, "gst_element_get_base_time");
			element_get_clock = (ElementGetClockFunc) Gum.Module.find_export_by_name (core_module_name, "gst_element_get_clock");
			clock_get_time = (ClockGetTimeFunc) Gum.Module.find_export_by_name (core_module_name, "gst_clock_get_time");
			if (object_unref == null || element_get_base_time == null || element_get_clock == null || clock_get_time == null)
				throw new IOError.FAILED ("core function not found");

			base_sink_get_latency = (BaseSinkGetLatencyFunc) Gum.Module.find_export_by_name (base_module_name, "gst_base_sink_get_latency");
			base_sink_get_render_delay = (BaseSinkGetRenderDelayFunc) Gum.Module.find_export_by_name (base_module_name, "gst_base_sink_get_render_delay");
			if (base_sink_get_latency == null || base_sink_get_render_delay == null)
				throw new IOError.FAILED ("core function not found");

			session_watch = new Stopwatch ();

			if (audio_module_name != null) {
				var base_audio_sink_get_type = (GetTypeFunc) Gum.Module.find_export_by_name (audio_module_name, "gst_base_audio_sink_get_type");
				if (base_audio_sink_get_type != null) {
					base_audio_sink_klass = (GstBaseSinkClass *) type_class_ref (base_audio_sink_get_type ());
					interceptor.attach_listener (base_audio_sink_klass->render, this);
				}
			}

			if (video_module_name != null) {
				var video_sink_get_type = (GetTypeFunc) Gum.Module.find_export_by_name (video_module_name, "gst_video_sink_get_type");
				if (video_sink_get_type != null) {
					video_sink_klass = (GstBaseSinkClass *) type_class_ref (video_sink_get_type ());
					interceptor.attach_listener (video_sink_klass->render, this);
				}
			}

			if (clutter_gst_module_name != null) {
				var clutter_video_sink_get_type = (GetTypeFunc) Gum.Module.find_export_by_name (clutter_gst_module_name, "clutter_gst_video_sink_get_type");
				if (clutter_video_sink_get_type != null) {
					clutter_video_sink_klass = (GstBaseSinkClass *) type_class_ref (clutter_video_sink_get_type ());
					interceptor.attach_listener (clutter_video_sink_klass->render, this);
				}
			}

			is_enabled = true;

			handle_tick ();
			timeout_id = Timeout.add (1000, handle_tick);
		}

		public void disable () throws IOError {
			if (!is_enabled)
				throw new IOError.FAILED ("already disabled");

			interceptor.detach_listener (this);

			if (base_audio_sink_klass != null) {
				type_class_unref (base_audio_sink_klass);
				base_audio_sink_klass = null;
			}

			if (video_sink_klass != null) {
				type_class_unref (video_sink_klass);
				video_sink_klass = null;
			}

			if (clutter_video_sink_klass != null) {
				type_class_unref (clutter_video_sink_klass);
				clutter_video_sink_klass = null;
			}

			type_class_ref = null;
			type_class_unref = null;

			object_unref = null;
			element_get_base_time = null;
			element_get_clock = null;
			clock_get_time = null;

			sink_info_by_address.clear ();
			monitored_sinks = new SinkInfo[0];

			var source = MainContext.default ().find_source_by_id (timeout_id);
			if (source != null)
				source.destroy ();
			timeout_id = 0;

			session_watch = null;
			period_watch = null;

			is_enabled = false;
		}

		public void on_enter (Gum.InvocationContext context) {
			GstObject * sink = (GstObject *) context.get_nth_argument (0);
			GstBuffer * buffer = (GstBuffer *) context.get_nth_argument (1);

			var elapsed = session_watch.elapsed_nanoseconds ();

			var clock = element_get_clock (sink);
			var time = clock_get_time (clock);
			object_unref (clock);

			var basetime = element_get_base_time (sink);
			uint64 runningtime = 0;
			if (time >= basetime)
				runningtime = time - basetime;

			var latency = base_sink_get_latency (sink);
			var render_delay = base_sink_get_render_delay (sink);

			lock (sink_info_by_address) {
				var info = sink_info_by_address[sink];
				if (info == null) {
					info = new SinkInfo (generate_name_from_sink (sink));
					sink_info_by_address[sink] = info;

					monitored_sinks += info;
				}

				info.total_buffer_count++;

				info.period_buffer_count++;
				info.period_timing_history.append_printf (
					"%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u\n",
					elapsed,
					info.total_buffer_count,
					buffer->offset,
					runningtime,
					buffer->timestamp,
					latency,
					render_delay);
			}
		}

		public void on_leave (Gum.InvocationContext context) {
		}

		public bool handle_tick () {
			if (period_watch == null) {
				lock (sink_info_by_address) {
					foreach (var info in monitored_sinks)
						info.period_buffer_count = 0;
				}

				period_watch = new Stopwatch ();

				return true;
			}

			var result = new GstPadStats[0];

			lock (sink_info_by_address) {
				double elapsed = period_watch.elapsed ();

				foreach (var info in monitored_sinks) {
					result += GstPadStats (info.name, (double) info.period_buffer_count / elapsed, info.period_timing_history.str);
					info.period_buffer_count = 0;
					info.period_timing_history.truncate ();
				}
			}

			period_watch.restart ();

			if (result.length > 0)
				pad_stats (result);

			return true;
		}

		private string? generate_name_from_sink (GstObject sink) {
			if (sink.name == null)
				return null;
			return sink.name + ".sink";
		}

		private class SinkInfo : Object {
			public string? name {
				get;
				construct;
			}

			public uint64 total_buffer_count;

			public uint period_buffer_count;
			public StringBuilder period_timing_history = new StringBuilder ();

			public SinkInfo (string name) {
				Object (name: name);
			}
		}
	}

	public struct GTypeInstance {
		public void * g_class;
	}

	public struct GTypeClass {
		public ulong g_type;
	}

	public struct GObjectClass {
		public GTypeClass g_type_class;

		public void * construct_properties;

		public void * constructor;
		public void * set_property;
		public void * get_property;
		public void * dispose;
		public void * finalize;
		public void * dispatch_properties_changed;
		public void * notify;

		public void * constructed;

		public size_t flags;

		public void * pdummy[6];
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

	public struct GstObjectClass {
		public GObjectClass parent_class;

		public string path_string_separator;
		public void * signal_object;

		public void * lock;

		public void * parent_set;
		public void * parent_unset;
		public void * object_saved;
		public void * deep_notify;

		public void * save_thyself;
		public void * restore_thyself;

		public void * _gst_reserved[4];
	}

	public struct GstElementDetails {
		public string longname;
		public string klass;
		public string description;
		public string author;

		public void * _gst_reserved[4];
	}

	public struct GstElementClass {
		public GstObjectClass parent_class;

		public GstElementDetails details;

		public void * elementfactory;

		public void * padtemplates;
		public int numpadtemplates;
		public uint32 pad_templ_cookie;

		public void * pad_added;
		public void * pad_removed;
		public void * no_more_pads;

		public void * request_new_pad;
		public void * release_pad;

		public void * get_state;
		public void * set_state;
		public void * change_state;

		public void * set_bus;

		public void * provide_clock;
		public void * set_clock;

		public void * get_index;
		public void * set_index;

		public void * send_event;

		public void * get_query_types;
		public void * query;

		public void * _gst_reserved[4];
	}

	public struct GstBaseSinkClass {
		public GstElementClass parent_class;

		public void * get_caps;
		public void * set_caps;

		public void * buffer_alloc;

		public void * get_times;

		public void * start;
		public void * stop;

		public void * unlock;

		public void * event;
		public void * preroll;
		public void * render;

		public void * async_play;

		public void * activate_pull;

		public void * fixate;

		public void * unlock_stop;

		public void * render_list;

		public void * _gst_reserved[15];
	}

	public struct GstMiniObject {
		public GTypeInstance instance;

		public int refcount;
		public uint flags;

		public void * _gst_reserved;
	}

	public struct GstBuffer {
		public GstMiniObject mini_object;

		public uint8 * data;
		public uint size;

		public uint64 timestamp;
		public uint64 duration;

		public void * caps;

		public uint64 offset;
		public uint64 offset_end;

		public uint8 * malloc_data;

		public void * free_func;
		public void * parent;

		public void * _gst_reserved[2];
	}
}
