namespace Zed.Agent {
	public class GstMonitor : Object, Gum.InvocationListener {
		public signal void pad_stats (GstPadStats[] stats);

		private Gum.Interceptor interceptor = Gum.Interceptor.obtain ();
		private bool is_enabled = false;

		enum FunctionId {
			BASE_SINK_RENDER,
			QUEUE_CHAIN,
			JBUF_CHAIN
		}

		private HostFunctions api;
		private class HostFunctions {
			public TypeClassRefFunc type_class_ref;
			public TypeClassUnrefFunc type_class_unref;

			public ObjectUnrefFunc object_unref;
			public ObjectGetParentFunc object_get_parent;

			public ElementGetBaseTimeFunc element_get_base_time;
			public ElementGetClockFunc element_get_clock;
			public ElementGetStaticPadFunc element_get_static_pad;
			public ElementFactoryMakeFunc element_factory_make;

			public ClockGetTimeFunc clock_get_time;

			public BaseSinkGetLatencyFunc base_sink_get_latency;
			public BaseSinkGetRenderDelayFunc base_sink_get_render_delay;

			public GetTypeFunc base_audio_sink_get_type;
			public GetTypeFunc video_sink_get_type;
			public GetTypeFunc clutter_video_sink_get_type;
		}

		[CCode (has_target = false)]
		private delegate void * TypeClassRefFunc (ulong type);
		[CCode (has_target = false)]
		private delegate void TypeClassUnrefFunc (void * g_class);
		[CCode (has_target = false)]
		private delegate ulong GetTypeFunc ();

		[CCode (has_target = false)]
		private delegate void ObjectUnrefFunc (GstObject object);
		[CCode (has_target = false)]
		private delegate GstObject * ObjectGetParentFunc (GstObject object);
		[CCode (has_target = false)]
		private delegate uint64 ElementGetBaseTimeFunc (GstObject element);
		[CCode (has_target = false)]
		private delegate GstObject * ElementGetClockFunc (GstObject element);
		[CCode (has_target = false)]
		private delegate GstObject * ElementGetStaticPadFunc (GstObject element, string name);
		[CCode (has_target = false)]
		private delegate GstObject * ElementFactoryMakeFunc (string factoryname, string name);
		[CCode (has_target = false)]
		private delegate uint64 BaseSinkGetLatencyFunc (GstObject base_sink);
		[CCode (has_target = false)]
		private delegate uint64 BaseSinkGetRenderDelayFunc (GstObject base_sink);
		[CCode (has_target = false)]
		private delegate uint64 ClockGetTimeFunc (GstObject clock);

		/* FIXME: should add definitions below instead */
		private const int PAD_OFFSET_CHAINFUNC = 128; 
		private const int QUEUE_OFFSET_INTERNAL_GQUEUE = 356;
		private const int GSTJBUF_OFFSET_PRIV = 136;
		private const int GSTJBUFPRIV_OFFSET_JBUF = 12;
		private const int GSTJBUFPRIV_OFFSET_LATENCY_MS = 48;
		private const int GSTJBUFPRIV_OFFSET_TS_OFFSET = 72;
		private const int JBUF_OFFSET_PACKETS = 12;

		private GstBaseSinkClass * base_audio_sink_klass;
		private GstBaseSinkClass * video_sink_klass;
		private GstBaseSinkClass * clutter_video_sink_klass;

		private Gee.HashMap<void *, PadInfo> shared_pad_info = new Gee.HashMap<void *, PadInfo> ();
		private PadInfo[] monitored_pads = new PadInfo[0];
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

			session_watch = new Stopwatch ();

			api = bind_to_api ();

			if (api.base_audio_sink_get_type != null) {
				base_audio_sink_klass = (GstBaseSinkClass *) api.type_class_ref (api.base_audio_sink_get_type ());
				interceptor.attach_listener (base_audio_sink_klass->render, this, (void *) FunctionId.BASE_SINK_RENDER);
			}

			if (api.video_sink_get_type != null) {
				video_sink_klass = (GstBaseSinkClass *) api.type_class_ref (api.video_sink_get_type ());
				interceptor.attach_listener (video_sink_klass->render, this, (void *) FunctionId.BASE_SINK_RENDER);
			}

			if (api.clutter_video_sink_get_type != null) {
				clutter_video_sink_klass = (GstBaseSinkClass *) api.type_class_ref (api.clutter_video_sink_get_type ());
				interceptor.attach_listener (clutter_video_sink_klass->render, this, (void *) FunctionId.BASE_SINK_RENDER);
			}

			attach_to_sinkpad_chain_on ("queue", FunctionId.QUEUE_CHAIN);
			attach_to_sinkpad_chain_on ("gstrtpjitterbuffer", FunctionId.JBUF_CHAIN);

			is_enabled = true;

			handle_tick ();
			timeout_id = Timeout.add (1000, handle_tick);
		}

		public void disable () throws IOError {
			if (!is_enabled)
				throw new IOError.FAILED ("already disabled");

			interceptor.detach_listener (this);

			if (base_audio_sink_klass != null) {
				api.type_class_unref (base_audio_sink_klass);
				base_audio_sink_klass = null;
			}

			if (video_sink_klass != null) {
				api.type_class_unref (video_sink_klass);
				video_sink_klass = null;
			}

			if (clutter_video_sink_klass != null) {
				api.type_class_unref (clutter_video_sink_klass);
				clutter_video_sink_klass = null;
			}

			api = null;

			shared_pad_info.clear ();
			monitored_pads = new PadInfo[0];

			var source = MainContext.default ().find_source_by_id (timeout_id);
			if (source != null)
				source.destroy ();
			timeout_id = 0;

			session_watch = null;
			period_watch = null;

			is_enabled = false;
		}

		public void on_enter (Gum.InvocationContext context) {
			var walltime = session_watch.elapsed_nanoseconds ();

			FunctionId function_id = (FunctionId) context.get_listener_function_data ();
			switch (function_id) {
				case FunctionId.BASE_SINK_RENDER:
					on_base_sink_render (context, walltime);
					break;

				case FunctionId.QUEUE_CHAIN:
					on_queue_chain (context, walltime);
					break;

				case FunctionId.JBUF_CHAIN:
					on_jbuf_chain (context, walltime);
					break;
			}
		}

		public void on_leave (Gum.InvocationContext context) {
		}

		private void on_base_sink_render (Gum.InvocationContext context, uint64 walltime) {
			GstObject * sink = (GstObject *) context.get_nth_argument (0);
			GstBuffer * buffer = (GstBuffer *) context.get_nth_argument (1);

			var runningtime = get_runningtime_from_element (sink);

			var latency = api.base_sink_get_latency (sink);
			var render_delay = api.base_sink_get_render_delay (sink);

			lock (shared_pad_info) {
				var info = get_pad_info_for (sink);
				info.bump ();
				info.period_timing_history.append_printf (
					"s" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u\n",
					walltime,
					info.total_buffer_count,
					buffer->offset,
					runningtime,
					buffer->timestamp,
					latency,
					render_delay);
			}
		}

		private void on_queue_chain (Gum.InvocationContext context, uint64 walltime) {
			GstObject * sinkpad = (GstObject *) context.get_nth_argument (0);
			GstBuffer * buffer = (GstBuffer *) context.get_nth_argument (1);

			GstObject * queue = api.object_get_parent (sinkpad);
			if (queue == null)
				return;

			var runningtime = get_runningtime_from_element (queue);

			Queue<GstBuffer> * internal_queue = *(Queue<GstBuffer> **) ((uint8 *) queue + QUEUE_OFFSET_INTERNAL_GQUEUE);
			var queue_length = internal_queue->length;

			lock (shared_pad_info) {
				var info = get_pad_info_for (queue);
				info.bump ();
				info.period_timing_history.append_printf (
					"q" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%u\n",
					walltime,
					info.total_buffer_count,
					buffer->offset,
					runningtime,
					buffer->timestamp,
					queue_length);
			}

			api.object_unref (queue);
		}

		private void on_jbuf_chain (Gum.InvocationContext context, uint64 walltime) {
			GstObject * sinkpad = (GstObject *) context.get_nth_argument (0);
			GstBuffer * buffer = (GstBuffer *) context.get_nth_argument (1);

			GstObject * gstjbuf = api.object_get_parent (sinkpad);
			if (gstjbuf == null)
				return;

			var runningtime = get_runningtime_from_element (gstjbuf);

			uint8 * priv = *(uint8 **) ((uint8 *) gstjbuf + GSTJBUF_OFFSET_PRIV);
			uint8 * jbuf = *(uint8 **) (priv + GSTJBUFPRIV_OFFSET_JBUF);
			uint latency_ms = *(uint *) (priv + GSTJBUFPRIV_OFFSET_LATENCY_MS);
			int64 ts_offset = *(int64 *) (priv + GSTJBUFPRIV_OFFSET_TS_OFFSET);

			Queue<GstBuffer> * packets = *(Queue<GstBuffer> **) (jbuf + JBUF_OFFSET_PACKETS);
			var queue_length = packets->length;

			lock (shared_pad_info) {
				var info = get_pad_info_for (gstjbuf);
				info.bump ();
				info.period_timing_history.append_printf (
					"j" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%" + uint64.FORMAT_MODIFIER + "u" +
					"\t%u" +
					"\t%" + int64.FORMAT_MODIFIER + "d" +
					"\t%u\n",
					walltime,
					info.total_buffer_count,
					buffer->offset,
					runningtime,
					buffer->timestamp,
					latency_ms,
					ts_offset,
					queue_length);
			}

			api.object_unref (gstjbuf);
		}

		private PadInfo get_pad_info_for (GstObject element) {
			var info = shared_pad_info[element];
			if (info == null) {
				info = new PadInfo (generate_pad_name_from_element (element));
				shared_pad_info[element] = info;

				monitored_pads += info;
			}
			return info;
		}

		private uint64 get_runningtime_from_element (GstObject element) {
			var clock = api.element_get_clock (element);
			var time = api.clock_get_time (clock);
			api.object_unref (clock);

			var basetime = api.element_get_base_time (element);
			uint64 runningtime = 0;
			if (time >= basetime)
				runningtime = time - basetime;

			return runningtime;
		}

		public bool handle_tick () {
			if (period_watch == null) {
				lock (shared_pad_info) {
					foreach (var info in monitored_pads)
						info.period_buffer_count = 0;
				}

				period_watch = new Stopwatch ();

				return true;
			}

			var result = new GstPadStats[0];

			lock (shared_pad_info) {
				double elapsed = period_watch.elapsed ();

				foreach (var info in monitored_pads) {
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

		private string? generate_pad_name_from_element (GstObject element) {
			if (element.name == null)
				return null;
			return element.name + ".sink";
		}

		private class PadInfo : Object {
			public string? name {
				get;
				construct;
			}

			public uint64 total_buffer_count;

			public uint period_buffer_count;
			public StringBuilder period_timing_history = new StringBuilder ();

			public PadInfo (string name) {
				Object (name: name);
			}

			public void bump () {
				total_buffer_count++;
				period_buffer_count++;
			}
		}

		private HostFunctions bind_to_api () throws IOError {
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

			var api = new HostFunctions ();
			api.type_class_ref = (TypeClassRefFunc) Gum.Module.find_export_by_name (gobj_module_name, "g_type_class_ref");
			api.type_class_unref = (TypeClassUnrefFunc) Gum.Module.find_export_by_name (gobj_module_name, "g_type_class_unref");

			api.object_unref = (ObjectUnrefFunc) Gum.Module.find_export_by_name (core_module_name, "gst_object_unref");
			api.object_get_parent = (ObjectGetParentFunc) Gum.Module.find_export_by_name (core_module_name, "gst_object_get_parent");
			api.element_get_base_time = (ElementGetBaseTimeFunc) Gum.Module.find_export_by_name (core_module_name, "gst_element_get_base_time");
			api.element_get_clock = (ElementGetClockFunc) Gum.Module.find_export_by_name (core_module_name, "gst_element_get_clock");
			api.element_get_static_pad = (ElementGetStaticPadFunc) Gum.Module.find_export_by_name (core_module_name, "gst_element_get_static_pad");
			api.element_factory_make = (ElementFactoryMakeFunc) Gum.Module.find_export_by_name (core_module_name, "gst_element_factory_make");
			api.clock_get_time = (ClockGetTimeFunc) Gum.Module.find_export_by_name (core_module_name, "gst_clock_get_time");

			api.base_sink_get_latency = (BaseSinkGetLatencyFunc) Gum.Module.find_export_by_name (base_module_name, "gst_base_sink_get_latency");
			api.base_sink_get_render_delay = (BaseSinkGetRenderDelayFunc) Gum.Module.find_export_by_name (base_module_name, "gst_base_sink_get_render_delay");
			if (api.base_sink_get_latency == null || api.base_sink_get_render_delay == null)
				throw new IOError.FAILED ("base sink function not found");

			if (audio_module_name != null)
				api.base_audio_sink_get_type = (GetTypeFunc) Gum.Module.find_export_by_name (audio_module_name, "gst_base_audio_sink_get_type");

			if (video_module_name != null)
				api.video_sink_get_type = (GetTypeFunc) Gum.Module.find_export_by_name (video_module_name, "gst_video_sink_get_type");

			if (clutter_gst_module_name != null)
				api.clutter_video_sink_get_type = (GetTypeFunc) Gum.Module.find_export_by_name (clutter_gst_module_name, "clutter_gst_video_sink_get_type");

			return api;
		}

		private void attach_to_sinkpad_chain_on (string element_name, FunctionId function_id) {
			var element = api.element_factory_make (element_name, "probe-element");
			if (element != null) {
				var pad = api.element_get_static_pad (element, "sink");
				void ** chain_address = (void **) ((uint8 *) pad + PAD_OFFSET_CHAINFUNC);
				interceptor.attach_listener (*chain_address, this, (void *) function_id);
				api.object_unref (pad);
				api.object_unref (element);
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
