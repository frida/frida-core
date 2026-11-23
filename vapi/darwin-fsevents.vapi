[CCode (cheader_filename = "CoreServices/CoreServices.h", gir_namespace = "Darwin", gir_version = "1.0")]
namespace Darwin.FSEvents {
	[Compact]
	[CCode (cname = "struct __FSEventStream", ref_function = "FSEventStreamRetain", ref_function_void = true,
		unref_function = "FSEventStreamRelease")]
	public class Stream {
		[CCode (cname = "FSEventStreamCreate")]
		public Stream (CoreFoundation.Allocator? allocator, StreamCallback callback, StreamContext context,
			CoreFoundation.Array paths_to_watch, EventId since_when, double latency, StreamCreateFlags flags);

		[CCode (cname = "FSEventStreamSetDispatchQueue")]
		public void set_dispatch_queue (Darwin.GCD.DispatchQueue? queue);

		[CCode (cname = "FSEventStreamStart")]
		public bool start ();

		[CCode (cname = "FSEventStreamStop")]
		public void stop ();

		[CCode (cname = "FSEventStreamInvalidate")]
		public void invalidate ();
	}

	[CCode (cname = "FSEventStreamCallback", has_target = false)]
	public delegate void StreamCallback ([CCode (type = "ConstFSEventStreamRef")] Stream stream, void * info, size_t num_events,
		[CCode (array_length = false, type = "void *")] string[] event_paths,
		[CCode (array_length = false, type = "const FSEventStreamEventFlags *")] EventFlags[] event_flags,
		[CCode (array_length = false, type = "const FSEventStreamEventId *")] EventId[] event_ids);

	[CCode (cname = "FSEventStreamContext")]
	public struct StreamContext {
		public CoreFoundation.Index version;
		public void * info;
		public RetainFunc? retain;
		public ReleaseFunc? release;
		public CopyDescriptionFunc? copyDescription;
	}

	[CCode (has_target = false)]
	public delegate void * RetainFunc (void * info);
	[CCode (has_target = false)]
	public delegate void ReleaseFunc (void * info);
	[CCode (has_target = false)]
	public delegate CoreFoundation.String CopyDescriptionFunc (void * info);

	[CCode (cname = "FSEventStreamEventId", has_type_id = false)]
	public struct EventId : uint64 {
		[CCode (cname = "kFSEventStreamEventIdSinceNow")]
		public const EventId SINCE_NOW;
	}

	[Flags]
	[CCode (cname = "FSEventStreamCreateFlags", cprefix = "kFSEventStreamCreateFlag", has_type_id = false)]
	public enum StreamCreateFlags {
		None,
		FileEvents,
	}

	[Flags]
	[CCode (cname = "FSEventStreamEventFlags", cprefix = "kFSEventStreamEventFlag", has_type_id = false)]
	public enum EventFlags {
		None,
		MustScanSubDirs,
		UserDropped,
		KernelDropped,
		ItemModified,
	}
}
