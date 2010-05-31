[CCode (cheader_filename = "gum/gum.h")]
namespace Gum {
	public interface InvocationListener : GLib.Object {
		public abstract void on_enter (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * cpu_context, void * function_arguments);
		public abstract void on_leave (Gum.InvocationContext context, Gum.InvocationContext parent_context, void * function_return_value);
		public abstract void * provide_thread_data (void * function_instance_data, uint thread_id);
	}

	[Compact]
	public class InvocationContext {
		public void * instance_data;
		public void * thread_data;
	}

	public class Stalker : GLib.Object {
		public Stalker ();

		public void follow_me (Gum.EventSink sink);
		public void unfollow_me ();
	}

	public interface EventSink : GLib.Object {
		public abstract Gum.EventType query_mask ();
		public abstract void process (void * opaque_event);
	}

	[CCode (cprefix = "GUM_")]
	public enum EventType {
		NOTHING = 0,
		CALL    = 1 << 0,
		RET     = 1 << 1,
		EXEC    = 1 << 2,
	}

	[Compact]
	public class AnyEvent {
		public EventType type;
	}

	[Compact]
	public class CallEvent {
		public EventType type;

		public void * location;
		public void * target;
	}

	[Compact]
	public class RetEvent {
		public EventType type;

		public void * location;
		public void * target;
	}

	[Compact]
	public class ExecEvent {
		public EventType type;

		public void * location;
	}
}
