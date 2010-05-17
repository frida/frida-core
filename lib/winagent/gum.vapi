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
}
