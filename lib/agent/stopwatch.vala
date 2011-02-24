namespace Zed.Agent {
	public class Stopwatch : Object {
		protected uint64 start_stamp;
		protected uint64 freq;

		public Stopwatch () {
			initialize ();
			restart ();
		}

		private extern void initialize ();

		public extern void restart ();

		public extern double elapsed ();
		public extern uint64 elapsed_nanoseconds ();
	}
}
