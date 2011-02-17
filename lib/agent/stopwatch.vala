namespace Zed.Agent {
	public class Stopwatch : Object {
		protected uint64 start_stamp;
		protected uint64 freq;

		public Stopwatch () {
			start ();
		}

		private extern void start ();

		public extern uint64 elapsed ();
	}
}
