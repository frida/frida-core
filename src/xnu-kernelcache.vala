namespace Frida {
	/**
	 * An XNU kernelcache, held as it arrived so a barebone session takes it apart itself.
	 */
	public sealed class XnuKernelcache : Object {
		internal Bytes blob {
			get;
			private set;
		}

		private XnuKernelcache (Bytes blob) {
			this.blob = blob;
		}

		/**
		 * Takes a kernelcache as it sits in memory.
		 *
		 * @param blob the kernelcache
		 */
		public static XnuKernelcache from_blob (Bytes blob) {
			return new XnuKernelcache (blob);
		}

		/**
		 * Reads the kernelcache at @path.
		 *
		 * @param path the kernelcache's location
		 */
		public static XnuKernelcache open (string path) throws Error {
			return from_blob (FS.read_all_bytes_sync (File.new_for_path (path)));
		}
	}
}
