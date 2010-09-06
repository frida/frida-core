public class Zed.ImageFactory {
	private Gee.HashMap<void *, ImageBlob> image_blob_by_pointer = new Gee.HashMap<void *, ImageBlob> ();

	public Gdk.Pixbuf? create_pixbuf_from_image_data (ImageData image_data) {
		if (image_data.width == 0)
			return null;

		var image_blob = new ImageBlob.from_image_data (image_data);
		image_blob_by_pointer[image_blob.pixels] = image_blob;

		return new Gdk.Pixbuf.from_data (image_blob.pixels, Gdk.Colorspace.RGB, true, 8, image_data.width, image_data.height, image_data.rowstride, (pixels) => {
			image_blob_by_pointer.unset (pixels);
		});
	}

	private class ImageBlob {
		public uchar[] pixels {
			get;
			private set;
		}

		public ImageBlob.from_image_data (ImageData image_data) {
			pixels = Base64.decode (image_data.pixels);
		}
	}
}
