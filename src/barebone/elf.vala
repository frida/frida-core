[CCode (gir_namespace = "FridaBarebone", gir_version = "1.0")]
namespace Frida.Barebone {
	public async Allocation inject_elf (Gum.ElfModule elf, Machine machine, Allocator allocator, Cancellable? cancellable)
			throws Error, IOError {
		size_t vm_size = (size_t) elf.mapped_size;

		size_t page_size = yield machine.query_page_size (cancellable);
		uint num_pages = (uint) (vm_size / page_size);
		if (vm_size % page_size != 0)
			num_pages++;

		uint64 text_base = 0;
		size_t text_size = 0;
		elf.enumerate_segments (s => {
			if ((s.protection & Gum.PageProtection.EXECUTE) != 0) {
				text_base = s.vm_address;
				text_size = (size_t) s.vm_size;
				return false;
			}
			return true;
		});
		if (text_size == 0)
			throw new Error.NOT_SUPPORTED ("Unable to detect text segment");

		var allocation = yield allocator.allocate (num_pages * page_size, page_size, cancellable);
		try {
			uint64 base_va = allocation.virtual_address;

			Bytes relocated_image = machine.relocate (elf, base_va);
			var timer = new Timer ();
			yield machine.gdb.write_byte_array (base_va, relocated_image, cancellable);
			printerr ("Uploaded %zu bytes ELF in %u ms\n\n",
				relocated_image.get_size (),
				(uint) (timer.elapsed () * 1000.0));

			yield machine.protect_pages (base_va + text_base, text_size, READ | EXECUTE, cancellable);
		} catch (GLib.Error e) {
			yield allocation.deallocate (cancellable);
			throw_api_error (e);
		}

		return allocation;
	}
}
