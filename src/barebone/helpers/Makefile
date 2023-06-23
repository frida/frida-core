build: memory-scanner-arm64.elf

memory-scanner-arm64.elf:
	RUSTFLAGS="-C code-model=tiny -C link-arg=--emit-relocs -C link-arg=-n -C link-arg=--discard-all" \
		cargo build -r --target aarch64-unknown-none
	cp target/aarch64-unknown-none/release/memory-scanner $@.tmp
	rust-strip \
		--strip-unneeded \
		--remove-section=.rela.text \
		$@.tmp
	mv $@.tmp $@

.PHONY: build
