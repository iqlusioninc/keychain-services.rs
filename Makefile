target/doc:
	cargo rustdoc

docs: target/doc
	cp -r target/doc/* docs/
