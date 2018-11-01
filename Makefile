target/doc:
	cargo rustdoc

docs: target/doc
	-git branch -D gh-pages
	git checkout --orphan gh-pages
	git reset --hard
	cp -r target/doc/* .
	mv keychain_services docs
	rm -rf target
	echo '<meta http-equiv="refresh" content="0;url=./docs">' > index.html
	git add .
	git commit -m "Generate docs using 'make docs'"
	@echo "Use 'git push -f origin gh-pages' to deploy"
