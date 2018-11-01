target/doc/keychain_services:
	cargo rustdoc

docs: target/doc/keychain_services
	-git branch -D gh-pages
	git checkout --orphan gh-pages
	git reset README.md
	git reset --hard
	cp -r target/doc/* .
	cp -r keychain_services docs
	rm -rf target
	echo 'keychain-services.rs' > CNAME
	git add .
	git commit -m "Generate docs using 'make docs'"
	@echo "Use 'git push -f origin gh-pages' to deploy"
