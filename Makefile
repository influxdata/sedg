all:
	# Nothing to install. Use 'make check'
	exit 1

DEB_DEPENDENCIES := \
	python3-coverage

check-deb-deps:
	@for dep in $(DEB_DEPENDENCIES); do if test -z "$(VIRTUAL_ENV)" && ! dpkg -l $$dep 1>/dev/null 2>&1; then echo "Please apt install $$dep" ; exit 1; fi; done

check-deps: check-deb-deps

test:
	if test -z "$(VIRTUAL_ENV)" ; then \
		echo "WARN: not running in venv. Did you forget to '. ./.venv/bin/activate'? Proceeding anyway..." ; \
	fi
	./tests/run-tests

syntax-check: clean
	./tests/run-flake8
	./tests/run-pylint

style-check: clean
	./tests/run-black

# require woke to be installed in CI but not one local system
inclusivity-check: clean
	echo "# Check for non-inclusive language"; \
	if test -n "$(CI)" ; then \
		woke --exit-1-on-failure . ; \
	elif which woke >/dev/null ; then \
		woke --exit-1-on-failure . ; \
	else \
		echo "Could not find woke!" ; \
	fi \

check: check-deps test inclusivity-check syntax-check style-check

coverage: check-deb-deps
	python3 -m coverage run ./tests/run-tests

coverage-report:
	python3 -m coverage report --show-missing --omit="*/dist-packages/*"

clean:
	rm -rf ./bin/__pycache__ ./cvelib/__pycache__ ./tests/__pycache__
	rm -rf .coverage
