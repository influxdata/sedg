all:
	# Nothing to install. Use 'make check'
	exit 1

DEB_DEPENDENCIES := \
	python3-coverage

check-deb-deps:
	@for dep in $(DEB_DEPENDENCIES); do if ! dpkg -l $$dep 1>/dev/null 2>&1; then echo "Please apt install $$dep" ; exit 1; fi; done

check-deps: check-deb-deps

test:
	PYTHONPATH=./ ./cvelib/run-tests

syntax-check: clean
	./cvelib/run-flake8
	./cvelib/run-pylint

style-check: clean
	./cvelib/run-black

check: check-deps test syntax-check style-check

coverage: check-deb-deps
	PYTHONPATH=./ python3 -m coverage run ./cvelib/run-tests

coverage-report:
	python3 -m coverage report --show-missing --omit="*/dist-packages/*"

clean:
	rm -rf ./bin/__pycache__ ./cvelib/__pycache__
	rm -rf .coverage
