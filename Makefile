VENV = .venv

all:
	# Nothing to install. Use 'make check'
	exit 1

# for now, install-venv. Someday, install...
install-venv:
	@if ! test -d "./$(VENV)" ; then \
		echo "Running 'python3 -m venv $(VENV)'" ; \
		python3 -m venv $(VENV) ; \
	fi
	@if test -z "$(VIRTUAL_ENV)" ; then \
		echo "Installing to '$(VENV)'" ; \
		. ./$(VENV)/bin/activate && \
		pip install -r ./requirements.txt . || exit 1; \
		echo "\nInstalled sedg to ./$(VENV). To use, run '. ./$(VENV)/bin/activate'" ; \
	else \
		echo "Updating '$(VENV)'" ; \
		pip install -r ./requirements.txt . ; \
		echo "\nUpdated sedg in ./$(VENV)." ; \
	fi

install-venv-dev:
	@if ! test -d "./$(VENV)" ; then \
		echo "Running 'python3 -m venv $(VENV)'" ; \
		python3 -m venv $(VENV) ; \
	fi
	@if test -z "$(VIRTUAL_ENV)" ; then \
		echo "Installing to '$(VENV)'" ; \
		. ./$(VENV)/bin/activate && \
		pip install -r ./requirements_dev.txt -e . || exit 1; \
		echo "\nInstalled sedg development to ./$(VENV). To use, run '. ./$(VENV)/bin/activate'" ; \
	else \
		echo "Updating '$(VENV)'" ; \
		pip install -r ./requirements_dev.txt -e . ; \
		echo "\nUpdated sedg development in ./$(VENV)." ; \
	fi

test:
	@if test -z "$(VIRTUAL_ENV)" ; then \
		echo "WARN: not running in venv. Did you forget to '. ./$(VENV)/bin/activate'? Proceeding anyway..." ; \
	fi
	./tests/run-tests

syntax-check: clean
	./tests/run-flake8
	./tests/run-pylint

style-check: clean
	./tests/run-black

style-fix: clean
	black ./cvelib/*py ./tests/*py

# require woke to be installed in CI but not one local system
inclusivity-check: clean
	@echo "\n# Check for non-inclusive language"; \
	if test -n "$(CI)" ; then \
		woke --exit-1-on-failure . ; \
	elif which woke >/dev/null ; then \
		woke --exit-1-on-failure . ; \
	else \
		echo "Could not find woke!" ; \
	fi \

check: test inclusivity-check syntax-check style-check

coverage:
	python3 -m coverage run ./tests/run-tests

coverage-report:
	python3 -m coverage report --show-missing --omit="*/dist-packages/*"

clean:
	rm -rf ./bin/__pycache__ ./cvelib/__pycache__ ./tests/__pycache__
	rm -rf .coverage
