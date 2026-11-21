.PHONY: all test test-python test-rust helpers build-agent homologate h8 deb clean

CARGO_ENV = PATH="$(HOME)/.cargo/bin:$(PATH)"

all: helpers build-agent test homologate deb

helpers:
	make -C helpers/mintsec-netmon
	make -C helpers/mintsec-containment

test: helpers test-python test-rust
	helpers/mintsec-netmon/mintsec-netmon --self-test
	helpers/mintsec-containment/mintsec-containment --self-test

test-python:
	PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v

test-rust:
	$(CARGO_ENV) cargo test --offline --manifest-path agent/Cargo.toml

build-agent:
	$(CARGO_ENV) cargo build --release --offline --manifest-path agent/Cargo.toml

homologate: helpers build-agent
	PYTHONPATH=src python3 scripts/run_homologation.py

h8:
	PYTHONPATH=src python3 scripts/verify_h8.py

deb: helpers build-agent
	python3 scripts/build_debs.py

clean:
	make -C helpers/mintsec-netmon clean
	make -C helpers/mintsec-containment clean
	rm -rf dist build __pycache__
	find src tests homologation -name "__pycache__" -exec rm -rf {} +
