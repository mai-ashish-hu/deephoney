SHELL := /bin/bash
PYTHON ?= python3.12
VENV ?= .venv
COMPOSE ?= docker compose

.PHONY: help prepare install-dev migrate seed run test lint format docker-build docker-up docker-down docker-logs docker-seed docker-smoke clean attack-demo check-versions

help:
	@echo "DeepHoney targets"
	@echo "  make prepare        Create local data directories and .env"
	@echo "  make install-dev    Create $(VENV) and install the frozen dev lock"
	@echo "  make migrate        Apply database migrations"
	@echo "  make seed           Import sanitized samples and run detection"
	@echo "  make run            Start the Streamlit dashboard"
	@echo "  make docker-seed    Import sanitized samples inside the Docker lab"
	@echo "  make docker-smoke   Validate Compose config and app health"
	@echo "  make test           Run the test suite"
	@echo "  make lint           Run ruff checks"
	@echo "  make format         Format with ruff"
	@echo "  make docker-build   Build the DeepHoney application image"
	@echo "  make docker-up      Start the full isolated lab"
	@echo "  make docker-down    Stop the lab (keeps volumes)"
	@echo "  make attack-demo    Generate safe synthetic attack logs"
	@echo "  make check-versions Verify the 2024 dependency baseline"

prepare:
	mkdir -p data/raw data/processed data/artifacts data/samples/generated
	test -f .env || cp .env.example .env
	@echo "Edit .env, then run: make docker-up"

install-dev:
	@if command -v uv >/dev/null 2>&1; then \
		uv venv --python 3.12.5 $(VENV); \
		uv pip install --python $(VENV)/bin/python -r requirements-dev.lock; \
		uv pip install --python $(VENV)/bin/python --no-deps -e .; \
	else \
		$(PYTHON) -m venv $(VENV); \
		$(VENV)/bin/pip install -r requirements-dev.lock; \
		$(VENV)/bin/pip install --no-deps -e .; \
	fi
	@echo "Activate with: source $(VENV)/bin/activate"

migrate:
	. $(VENV)/bin/activate && alembic upgrade head

seed:
	. $(VENV)/bin/activate && python scripts/seed_demo_data.py

run:
	. $(VENV)/bin/activate && streamlit run src/deephoney/dashboard/app.py

seed-docker: docker-seed

docker-seed:
	$(COMPOSE) exec dashboard python -m deephoney ingest /app/data/samples/cowrie/cowrie-sample.json --engine cowrie
	$(COMPOSE) exec dashboard python -m deephoney ingest /app/data/samples/dionaea/dionaea-sample.json /app/data/samples/dionaea/dionaea-log-json-sample.json --engine dionaea
	$(COMPOSE) exec dashboard python -m deephoney import-pcap /app/data/samples/pcap/sample-ssh-scan.pcap
	$(COMPOSE) exec dashboard python -m deephoney detect

test:
	. $(VENV)/bin/activate && pytest

lint:
	. $(VENV)/bin/activate && ruff check .

format:
	. $(VENV)/bin/activate && ruff format .

docker-build:
	$(COMPOSE) build

docker-up:
	$(COMPOSE) up -d --build

docker-down:
	$(COMPOSE) down

docker-logs:
	$(COMPOSE) logs -f --tail=200

docker-smoke:
	$(COMPOSE) config --quiet
	$(COMPOSE) exec dashboard python -m deephoney healthcheck --json

attack-demo:
	. $(VENV)/bin/activate && python scripts/attack_simulator.py --mode generate --scenario all --out data/samples/generated

check-versions:
	. $(VENV)/bin/activate && pytest tests/unit/test_version_policy.py -q

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
