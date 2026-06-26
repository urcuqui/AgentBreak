# AgentBreak — convenience targets.
# Mirrors the commands documented in README.md, using a local virtualenv.

PYTHON ?= python3
VENV   := .venv
BIN    := $(VENV)/bin

HOST ?= 127.0.0.1
PORT ?= 8000

.DEFAULT_GOAL := run
.PHONY: install run serve test clean venv

# Create the virtualenv only if it does not exist yet.
venv:
	@test -d $(VENV) || $(PYTHON) -m venv $(VENV)

# Install the project (editable) plus dev extras into the virtualenv.
install: venv
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

# Run the offensive scan and write an English report.
# Override args with: make run ARGS="journal"
ARGS ?= scan --report
run: install
	$(BIN)/python -m agentbreak.cli $(ARGS)

# Start the FastAPI web app. Override with: make serve HOST=0.0.0.0 PORT=8080
serve: install
	$(BIN)/python -m agentbreak.cli serve --host $(HOST) --port $(PORT)

# Run the test suite.
test: install
	$(BIN)/pytest

# Remove the virtualenv and Python build/cache artifacts.
clean:
	rm -rf $(VENV) src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
