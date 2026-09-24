# ==============================================================================
# Makefile for Automated Python PCAP Analyzer & Threat Parser
# ==============================================================================

.PHONY: help install test lint format build docker up down clean retention-dry-run

PYTHON ?= python3
NPM ?= npm

help:
	@echo "Available commands:"
	@echo "  make install         - Install Python and Node dependencies"
	@echo "  make test            - Execute full Python unit test suite"
	@echo "  make lint            - Run TypeScript and Python code linters"
	@echo "  make format          - Format code with Ruff"
	@echo "  make build           - Build production frontend bundle"
	@echo "  make docker          - Build production Docker containers"
	@echo "  make up              - Start development Docker Compose stack"
	@echo "  make down            - Stop Docker Compose stack"
	@echo "  make clean           - Remove temporary build artifacts and caches"
	@echo "  make retention-dry-run - Run dry-run data retention cleanup"

install:
	$(PYTHON) -m pip install -r requirements.txt -r requirements-dev.txt || true
	$(NPM) install

test:
	PYTHONPATH=src $(PYTHON) -m unittest discover tests

lint:
	$(NPM) run lint
	@which ruff > /dev/null && ruff check src/ tests/ || echo "Ruff not found, skipping Python lint"

format:
	@which ruff > /dev/null && ruff format src/ tests/ || echo "Ruff not found, skipping Python format"

build:
	$(NPM) run build

docker:
	docker compose -f docker-compose.prod.yml build

up:
	docker compose up -d

down:
	docker compose down

clean:
	rm -rf dist htmlcov .coverage .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

retention-dry-run:
	PYTHONPATH=src $(PYTHON) scripts/cleanup_data.py --dry-run
