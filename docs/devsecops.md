# DevSecOps & Automated Quality Pipeline

This document details the automated continuous integration, security auditing, and code hygiene practices enforced across the project.

---

## Continuous Integration Workflow

```
                   Developer Push / PR
                            │
                            ▼
                     GitHub Actions
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
    Python CI          Frontend CI         Security
        │                   │                   │
   Ruff (Lint)         npm ci (Clean)      Gitleaks (Secrets)
   Ruff (Format)       TypeScript Lint     pip-audit (Deps)
   mypy (Types)        Production Build    Trivy (Containers)
   pytest (31 Tests)
   Coverage Report
```

---

## Automated Verification Tools

### 1. Python Code Quality & Testing
- **Linter & Formatter**: [Ruff](https://docs.astral.sh/ruff/) provides lightning-fast linting and code formatting checks configured in `pyproject.toml`.
  ```bash
  ruff check src/ tests/
  ruff format --check src/ tests/
  ```
- **Type Checker**: [mypy](https://mypy-lang.org/) validates static types across models, detectors, and storage handlers.
  ```bash
  mypy src/pcap_analyzer --ignore-missing-imports
  ```
- **Test Runner & Coverage**: [pytest](https://pytest.org/) executes 31 unit and integration tests across packet dissection, heuristic thresholds, and report generation.
  ```bash
  PYTHONPATH=src pytest --cov=src/pcap_analyzer --cov-report=term-missing tests/
  ```

### 2. Frontend Quality & Bundling
- **TypeScript Compiler**: Validates interface typing, props contracts, and module imports without suppressing errors.
  ```bash
  npm run lint
  ```
- **Production Bundler**: Vite compiles an optimized, tree-shaken static production bundle to `dist/`.
  ```bash
  npm run build
  ```

### 3. Security & Vulnerability Auditing
- **Secret Detection**: [Gitleaks](https://github.com/gitleaks/gitleaks) scans every git commit to prevent accidental leakage of API keys, private certificates, or tokens.
- **Dependency Scanning**:
  - Python: `pip-audit` checks installed packages against the Python Packaging Advisory Database (PyPA).
  - Frontend: `npm audit` scans Node dependencies.
- **Container Vulnerability Scanning**: [Trivy](https://github.com/aquasecurity/trivy) scans base images (`python:3.11-slim`, `nginx-unprivileged:alpine`) for CVE vulnerabilities.

---

## Reproducibility Guarantee

1. **Deterministic Ground-Truth Fixtures**: Test captures are generated with bit-level reproducibility by `tests/generate_test_pcaps.py`.
2. **Pinned Package Specifications**: Production dependencies specify strict version ranges in `requirements.txt` and `package.json`.
3. **Reproducible Container Images**: Multi-stage Docker builds isolate build-time dependencies from the lean production runtime.
