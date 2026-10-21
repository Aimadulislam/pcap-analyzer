# Production Release & Verification Checklist

Before publishing, deploying, or tagging a production release, verify each of the following criteria:

### 1. Code Quality & Test Verification
- [x] **Automated Test Suite**: All 50 unit and integration tests pass cleanly:
  ```bash
  PYTHONPATH=src python3 -m unittest discover tests -v
  ```
- [x] **Frontend TypeScript Linter**: Zero emit errors:
  ```bash
  npm run lint
  ```
- [x] **Frontend Production Build**: Vite compiles cleanly to `dist/`:
  ```bash
  npm run build
  ```
- [x] **Python Code Formatting & Linting**: Ruff / Flake8 reports zero syntax or fatal issues:
  ```bash
  ruff check src/ tests/
  ```

### 2. Security Controls & Hardening
- [x] **File Upload Validation**: Enforces 50MB ceiling (`HTTP 413`) and rejects non-PCAP files.
- [x] **Path Traversal Protection**: Analysis IDs validated against `^[a-zA-Z0-9_-]{12,64}$`.
- [x] **Subprocess Security**: All CLI invocations use strict argument arrays (`shell=False`).
- [x] **Concurrency & Timeout Limits**: Max 2 concurrent analyses (`HTTP 429`) and 60s execution timeout.
- [x] **Container Isolation**: Non-root user (`pcapuser`, UID `10001`) with `no-new-privileges:true`.
- [x] **Secret Scanner**: Gitleaks configuration in CI; no secrets or tokens committed.

### 3. Data Privacy & Retention
- [x] **Local Sandboxing**: Analysis outputs isolated to `data/analyses/<id>/`.
- [x] **Retention Purge Utility**: `python3 scripts/cleanup_data.py --dry-run` and `--execute` operational.
- [x] **Defensive Policy Notice**: Visible disclaimer regarding authorized defensive inspection.
- [x] **Demo Mode Isolation**: Pre-packaged synthetic scenarios marked with prominent `DEMO DATA` banners.

### 4. Documentation & Presentation
- [x] **Architecture Documented**: `docs/architecture.md` matches actual implementation.
- [x] **Threat Model Updated**: `docs/threat-model.md` covers assets, threats, controls, and residual risks.
- [x] **Portfolio Case Study**: Interactive `/case-study` view and `docs/portfolio-case-study.md` verified.
- [x] **Forensic Limitations Disclosed**: Encrypted payload limits and heuristic verification boundaries documented.

### 5. Version Alignment
- [x] **Version Synchronized (v0.1.0)** across:
  - `pyproject.toml`
  - `package.json`
  - `metadata.json`
  - `server.ts`
  - `CHANGELOG.md`
  - `README.md`
