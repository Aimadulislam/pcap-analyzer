# Production Release & Verification Checklist

Before publishing or tagging a new release, verify each of the following criteria:

- [ ] **Automated Test Suite**: All 31 unit tests pass cleanly:
  ```bash
  PYTHONPATH=src python3 -m unittest discover tests
  ```
- [ ] **Python Code Formatting & Linting**: Ruff reports zero errors:
  ```bash
  ruff check src/ tests/
  ruff format --check src/ tests/
  ```
- [ ] **Static Type Checking**: mypy completes without fatal type errors:
  ```bash
  mypy src/pcap_analyzer --ignore-missing-imports
  ```
- [ ] **Frontend Production Build**: Compiles cleanly to `dist/`:
  ```bash
  npm run build
  ```
- [ ] **Frontend TypeScript Linter**: Zero emit errors:
  ```bash
  npm run lint
  ```
- [ ] **Security Vulnerability Audit**:
  ```bash
  pip-audit
  npm audit
  ```
- [ ] **Secret Scanner Verification**: Gitleaks reports no API keys, private certs, or tokens:
  ```bash
  gitleaks detect --verbose
  ```
- [ ] **Docker Multi-Stage Build**: Containers build without root privileges:
  ```bash
  docker compose -f docker-compose.prod.yml build
  ```
- [ ] **System Health & Readiness**: `/health` and `/ready` return HTTP 200 OK.
- [ ] **Demo Mode Functional**: Static demo fixtures render correctly with explicit `DEMO DATA` banner.
- [ ] **Data Retention Script**: `python3 scripts/cleanup_data.py --dry-run` executes without exceptions.
- [ ] **Version Synchronization**: Version number `0.1.0` aligned across:
  - `pyproject.toml`
  - `package.json`
  - `metadata.json`
  - `server.ts`
  - `CHANGELOG.md`
- [ ] **Documentation Current**: All detection rules, ATT&CK mappings, and configuration profile documentation verified.
