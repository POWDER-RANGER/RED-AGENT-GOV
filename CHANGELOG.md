# Changelog

All notable changes to RED Agent will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.0.0] - 2026-04-14

### Added
- Governance-Enforced Autonomous Operations Framework
- Six-directive output gate with D01-D06 behavioral filters
- Deterministic FSM for state management
- Hash-chained audit trail
- Cryptographic teardown procedures
- Sealed-envelope tasking system
- 7-step initialization/teardown lifecycle
- Python Package CI/CD workflow (GitHub Actions)
- Comprehensive test suites (gate tests and compliance regression)
- `tests/` directory structure
- CI badge in README
- CHANGELOG.md and SECURITY.md

### Changed
- Renamed `RED script.py` to `red_script.py`
- Restructured repository layout with `red_agent/` core module
- Upgraded CI workflow to production-grade
- Moved test files into dedicated `tests/` folder

### Removed
- Root-level duplicate .py files (agent.py, audit.py, constants.py, crypto.py,
  entropy.py, fsm.py, gate.py, intelligence.py, main.py, recovery.py,
  serialization.py, settings.py, tasking.py, timing.py)
- Legacy redundant configuration files

### Fixed
- D03/D04 regex patterns in compliance test suite
- 5 failing gate compliance tests

[3.0.0]: https://github.com/POWDER-RANGER/red-agent/releases/tag/v3.0.0
