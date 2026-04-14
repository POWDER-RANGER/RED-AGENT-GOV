# Security Policy

## Reporting a Vulnerability

The RED Agent project takes security seriously. If you discover a security vulnerability, please report it responsibly.

### How to Report

- **Do NOT** open a public issue for security vulnerabilities
- Send a detailed report to the repository owner via GitHub's private vulnerability reporting
- Include: description, affected versions, reproduction steps, and potential impact

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 3.0.x   | :white_check_mark: |
| < 3.0   | :x:                |

## Security Architecture

RED Agent enforces behavioral compliance through architectural constraints:

- **Six-Directive Output Gate**: All outputs pass through D01-D06 behavioral filters
- **Cryptographic Audit Trail**: Hash-chained audit log with tamper detection
- **Deterministic FSM**: State machine prevents unauthorized state transitions
- **Cryptographic Teardown**: Secure memory wiping on agent termination
- **Sealed-Envelope Tasking**: Task payloads are cryptographically sealed

## Best Practices

1. Never commit secrets, API keys, or credentials to the repository
2. Use environment variables for sensitive configuration
3. Keep dependencies updated (`pip install --upgrade -r requirements.txt`)
4. Run the test suite before deploying: `python -m pytest tests/ -v`
5. Review CI/CD logs for failed security checks

## Dependencies

All dependencies are pinned in `requirements.txt`. Security updates are managed through:
- Dependabot alerts (GitHub)
- Manual `pip audit` checks
- Regular review of transitive dependencies

## Compliance Directives

The six behavioral directives (D01-D06) form the core security boundary:
- **D01**: No unauthorized network egress
- **D02**: No credential leakage in outputs
- **D03**: Heroic signal suppression
- **D04**: Capability signal suppression
- **D05**: Intelligence hygiene enforcement
- **D06**: Atomic snapshot integrity
