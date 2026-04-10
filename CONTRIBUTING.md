# Contributing to nur

## Contributing Data

The most valuable contribution is your security data. Every evaluation, attack observation, and IOC bundle makes the aggregate intelligence more accurate for everyone.

### Web Form

Visit [nur.saramena.us/contribute](https://nur.saramena.us/contribute) and use the browser-based contribution form. No technical setup required. The form guides you through structured evaluation fields and runs anonymization client-side before submission.

### CLI

Install the nur CLI and contribute from your terminal:

```bash
nur eval --vendor crowdstrike
nur attack-map --input incident_report.json
nur ioc --input indicators.csv
```

The CLI runs the same anonymization pipeline as the web form. All PII stripping and hashing happens locally before any data leaves your machine.

### Voice

Record a verbal evaluation at [nur.saramena.us/contribute/voice](https://nur.saramena.us/contribute/voice) and the system will structure it automatically. Useful for capturing assessments during or immediately after incidents.

---

## Contributing Code

### Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `pytest`
5. Submit a pull request
6. Sign the CLA (see below)

### Contributor License Agreement

By submitting a pull request, you agree that your contributions are licensed under the same terms as the project (AGPL-3.0 for code, CDLA-Permissive-2.0 for data schemas).

---

## Code of Conduct

Vendor employees must disclose their affiliation when contributing evaluations or participating in discussions. Undisclosed vendor contributions undermine the integrity of the aggregate intelligence.

---

## Data Quality

The BDP (Behavioral Differential Privacy) credibility system tracks contribution patterns over time. Consistent, honest contributions build trust and receive greater weight in aggregates. Gaming the system is detectable and self-defeating -- outlier patterns are down-weighted automatically.

---

## Reporting Issues

Open an issue on the repository with:
- A clear description of the problem or suggestion
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Environment details (OS, Python version, CLI version)

---

## Security Vulnerabilities

If you discover a security vulnerability, do **not** open a public issue. Email security@saramena.us with details. We will acknowledge receipt within 48 hours and provide a timeline for resolution.
