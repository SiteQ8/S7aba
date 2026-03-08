# Changelog

All notable changes to S7aba will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-08

### Added
- Initial release of S7aba
- AWS reconnaissance module (identity, permissions, services, network, secrets)
- AWS privilege escalation module (14+ IAM escalation methods)
- Cloud provider auto-detection (AWS, Azure, GCP, Kubernetes)
- Interactive TUI mode
- Multi-format reporting (text, JSON, HTML)
- Dry-run mode for safe testing
- Modular architecture with provider-specific modules
- Comprehensive logging system
- Web UI landing page
- Security policy (SECURITY.md)
- Contributing guidelines
- CI/CD with GitHub Actions (ShellCheck, syntax validation)

### Providers
- **AWS**: Recon and Privesc modules fully implemented
- **Azure**: Module stubs created (contributions welcome)
- **GCP**: Module stubs created (contributions welcome)
- **Kubernetes**: Module stubs created (contributions welcome)
