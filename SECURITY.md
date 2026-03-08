# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Yes             |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in S7aba, please report it responsibly.

### How to Report

1. **DO NOT** open a public GitHub issue for security vulnerabilities
2. Email: **Site@hotmail.com**
3. Subject: `[S7aba Security] Brief description`
4. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours
- **Status update** within 7 days
- **Resolution target** within 30 days for critical issues

### Scope

The following are **in scope**:
- Code injection through module loading
- Credential leakage through logging
- Unsafe command execution
- Path traversal in module resolution
- Privilege escalation within the tool itself

The following are **out of scope**:
- The cloud escalation techniques themselves (these are the tool's intended function)
- Issues in third-party cloud CLI tools (aws, az, gcloud, kubectl)
- Social engineering attacks

## Responsible Use

S7aba is an offensive security tool intended for authorized testing only. By using this tool, you agree to:

1. Only use S7aba on systems you own or have explicit written authorization to test
2. Follow all applicable local, state, national, and international laws
3. Report any vulnerabilities you discover in target systems to the appropriate parties
4. Not use S7aba for malicious purposes, unauthorized access, or illegal activities

## Security Best Practices

When using S7aba:

- Always use `--dry-run` mode first to understand what actions will be performed
- Review logs after each operation
- Run cleanup after assessments to remove artifacts
- Store reports securely and limit access
- Rotate any credentials that may have been exposed during testing
- Use the tool in isolated/sandboxed environments when possible

## Disclosure Policy

We follow a **90-day coordinated disclosure** policy. After reporting, we will work with you to understand and address the issue before any public disclosure.

## Recognition

We appreciate security researchers who help improve S7aba. With your permission, we will acknowledge your contribution in our changelog and README.

---

Thank you for helping keep S7aba and its users safe.
