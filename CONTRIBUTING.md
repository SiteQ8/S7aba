# Contributing to S7aba

Thank you for your interest in contributing to S7aba! This guide will help you get started.

## How to Contribute

### Reporting Bugs

1. Check existing [issues](https://github.com/SiteQ8/S7aba/issues) to avoid duplicates
2. Use the **Bug Report** issue template
3. Include your OS, Bash version, and cloud CLI versions
4. Provide steps to reproduce the issue

### Suggesting Features

1. Use the **Feature Request** issue template
2. Describe the use case and expected behavior
3. If proposing a new escalation technique, include references

### Submitting Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes following the coding standards below
4. Test thoroughly
5. Commit with clear messages: `git commit -m "feat: add Azure recon module"`
6. Push and create a Pull Request

## Coding Standards

### Bash Style

- Use `#!/usr/bin/env bash` shebang
- Enable strict mode: `set -euo pipefail`
- Use `readonly` for constants
- Use `local` for function variables
- Quote all variable expansions: `"$var"` not `$var`
- Use `[[ ]]` instead of `[ ]` for conditionals
- Use `$(command)` instead of backticks

### Naming Conventions

- Functions: `snake_case` (e.g., `enum_permissions`)
- Constants: `UPPER_SNAKE_CASE` (e.g., `CLOUD_PROVIDER`)
- Local variables: `snake_case`
- Files: `command_provider.sh` (e.g., `recon_aws.sh`)

### Module Structure

New modules should follow this pattern:

```bash
#!/usr/bin/env bash
# S7aba - [Provider] [Command] Module

function_name() {
    log_info "Description of what this does..."
    
    # Implementation
    local result
    result=$(some_command 2>/dev/null)
    
    if [[ -n "$result" ]]; then
        log_finding "SEVERITY" "Title" "Detail"
    fi
}
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `refactor:` Code refactoring
- `test:` Tests
- `chore:` Maintenance

## Adding a New Cloud Provider

1. Create module files in `src/modules/`:
   - `recon_<provider>.sh`
   - `privesc_<provider>.sh`
   - `lateral_<provider>.sh`
   - `persist_<provider>.sh`
   - `exfil_<provider>.sh`
   - `cleanup_<provider>.sh`

2. Add detection logic in `src/lib/cloud_detect.sh`

3. Update README provider table

4. Add tests

## Code of Conduct

Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before contributing.

## Questions?

Open a [Discussion](https://github.com/SiteQ8/S7aba/discussions) or reach out to [@SiteQ8](https://github.com/SiteQ8).

---

Thank you for making S7aba better! 🚀
