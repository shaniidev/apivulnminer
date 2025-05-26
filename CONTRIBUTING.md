# Contributing to APIVulnMiner

First off, thank you for considering contributing to APIVulnMiner! We value your help in making this tool even better. Every contribution is appreciated, from reporting a bug to submitting a new feature.

This document provides guidelines for contributing to the project. Please read it carefully to ensure a smooth collaboration process.

## Table of Contents
- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Enhancements](#suggesting-enhancements)
  - [Your First Code Contribution](#your-first-code-contribution)
  - [Pull Requests](#pull-requests)
- [Development Setup](#development-setup)
- [Coding Style Guide](#coding-style-guide)
- [Testing](#testing)
- [Commit Message Guidelines](#commit-message-guidelines)

## Code of Conduct

This project and everyone participating in it is governed by the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to jumbubly@gmail.com.

## How Can I Contribute?

### Reporting Bugs

If you encounter a bug, please help us by submitting an issue to our [GitHub Issues page](https://github.com/shaniidev/apivulnminer/issues).

When reporting a bug, please include:
- **A clear and descriptive title.**
- **Steps to reproduce the bug:** Provide as much detail as possible, including the command you ran, the target URL (if permissible), and any relevant configuration.
- **Expected behavior:** What did you expect to happen?
- **Actual behavior:** What actually happened? Include error messages and stack traces if available.
- **Your environment:** Operating system, Python version, APIVulnMiner version.
- **Screenshots or logs** that demonstrate the issue.

### Suggesting Enhancements

We welcome suggestions for new features or improvements to existing ones. You can submit an enhancement suggestion by creating an issue on our [GitHub Issues page](https://github.com/shaniidev/apivulnminer/issues).

Please include:
- **A clear and descriptive title.**
- **A detailed description of the proposed enhancement:** Explain the problem it solves or the value it adds.
- **Any potential alternatives or use cases** you've considered.
- **Mockups or code snippets** if applicable.

### Your First Code Contribution

Unsure where to begin contributing to APIVulnMiner?
- Look for issues tagged `good first issue` or `help wanted`.
- Start with small changes, like documentation improvements or bug fixes.
- Feel free to ask for guidance on an issue!

### Pull Requests

When you're ready to contribute code, please follow these steps:
1.  **Fork the repository** to your own GitHub account.
2.  **Clone your fork** locally: `git clone https://github.com/YOUR_USERNAME/apivulnminer.git`
3.  **Create a new branch** for your changes: `git checkout -b feature/your-feature-name` or `bugfix/issue-number`.
4.  **Make your changes**, adhering to the [Coding Style Guide](#coding-style-guide).
5.  **Add tests** for your changes.
6.  **Ensure all tests pass**: `python -m pytest tests/`
7.  **Commit your changes** with a descriptive commit message (see [Commit Message Guidelines](#commit-message-guidelines)).
8.  **Push your branch** to your fork: `git push origin feature/your-feature-name`
9.  **Open a Pull Request (PR)** to the `master` branch of the main `apivulnminer` repository.
    - Provide a clear title and description for your PR, explaining the changes and linking to any relevant issues.
    - Ensure your PR passes all automated checks (CI/CD).

## Development Setup

Please refer to the "Development Setup" section in the `README.md` for instructions on how to set up your development environment.

Ensure you have development dependencies installed:
```bash
pip install -r requirements-dev.txt 
# (You might need to create this file if it doesn't exist, listing tools like pytest, flake8, mypy, black)
```

## Coding Style Guide

Please adhere to the following coding conventions:
- **Follow PEP 8** for Python code. We recommend using a linter like `Flake8` and a formatter like `Black`.
- **Concise, technical responses with accurate Python examples.**
- **Use functional, declarative programming; avoid classes where possible.**
- **Prefer iteration and modularization over code duplication.**
- **Use descriptive variable names with auxiliary verbs** (e.g., `is_encrypted`, `has_valid_signature`).
- **Use lowercase with underscores for directories and files** (e.g., `scanners/port_scanner.py`).
- **Favor named exports for commands and utility functions.**
- **Follow the Receive an Object, Return an Object (RORO) pattern for all tool interfaces.**
- **Use `def` for pure, CPU-bound routines; `async def` for network- or I/O-bound operations.**
- **Add type hints for all function signatures.** Validate inputs with Pydantic v2 models where structured config is required.
- **Organize file structure into modules:**
    - `scanners/` (port, vulnerability, web)
    - `enumerators/` (dns, smb, ssh)
    - `attackers/` (brute_forcers, exploiters)
    - `reporting/` (console, HTML, JSON)
    - `utils/` (crypto_helpers, network_helpers)
    - `types/` (models, schemas)
- **Perform error and edge-case checks at the top of each function (guard clauses).**
- **Use early returns for invalid inputs.**
- **Log errors with structured context.**
- **Raise custom exceptions.**
- **Avoid nested conditionals; keep the "happy path" last.**
- **Sanitize all external inputs.**
- **Use secure defaults.**
- **Rely on dependency injection for shared resources.**

## Testing

- All new features and bug fixes **must** include tests.
- We use `pytest` for testing.
- Run tests using: `python -m pytest tests/`
- Ensure your changes do not break existing tests.
- Aim for high test coverage.

## Commit Message Guidelines

Please follow these conventions for your commit messages:
- Start with a relevant emoji and a short, imperative summary (e.g., "✨ Feat: Add new reporting module").
- Use the present tense ("Add feature" not "Added feature").
- Optionally, provide a more detailed explanation in the commit body, explaining the "what" and "why" of your changes, not just the "how."
- Reference any relevant issue numbers (e.g., "Closes #123").

Example:
```
✨ Feat: Add support for custom headers in scans

- Implemented functionality to allow users to specify custom HTTP headers
  for API requests.
- Updated documentation and added examples for usage.

Closes #42
```

---

Thank you for your interest in contributing to APIVulnMiner! We look forward to your contributions. 