# TraceCrypt Development Setup Guide

## System Requirements
- **Operating System:** Windows 10/11, Linux (RHEL/Ubuntu LTS), or macOS.
- **Python Runtime:** Python 3.11.x (verified on Python 3.11.9).
- **Network Requirement:** Zero external internet access required for operation.

## Local Environment Verification
TraceCrypt is designed to use pre-installed local packages without pulling from remote PyPI indexes.

Verify that required dependencies are installed:
```bash
python -m tracecrypt.cli.main doctor
```

## Running Tests
Run the complete test suite:
```bash
pytest
```

Run only unit tests:
```bash
pytest tests/unit
```

Run only security and air-gap tests:
```bash
pytest tests/security
```

## Static Analysis & Code Hygiene
Check formatting and linting:
```bash
flake8 tracecrypt tests
```
