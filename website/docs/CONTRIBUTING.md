---
layout: doc
title: Contributing
permalink: /docs/CONTRIBUTING/
---

# Contributing

Use [GitHub Issues](https://github.com/F1xGOD/basefwx/issues) for reproducible
bugs and focused feature proposals. Discuss a format, security, ABI, or broad
cross-runtime change before implementing it.

BaseFWX keeps C++, Python, and Java in one repository. A shared format change
must update every affected runtime and the shared known-answer tests in the same
pull request. Runtime-specific APIs must say so in the public contract.

Before opening a pull request:

1. Keep the change scoped and explain the compatibility boundary.
2. Add negative tests for invalid input and authentication failure.
3. Run the focused tests, then the cross-runtime or packaging suite required by
   the changed surface.
4. Update the README, CLI reference, compatibility page, ABI page, or security
   page when their contract changes.
5. Check that no keys, generated encrypted files, machine logs, or private task
   notes entered the diff.

The full repository policy and build details are in
[CONTRIBUTING.md](https://github.com/F1xGOD/basefwx/blob/main/CONTRIBUTING.md).

## Security reports

Do not open a public issue for a suspected vulnerability. Follow the private
reporting instructions in
[SECURITY.md](https://github.com/F1xGOD/basefwx/blob/main/SECURITY.md).
