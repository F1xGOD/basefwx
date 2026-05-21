# Contributing to BaseFWX

> Short version: open a PR; for non-trivial changes, expect to sign a
> one-page CLA. The CLA exists because BaseFWX is dual-licensed and
> the dual-license model only works if every contributor agrees that
> their code can flow through both licenses.

## What contributions are welcome

- Bug fixes against the current release (3.7.0 + `[Unreleased]`).
- Cross-runtime parity fixes (C++ ↔ Java ↔ Python drift).
- New plugins for `examples/plugins/` (they live outside the
  GPL-licensed core, see [LICENSING.md](./LICENSING.md)).
- Documentation improvements, including AI-agent docs
  (`AGENTS.md`).
- Test-suite improvements in `scripts/test_all.sh` or its
  per-runtime equivalents.

## What's *not* welcome (without prior discussion)

- New cryptographic primitives. Open an issue first.
- Wire-format changes. Open an issue, and read
  [`SECURITY.md`](./SECURITY.md) compatibility policy first.
- Resurrecting retired methods (`b1024`, etc.). The decisions are
  documented in `CHANGELOG.md`.
- "I rewrote everything in Rust." This isn't a port-the-library
  project.

## Process

1. **Open an issue first** for anything bigger than a typo fix.
   A 5-line sketch of what you're planning to do is enough; it
   saves both of us from a PR that doesn't land.
2. **Branch from `main`.** Name the branch `topic/<short-slug>`.
3. **Keep PRs focused.** One logical change per PR. If you find
   yourself bundling unrelated fixes, split them.
4. **Run the per-runtime tests** for the runtime you're changing.
   The full `scripts/test_all.sh` cross-runtime suite is the
   project's gold standard; CI runs it. Heavy local runs go on the
   project's remote build box (see `AGENTS.md`).
5. **Update CHANGELOG.md** under `[Unreleased]` for any
   user-visible change.
6. **Sign the CLA** (below) if it's your first non-trivial PR.

## Style

- C++: follow the existing pattern. `clang-format` config in
  `.clang-format` is the source of truth; format your patch before
  pushing.
- Java: 4-space indent, `// SPDX-License-Identifier: GPL-3.0-or-later`
  at the top of new files, javadoc on public methods.
- Python: PEP 8, type hints on public functions, `# SPDX-License-Identifier:
  GPL-3.0-or-later` on new files.
- Markdown: prose; one sentence per line in long files for clean
  diffs.

## The Contributor License Agreement (CLA)

By signing the CLA, you grant FixCraft Inc. the right to redistribute
your contribution under both:

1. The free track — GPL-3.0 plus the Additional Terms in `LICENCE`
   (Plugin Exception, Attribution requirement).
2. The commercial track — separate commercial licenses sold by
   FixCraft Inc. to customers who need different terms.

You keep your copyright. You give FixCraft Inc. the right to
relicense your contribution as part of the dual-license model. This
is the standard pattern used by every dual-licensed open-source
project (Qt, MongoDB, MySQL, GitLab, etc.).

If you don't want to sign the CLA, that's fine — but your patch will
need to be small enough to be considered de minimis (i.e., not
copyrightable; typically <10 lines of code, or pure formatting / typo
fixes). For anything larger, the CLA is required.

### CLA text (sign by replying in your PR)

> I, the contributor, agree to the BaseFWX Contributor License
> Agreement. I am the sole author of the contribution submitted in
> this pull request, or I have permission from all authors to submit
> it. I grant FixCraft Inc. a perpetual, worldwide, non-exclusive,
> royalty-free, irrevocable license to use, copy, modify, prepare
> derivative works of, publicly display, publicly perform,
> sublicense, and distribute my contribution and such derivative
> works under (a) the terms of the GNU General Public License
> version 3 plus the BaseFWX Additional Terms in `LICENCE`, and
> (b) any other license terms FixCraft Inc. may apply to BaseFWX
> as a whole, including commercial licenses. I retain all other
> rights, including the right to use my contribution under other
> licenses.

To sign: reply in your PR with the line **"I agree to the BaseFWX
CLA above."** That's it. We'll record the agreement against your
GitHub username.

If you're contributing on behalf of an employer, your employer must
also acknowledge (typically a one-line approval from a manager
copied into the PR). For corporate contributors with a lot of
ongoing involvement, a separate signed Corporate CLA is available
on request — email `admin@fixcraft.jp`.

## Security issues

Do **not** open public issues for security bugs. See `SECURITY.md`
for the disclosure path (GitHub Security Advisory, then private
contact). The same dual-license CLA applies to security-related
patches.

## Code of conduct

Be civil. Disagreements about technical choices are welcome;
personal attacks aren't. The maintainers can and will close PRs
or block contributors who can't keep discussions on the technical
substance.

## Questions

- About the code: open an issue, tag it `question`.
- About licensing: `admin@fixcraft.jp` or open an issue tagged
  `licensing`.
- About a commercial license: `admin@fixcraft.jp`.
