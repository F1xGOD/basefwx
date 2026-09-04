# Public automation context

This page contains repository facts that are useful to coding tools and safe to
publish. Human users should start with the root README.

## Before you act

1. Restate the request in one or two sentences: what changes, what must not
   change, and what "done" looks like. Name the reading you take when two are
   possible, or ask when the wrong choice would waste the work.
2. Check the decision, not only the instruction. Released ciphertext stays
   decodable as `COMPATIBILITY.md` records; authentication never falls back;
   C++, Java, and Python stay in sync on shared formats; and an API field,
   flag, or header that does nothing is removed, not retained. When a request
   conflicts with one of these, or rests on a claim the source disproves, say
   so with the evidence and offer the nearest sound alternative before
   building. A repeated instruction after that is the owner's decision.
3. Verify the premise in live source and tests before changing behavior. A
   note or a handoff is a pointer, not evidence.

## Before you finish

Report completion only after this list is done, and include it in the final
message:

- every document that describes the changed behavior is corrected in the same
  change, and `scripts/sync_website_docs.py --check`,
  `scripts/check_website_catalog.py`, and `scripts/check_version_sync.py`
  pass;
- `CHANGELOG.md` names the change under `[Unreleased]`;
- private lasting notes under `.private/ai/` are corrected in place, and
  dated handoffs whose facts were promoted are deleted;
- rejected changes and disproved claims are recorded once where the next
  reader will look;
- the checks that ran, with results, and the gates that did not run are
  listed without softening.

## What to update when you change something

| You changed | Update in the same change |
| --- | --- |
| a format writer or reader (`cpp/src/file/`, `cpp/src/formats/`, `cpp/src/crypto/keywrap.cpp`) | `COMPATIBILITY.md`, the Java and Python counterparts, `testdata/protocol_kats/` through `scripts/gen_protocol_kats.py` |
| a public header under `cpp/include/basefwx/` | `ABI.md`, `cpp/cmake/check_core_abi_exports.cmake` when a required symbol moves |
| CLI flags, commands, or completions (`cpp/src/cli/`, `cpp/src/main.cpp`) | `docs/CLI.md`, `docs/man/basefwx.1`, the help text and completion strings in `cpp/src/cli/output.cpp` |
| any `BASEFWX_*` environment read | `SECURITY.md` and `docs/CLI.md` environment sections |
| password policy, KDF defaults, master recovery | `SECURITY.md`, `COMPATIBILITY.md`, `docs/EXPLAINED.md` |
| `VERSION` or packaging | `scripts/check_version_sync.py` must pass, `CHANGELOG.md` section heading |
| any root or `docs/` Markdown | `python3 scripts/sync_website_docs.py`, then `--check` and `scripts/check_website_catalog.py` |

Every behaviour change also gets a line under `[Unreleased]` in
`CHANGELOG.md`. If a row above is missing for what you touched, add the row.

## Temporary: no compatibility debt while nothing depends on us

**Delete this section once BaseFWX has real downstream users.**

Released *ciphertext* must stay readable, and that rule is permanent: it is
recorded in `COMPATIBILITY.md` and is not what this section is about. What is
temporary is politeness toward *callers*. No API, flag, struct field, or CLI
spelling needs to survive for a consumer that does not exist. A field
documented as having no effect is a defect, not a courtesy, and it gets
removed rather than annotated.

Two rules survive this section and are permanent. Write careful, lasting code
anyway, because this is the code that reaches production. And redundancy is
never acceptable at any stage: two identical structs, two copies of one
document, or a parameter nothing reads are defects before and after release.

## Sources of truth

- `VERSION` is the one repository version source. C++, Python, Java, packaging,
  and releases derive from it.
- `COMPATIBILITY.md` defines cross-runtime format support.
- `ABI.md` separates the frozen plugin C ABI from the pre-stable C++ library.
- `SECURITY.md` defines the supported release and legacy-recovery policy.
- Source and shared known-answer tests outrank prose when they disagree.

Do not copy the current version, benchmark output, dependency revision, or
machine state into a new planning document. Link to its live source or record
it in the ignored `.private/` overlay when it is task-specific.

## Change rules

Shared format and cryptographic changes must keep C++, Python, and Java in sync
unless the public contract explicitly limits the API to one runtime. Validate
all lengths and format tags before allocation or use. Authentication failure
must not fall back to a legacy or unauthenticated parser.

The default build contains maintained formats only. Retired codecs and media
paths are recovery code behind an explicit build profile. Do not add features,
benchmarks, or new writers to that surface.

Keep secret keys, generated payloads, test credentials, benchmark artifacts,
machine logs, and private task state out of Git. Run focused tests first, then
the cross-runtime and packaging checks required by the touched contract.

A behavior change is not finished until every document that describes that
behavior is corrected in the same change. `COMPATIBILITY.md`, `SECURITY.md`,
`ABI.md`, `docs/man/basefwx.1`, and the pages under `website/docs/` go stale
first. Describe the boundary the code now enforces, not the intent behind the
change: a guard that covers one decode path is not a runtime-wide refusal, and
a document that claims the wider behavior is a defect in its own right.

## Documentation boundary

Public human docs describe current behavior, supported recovery, and durable
contracts. Public automation docs live only under `docs/agents/`. Dated
handoffs, speculative speedups, generated implementation summaries, and task
queues belong in `.private/` or Git history.
