# Public automation context

This page contains repository facts that are useful to coding tools and safe to
publish. Human users should start with the root README.

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
