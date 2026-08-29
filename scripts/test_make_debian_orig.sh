#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmp_root="$(mktemp -d)"
cleanup() {
  rm -rf -- "${tmp_root}"
}
trap cleanup EXIT

source_root="${tmp_root}/source"
out="${tmp_root}/basefwx_3.8.0~dev1.orig.tar.xz"
mkdir -p "${source_root}/cpp/src"

printf '3.8.0-dev1\n' > "${source_root}/VERSION"
printf 'public\n' > "${source_root}/cpp/src/keep.cpp"
printf 'untracked public\n' > "${source_root}/UNTRACKED.md"
printf '%s\n' \
  'AI_gen/' \
  '.private/' \
  '.claude/' \
  '.codex/' \
  '.cursor/' \
  '.copilot/' \
  '.secrets/' \
  '.env' \
  '.env.*' \
  '.envrc' \
  '.aider*' \
  'AGENTS.md' \
  'AI_NOTES.md' \
  'CLAUDE.md' \
  'RULE.md' \
  '.cursorrules' > "${source_root}/.gitignore"

ignored_paths=(
  "AI_gen/notes.md"
  "nested/.private/kickoff.md"
  "nested/.claude/settings.json"
  "nested/.codex/agent.md"
  "nested/.cursor/rules.json"
  "nested/.copilot/config.json"
  "nested/.secrets/token"
  ".env"
  "nested/.envrc"
  "nested/.env.production"
  ".aider.conf.yml"
  "nested/.aider.chat.history.md"
  "nested/.aider/session.md"
  "nested/docs/AGENTS.md"
  "nested/docs/AI_NOTES.md"
  "nested/docs/CLAUDE.md"
  "nested/docs/RULE.md"
  "nested/docs/.cursorrules"
)
for private_path in "${ignored_paths[@]}"; do
  mkdir -p "${source_root}/$(dirname "${private_path}")"
  printf 'private\n' > "${source_root}/${private_path}"
done

snapshot_root="${tmp_root}/snapshot"
snapshot_manifest="${tmp_root}/snapshot.manifest"
snapshot_out="${tmp_root}/snapshot.orig.tar.xz"
mkdir -p "${snapshot_root}/cpp/src"
cp -- "${source_root}/VERSION" "${snapshot_root}/VERSION"
cp -- "${source_root}/UNTRACKED.md" "${snapshot_root}/UNTRACKED.md"
cp -- "${source_root}/cpp/src/keep.cpp" "${snapshot_root}/cpp/src/keep.cpp"
printf '%s\0' 'UNTRACKED.md' 'VERSION' 'cpp/src/keep.cpp' > "${snapshot_manifest}"

if SOURCE_DATE_EPOCH=1 \
     "${repo_root}/scripts/make_debian_orig.sh" \
     --source-root "${snapshot_root}" --output "${snapshot_out}" \
     >/dev/null 2>"${tmp_root}/snapshot-no-manifest.stderr"; then
  echo "orig tarball accepted a non-Git snapshot without an explicit manifest" >&2
  exit 1
fi
grep -Fq 'use --source-manifest for an auditable frozen snapshot' \
  "${tmp_root}/snapshot-no-manifest.stderr"

SOURCE_DATE_EPOCH=1 \
  "${repo_root}/scripts/make_debian_orig.sh" \
  --source-root "${snapshot_root}" --source-manifest "${snapshot_manifest}" \
  --output "${snapshot_out}" >/dev/null
snapshot_listing="$(tar -tf "${snapshot_out}")"
grep -qx 'basefwx-3.8.0~dev1/VERSION' <<<"${snapshot_listing}"
grep -qx 'basefwx-3.8.0~dev1/cpp/src/keep.cpp' <<<"${snapshot_listing}"
grep -qx 'basefwx-3.8.0~dev1/UNTRACKED.md' <<<"${snapshot_listing}"

mkdir -p "${snapshot_root}/config/runtime"
printf 'secret\n' > "${snapshot_root}/config/runtime/.env.production"
printf '%s\0' \
  'UNTRACKED.md' 'VERSION' 'config/runtime/.env.production' 'cpp/src/keep.cpp' \
  > "${tmp_root}/snapshot-secret.manifest"
if SOURCE_DATE_EPOCH=1 \
     "${repo_root}/scripts/make_debian_orig.sh" \
     --source-root "${snapshot_root}" \
     --source-manifest "${tmp_root}/snapshot-secret.manifest" \
     --output "${tmp_root}/snapshot-secret.orig.tar.xz" \
     >/dev/null 2>"${tmp_root}/snapshot-secret.stderr"; then
  echo "manifest-driven orig tarball accepted a high-risk secret path" >&2
  exit 1
fi
grep -Fq \
  'refusing to archive high-risk private path: config/runtime/.env.production' \
  "${tmp_root}/snapshot-secret.stderr"

git -C "${source_root}" init -q
git -C "${source_root}" config user.name "BaseFWX Test"
git -C "${source_root}" config user.email "basefwx-test@example.invalid"
git -C "${source_root}" add VERSION .gitignore cpp/src/keep.cpp
git -C "${source_root}" -c commit.gpgsign=false commit -qm initial
for private_path in "${ignored_paths[@]}"; do
  if ! git -C "${source_root}" check-ignore -q -- "${private_path}"; then
    echo "synthetic private fixture is not ignored: ${private_path}" >&2
    exit 1
  fi
done

SOURCE_DATE_EPOCH=1 \
  "${repo_root}/scripts/make_debian_orig.sh" \
  --source-root "${source_root}" \
  --output "${out}" >/dev/null

listing="$(tar -tf "${out}")"
grep -qx 'basefwx-3.8.0~dev1/VERSION' <<<"${listing}"
grep -qx 'basefwx-3.8.0~dev1/cpp/src/keep.cpp' <<<"${listing}"
grep -qx 'basefwx-3.8.0~dev1/UNTRACKED.md' <<<"${listing}"

high_risk_pattern='(^|/)(AI_gen|\.private|\.claude|\.codex|\.cursor|\.copilot|\.secrets|\.env(\.[^/]*)?|\.envrc|\.aider[^/]*)(/|$)|(^|/)(AGENTS\.md|AI_NOTES\.md|CLAUDE\.md|RULE\.md|\.cursorrules)$'
if grep -Eqi "${high_risk_pattern}" <<<"${listing}"; then
  echo "orig tarball contains a private or generated path" >&2
  printf '%s\n' "${listing}" >&2
  exit 1
fi
for private_path in "${ignored_paths[@]}"; do
  if grep -Fqx "basefwx-3.8.0~dev1/${private_path}" <<<"${listing}"; then
    echo "orig tarball contains seeded private path: ${private_path}" >&2
    exit 1
  fi
done

danger_root="${tmp_root}/danger"
danger_out="${tmp_root}/danger.orig.tar.xz"
danger_log="${tmp_root}/danger.stderr"
mkdir -p "${danger_root}/config/runtime"
printf '3.8.0\n' > "${danger_root}/VERSION"
printf 'secret\n' > "${danger_root}/config/runtime/.env.production"
git -C "${danger_root}" init -q
git -C "${danger_root}" config user.name "BaseFWX Test"
git -C "${danger_root}" config user.email "basefwx-test@example.invalid"
git -C "${danger_root}" add VERSION config/runtime/.env.production
git -C "${danger_root}" -c commit.gpgsign=false commit -qm initial
if SOURCE_DATE_EPOCH=1 \
     "${repo_root}/scripts/make_debian_orig.sh" \
     --source-root "${danger_root}" --output "${danger_out}" \
     >/dev/null 2>"${danger_log}"; then
  echo "orig tarball accepted a tracked nested high-risk secret path" >&2
  exit 1
fi
if ! grep -Fq \
     'refusing to archive high-risk private path: config/runtime/.env.production' \
     "${danger_log}"; then
  echo "orig tarball failed for the wrong reason in tracked-path test" >&2
  cat "${danger_log}" >&2
  exit 1
fi
if [[ -e "${danger_out}" ]]; then
  echo "failed orig tarball creation left a partial output" >&2
  exit 1
fi

live_out="${tmp_root}/live.orig.tar.xz"
live_args=(--source-root "${repo_root}" --output "${live_out}")
if ! git -C "${repo_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [[ -z "${BASEFWX_SOURCE_MANIFEST:-}" ]]; then
    echo "live orig privacy check requires Git metadata or BASEFWX_SOURCE_MANIFEST" >&2
    exit 1
  fi
  live_args+=(--source-manifest "${BASEFWX_SOURCE_MANIFEST}")
fi
SOURCE_DATE_EPOCH=1 \
  "${repo_root}/scripts/make_debian_orig.sh" \
  "${live_args[@]}" >/dev/null
live_listing="$(tar -tf "${live_out}")"
if grep -Eqi "${high_risk_pattern}" <<<"${live_listing}"; then
  echo "live orig tarball contains an ignored/private path" >&2
  exit 1
fi

echo "make_debian_orig privacy regression: PASS"
