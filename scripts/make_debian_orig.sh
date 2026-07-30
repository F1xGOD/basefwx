#!/usr/bin/env bash
# BaseFWX - Cryptography Engine
# Copyright (C) 2020-2026  FixCraft Inc.
# Licensed under the GNU General Public License v3.0 or later.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: make_debian_orig.sh [--source-root PATH] [--output PATH]

Create a reproducible Debian orig tarball without repository-private or
generated files. Options are primarily intended for packaging tests; the
defaults package the current BaseFWX checkout beside the repository.
EOF
}

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source_root="${script_root}"
out=""

while (($# > 0)); do
  case "$1" in
    --source-root)
      (($# >= 2)) || { echo "--source-root requires a path" >&2; exit 2; }
      source_root="$2"
      shift 2
      ;;
    --output)
      (($# >= 2)) || { echo "--output requires a path" >&2; exit 2; }
      out="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ ! -d "${source_root}" ]]; then
  echo "source root is not a directory: ${source_root}" >&2
  exit 1
fi
source_root="$(cd "${source_root}" && pwd -P)"

if [[ ! -f "${source_root}/VERSION" ]]; then
  echo "missing VERSION in source root: ${source_root}" >&2
  exit 1
fi

if ! git -C "${source_root}" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "source root must be a Git work tree so archive membership is auditable" >&2
  exit 1
fi
git_root="$(git -C "${source_root}" rev-parse --show-toplevel)"
git_root="$(cd "${git_root}" && pwd -P)"
if [[ "${git_root}" != "${source_root}" ]]; then
  echo "source root must be the Git work-tree root: ${source_root}" >&2
  exit 1
fi
version="$(tr -d '[:space:]' < "${source_root}/VERSION")"

if [[ -z "${version}" || "${version}" == */* ]]; then
  echo "invalid BaseFWX version in VERSION" >&2
  exit 1
fi

archive_version="${version/-dev/~dev}"

if [[ -z "${out}" ]]; then
  out="${source_root}/../basefwx_${archive_version}.orig.tar.xz"
fi
out_parent="$(cd "$(dirname "${out}")" && pwd -P)"
out="${out_parent}/$(basename "${out}")"

case "${out}" in
  "${source_root}"/*)
    echo "output must be outside the source root: ${out}" >&2
    exit 1
    ;;
esac

prefix="basefwx-${archive_version}"

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
  SOURCE_DATE_EPOCH="$(git -C "${source_root}" log -1 --format=%ct)"
fi
if [[ ! "${SOURCE_DATE_EPOCH}" =~ ^[0-9]+$ ]]; then
  echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2
  exit 1
fi

cd "${source_root}"

tmp_out="$(mktemp "${out_parent}/.basefwx-orig.XXXXXX.tar.xz")"
manifest="$(mktemp "${out_parent}/.basefwx-orig.XXXXXX.manifest")"
cleanup() {
  rm -f -- "${tmp_out}"
  rm -f -- "${manifest}"
}
trap cleanup EXIT

git ls-files --cached --others --exclude-standard -z \
  | LC_ALL=C sort -z > "${manifest}"

while IFS= read -r -d '' path; do
  if [[ -z "${path}" || "${path}" == /* || "${path}" == ../* || "${path}" == */../* ]]; then
    echo "unsafe Git archive path: ${path}" >&2
    exit 1
  fi
  lower_path="${path,,}"
  if [[ "${lower_path}" =~ (^|/)(ai_gen|\.private|private|\.claude|\.codex|\.cursor|\.copilot|\.secrets|secrets|\.env(\.[^/]*)?|\.envrc)(/|$) ]] \
     || [[ "${lower_path}" =~ (^|/)\.aider[^/]*(/|$) ]] \
     || [[ "${lower_path}" =~ (^|/)(agents\.md|ai_notes\.md|claude\.md|rule\.md|\.cursorrules)$ ]]; then
    echo "refusing to archive high-risk private path: ${path}" >&2
    exit 1
  fi
  if [[ ! -f "${path}" && ! -L "${path}" ]]; then
    echo "Git archive member is not a file or symlink: ${path}" >&2
    exit 1
  fi
done < "${manifest}"

tar --null --no-recursion --files-from "${manifest}" \
        --transform "s#^\\./#${prefix}/#" \
        --transform "s#^\\([^/]\\)#${prefix}/\\1#" \
        --sort=name \
        --owner=0 --group=0 --numeric-owner \
        --mtime="@${SOURCE_DATE_EPOCH}" \
        -cJf "${tmp_out}"

mv -f -- "${tmp_out}" "${out}"
rm -f -- "${manifest}"
trap - EXIT

echo "${out}"
