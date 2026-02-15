#!/usr/bin/env bash
set -euo pipefail

BASE_BRANCH="${1:-main}"
DEV_BRANCH="${2:-DEV}"
ALLOWLIST_FILE="${ALLOWLIST_FILE:-.branch-parity-allowlist}"

resolve_ref() {
  local ref="$1"
  if git rev-parse --verify --quiet "${ref}" >/dev/null; then
    echo "${ref}"
    return 0
  fi
  if git rev-parse --verify --quiet "origin/${ref}" >/dev/null; then
    echo "origin/${ref}"
    return 0
  fi
  return 1
}

BASE_REF="$(resolve_ref "${BASE_BRANCH}")" || {
  echo "Unable to resolve base branch: ${BASE_BRANCH}" >&2
  exit 2
}
DEV_REF="$(resolve_ref "${DEV_BRANCH}")" || {
  echo "Unable to resolve dev branch: ${DEV_BRANCH}" >&2
  exit 2
}

mapfile -t ALL_CHANGED < <(git diff --name-only "${BASE_REF}" "${DEV_REF}" -- | sort -u)

if [[ ${#ALL_CHANGED[@]} -eq 0 ]]; then
  echo "Branch parity OK: ${BASE_REF} and ${DEV_REF} are identical."
  exit 0
fi

ALLOW_PATTERNS=()
if [[ -f "${ALLOWLIST_FILE}" ]]; then
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "${line}" ]] && continue
    [[ "${line}" == \#* ]] && continue
    ALLOW_PATTERNS+=("${line}")
  done < "${ALLOWLIST_FILE}"
fi

is_allowed() {
  local path="$1"
  local pattern
  for pattern in "${ALLOW_PATTERNS[@]:-}"; do
    if [[ "${path}" == ${pattern} ]]; then
      return 0
    fi
  done
  return 1
}

DISALLOWED=()
for path in "${ALL_CHANGED[@]}"; do
  if ! is_allowed "${path}"; then
    DISALLOWED+=("${path}")
  fi
done

if [[ ${#DISALLOWED[@]} -gt 0 ]]; then
  echo "Branch parity FAILED for ${BASE_REF}...${DEV_REF}."
  echo "Files that differ outside '${ALLOWLIST_FILE}':"
  printf '  - %s\n' "${DISALLOWED[@]}"
  exit 1
fi

echo "Branch parity OK with allowlist (${ALLOWLIST_FILE})."
echo "Allowed differences:"
printf '  - %s\n' "${ALL_CHANGED[@]}"
