#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: tools/scripts/run-m33mu-workflow.sh <workflow> [job]

Run the local equivalent of the m33mu GitHub Actions workflow inside the
same CI container image via podman.

Accepted workflows:
  stm32h563-m33mu
  stm32h563-m33mu.yml
  .github/workflows/stm32h563-m33mu.yml
  stm32h563-m33mu-freertos
  stm32h563-m33mu-freertos.yml
  .github/workflows/stm32h563-m33mu-freertos.yml
  stm32h563-m33mu-ssh-tzen
  stm32h563-m33mu-ssh-tzen.yml
  .github/workflows/stm32h563-m33mu-ssh-tzen.yml

Optional job names:
  stm32h563_m33mu_echo
  stm32h563_m33mu_echo_freertos
  stm32h563_m33mu_full
  stm32h563_m33mu_https_tls13
  stm32h563_m33mu_https_freertos
  stm32h563_m33mu_ssh_tzen

Environment:
  M33MU_CI_IMAGE   Override container image
EOF
}

normalize_workflow() {
  case "$1" in
    stm32h563-m33mu|stm32h563-m33mu.yml|.github/workflows/stm32h563-m33mu.yml)
      printf '%s\n' stm32h563-m33mu
      ;;
    stm32h563-m33mu-freertos|stm32h563-m33mu-freertos.yml|.github/workflows/stm32h563-m33mu-freertos.yml)
      printf '%s\n' stm32h563-m33mu-freertos
      ;;
    stm32h563-m33mu-ssh-tzen|stm32h563-m33mu-ssh-tzen.yml|.github/workflows/stm32h563-m33mu-ssh-tzen.yml)
      printf '%s\n' stm32h563-m33mu-ssh-tzen
      ;;
    *)
      return 1
      ;;
  esac
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  usage
  exit 1
fi

if ! command -v podman >/dev/null 2>&1; then
  echo "podman is required" >&2
  exit 1
fi

workflow="$(normalize_workflow "$1")" || {
  echo "Unsupported workflow: $1" >&2
  usage
  exit 1
}
job="${2:-}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/../.." && pwd)"
workspace_root="$(cd "${repo_root}/.." && pwd)"
repo_name="$(basename "${repo_root}")"
image="${M33MU_CI_IMAGE:-ghcr.io/wolfssl/wolfboot-ci-m33mu:v1.2}"
podman_tty_args=(--rm --privileged --security-opt label=disable)

if [ -t 0 ] && [ -t 1 ]; then
  podman_tty_args=(-it "${podman_tty_args[@]}")
fi

exec podman run \
  "${podman_tty_args[@]}" \
  -e DEBIAN_FRONTEND=noninteractive \
  -v "${workspace_root}:/workspace" \
  -w "/workspace/${repo_name}" \
  "${image}" \
  /bin/bash tools/scripts/run-m33mu-ci-in-container.sh "${workflow}" "${job}"
