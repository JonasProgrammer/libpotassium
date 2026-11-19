#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 libpotassium team
# SPDX-License-Identifier: BSL-1.0

# Source this file from CLion's toolchain environment settings.
# Must run in Bash: `nix print-dev-env` generates Bash source code (including
# shell functions and Bash-specific variables), not a POSIX sh environment.
# The shebang only takes effect when executing the file, not when CLion sources it.

if [ -z "${BASH_VERSION:-}" ]; then
  printf '%s\n' 'CLion Nix environment: this file must be sourced by Bash. CLion sources with your login shell; configure that shell as Bash.' >&2
  return 1 2>/dev/null || exit 1
fi

# CLion sources this script; BASH_SOURCE[0] identifies its location, unlike $0.
_devenv_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P) || return 1

# Fail before evaluating anything if the flake is missing.
if [[ ! -f "$_devenv_root/flake.nix" ]]; then
  printf '%s\n' 'CLion Nix environment: cannot find flake.nix beside clion-env.sh.' >&2
  unset _devenv_root
  return 1
fi

# Nix prints Bash code to reproduce the derivation's development environment.
# Source that directly rather than exporting *every* variable of a child shell
# (which would also include unrelated inherited environment variables).
# Check command status separately: `eval "$(...)"` masks failures of nix.
_devenv_code=$(
  nix --extra-experimental-features 'nix-command flakes' \
    print-dev-env "$_devenv_root#full"
) || {
  printf '%s\n' 'CLion Nix environment: nix print-dev-env failed.' >&2
  unset _devenv_root _devenv_code
  return 1
}

# This evaluates trusted, generated shell code from your pinned Nix flake.
eval "$_devenv_code" || {
  printf '%s\n' 'CLion Nix environment: failed to initialize Nix environment.' >&2
  unset _devenv_root _devenv_code
  return 1
}

unset _devenv_code _devenv_root
