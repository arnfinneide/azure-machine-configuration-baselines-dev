#!/bin/bash
# post-create.sh — devcontainer post-create hook
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common/common-bootstrap.sh"
