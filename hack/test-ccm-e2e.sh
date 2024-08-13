#!/usr/bin/env bash

# Copyright 2022 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o pipefail

REPO_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
DEFAULT_LABEL_FILTER="!Serial && !Slow"
LABEL_FILTER="${LABEL_FILTER:-${DEFAULT_LABEL_FILTER}}"

source "${REPO_ROOT}/hack/ensure-ginkgo-v2.sh"

ginkgo -flake-attempts 2 -skip "${SKIP_ARGS}" -label-filter "TESTTEST" "${REPO_ROOT}"/tests/e2e/
