# Copyright 2026 FENGARDE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder-python

RUN git clone --depth 1 https://github.com/supermhel/fengarde fengarde

# The harnesses (tools/fuzz/fuzz_<name>.py) import `_common` and the
# services modules by module name, and shared/ocsf.py locates
# tools/validate_contract.py relative to the repo root at import time, so
# put the repo's relevant roots on PYTHONPATH.
ENV PYTHONPATH="$SRC/fengarde/tools/fuzz:$SRC/fengarde"

# Atheris is pre-installed on the base image, but pin the latest release
# explicitly so the project does not silently depend on the base image tag.
RUN python3 -m pip install --upgrade atheris

COPY build.sh $SRC/build.sh
WORKDIR $SRC/fengarde