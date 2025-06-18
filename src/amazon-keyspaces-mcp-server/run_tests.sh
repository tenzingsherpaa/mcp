#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

# Exit on error
set -e

echo "========================================================"
echo "Running tests for amazon-keyspaces-mcp-server"
echo "========================================================"

# Install dependencies if not already installed
if [ ! -d ".venv" ]; then
    echo "Installing dependencies..."
    uv sync --frozen --all-extras --dev
else
    echo "Using existing virtual environment"
fi

# Activate the virtual environment
source .venv/bin/activate

# Run the tests with coverage
echo "Running tests with coverage..."
uv run --frozen pytest --cov --cov-branch --cov-report=term-missing

echo "Tests completed successfully!"
