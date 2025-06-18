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
from importlib import (  # nosem: python.lang.compatibility.python37.python37-compatibility-importlib2
    # nosem: python.lang.compatibility.python37.python37-compatibility-importlib2
    resources,  # nosem: python.lang.compatibility.python37.python37-compatibility-importlib2
)  # nosem: python.lang.compatibility.python37.python37-compatibility-importlib2

with (
    resources.files('awslabs.cost_analysis_mcp_server.static')
    .joinpath('COST_REPORT_TEMPLATE.md')
    .open('r', encoding='utf-8') as f
):
    COST_REPORT_TEMPLATE = f.read()
