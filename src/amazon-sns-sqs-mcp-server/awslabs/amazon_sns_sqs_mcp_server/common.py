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

"""Common utilities for MCP server."""

from typing import Dict, Tuple


# Tag name constant
MCP_SERVER_VERSION_TAG = 'mcp_server_version'


def validate_mcp_server_version_tag(tags: Dict[str, str]) -> Tuple[bool, str]:
    """Check if the tags contain the mcp_server_version tag.

    Args:
        tags: Dictionary where keys are tag names and values are tag values

    Returns:
        Tuple of (is_valid, error_message)

    """
    return (
        (True, '')
        if MCP_SERVER_VERSION_TAG in tags
        else (False, 'mutating a resource without the mcp_server_version tag is not allowed')
    )
