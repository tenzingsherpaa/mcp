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

"""Models for the diagrams-mcp-server."""

from enum import Enum
from pydantic import BaseModel, Field, field_validator
from typing import Dict, List, Literal, Optional


class DiagramType(str, Enum):
    """Enum for supported diagram types."""

    AWS = 'aws'
    SEQUENCE = 'sequence'
    FLOW = 'flow'
    CLASS = 'class'
    K8S = 'k8s'
    ONPREM = 'onprem'
    CUSTOM = 'custom'
    ALL = 'all'


class DiagramGenerateRequest(BaseModel):
    """Request model for diagram generation."""

    code: str = Field(..., description='Python code string using the diagrams package DSL')
    filename: Optional[str] = Field(
        None,
        description='Output filename (without extension). If not provided, a random name will be generated.',
    )
    timeout: int = Field(90, description='Timeout in seconds for diagram generation', ge=1, le=300)
    workspace_dir: Optional[str] = Field(
        None,
        description='The user\'s current workspace directory. If provided, diagrams will be saved to a "generated-diagrams" subdirectory.',
    )

    @field_validator('code')
    @classmethod
    def validate_code(cls, v):
        """Validate that the code contains a Diagram definition."""
        if 'Diagram(' not in v:
            raise ValueError('Code must contain a Diagram definition')
        return v


class DiagramExampleRequest(BaseModel):
    """Request model for diagram examples."""

    diagram_type: DiagramType = Field(
        DiagramType.ALL,
        description='Type of diagram example to return',
    )


class DiagramGenerateResponse(BaseModel):
    """Response model for diagram generation."""

    status: Literal['success', 'error']
    path: Optional[str] = None
    message: str


class DiagramExampleResponse(BaseModel):
    """Response model for diagram examples."""

    examples: Dict[str, str]


class DiagramIconsRequest(BaseModel):
    """Request model for listing available diagram icons."""

    provider_filter: Optional[str] = Field(
        None, description='Filter icons by provider name (e.g., "aws", "gcp", "k8s")'
    )
    service_filter: Optional[str] = Field(
        None, description='Filter icons by service name (e.g., "compute", "database", "network")'
    )


class DiagramIconsResponse(BaseModel):
    """Response model for listing available diagram icons."""

    providers: Dict[str, Dict[str, List[str]]]
    filtered: bool = False
    filter_info: Optional[Dict[str, str]] = None
