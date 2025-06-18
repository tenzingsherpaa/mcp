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

"""Utility functions for Terraform MCP server tools."""

import asyncio
import re
import requests
import time
import traceback
from awslabs.terraform_mcp_server.models import SubmoduleInfo, TerraformVariable
from loguru import logger
from typing import Any, Dict, List, Optional, Tuple


def clean_description(description: str) -> str:
    """Remove emoji characters from description strings.

    Args:
        description: The module description text

    Returns:
        Cleaned description without emojis
    """
    # This regex pattern targets common emoji Unicode ranges
    emoji_pattern = re.compile(
        '['
        '\U0001f1e0-\U0001f1ff'  # flags (iOS)
        '\U0001f300-\U0001f5ff'  # symbols & pictographs
        '\U0001f600-\U0001f64f'  # emoticons
        '\U0001f680-\U0001f6ff'  # transport & map symbols
        '\U0001f700-\U0001f77f'  # alchemical symbols
        '\U0001f780-\U0001f7ff'  # Geometric Shapes
        '\U0001f800-\U0001f8ff'  # Supplemental Arrows-C
        '\U0001f900-\U0001f9ff'  # Supplemental Symbols and Pictographs
        '\U0001fa00-\U0001fa6f'  # Chess Symbols
        '\U0001fa70-\U0001faff'  # Symbols and Pictographs Extended-A
        '\U00002702-\U000027b0'  # Dingbats
        ']+',
        flags=re.UNICODE,
    )

    # Clean the description
    return emoji_pattern.sub(r'', description).strip()


async def get_github_release_details(owner: str, repo: str) -> Dict[str, Any]:
    """Fetch detailed release information from GitHub API.

    Args:
        owner: The GitHub repository owner
        repo: The GitHub repository name

    Returns:
        Dictionary containing version details and cleaned version string
    """
    logger.info(f'Fetching GitHub release details for {owner}/{repo}')

    # Try to get the latest release first
    release_url = f'https://api.github.com/repos/{owner}/{repo}/releases/latest'
    logger.debug(f'Making request to GitHub releases API: {release_url}')

    try:
        response = requests.get(release_url)
        logger.debug(f'GitHub releases API response code: {response.status_code}')

        if response.status_code == 200:
            release_data = response.json()
            logger.info(f'Found latest GitHub release: {release_data.get("tag_name")}')

            # Extract just the requested fields (tag name and publish date)
            version_details = {
                'tag_name': release_data.get('tag_name'),
                'published_at': release_data.get('published_at'),
            }

            # Use clean version for the module result
            clean_version = release_data.get('tag_name', '')
            if clean_version.startswith('v'):
                clean_version = clean_version[1:]

            logger.debug(f'Extracted version: {clean_version}')

            return {'details': version_details, 'version': clean_version}
    except Exception as ex:
        logger.error(f'Error fetching GitHub release details: {ex}')
        logger.debug(f'Stack trace: {traceback.format_exc()}')

    # Fallback to tags if no releases found
    tags_url = f'https://api.github.com/repos/{owner}/{repo}/tags'
    logger.debug(f'No releases found, trying tags: {tags_url}')

    try:
        response = requests.get(tags_url)
        logger.debug(f'GitHub tags API response code: {response.status_code}')

        if response.status_code == 200 and response.json():
            tags_data = response.json()
            if tags_data:
                latest_tag = tags_data[0]  # Tags are typically sorted newest first
                logger.info(f'Found latest GitHub tag: {latest_tag.get("name")}')

                version_details = {
                    'tag_name': latest_tag.get('name'),
                    'published_at': None,  # Tags don't have publish dates in GitHub API
                }

                # Use clean version for the module result
                clean_version = latest_tag.get('name', '')
                if clean_version.startswith('v'):
                    clean_version = clean_version[1:]

                logger.debug(f'Extracted version from tag: {clean_version}')

                return {'details': version_details, 'version': clean_version}
    except Exception as ex:
        logger.error(f'Error fetching GitHub tags: {ex}')
        logger.debug(f'Stack trace: {traceback.format_exc()}')

    # Return empty details if nothing was found
    logger.warning('No GitHub release or tag information found')
    return {'details': {}, 'version': ''}


async def get_submodules(owner: str, repo: str, branch: str = 'master') -> List[SubmoduleInfo]:
    """Fetch submodules from a module's GitHub repository.

    Args:
        owner: GitHub repository owner
        repo: GitHub repository name
        branch: Branch name (default: master)

    Returns:
        List of SubmoduleInfo objects
    """
    logger.info(f'Checking for submodules in {owner}/{repo} ({branch} branch)')
    submodules = []

    # Check if modules directory exists
    modules_url = f'https://api.github.com/repos/{owner}/{repo}/contents/modules?ref={branch}'
    logger.debug(f'Checking for modules directory: {modules_url}')

    try:
        # Get list of directories in /modules
        start_time = time.time()
        response = requests.get(
            modules_url,
            headers={'Accept': 'application/vnd.github.v3+json'},
            timeout=3.0,  # Add timeout
        )
        logger.debug(f'GitHub API request took {time.time() - start_time:.2f} seconds')

        if response.status_code == 404:
            logger.debug(f'No modules directory found in {branch} branch')
            return []

        if response.status_code == 403:
            logger.warning(f'GitHub API rate limit reached, status: {response.status_code}')
            # Return empty list but don't fail completely
            return []

        if response.status_code != 200:
            logger.warning(f'Failed to get modules directory: status {response.status_code}')
            return []

        modules_list = response.json()
        if not isinstance(modules_list, list):
            logger.warning('Unexpected API response format for modules listing')
            return []

        # Filter for directories only
        submodule_dirs = [item for item in modules_list if item.get('type') == 'dir']
        logger.info(f'Found {len(submodule_dirs)} potential submodules')

        # Process submodules with concurrency limits
        # Only process up to 5 submodules to avoid timeouts
        max_submodules = min(len(submodule_dirs), 5)
        logger.info(f'Processing {max_submodules} out of {len(submodule_dirs)} submodules')

        # Process each submodule
        for i, submodule in enumerate(submodule_dirs[:max_submodules]):
            name = submodule.get('name')
            path = submodule.get('path', f'modules/{name}')

            # Create basic submodule info
            submodule_info = SubmoduleInfo(
                name=name,
                path=path,
            )

            # Add a slight delay between API requests to avoid rate limiting
            if i > 0:
                await asyncio.sleep(0.2)  # 200ms delay between requests

            # Try to get README content
            readme_url = (
                f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}/README.md'
            )
            logger.debug(f'Fetching README for submodule {name}: {readme_url}')

            try:
                start_time = time.time()
                readme_response = requests.get(readme_url, timeout=2.0)  # Add timeout
                logger.debug(f'README fetch took {time.time() - start_time:.2f} seconds')

                if readme_response.status_code == 200:
                    readme_content = readme_response.text
                    # Truncate if too long
                    if len(readme_content) > 8000:
                        readme_content = (
                            readme_content[:8000] + '...\n[README truncated due to length]'
                        )

                    # Extract description from first paragraph if available
                    description = extract_description_from_readme(readme_content)
                    if description:
                        submodule_info.description = description

                    submodule_info.readme_content = readme_content
                    logger.debug(
                        f'Found README for submodule {name} ({len(readme_content)} chars)'
                    )
                else:
                    logger.debug(
                        f'No README found for submodule {name}, status: {readme_response.status_code}'
                    )
                    # Try lowercase readme.md as fallback
                    lowercase_readme_url = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}/readme.md'
                    logger.debug(f'Trying lowercase readme.md: {lowercase_readme_url}')

                    lowercase_response = requests.get(lowercase_readme_url, timeout=2.0)
                    if lowercase_response.status_code == 200:
                        readme_content = lowercase_response.text
                        if len(readme_content) > 8000:
                            readme_content = (
                                readme_content[:8000] + '...\n[README truncated due to length]'
                            )

                        description = extract_description_from_readme(readme_content)
                        if description:
                            submodule_info.description = description

                        submodule_info.readme_content = readme_content
                        logger.debug(
                            f'Found lowercase readme.md for {name} ({len(readme_content)} chars)'
                        )
            except Exception as ex:
                logger.error(f'Error fetching README for submodule {name}: {ex}')

            # Add the submodule to our result list
            submodules.append(submodule_info)

        if len(submodule_dirs) > max_submodules:
            logger.warning(
                f'Only processed {max_submodules} out of {len(submodule_dirs)} submodules to avoid timeouts'
            )

        return submodules

    except Exception as e:
        logger.error(f'Error fetching submodules: {e}')
        logger.debug(f'Stack trace: {traceback.format_exc()}')
        return []


def extract_description_from_readme(readme_content: str) -> Optional[str]:
    """Extract a short description from the README content.

    Args:
        readme_content: The README markdown content

    Returns:
        Short description or None if not found
    """
    if not readme_content:
        return None

    # Try to find the first paragraph after any headings
    lines = readme_content.split('\n')
    paragraph_text = []

    for line in lines:
        # Skip headings, horizontal rules and blank lines
        if line.startswith('#') or line.startswith('---') or not line.strip():
            # If we already found a paragraph, return it
            if paragraph_text:
                break
            continue

        # Found text content, add to paragraph
        paragraph_text.append(line)

        # If this line ends a paragraph, break
        if not line.endswith('\\') and len(paragraph_text) > 0:
            break

    if paragraph_text:
        description = ' '.join(paragraph_text).strip()
        # Limit to 200 chars max
        if len(description) > 200:
            description = description[:197] + '...'
        return description

    return None


def extract_outputs_from_readme(readme_content: str) -> List[Dict[str, str]]:
    """Extract module outputs from the README content.

    Looks for the Outputs section in the README, which is typically at the bottom
    of the file and contains a table of outputs with descriptions.

    Args:
        readme_content: The README markdown content

    Returns:
        List of dictionaries containing output name and description
    """
    if not readme_content:
        return []

    outputs = []

    # Find the Outputs section
    lines = readme_content.split('\n')
    in_outputs_section = False
    in_outputs_table = False

    for i, line in enumerate(lines):
        # Look for Outputs heading
        if re.match(r'^#+\s+Outputs?$', line, re.IGNORECASE):
            in_outputs_section = True
            continue

        # If we're in the outputs section, look for the table header
        if in_outputs_section and not in_outputs_table:
            if '|' in line and ('Name' in line or 'Output' in line) and 'Description' in line:
                in_outputs_table = True
                continue

        # If we're in the outputs table, parse each row
        if in_outputs_section and in_outputs_table:
            # Skip the table header separator line
            if line.strip().startswith('|') and all(c in '|-: ' for c in line):
                continue

            # If we hit another heading or the table ends, stop parsing
            if line.strip().startswith('#') or not line.strip() or '|' not in line:
                break

            # Parse the table row
            if '|' in line:
                parts = [part.strip() for part in line.split('|')]
                if len(parts) >= 3:  # Should have at least empty, name, description columns
                    name_part = parts[1].strip()
                    desc_part = parts[2].strip()

                    # Clean up any markdown formatting
                    name = re.sub(r'`(.*?)`', r'\1', name_part).strip()
                    description = re.sub(r'`(.*?)`', r'\1', desc_part).strip()

                    if name:
                        outputs.append({'name': name, 'description': description})

    # If we didn't find a table, try looking for a list format
    if not outputs and in_outputs_section:
        for line in lines:
            # If we hit another heading, stop parsing
            if line.strip().startswith('#'):
                break

            # Look for list items that might be outputs
            list_match = re.match(r'^[-*]\s+`([^`]+)`\s*[-:]\s*(.+)$', line)
            if list_match:
                name = list_match.group(1).strip()
                description = list_match.group(2).strip()

                outputs.append({'name': name, 'description': description})

    logger.debug(f'Extracted {len(outputs)} outputs from README')
    return outputs


async def get_variables_tf(
    owner: str, repo: str, branch: str = 'main'
) -> Tuple[Optional[str], Optional[List[TerraformVariable]]]:
    """Fetch and parse the variables.tf file from a GitHub repository.

    Args:
        owner: GitHub repository owner
        repo: GitHub repository name
        branch: Branch name (default: main)

    Returns:
        Tuple containing the raw variables.tf content and a list of parsed TerraformVariable objects
    """
    logger.info(f'Fetching variables.tf from {owner}/{repo} ({branch} branch)')

    # Try to get the variables.tf file
    variables_url = f'https://raw.githubusercontent.com/{owner}/{repo}/{branch}/variables.tf'
    logger.debug(f'Fetching variables.tf: {variables_url}')

    try:
        start_time = time.time()
        response = requests.get(variables_url, timeout=3.0)
        logger.debug(f'variables.tf fetch took {time.time() - start_time:.2f} seconds')

        if response.status_code == 200:
            variables_content = response.text
            logger.info(f'Found variables.tf ({len(variables_content)} chars)')

            # Parse the variables.tf file
            variables = parse_variables_tf(variables_content)
            logger.info(f'Parsed {len(variables)} variables from variables.tf')

            return variables_content, variables
        else:
            logger.debug(
                f'No variables.tf found at {branch} branch, status: {response.status_code}'
            )

            # Try master branch as fallback
            if branch != 'master':
                logger.debug('Trying master branch for variables.tf')
                master_variables_url = (
                    f'https://raw.githubusercontent.com/{owner}/{repo}/master/variables.tf'
                )
                master_response = requests.get(master_variables_url, timeout=3.0)

                if master_response.status_code == 200:
                    variables_content = master_response.text
                    logger.info(
                        f'Found variables.tf in master branch ({len(variables_content)} chars)'
                    )

                    # Parse the variables.tf file
                    variables = parse_variables_tf(variables_content)
                    logger.info(f'Parsed {len(variables)} variables from variables.tf')

                    return variables_content, variables
    except Exception as ex:
        logger.error(f'Error fetching variables.tf: {ex}')
        logger.debug(f'Stack trace: {traceback.format_exc()}')

    return None, None


def parse_variables_tf(content: str) -> List[TerraformVariable]:
    """Parse variables.tf content to extract variable definitions.

    Args:
        content: The content of the variables.tf file

    Returns:
        List of TerraformVariable objects
    """
    if not content:
        return []

    variables = []

    # Simple regex pattern to match variable blocks
    # This is a simplified approach and may not handle all complex HCL syntax
    variable_blocks = re.finditer(r'variable\s+"([^"]+)"\s*{([^}]+)}', content, re.DOTALL)

    for match in variable_blocks:
        var_name = match.group(1)
        var_block = match.group(2)

        # Initialize variable with name
        variable = TerraformVariable(name=var_name)

        # Extract type
        type_match = re.search(r'type\s*=\s*(.+?)($|\n)', var_block)
        if type_match:
            variable.type = type_match.group(1).strip()

        # Extract description
        desc_match = re.search(r'description\s*=\s*"([^"]+)"', var_block)
        if desc_match:
            variable.description = desc_match.group(1).strip()

        # Check for default value
        default_match = re.search(r'default\s*=\s*(.+?)($|\n)', var_block)
        if default_match:
            default_value = default_match.group(1).strip()
            variable.default = default_value
            variable.required = False

        variables.append(variable)

    return variables


# Security-related constants and utilities
# These are used to prevent command injection and other security issues


def get_dangerous_patterns() -> List[str]:
    """Get a list of dangerous patterns for command injection detection.

    Returns:
        List of dangerous patterns to check for
    """
    # Dangerous patterns that could indicate command injection attempts
    # Separated by platform for better organization and maintainability
    patterns = [
        '|',
        ';',
        '&',
        '&&',
        '||',  # Command chaining
        '>',
        '>>',
        '<',  # Redirection
        '`',
        '$(',  # Command substitution
        '--',  # Double dash options
        'rm',
        'mv',
        'cp',  # Potentially dangerous commands
        '/bin/',
        '/usr/bin/',  # Path references
        '../',
        './',  # Directory traversal
        # Unix/Linux specific dangerous patterns
        'sudo',  # Privilege escalation
        'chmod',
        'chown',  # File permission changes
        'su',  # Switch user
        'bash',
        'sh',
        'zsh',  # Shell execution
        'curl',
        'wget',  # Network access
        'ssh',
        'scp',  # Remote access
        'eval',  # Command evaluation
        'exec',  # Command execution
        'source',  # Script sourcing
        # Windows specific dangerous patterns
        'cmd',
        'powershell',
        'pwsh',  # Command shells
        'net',  # Network commands
        'reg',  # Registry access
        'runas',  # Privilege escalation
        'del',
        'rmdir',  # File deletion
        'start',  # Process execution
        'taskkill',  # Process termination
        'sc',  # Service control
        'schtasks',  # Scheduled tasks
        'wmic',  # WMI commands
        '%SYSTEMROOT%',
        '%WINDIR%',  # System directories
        '.bat',
        '.cmd',
        '.ps1',  # Script files
    ]
    return patterns
