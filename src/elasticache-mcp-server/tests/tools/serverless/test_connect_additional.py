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

"""Additional tests for serverless cache connection tools to improve coverage."""

import pytest
from awslabs.elasticache_mcp_server.context import Context
from awslabs.elasticache_mcp_server.tools.serverless.connect import (
    _configure_security_groups,
    connect_jump_host_serverless,
    create_jump_host_serverless,
    get_ssh_tunnel_command_serverless,
)
from unittest.mock import MagicMock, patch


@pytest.mark.asyncio
async def test_configure_security_groups_no_security_groups():
    """Test when no security groups are found."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock ElastiCache responses with missing security group IDs
    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': [],  # Empty security groups
                'SubnetIds': ['subnet-1234'],
                'Engine': 'redis',
            }
        ]
    }

    # Mock subnet response for VPC ID retrieval
    mock_ec2.describe_subnets.return_value = {'Subnets': [{'VpcId': 'vpc-1234'}]}

    # Verify exception is raised
    with pytest.raises(ValueError) as excinfo:
        await _configure_security_groups(
            'cache-1',
            'i-123',
            ec2_client=mock_ec2,
            elasticache_client=mock_elasticache,
        )
    assert 'No security groups found for serverless cache' in str(excinfo.value)


@pytest.mark.asyncio
async def test_configure_security_groups_instance_not_found():
    """Test when EC2 instance is not found."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock ElastiCache responses
    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': ['sg-cache'],
                'SubnetIds': ['subnet-1234'],
                'Engine': 'redis',
            }
        ]
    }

    # Mock subnet response for VPC ID retrieval
    mock_ec2.describe_subnets.return_value = {'Subnets': [{'VpcId': 'vpc-1234'}]}

    # Instance not found
    mock_ec2.describe_instances.return_value = {'Reservations': []}

    # Verify exception is raised
    with pytest.raises(ValueError) as excinfo:
        await _configure_security_groups(
            'cache-1',
            'i-123',
            ec2_client=mock_ec2,
            elasticache_client=mock_elasticache,
        )
    assert 'EC2 instance i-123 not found' in str(excinfo.value)


@pytest.mark.asyncio
async def test_configure_security_groups_no_instance_security_groups():
    """Test when no security groups are found for the EC2 instance."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock ElastiCache responses
    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': ['sg-cache'],
                'SubnetIds': ['subnet-1234'],
                'Engine': 'redis',
            }
        ]
    }

    # Mock subnet response for VPC ID retrieval
    mock_ec2.describe_subnets.return_value = {'Subnets': [{'VpcId': 'vpc-1234'}]}

    # Instance with no security groups
    mock_ec2.describe_instances.return_value = {
        'Reservations': [
            {
                'Instances': [
                    {
                        'VpcId': 'vpc-1234',
                        'SecurityGroups': [],  # Empty security groups
                    }
                ]
            }
        ]
    }

    # Verify exception is raised
    with pytest.raises(ValueError) as excinfo:
        await _configure_security_groups(
            'cache-1',
            'i-123',
            ec2_client=mock_ec2,
            elasticache_client=mock_elasticache,
        )
    assert 'No security groups found for EC2 instance' in str(excinfo.value)


@pytest.mark.asyncio
async def test_connect_jump_host_serverless_error():
    """Test error handling in connect_jump_host_serverless."""
    # Mock an error in _configure_security_groups
    with patch(
        'awslabs.elasticache_mcp_server.tools.serverless.connect._configure_security_groups',
        side_effect=ValueError('Test error'),
    ):
        result = await connect_jump_host_serverless('cache-1', 'i-123')
        assert 'error' in result
        assert 'Test error' in result['error']


@pytest.mark.asyncio
async def test_get_ssh_tunnel_command_serverless_instance_not_found():
    """Test get_ssh_tunnel_command_serverless when instance is not found."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Instance not found
    mock_ec2.describe_instances.return_value = {'Reservations': []}

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await get_ssh_tunnel_command_serverless('cache-1', 'i-123')
        assert 'error' in result
        assert 'EC2 instance i-123 not found' in result['error']


@pytest.mark.asyncio
async def test_get_ssh_tunnel_command_serverless_no_key_pair():
    """Test get_ssh_tunnel_command_serverless when instance has no key pair."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Instance with no key pair
    mock_ec2.describe_instances.return_value = {
        'Reservations': [
            {
                'Instances': [
                    {
                        # No KeyName
                    }
                ]
            }
        ]
    }

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await get_ssh_tunnel_command_serverless('cache-1', 'i-123')
        assert 'error' in result
        assert 'No key pair associated with EC2 instance' in result['error']


@pytest.mark.asyncio
async def test_get_ssh_tunnel_command_serverless_no_public_dns():
    """Test get_ssh_tunnel_command_serverless when instance has no public DNS."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Instance with no public DNS
    mock_ec2.describe_instances.return_value = {
        'Reservations': [
            {
                'Instances': [
                    {
                        'KeyName': 'test-key',
                        # No PublicDnsName
                    }
                ]
            }
        ]
    }

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await get_ssh_tunnel_command_serverless('cache-1', 'i-123')
        assert 'error' in result
        assert 'No public DNS name found for EC2 instance' in result['error']


@pytest.mark.asyncio
async def test_get_ssh_tunnel_command_serverless_windows_instance():
    """Test get_ssh_tunnel_command_serverless with Windows instance."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Windows instance
    mock_ec2.describe_instances.return_value = {
        'Reservations': [
            {
                'Instances': [
                    {
                        'KeyName': 'test-key',
                        'PublicDnsName': 'ec2-1-2-3-4.compute-1.amazonaws.com',
                        'Platform': 'windows',
                    }
                ]
            }
        ]
    }

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await get_ssh_tunnel_command_serverless('cache-1', 'i-123')
        assert 'error' in result
        assert 'Windows instances are not supported for SSH tunneling' in result['error']


@pytest.mark.asyncio
async def test_create_jump_host_serverless_vpc_mismatch():
    """Test create_jump_host_serverless with VPC mismatch."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock responses
    mock_ec2.describe_key_pairs.return_value = {'KeyPairs': [{'KeyName': 'test-key'}]}

    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': ['sg-cache'],
                'SubnetIds': ['subnet-123'],
                'Engine': 'redis',
            }
        ]
    }

    # Use side_effect to return different values for each call
    mock_ec2.describe_subnets.side_effect = [
        {'Subnets': [{'VpcId': 'vpc-123'}]},  # First call for cache VPC ID
        {'Subnets': [{'VpcId': 'vpc-456'}]},  # Second call for subnet VPC ID
    ]

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await create_jump_host_serverless('cache-1', 'subnet-123', 'sg-123', 'test-key')
        assert 'error' in result
        assert (
            'Subnet VPC (vpc-456) does not match serverless cache VPC (vpc-123)' in result['error']
        )


@pytest.mark.asyncio
async def test_create_jump_host_serverless_main_route_table():
    """Test create_jump_host_serverless with main route table."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock responses
    mock_ec2.describe_key_pairs.return_value = {'KeyPairs': [{'KeyName': 'test-key'}]}

    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': ['sg-cache'],
                'SubnetIds': ['subnet-123'],
                'Engine': 'redis',
            }
        ]
    }

    mock_ec2.describe_subnets.return_value = {'Subnets': [{'VpcId': 'vpc-123'}]}

    # No explicit route table association, but main route table has no IGW
    mock_ec2.describe_route_tables.side_effect = [
        {'RouteTables': []},  # First call for subnet-specific route table
        {'RouteTables': [{'Routes': []}]},  # Second call for main route table with no IGW
    ]

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await create_jump_host_serverless('cache-1', 'subnet-123', 'sg-123', 'test-key')

        # Should fail because subnet is not public
        assert 'error' in result
        assert (
            'Subnet subnet-123 is not public (no route to internet gateway found)'
            in result['error']
        )


@pytest.mark.asyncio
async def test_configure_security_groups_no_subnet_ids():
    """Test when no subnet IDs are found."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock ElastiCache responses with missing subnet IDs
    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': ['sg-cache'],
                'SubnetIds': [],  # Empty subnet IDs
                'Engine': 'redis',
            }
        ]
    }

    # Verify exception is raised
    with pytest.raises(ValueError) as excinfo:
        await _configure_security_groups(
            'cache-1',
            'i-123',
            ec2_client=mock_ec2,
            elasticache_client=mock_elasticache,
        )
    assert 'No subnet IDs found for serverless cache' in str(excinfo.value)


@pytest.mark.asyncio
async def test_create_jump_host_serverless_readonly_mode():
    """Test create_jump_host_serverless in readonly mode."""
    # Properly patch the class method and check for error dictionary
    with patch.object(Context, 'readonly_mode', return_value=True):
        result = await create_jump_host_serverless('cache-1', 'subnet-123', 'sg-123', 'test-key')
        assert 'error' in result
        assert 'You have configured this tool in readonly mode' in result['error']


@pytest.mark.asyncio
async def test_connect_jump_host_serverless_readonly_mode():
    """Test connect_jump_host_serverless in readonly mode."""
    # Properly patch the class method and check for error dictionary
    with patch.object(Context, 'readonly_mode', return_value=True):
        result = await connect_jump_host_serverless('cache-1', 'i-123')
        assert 'error' in result
        assert 'You have configured this tool in readonly mode' in result['error']


@pytest.mark.asyncio
async def test_create_jump_host_serverless_invalid_key_pair():
    """Test create_jump_host_serverless with invalid key pair."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock responses for invalid key pair
    mock_ec2.describe_key_pairs.side_effect = Exception('Key pair not found')

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await create_jump_host_serverless(
            'cache-1', 'subnet-123', 'sg-123', 'invalid-key'
        )
        assert 'error' in result
        assert 'Key pair not found' in result['error']


@pytest.mark.asyncio
async def test_create_jump_host_serverless_client_error():
    """Test create_jump_host_serverless with ClientError."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock responses
    mock_ec2.describe_key_pairs.return_value = {'KeyPairs': [{'KeyName': 'test-key'}]}

    # Mock ClientError for describe_subnets
    from botocore.exceptions import ClientError

    error_response = {'Error': {'Code': 'InvalidSubnetID.NotFound', 'Message': 'Subnet not found'}}
    mock_ec2.describe_subnets.side_effect = ClientError(error_response, 'DescribeSubnets')

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await create_jump_host_serverless('cache-1', 'subnet-123', 'sg-123', 'test-key')
        assert 'error' in result
        assert 'InvalidSubnetID.NotFound' in result['error']


@pytest.mark.asyncio
async def test_create_jump_host_serverless_missing_key_name():
    """Test create_jump_host_serverless with missing key name."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await create_jump_host_serverless('cache-1', 'subnet-123', 'sg-123', '')
        assert 'error' in result
        assert 'key_name is required' in result['error']


@pytest.mark.asyncio
async def test_create_jump_host_serverless_existing_ssh_rule():
    """Test create_jump_host_serverless with existing SSH rule."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock responses
    mock_ec2.describe_key_pairs.return_value = {'KeyPairs': [{'KeyName': 'test-key'}]}

    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': ['sg-cache'],
                'SubnetIds': ['subnet-123'],
                'Engine': 'redis',
            }
        ]
    }

    mock_ec2.describe_subnets.return_value = {'Subnets': [{'VpcId': 'vpc-123'}]}
    mock_ec2.describe_route_tables.return_value = {
        'RouteTables': [{'Routes': [{'GatewayId': 'igw-123'}]}]
    }
    mock_ec2.describe_images.return_value = {
        'Images': [{'ImageId': 'ami-123', 'CreationDate': '2023-01-01'}]
    }

    # Security group with existing SSH rule
    mock_ec2.describe_security_groups.return_value = {
        'SecurityGroups': [
            {
                'IpPermissions': [
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 22,
                        'ToPort': 22,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0'}],
                    }
                ]
            }
        ]
    }

    mock_ec2.run_instances.return_value = {'Instances': [{'InstanceId': 'i-new1234'}]}
    mock_ec2.describe_instances.return_value = {
        'Reservations': [{'Instances': [{'PublicIpAddress': '1.2.3.4'}]}]
    }

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
        patch(
            'awslabs.elasticache_mcp_server.tools.serverless.connect._configure_security_groups',
            return_value=(True, 'vpc-123', 6379),
        ),
    ):
        result = await create_jump_host_serverless('cache-1', 'subnet-123', 'sg-123', 'test-key')

        # Should succeed and not try to add SSH rule
        assert 'InstanceId' in result
        assert result['InstanceId'] == 'i-new1234'
        mock_ec2.authorize_security_group_ingress.assert_not_called()


@pytest.mark.asyncio
async def test_create_jump_host_serverless_no_security_groups():
    """Test create_jump_host_serverless when serverless cache has no security groups."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock responses
    mock_ec2.describe_key_pairs.return_value = {'KeyPairs': [{'KeyName': 'test-key'}]}

    # Serverless cache with no security groups
    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': [],  # Empty security groups
                'SubnetIds': ['subnet-123'],
                'Engine': 'redis',
            }
        ]
    }

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await create_jump_host_serverless('cache-1', 'subnet-123', 'sg-123', 'test-key')

        # Should fail with appropriate error message
        assert 'error' in result
        assert 'No security groups found for serverless cache cache-1' in result['error']


@pytest.mark.asyncio
async def test_create_jump_host_serverless_no_subnet_ids():
    """Test create_jump_host_serverless when serverless cache has no subnet IDs."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Mock responses
    mock_ec2.describe_key_pairs.return_value = {'KeyPairs': [{'KeyName': 'test-key'}]}

    # Serverless cache with no subnet IDs
    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': ['sg-cache'],
                'SubnetIds': [],  # Empty subnet IDs
                'Engine': 'redis',
            }
        ]
    }

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
    ):
        result = await create_jump_host_serverless('cache-1', 'subnet-123', 'sg-123', 'test-key')

        # Should fail with appropriate error message
        assert 'error' in result
        assert 'No subnet IDs found for serverless cache cache-1' in result['error']


@pytest.mark.asyncio
async def test_connect_jump_host_serverless_no_security_groups():
    """Test connect_jump_host_serverless when serverless cache has no security groups."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Serverless cache with no security groups
    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': [],  # Empty security groups
                'SubnetIds': ['subnet-123'],
                'Engine': 'redis',
            }
        ]
    }

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
        patch(
            'awslabs.elasticache_mcp_server.tools.serverless.connect._configure_security_groups',
            side_effect=ValueError('No security groups found for serverless cache cache-1'),
        ),
    ):
        result = await connect_jump_host_serverless('cache-1', 'i-123')

        # Should fail with appropriate error message
        assert 'error' in result
        assert 'No security groups found for serverless cache cache-1' in result['error']


@pytest.mark.asyncio
async def test_connect_jump_host_serverless_no_subnet_ids():
    """Test connect_jump_host_serverless when serverless cache has no subnet IDs."""
    mock_ec2 = MagicMock()
    mock_elasticache = MagicMock()

    # Serverless cache with no subnet IDs
    mock_elasticache.describe_serverless_caches.return_value = {
        'ServerlessCaches': [
            {
                'SecurityGroupIds': ['sg-cache'],
                'SubnetIds': [],  # Empty subnet IDs
                'Engine': 'redis',
            }
        ]
    }

    with (
        patch(
            'awslabs.elasticache_mcp_server.common.connection.EC2ConnectionManager.get_connection',
            return_value=mock_ec2,
        ),
        patch(
            'awslabs.elasticache_mcp_server.common.connection.ElastiCacheConnectionManager.get_connection',
            return_value=mock_elasticache,
        ),
        patch(
            'awslabs.elasticache_mcp_server.tools.serverless.connect._configure_security_groups',
            side_effect=ValueError('No subnet IDs found for serverless cache cache-1'),
        ),
    ):
        result = await connect_jump_host_serverless('cache-1', 'i-123')

        # Should fail with appropriate error message
        assert 'error' in result
        assert 'No subnet IDs found for serverless cache cache-1' in result['error']
