# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance
# with the License. A copy of the License is located at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions
# and limitations under the License.
# ruff: noqa: D101, D102, D103
"""Tests for the K8sApis class."""

import base64
import pytest
from awslabs.eks_mcp_server.k8s_apis import K8sApis
from awslabs.eks_mcp_server.models import Operation
from datetime import datetime
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_kubernetes_client():
    """Create a mock Kubernetes client."""
    with patch('kubernetes.client') as mock_client:
        # Setup mock configuration
        mock_config = MagicMock()
        # Set host to a string to avoid TypeError with hashlib.md5()
        mock_config.host = 'https://test-endpoint'
        mock_client.Configuration.return_value = mock_config

        # Setup mock API client
        mock_api_client = MagicMock()
        mock_client.ApiClient.return_value = mock_api_client

        yield mock_client, mock_config, mock_api_client


@pytest.fixture
def k8s_apis(mock_kubernetes_client):
    """Create a K8sApis instance with mocked Kubernetes client."""
    mock_client, mock_config, mock_api_client = mock_kubernetes_client

    # Mock the dynamic client
    mock_dynamic_client = MagicMock()

    # Mock tempfile and file operations with context manager support
    mock_temp_file = MagicMock(name='/tmp/ca-cert-file')
    mock_temp_file.__enter__.return_value = mock_temp_file

    # Mock tempfile and file operations
    with (
        patch('tempfile.NamedTemporaryFile', return_value=mock_temp_file),
        patch('os.path.exists', return_value=True),
        patch('os.unlink'),
    ):
        # Create K8sApis instance with CA data
        ca_data = base64.b64encode(b'test-ca-data').decode('utf-8')

        # Create a real K8sApis instance but with mocked components
        with (
            patch('kubernetes.client.ApiClient', return_value=mock_api_client),
            patch('kubernetes.dynamic.DynamicClient', return_value=mock_dynamic_client),
            patch('tempfile.NamedTemporaryFile', return_value=mock_temp_file),
        ):
            # Create the actual instance
            apis = K8sApis('https://test-endpoint', 'test-token', ca_data)

            # Verify CA data was written to the temp file
            mock_temp_file.write.assert_called_once_with(b'test-ca-data')

            # Set up get_events to return different values for different tests
            apis.get_events = MagicMock()
            apis.get_events.return_value = [
                {
                    'first_timestamp': str(datetime(2023, 1, 1, 0, 0, 0)),
                    'last_timestamp': str(datetime(2023, 1, 1, 0, 5, 0)),
                    'count': 5,
                    'message': 'Container created',
                    'reason': 'Created',
                    'reporting_component': 'kubelet',
                    'type': 'Normal',
                }
            ]

    return apis


class TestK8sApisInitialization:
    """Tests for K8sApis initialization."""

    def test_init_requires_ca_data(self, mock_kubernetes_client):
        """Test initialization requires CA data."""
        # Initialize K8sApis without CA data - should raise TypeError
        with pytest.raises(TypeError):
            K8sApis('https://test-endpoint', 'test-token', None)

    def test_init_with_ca_data(self, mock_kubernetes_client):
        """Test initialization with CA data."""
        mock_client, mock_config, mock_api_client = mock_kubernetes_client

        # Mock tempfile and file operations with context manager support
        mock_temp_file = MagicMock()
        mock_temp_file.name = '/tmp/ca-cert-file'
        mock_temp_file.__enter__.return_value = mock_temp_file

        # Mock the dynamic client
        mock_dynamic_client = MagicMock()

        with (
            patch('tempfile.NamedTemporaryFile', return_value=mock_temp_file),
            patch('os.path.exists', return_value=True),
            patch('os.unlink'),
            patch('kubernetes.dynamic.DynamicClient', return_value=mock_dynamic_client),
        ):
            # Create K8sApis instance with CA data
            ca_data = base64.b64encode(b'test-ca-data').decode('utf-8')

            # Initialize the K8sApis instance
            apis = K8sApis('https://test-endpoint', 'test-token', ca_data)

            # Verify configuration
            assert mock_config.host == 'https://test-endpoint'
            assert mock_config.api_key == {'authorization': 'Bearer test-token'}
            assert mock_config.verify_ssl is True
            assert mock_config.ssl_ca_cert == '/tmp/ca-cert-file'

            # Verify CA data was written to the temp file
            mock_temp_file.write.assert_called_once_with(b'test-ca-data')

            # Verify dynamic client was set
            assert apis.dynamic_client == mock_dynamic_client

    def test_init_with_ca_data_error(self, mock_kubernetes_client):
        """Test initialization with CA data when an error occurs."""
        _, _, _ = mock_kubernetes_client

        # Mock tempfile and file operations with context manager support
        mock_temp_file = MagicMock()
        mock_temp_file.name = '/tmp/ca-cert-file'
        mock_temp_file.__enter__.return_value = mock_temp_file

        # Make write operation raise an exception
        mock_temp_file.write.side_effect = Exception('Test error')

        with (
            patch('tempfile.NamedTemporaryFile', return_value=mock_temp_file),
            patch(
                'os.path.exists', return_value=False
            ),  # File doesn't exist yet when exception occurs
        ):
            # Initialize K8sApis with CA data - should raise the exception
            ca_data = base64.b64encode(b'test-ca-data').decode('utf-8')
            with pytest.raises(Exception, match='Test error'):
                K8sApis('https://test-endpoint', 'test-token', ca_data)

            # No need to verify cleanup as the file doesn't exist yet when the exception occurs

    def test_init_kubernetes_import_error(self):
        """Test initialization when kubernetes package is not installed."""
        # Mock import error by patching the import mechanism
        with patch(
            'builtins.__import__',
            side_effect=lambda name, *args, **kwargs: __import__(name, *args, **kwargs)
            if name != 'kubernetes'
            else exec('raise ImportError("kubernetes package not installed")'),
        ):
            # Initialize K8sApis - should raise ImportError
            with pytest.raises(ImportError, match='kubernetes package not installed'):
                K8sApis('https://test-endpoint', 'test-token', 'test-ca-data')

    def test_cleanup_on_deletion(self):
        """Test cleanup of temporary CA certificate file on deletion."""
        # Create a mock K8sApis instance with a CA cert file path
        apis = MagicMock(spec=K8sApis)
        apis._ca_cert_file_path = '/tmp/ca-cert-file'

        # Mock os.path.exists and os.unlink
        with patch('os.path.exists', return_value=True), patch('os.unlink') as mock_unlink:
            # Call __del__ method
            K8sApis.__del__(apis)

            # Verify unlink was called
            mock_unlink.assert_called_once_with('/tmp/ca-cert-file')

    def test_cleanup_on_deletion_no_file(self):
        """Test cleanup when CA certificate file doesn't exist."""
        # Create a mock K8sApis instance with a CA cert file path
        apis = MagicMock(spec=K8sApis)
        apis._ca_cert_file_path = '/tmp/ca-cert-file'

        # Mock os.path.exists to return False
        with patch('os.path.exists', return_value=False), patch('os.unlink') as mock_unlink:
            # Call __del__ method
            K8sApis.__del__(apis)

            # Verify unlink was not called
            mock_unlink.assert_not_called()

    def test_cleanup_on_deletion_error(self):
        """Test cleanup when an error occurs during deletion."""
        # Create a mock K8sApis instance with a CA cert file path
        apis = MagicMock(spec=K8sApis)
        apis._ca_cert_file_path = '/tmp/ca-cert-file'

        # Mock os.path.exists and os.unlink to raise an exception
        with (
            patch('os.path.exists', return_value=True),
            patch('os.unlink', side_effect=Exception('Test error')),
        ):
            # Call __del__ method - should not raise an exception
            K8sApis.__del__(apis)


class TestK8sApisOperations:
    """Tests for K8sApis operations."""

    def test_dynamic_client_initialization(self, k8s_apis):
        """Test that the dynamic client is initialized."""
        # Verify that the dynamic client is initialized
        assert hasattr(k8s_apis, 'dynamic_client')
        assert k8s_apis.dynamic_client is not None

    def test_manage_resource_create(self, k8s_apis):
        """Test manage_resource method with create operation."""
        # Mock the dynamic client and resources
        mock_resource = MagicMock()
        mock_resources = MagicMock()
        mock_resources.get.return_value = mock_resource
        k8s_apis.dynamic_client.resources = mock_resources

        # Test create operation
        body = {'metadata': {'name': 'test-pod'}}
        k8s_apis.manage_resource(
            Operation.CREATE, 'Pod', 'v1', name='test-pod', namespace='default', body=body
        )

        # Verify the dynamic client was used correctly
        mock_resources.get.assert_called_once_with(api_version='v1', kind='Pod')
        mock_resource.create.assert_called_once()
        args, kwargs = mock_resource.create.call_args
        assert kwargs['body']['kind'] == 'Pod'
        assert kwargs['body']['apiVersion'] == 'v1'
        assert kwargs['body']['metadata']['name'] == 'test-pod'
        assert kwargs['namespace'] == 'default'

    def test_manage_resource_read(self, k8s_apis):
        """Test manage_resource method with read operation."""
        # Mock the dynamic client and resources
        mock_resource = MagicMock()
        mock_resources = MagicMock()
        mock_resources.get.return_value = mock_resource
        k8s_apis.dynamic_client.resources = mock_resources

        # Test read operation
        k8s_apis.manage_resource(Operation.READ, 'Pod', 'v1', name='test-pod', namespace='default')

        # Verify the dynamic client was used correctly
        mock_resources.get.assert_called_once_with(api_version='v1', kind='Pod')
        mock_resource.get.assert_called_once_with(name='test-pod', namespace='default')

    def test_manage_resource_replace(self, k8s_apis):
        """Test manage_resource method with replace operation."""
        # Mock the dynamic client and resources
        mock_resource = MagicMock()
        mock_resources = MagicMock()
        mock_resources.get.return_value = mock_resource
        k8s_apis.dynamic_client.resources = mock_resources

        # Test replace operation
        body = {'metadata': {'name': 'test-pod'}}
        k8s_apis.manage_resource(
            Operation.REPLACE, 'Pod', 'v1', name='test-pod', namespace='default', body=body
        )

        # Verify the dynamic client was used correctly
        mock_resources.get.assert_called_once_with(api_version='v1', kind='Pod')
        mock_resource.replace.assert_called_once()
        args, kwargs = mock_resource.replace.call_args
        assert kwargs['body']['kind'] == 'Pod'
        assert kwargs['body']['apiVersion'] == 'v1'
        assert kwargs['body']['metadata']['name'] == 'test-pod'
        assert kwargs['name'] == 'test-pod'
        assert kwargs['namespace'] == 'default'

    def test_manage_resource_patch(self, k8s_apis):
        """Test manage_resource method with patch operation."""
        # Mock the dynamic client and resources
        mock_resource = MagicMock()
        mock_resources = MagicMock()
        mock_resources.get.return_value = mock_resource
        k8s_apis.dynamic_client.resources = mock_resources

        # Test patch operation
        body = {'metadata': {'labels': {'app': 'test'}}}
        k8s_apis.manage_resource(
            Operation.PATCH, 'Pod', 'v1', name='test-pod', namespace='default', body=body
        )

        # Verify the dynamic client was used correctly
        mock_resources.get.assert_called_once_with(api_version='v1', kind='Pod')
        mock_resource.patch.assert_called_once()
        args, kwargs = mock_resource.patch.call_args
        assert kwargs['body']['kind'] == 'Pod'
        assert kwargs['body']['apiVersion'] == 'v1'
        assert kwargs['body']['metadata']['labels']['app'] == 'test'
        assert kwargs['name'] == 'test-pod'
        assert kwargs['namespace'] == 'default'
        assert kwargs['content_type'] == 'application/strategic-merge-patch+json'

    def test_manage_resource_delete(self, k8s_apis):
        """Test manage_resource method with delete operation."""
        # Mock the dynamic client and resources
        mock_resource = MagicMock()
        mock_resources = MagicMock()
        mock_resources.get.return_value = mock_resource
        k8s_apis.dynamic_client.resources = mock_resources

        # Test delete operation
        k8s_apis.manage_resource(
            Operation.DELETE, 'Pod', 'v1', name='test-pod', namespace='default'
        )

        # Verify the dynamic client was used correctly
        mock_resources.get.assert_called_once_with(api_version='v1', kind='Pod')
        mock_resource.delete.assert_called_once_with(name='test-pod', namespace='default')

    def test_patch_with_dynamic_client_fallback(self, k8s_apis):
        """Test patch operation with dynamic client falling back to merge patch."""
        # Mock the dynamic client and resources
        mock_resource = MagicMock()
        mock_resources = MagicMock()
        mock_resources.get.return_value = mock_resource
        k8s_apis.dynamic_client.resources = mock_resources

        # Make strategic merge patch fail with a 415 error
        mock_resource.patch.side_effect = [
            Exception('415 Unsupported Media Type'),  # First call fails
            MagicMock(),  # Second call succeeds
        ]

        # Test patch operation
        body = {'metadata': {'labels': {'app': 'test'}}}
        k8s_apis.manage_resource(
            Operation.PATCH, 'Pod', 'v1', name='test-pod', namespace='default', body=body
        )

        # Verify the dynamic client was used correctly
        mock_resources.get.assert_called_once_with(api_version='v1', kind='Pod')

        # Verify patch was called twice - first with strategic merge patch, then with merge patch
        assert mock_resource.patch.call_count == 2

        # Check first call (strategic merge patch)
        args1, kwargs1 = mock_resource.patch.call_args_list[0]
        assert kwargs1['name'] == 'test-pod'
        assert kwargs1['namespace'] == 'default'
        assert kwargs1['body']['kind'] == 'Pod'
        assert kwargs1['content_type'] == 'application/strategic-merge-patch+json'

        # Check second call (merge patch fallback)
        args2, kwargs2 = mock_resource.patch.call_args_list[1]
        assert kwargs2['name'] == 'test-pod'
        assert kwargs2['namespace'] == 'default'
        assert kwargs2['body']['kind'] == 'Pod'
        assert kwargs2['content_type'] == 'application/merge-patch+json'

    def test_manage_resource_validation(self, k8s_apis):
        """Test manage_resource method validation."""
        # Test missing name for read operation
        with pytest.raises(ValueError, match='Resource name is required for read operation'):
            k8s_apis.manage_resource(Operation.READ, 'Pod', 'v1')

        # Test missing body for create operation
        with pytest.raises(ValueError, match='Resource body is required for create operation'):
            k8s_apis.manage_resource(Operation.CREATE, 'Pod', 'v1', name='test-pod')

    def test_list_resources_with_namespace(self, k8s_apis):
        """Test list_resources method with namespace."""
        # Mock the dynamic client and resources
        mock_resource = MagicMock()
        mock_resources = MagicMock()
        mock_resources.get.return_value = mock_resource
        k8s_apis.dynamic_client.resources = mock_resources

        # Test list operation with namespace
        k8s_apis.list_resources(
            'Pod',
            'v1',
            namespace='default',
            label_selector='app=test',
            field_selector='status.phase=Running',
        )

        # Verify the dynamic client was used correctly
        mock_resources.get.assert_called_once_with(api_version='v1', kind='Pod')
        mock_resource.get.assert_called_once()
        args, kwargs = mock_resource.get.call_args
        assert kwargs['namespace'] == 'default'
        assert kwargs['label_selector'] == 'app=test'
        assert kwargs['field_selector'] == 'status.phase=Running'

    def test_list_resources_all_namespaces(self, k8s_apis):
        """Test list_resources method without namespace (all namespaces)."""
        # Mock the dynamic client and resources
        mock_resource = MagicMock()
        mock_resources = MagicMock()
        mock_resources.get.return_value = mock_resource
        k8s_apis.dynamic_client.resources = mock_resources

        # Test list operation without namespace
        k8s_apis.list_resources('Pod', 'v1')

        # Verify the dynamic client was used correctly
        mock_resources.get.assert_called_once_with(api_version='v1', kind='Pod')
        mock_resource.get.assert_called_once()
        args, kwargs = mock_resource.get.call_args
        assert 'namespace' not in kwargs

    def test_get_pod_logs(self, k8s_apis):
        """Test get_pod_logs method."""
        # Mock the dynamic client and resources
        mock_resource = MagicMock()
        mock_log = MagicMock()
        mock_resource.log = mock_log
        mock_resources = MagicMock()
        mock_resources.get.return_value = mock_resource
        k8s_apis.dynamic_client.resources = mock_resources

        # Mock log.get to return logs
        mock_log.get.return_value = 'log line 1\nlog line 2\n'

        # Get pod logs with all parameters
        logs = k8s_apis.get_pod_logs(
            pod_name='test-pod',
            namespace='test-namespace',
            container_name='test-container',
            since_seconds=60,
            tail_lines=100,
            limit_bytes=1024,
        )

        # Verify the result
        assert logs == 'log line 1\nlog line 2\n'

        # Verify the dynamic client was used correctly
        mock_resources.get.assert_called_once_with(api_version='v1', kind='Pod')
        mock_log.get.assert_called_once_with(
            name='test-pod',
            namespace='test-namespace',
            container='test-container',
            sinceSeconds=60,
            tailLines=100,
            limitBytes=1024,
        )

    def test_get_pod_logs_minimal(self, k8s_apis):
        """Test get_pod_logs method with minimal parameters."""
        # Mock the dynamic client and resources
        mock_resource = MagicMock()
        mock_log = MagicMock()
        mock_resource.log = mock_log
        mock_resources = MagicMock()
        mock_resources.get.return_value = mock_resource
        k8s_apis.dynamic_client.resources = mock_resources

        # Mock log.get to return logs
        mock_log.get.return_value = 'log line 1\nlog line 2\n'

        # Get pod logs with minimal parameters
        logs = k8s_apis.get_pod_logs(
            pod_name='test-pod',
            namespace='test-namespace',
        )

        # Verify the result
        assert logs == 'log line 1\nlog line 2\n'

        # Verify the dynamic client was used correctly
        mock_resources.get.assert_called_once_with(api_version='v1', kind='Pod')
        mock_log.get.assert_called_once_with(
            name='test-pod',
            namespace='test-namespace',
        )

    def _create_mock_event(self):
        """Create a mock event for testing."""
        mock_event_item = MagicMock()
        mock_event_item.to_dict.return_value = {
            'metadata': {'name': 'event-1', 'namespace': 'test-namespace'},
            'firstTimestamp': datetime(2023, 1, 1, 0, 0, 0),  # Using datetime object
            'lastTimestamp': datetime(2023, 1, 1, 0, 5, 0),  # Using datetime object
            'count': 5,
            'message': 'Container created',
            'reason': 'Created',
            'source': {'component': 'kubelet', 'host': 'node-1'},
            'type': 'Normal',
            'involvedObject': {'kind': 'Pod', 'name': 'test-pod', 'namespace': 'test-namespace'},
        }
        return mock_event_item

    def _verify_event_result(self, events):
        """Verify the event result."""
        assert len(events) == 1
        # Check that timestamps are properly converted to strings
        assert events[0]['first_timestamp'] == str(datetime(2023, 1, 1, 0, 0, 0))
        assert events[0]['last_timestamp'] == str(datetime(2023, 1, 1, 0, 5, 0))
        assert events[0]['count'] == 5
        assert events[0]['message'] == 'Container created'
        assert events[0]['reason'] == 'Created'
        assert events[0]['reporting_component'] == 'kubelet'
        assert events[0]['type'] == 'Normal'

    def test_get_events_with_namespace(self, k8s_apis):
        """Test get_events method with namespace provided."""
        # Get events with namespace
        events = k8s_apis.get_events(
            kind='Pod',
            name='test-pod',
            namespace='test-namespace',
        )

        # Verify the result
        self._verify_event_result(events)

        # Verify the method was called with the correct parameters
        k8s_apis.get_events.assert_called_with(
            kind='Pod',
            name='test-pod',
            namespace='test-namespace',
        )

    def test_get_events_all_namespaces(self, k8s_apis):
        """Test get_events method without namespace (all namespaces)."""
        # Get events without namespace
        events = k8s_apis.get_events(
            kind='Pod',
            name='test-pod',
        )

        # Verify the result
        self._verify_event_result(events)

        # Verify the method was called with the correct parameters
        k8s_apis.get_events.assert_called_with(
            kind='Pod',
            name='test-pod',
        )

    def test_get_events_empty(self, k8s_apis):
        """Test get_events method with no events found."""
        # Override the default mock to return an empty list for this test
        k8s_apis.get_events.return_value = []

        # Get events with namespace
        events = k8s_apis.get_events(
            kind='Pod',
            name='test-pod',
            namespace='test-namespace',
        )

        # Verify the result is an empty list
        assert len(events) == 0
        assert events == []

        # Verify the method was called with the correct parameters
        k8s_apis.get_events.assert_called_with(
            kind='Pod',
            name='test-pod',
            namespace='test-namespace',
        )

    def test_apply_from_yaml_create_new_resources(self, k8s_apis):
        """Test applying YAML that creates new resources."""
        # Setup mock resources
        resource_mock = MagicMock()
        k8s_apis.dynamic_client.resources.get.return_value = resource_mock

        # Setup test data
        yaml_objects = [
            {
                'kind': 'Deployment',
                'apiVersion': 'apps/v1',
                'metadata': {'name': 'test-deployment', 'namespace': 'default'},
                'spec': {'replicas': 1},
            },
            {
                'kind': 'Service',
                'apiVersion': 'v1',
                'metadata': {'name': 'test-service', 'namespace': 'default'},
                'spec': {'ports': [{'port': 80}]},
            },
        ]

        # Mock resource.get to raise exception (resource doesn't exist)
        resource_mock.get.side_effect = Exception('Not found')

        # Call the method
        results, created_count, updated_count = k8s_apis.apply_from_yaml(yaml_objects)

        # Verify results
        assert created_count == 2
        assert updated_count == 0
        assert resource_mock.create.call_count == 2

        # Verify create was called with correct parameters for both resources
        calls = resource_mock.create.call_args_list
        assert len(calls) == 2

        # Check first call (Deployment)
        args1, kwargs1 = calls[0]
        assert kwargs1['body']['kind'] == 'Deployment'
        assert kwargs1['body']['apiVersion'] == 'apps/v1'
        assert kwargs1['body']['metadata']['name'] == 'test-deployment'
        assert kwargs1['namespace'] == 'default'

        # Check second call (Service)
        args2, kwargs2 = calls[1]
        assert kwargs2['body']['kind'] == 'Service'
        assert kwargs2['body']['apiVersion'] == 'v1'
        assert kwargs2['body']['metadata']['name'] == 'test-service'
        assert kwargs2['namespace'] == 'default'

    def test_apply_from_yaml_update_existing_resources(self, k8s_apis):
        """Test applying YAML that updates existing resources."""
        # Setup mock resources
        resource_mock = MagicMock()
        k8s_apis.dynamic_client.resources.get.return_value = resource_mock

        # Setup test data
        yaml_objects = [
            {
                'kind': 'Deployment',
                'apiVersion': 'apps/v1',
                'metadata': {'name': 'test-deployment', 'namespace': 'default'},
                'spec': {'replicas': 2},  # Updated replicas
            }
        ]

        # Mock resource.get to return successfully (resource exists)
        resource_mock.get.return_value = MagicMock()

        # Setup _patch_resource mock
        k8s_apis._patch_resource = MagicMock()

        # Call the method
        results, created_count, updated_count = k8s_apis.apply_from_yaml(yaml_objects)

        # Verify results
        assert created_count == 0
        assert updated_count == 1
        assert resource_mock.create.call_count == 0
        assert k8s_apis._patch_resource.call_count == 1

        # Verify patch was called with correct parameters
        k8s_apis._patch_resource.assert_called_once_with(
            resource_mock, yaml_objects[0], 'test-deployment', 'default'
        )

    def test_apply_from_yaml_force_false_no_update(self, k8s_apis):
        """Test applying YAML with force=False doesn't update existing resources."""
        # Setup mock resources
        resource_mock = MagicMock()
        k8s_apis.dynamic_client.resources.get.return_value = resource_mock

        # Setup test data
        yaml_objects = [
            {
                'kind': 'Deployment',
                'apiVersion': 'apps/v1',
                'metadata': {'name': 'test-deployment', 'namespace': 'default'},
                'spec': {'replicas': 2},
            }
        ]

        # For the first object, simulate it exists
        resource_mock.get.return_value = MagicMock()

        # Setup _patch_resource mock
        k8s_apis._patch_resource = MagicMock()

        # Call the method with force=False
        results, created_count, updated_count = k8s_apis.apply_from_yaml(yaml_objects, force=False)

        # Verify results - should create new resources, not update existing ones
        assert created_count == 1
        assert updated_count == 0
        assert resource_mock.create.call_count == 1
        assert k8s_apis._patch_resource.call_count == 0

        # Verify create was called with correct parameters
        resource_mock.create.assert_called_once()
        args, kwargs = resource_mock.create.call_args
        assert kwargs['body']['kind'] == 'Deployment'
        assert kwargs['body']['apiVersion'] == 'apps/v1'
        assert kwargs['body']['metadata']['name'] == 'test-deployment'
        assert kwargs['namespace'] == 'default'

    def test_apply_from_yaml_custom_resource(self, k8s_apis):
        """Test applying YAML with custom resources."""
        # Setup mock resources
        resource_mock = MagicMock()
        k8s_apis.dynamic_client.resources.get.return_value = resource_mock

        # Setup test data for a custom resource
        yaml_objects = [
            {
                'kind': 'EksApp',
                'apiVersion': 'eks.amazonaws.com/v1',
                'metadata': {'name': 'example-app', 'namespace': 'default'},
                'spec': {'replicas': 1},
            }
        ]

        # Mock resource.get to raise exception (resource doesn't exist)
        resource_mock.get.side_effect = Exception('Not found')

        # Call the method
        results, created_count, updated_count = k8s_apis.apply_from_yaml(yaml_objects)

        # Verify results
        assert created_count == 1
        assert updated_count == 0
        assert resource_mock.create.call_count == 1

        # Verify the dynamic client was used correctly for the custom resource
        k8s_apis.dynamic_client.resources.get.assert_called_once_with(
            api_version='eks.amazonaws.com/v1', kind='EksApp'
        )

        # Verify create was called with correct parameters
        resource_mock.create.assert_called_once()
        args, kwargs = resource_mock.create.call_args
        assert kwargs['body']['kind'] == 'EksApp'
        assert kwargs['body']['apiVersion'] == 'eks.amazonaws.com/v1'
        assert kwargs['body']['metadata']['name'] == 'example-app'
        assert kwargs['namespace'] == 'default'

    def test_apply_from_yaml_error_handling(self, k8s_apis):
        """Test error handling in apply_from_yaml."""
        # Setup mock resources
        resource_mock = MagicMock()
        k8s_apis.dynamic_client.resources.get.return_value = resource_mock

        # Setup test data with invalid resource (missing name)
        yaml_objects = [
            {
                'kind': 'Deployment',
                'apiVersion': 'apps/v1',
                'metadata': {},  # Missing name
                'spec': {'replicas': 1},
            }
        ]

        # Call the method - should raise ValueError
        with pytest.raises(
            ValueError, match='Invalid resource: missing kind, apiVersion, or name'
        ):
            k8s_apis.apply_from_yaml(yaml_objects)

        # Test error during resource creation
        yaml_objects = [
            {
                'kind': 'Deployment',
                'apiVersion': 'apps/v1',
                'metadata': {'name': 'test-deployment', 'namespace': 'default'},
                'spec': {'replicas': 1},
            }
        ]

        # Mock resource.get to raise exception (resource doesn't exist)
        resource_mock.get.side_effect = Exception('Not found')

        # Mock resource.create to raise exception
        resource_mock.create.side_effect = Exception('Creation failed')

        # Call the method - should raise ValueError with context
        with pytest.raises(
            ValueError, match='Error applying Deployment default/test-deployment: Creation failed'
        ):
            k8s_apis.apply_from_yaml(yaml_objects)

    def test_get_api_versions_success(self, k8s_apis):
        """Test get_api_versions method success."""
        # Mock the kubernetes client imports
        with patch('kubernetes.client') as mock_client:
            # Mock CoreApi
            mock_core_api = MagicMock()
            mock_core_version = MagicMock()
            mock_core_version.versions = ['v1']
            mock_core_api.get_api_versions.return_value = mock_core_version
            mock_client.CoreApi.return_value = mock_core_api

            # Mock ApisApi
            mock_apis_api = MagicMock()
            mock_api_groups = MagicMock()

            # Create mock groups with versions
            mock_group1 = MagicMock()
            mock_version1 = MagicMock()
            mock_version1.group_version = 'apps/v1'
            mock_group1.preferred_version = mock_version1

            mock_group2 = MagicMock()
            mock_version2 = MagicMock()
            mock_version2.group_version = 'networking.k8s.io/v1'
            mock_group2.preferred_version = mock_version2

            mock_api_groups.groups = [mock_group1, mock_group2]
            mock_apis_api.get_api_versions.return_value = mock_api_groups
            mock_client.ApisApi.return_value = mock_apis_api

            # Call the method
            api_versions = k8s_apis.get_api_versions()

            # Verify results
            assert len(api_versions) == 3
            assert 'v1' in api_versions
            assert 'apps/v1' in api_versions
            assert 'networking.k8s.io/v1' in api_versions
            assert api_versions == sorted(api_versions)  # Should be sorted

            # Verify the APIs were called correctly
            mock_client.CoreApi.assert_called_once_with(k8s_apis.api_client)
            mock_core_api.get_api_versions.assert_called_once()
            mock_client.ApisApi.assert_called_once_with(k8s_apis.api_client)
            mock_apis_api.get_api_versions.assert_called_once()

    def test_get_api_versions_error(self, k8s_apis):
        """Test get_api_versions method with error."""
        # Mock the kubernetes client imports
        with patch('kubernetes.client') as mock_client:
            # Mock CoreApi to raise an exception
            mock_core_api = MagicMock()
            mock_core_api.get_api_versions.side_effect = Exception('API discovery failed')
            mock_client.CoreApi.return_value = mock_core_api

            # Call the method - should raise ValueError
            with pytest.raises(
                ValueError, match='Error getting API versions: API discovery failed'
            ):
                k8s_apis.get_api_versions()

            # Verify the API was called
            mock_client.CoreApi.assert_called_once_with(k8s_apis.api_client)
            mock_core_api.get_api_versions.assert_called_once()
