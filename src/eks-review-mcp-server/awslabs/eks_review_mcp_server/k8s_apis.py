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

"""Kubernetes API client for the EKS Review MCP Server."""

import base64
import os
import tempfile
from awslabs.eks_review_mcp_server import __version__
from loguru import logger
from typing import Any, Dict, List, Optional


class K8sApis:
    """Class for managing Kubernetes API client.

    This class provides a simplified interface for interacting with the Kubernetes API
    using the official Kubernetes Python client.
    """

    def __init__(self, endpoint, token, ca_data):
        """Initialize Kubernetes API client.

        Args:
            endpoint: Kubernetes API endpoint
            token: Authentication token
            ca_data: CA certificate data (base64 encoded) - required for SSL verification
        """
        try:
            from kubernetes import client, dynamic

            configuration = client.Configuration()
            configuration.host = endpoint
            configuration.api_key = {'authorization': f'Bearer {token}'}

            # Store the CA cert file path for cleanup
            self._ca_cert_file_path = None

            # Always enable SSL verification with CA data
            configuration.verify_ssl = True

            # Create a temporary file for the CA certificate using a context manager
            try:
                with tempfile.NamedTemporaryFile(delete=False) as ca_cert_file:
                    ca_cert_data = base64.b64decode(ca_data)
                    ca_cert_file.write(ca_cert_data)
                    # File is automatically closed when exiting the with block

                    # Store the path for cleanup and set the SSL CA cert
                    self._ca_cert_file_path = ca_cert_file.name
                    # Set the SSL CA cert to the temporary file path
                    # Use setattr to avoid potential attribute access issues
                    setattr(configuration, 'ssl_ca_cert', ca_cert_file.name)
            except Exception as e:
                # If we have a path and the file exists, clean it up
                if (
                    hasattr(self, '_ca_cert_file_path')
                    and self._ca_cert_file_path
                    and os.path.exists(self._ca_cert_file_path)
                ):
                    os.unlink(self._ca_cert_file_path)
                raise e

            # Configure HTTP proxy settings if environment variables are present
            self._configure_proxy_settings(configuration)

            # Create base API client
            self.api_client = client.ApiClient(configuration)

            # Set user-agent directly on the ApiClient
            self.api_client.user_agent = f'awslabs/mcp/eks-review-mcp-server/{__version__}'

            # Create dynamic client
            self.dynamic_client = dynamic.DynamicClient(self.api_client)

        except ImportError:
            logger.error('kubernetes package not installed')
            raise

    def _configure_proxy_settings(self, config):
        """Configure proxy settings for Kubernetes client from environment variables."""
        # Get proxy URL (HTTPS proxy takes precedence over HTTP proxy)
        proxy_url = (
            os.environ.get('HTTPS_PROXY')
            or os.environ.get('https_proxy')
            or os.environ.get('HTTP_PROXY')
            or os.environ.get('http_proxy')
        )

        if not proxy_url:
            return

        logger.debug(f'Configuring proxy: {proxy_url}')
        config.proxy = proxy_url

    def list_resources(
        self,
        kind: str,
        api_version: str,
        namespace: Optional[str] = None,
        label_selector: Optional[str] = None,
        field_selector: Optional[str] = None,
        **kwargs,
    ) -> Any:
        """List Kubernetes resources of a specific kind using dynamic client.

        Args:
            kind: Resource kind (e.g., 'Pod', 'Service')
            api_version: API version (e.g., 'v1', 'apps/v1')
            namespace: Namespace to list resources from (optional)
            label_selector: Label selector to filter resources (optional)
            field_selector: Field selector to filter resources (optional)
            **kwargs: Additional arguments for the API call

        Returns:
            The API response containing the list of resources
        """
        try:
            # Get the API resource
            resource = self.dynamic_client.resources.get(api_version=api_version, kind=kind)

            # Prepare kwargs for the list operation
            list_kwargs = {}
            if label_selector:
                list_kwargs['label_selector'] = label_selector
            if field_selector:
                list_kwargs['field_selector'] = field_selector

            # Add any additional kwargs
            list_kwargs.update(kwargs)

            # List resources
            if namespace:
                return resource.get(namespace=namespace, **list_kwargs)
            else:
                return resource.get(**list_kwargs)

        except Exception as e:
            # Re-raise with more context
            raise ValueError(f'Error listing {kind} resources: {str(e)}')

    def __del__(self):
        """Clean up temporary files when the object is garbage collected."""
        if (
            hasattr(self, '_ca_cert_file_path')
            and self._ca_cert_file_path
            and os.path.exists(self._ca_cert_file_path)
        ):
            try:
                os.unlink(self._ca_cert_file_path)
            except Exception:
                # Ignore errors during cleanup
                pass