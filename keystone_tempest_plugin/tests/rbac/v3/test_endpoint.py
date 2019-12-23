# Copyright 2020 SUSE LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import abc

from tempest.api.identity import base
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from keystone_tempest_plugin.tests.rbac.v3 import base as rbac_base


class IdentityV3RbacEndpointTests(rbac_base.IdentityV3RbacBaseTests,
                                  metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacEndpointTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.endpoints_v3_client
        admin_client = cls.os_system_admin
        cls.services_client = admin_client.identity_services_v3_client
        cls.admin_endpoints_client = admin_client.endpoints_v3_client

    @classmethod
    def setUpClass(cls):
        super(IdentityV3RbacEndpointTests, cls).setUpClass()
        cls.service_id = cls.services_client.create_service(
            type=data_utils.rand_name(),
            name=data_utils.rand_name())['service']['id']
        cls.addClassResourceCleanup(
            cls.services_client.delete_service,
            cls.service_id)

    def endpoint(self):
        return {
            'interface': 'public',
            'service_id': self.service_id,
            'url': 'http://localhost/service'
        }

    @abc.abstractmethod
    def test_identity_create_endpoint(self):
        """Test identity:create_endpoint policy.

        This test must check:
          * whether the persona can create an endpoint
        """
        pass

    @abc.abstractmethod
    def test_identity_get_endpoint(self):
        """Test identity:get_endpoint policy.

        This test must check:
          * whether the persona can get an endpoint
          * whether the persona can get an endpoint that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_endpoints(self):
        """Test identity:list_endpoints policy.

        This test must check:
          * whether the persona can list all endpoints
        """
        pass

    @abc.abstractmethod
    def test_identity_update_endpoint(self):
        """Test identity:update_endpoint policy.

        This test must check:
          * whether the persona can update an endpoint
          * whether the persona can update an endpoint that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_endpoint(self):
        """Test identity:delete_endpoint policy.

        This test must check
          * whether the persona can delete an endpoint
          * whether the persona can delete an endpoint that does not exist
        """
        pass


class SystemAdminTests(IdentityV3RbacEndpointTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_endpoint(self):
        endpoint_id = self.do_request(
            'create_endpoint', expected_status=201,
            **self.endpoint())['endpoint']['id']
        self.addCleanup(
            self.admin_endpoints_client.delete_endpoint,
            endpoint_id=endpoint_id)

    def test_identity_get_endpoint(self):
        endpoint_id = self.admin_endpoints_client.create_endpoint(
            **self.endpoint())['endpoint']['id']
        self.addCleanup(
            self.admin_endpoints_client.delete_endpoint,
            endpoint_id=endpoint_id)
        self.do_request('show_endpoint', endpoint_id=endpoint_id)
        # user gets a 404 for nonexistent endpoint
        self.do_request('show_endpoint', expected_status=exceptions.NotFound,
                        endpoint_id=data_utils.rand_uuid_hex())

    def test_identity_list_endpoints(self):
        endpoint_id = self.admin_endpoints_client.create_endpoint(
            **self.endpoint())['endpoint']['id']
        self.addCleanup(
            self.admin_endpoints_client.delete_endpoint,
            endpoint_id=endpoint_id)
        resp = self.do_request('list_endpoints')
        self.assertIn(endpoint_id, [e['id'] for e in resp['endpoints']])

    def test_identity_update_endpoint(self):
        endpoint_id = self.admin_endpoints_client.create_endpoint(
            **self.endpoint())['endpoint']['id']
        self.addCleanup(
            self.admin_endpoints_client.delete_endpoint,
            endpoint_id=endpoint_id)
        self.do_request('update_endpoint',
                        endpoint_id=endpoint_id,
                        interface='internal')
        # user gets a 404 for nonexistent endpoint
        self.do_request('update_endpoint', expected_status=exceptions.NotFound,
                        endpoint_id=data_utils.rand_uuid_hex(),
                        interface='internal')

    def test_identity_delete_endpoint(self):
        endpoint_id = self.admin_endpoints_client.create_endpoint(
            **self.endpoint())['endpoint']['id']
        self.do_request('delete_endpoint', expected_status=204,
                        endpoint_id=endpoint_id)
        # user gets a 404 for nonexistent endpoint
        self.do_request('delete_endpoint', expected_status=exceptions.NotFound,
                        endpoint_id=data_utils.rand_uuid_hex())


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_endpoint(self):
        self.do_request(
            'create_endpoint', expected_status=exceptions.Forbidden,
            **self.endpoint())

    def test_identity_update_endpoint(self):
        endpoint_id = self.admin_endpoints_client.create_endpoint(
            **self.endpoint())['endpoint']['id']
        self.addCleanup(
            self.admin_endpoints_client.delete_endpoint,
            endpoint_id=endpoint_id)
        self.do_request('update_endpoint',
                        expected_status=exceptions.Forbidden,
                        endpoint_id=endpoint_id,
                        interface='internal')
        # user gets a 404 for nonexistent endpoint
        self.do_request('update_endpoint', expected_status=exceptions.NotFound,
                        endpoint_id=data_utils.rand_uuid_hex(),
                        interface='internal')

    def test_identity_delete_endpoint(self):
        endpoint_id = self.admin_endpoints_client.create_endpoint(
            **self.endpoint())['endpoint']['id']
        self.do_request('delete_endpoint',
                        expected_status=exceptions.Forbidden,
                        endpoint_id=endpoint_id)
        # user gets a 404 for nonexistent endpoint
        self.do_request('delete_endpoint', expected_status=exceptions.NotFound,
                        endpoint_id=data_utils.rand_uuid_hex())


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_endpoint(self):
        endpoint_id = self.admin_endpoints_client.create_endpoint(
            **self.endpoint())['endpoint']['id']
        self.addCleanup(
            self.admin_endpoints_client.delete_endpoint,
            endpoint_id=endpoint_id)
        self.do_request('show_endpoint', expected_status=exceptions.Forbidden,
                        endpoint_id=endpoint_id)
        # user gets a 404 for nonexistent endpoint
        self.do_request('show_endpoint', expected_status=exceptions.NotFound,
                        endpoint_id=data_utils.rand_uuid_hex())

    def test_identity_list_endpoints(self):
        endpoint_id = self.admin_endpoints_client.create_endpoint(
            **self.endpoint())['endpoint']['id']
        self.addCleanup(
            self.admin_endpoints_client.delete_endpoint,
            endpoint_id=endpoint_id)
        self.do_request('list_endpoints', expected_status=exceptions.Forbidden)


class DomainMemberTests(DomainAdminTests, base.BaseIdentityTest):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainMemberTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(DomainReaderTests, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
