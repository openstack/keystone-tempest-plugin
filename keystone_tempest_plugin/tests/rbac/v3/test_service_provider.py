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

from keystone_tempest_plugin import clients
from keystone_tempest_plugin.tests.rbac.v3 import base as rbac_base


class IdentityV3RbacServiceProviderTests(rbac_base.IdentityV3RbacBaseTests,
                                         metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacServiceProviderTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        persona_mgr = clients.Manager(cls.persona.credentials)
        cls.client = persona_mgr.service_providers_client
        admin_client = cls.os_system_admin
        admin_mgr = clients.Manager(admin_client.credentials)
        cls.admin_sp_client = admin_mgr.service_providers_client

    @abc.abstractmethod
    def test_identity_create_service_provider(self):
        """Test identity:create_service_provider policy.

        This test must check:
          * whether the persona can create a service provider
        """
        pass

    @abc.abstractmethod
    def test_identity_get_service_provider(self):
        """Test identity:get_service_provider policy.

        This test must check:
          * whether the persona can get a service provider
          * whether the persona can get a service provider that does not
            exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_service_providers(self):
        """Test identity:list_service_providers policy.

        This test must check:
          * whether the persona can list all identity providers
        """
        pass

    @abc.abstractmethod
    def test_identity_update_service_provider(self):
        """Test identity:update_service_provider policy.

        This test must check:
          * whether the persona can update a service provider
          * whether the persona can update a service provider that does not
            exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_service_provider(self):
        """Test identity:delete_service_provider policy.

        This test must check
          * whether the persona can delete a service provider
          * whether the persona can delete a service provider that does not
            exist
        """
        pass


class SystemAdminTests(IdentityV3RbacServiceProviderTests,
                       base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_service_provider(self):
        sp_id = self.do_request(
            'create_service_provider', expected_status=201,
            sp_id=data_utils.rand_name(),
            auth_url=data_utils.rand_url(),
            sp_url=data_utils.rand_url()
        )['service_provider']['id']
        self.addCleanup(self.admin_sp_client.delete_service_provider, sp_id)

    def test_identity_get_service_provider(self):
        sp_id = self.admin_sp_client.create_service_provider(
            sp_id=data_utils.rand_name(),
            auth_url=data_utils.rand_url(),
            sp_url=data_utils.rand_url())['service_provider']['id']
        self.addCleanup(self.admin_sp_client.delete_service_provider, sp_id)
        self.do_request('show_service_provider', sp_id=sp_id)
        # user gets a 404 for nonexistent sp
        self.do_request('show_service_provider',
                        expected_status=exceptions.NotFound,
                        sp_id=data_utils.rand_uuid_hex())

    def test_identity_list_service_providers(self):
        sp_id = self.admin_sp_client.create_service_provider(
            sp_id=data_utils.rand_name(),
            auth_url=data_utils.rand_url(),
            sp_url=data_utils.rand_url())['service_provider']['id']
        self.addCleanup(self.admin_sp_client.delete_service_provider, sp_id)
        resp = self.do_request('list_service_providers')
        self.assertIn(sp_id, [i['id'] for i in resp['service_providers']])

    def test_identity_update_service_provider(self):
        sp_id = self.admin_sp_client.create_service_provider(
            sp_id=data_utils.rand_name(),
            auth_url=data_utils.rand_url(),
            sp_url=data_utils.rand_url())['service_provider']['id']
        self.addCleanup(self.admin_sp_client.delete_service_provider, sp_id)
        self.do_request('update_service_provider',
                        sp_id=sp_id,
                        description=data_utils.arbitrary_string())
        # user gets a 404 for nonexistent sp
        self.do_request('update_service_provider',
                        expected_status=exceptions.NotFound,
                        sp_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_service_provider(self):
        sp_id = self.admin_sp_client.create_service_provider(
            sp_id=data_utils.rand_name(),
            auth_url=data_utils.rand_url(),
            sp_url=data_utils.rand_url())['service_provider']['id']
        self.do_request('delete_service_provider', expected_status=204,
                        sp_id=sp_id)
        # user gets a 404 for nonexistent sp
        self.do_request('delete_service_provider',
                        expected_status=exceptions.NotFound,
                        sp_id=sp_id)


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_service_provider(self):
        self.do_request('create_service_provider',
                        expected_status=exceptions.Forbidden,
                        sp_id=data_utils.rand_name(),
                        auth_url=data_utils.rand_url(),
                        sp_url=data_utils.rand_url())

    def test_identity_update_service_provider(self):
        sp_id = self.admin_sp_client.create_service_provider(
            sp_id=data_utils.rand_name(),
            auth_url=data_utils.rand_url(),
            sp_url=data_utils.rand_url())['service_provider']['id']
        self.addCleanup(self.admin_sp_client.delete_service_provider, sp_id)
        self.do_request('update_service_provider',
                        expected_status=exceptions.Forbidden,
                        sp_id=sp_id,
                        description=data_utils.arbitrary_string())
        # user gets a 403 for nonexistent sp
        self.do_request('update_service_provider',
                        expected_status=exceptions.Forbidden,
                        sp_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_service_provider(self):
        sp_id = self.admin_sp_client.create_service_provider(
            sp_id=data_utils.rand_name(),
            auth_url=data_utils.rand_url(),
            sp_url=data_utils.rand_url())['service_provider']['id']
        self.addCleanup(self.admin_sp_client.delete_service_provider, sp_id)
        self.do_request('delete_service_provider',
                        expected_status=exceptions.Forbidden,
                        sp_id=sp_id)
        # user gets a 403 for nonexistent sp
        self.do_request('delete_service_provider',
                        expected_status=exceptions.Forbidden,
                        sp_id=sp_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_service_provider(self):
        sp_id = self.admin_sp_client.create_service_provider(
            sp_id=data_utils.rand_name(),
            auth_url=data_utils.rand_url(),
            sp_url=data_utils.rand_url())['service_provider']['id']
        self.addCleanup(self.admin_sp_client.delete_service_provider, sp_id)
        self.do_request('show_service_provider',
                        expected_status=exceptions.Forbidden,
                        sp_id=sp_id)
        # user gets a 403 for nonexistent sp
        self.do_request('show_service_provider',
                        expected_status=exceptions.Forbidden,
                        sp_id=data_utils.rand_uuid_hex())

    def test_identity_list_service_providers(self):
        sp_id = self.admin_sp_client.create_service_provider(
            sp_id=data_utils.rand_name(),
            auth_url=data_utils.rand_url(),
            sp_url=data_utils.rand_url())['service_provider']['id']
        self.addCleanup(self.admin_sp_client.delete_service_provider, sp_id)
        self.do_request('list_service_providers',
                        expected_status=exceptions.Forbidden)


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
