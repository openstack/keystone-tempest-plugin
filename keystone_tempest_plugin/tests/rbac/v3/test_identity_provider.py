# Copyright 2020 SUSE LLC #
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


class IdentityV3RbacIdentityProviderTests(rbac_base.IdentityV3RbacBaseTests,
                                          metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacIdentityProviderTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.keystone_manager = clients.Manager(cls.persona.credentials)
        persona_mgr = clients.Manager(cls.persona.credentials)
        cls.client = persona_mgr.identity_providers_client
        cls.admin_client = cls.os_system_admin
        admin_mgr = clients.Manager(cls.admin_client.credentials)
        cls.admin_idp_client = admin_mgr.identity_providers_client

    @abc.abstractmethod
    def test_identity_create_identity_provider(self):
        """Test identity:create_identity_provider policy.

        This test must check:
          * whether the persona can create an identity provider
        """
        pass

    @abc.abstractmethod
    def test_identity_get_identity_provider(self):
        """Test identity:get_identity_provider policy.

        This test must check:
          * whether the persona can get an identity provider
          * whether the persona can get an identity provider that does not
            exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_identity_providers(self):
        """Test identity:list_identity_providers policy.

        This test must check:
          * whether the persona can list all identity providers
        """
        pass

    @abc.abstractmethod
    def test_identity_update_identity_provider(self):
        """Test identity:update_identity_provider policy.

        This test must check:
          * whether the persona can update an identity provider
          * whether the persona can update an identity provider that does not
            exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_identity_provider(self):
        """Test identity:delete_identity_provider policy.

        This test must check
          * whether the persona can delete an identity provider
          * whether the persona can delete an identity provider that does not
            exist
        """
        pass


class SystemAdminTests(IdentityV3RbacIdentityProviderTests,
                       base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_identity_provider(self):
        idp = self.do_request(
            'create_identity_provider', expected_status=201,
            idp_id=data_utils.rand_name()
        )['identity_provider']
        self.addCleanup(
            self.admin_client.domains_client.delete_domain, idp['domain_id'])
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            idp['domain_id'], enabled=False)
        self.addCleanup(
            self.admin_idp_client.delete_identity_provider, idp['id'])

    def test_identity_get_identity_provider(self):
        idp = self.admin_idp_client.create_identity_provider(
            idp_id=data_utils.rand_name())['identity_provider']
        self.addCleanup(
            self.admin_client.domains_client.delete_domain, idp['domain_id'])
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            idp['domain_id'], enabled=False)
        self.addCleanup(
            self.admin_idp_client.delete_identity_provider, idp['id'])
        self.do_request('show_identity_provider', idp_id=idp['id'])
        # user gets a 404 for nonexistent idp
        self.do_request('show_identity_provider',
                        expected_status=exceptions.NotFound,
                        idp_id=data_utils.rand_uuid_hex())

    def test_identity_list_identity_providers(self):
        idp = self.admin_idp_client.create_identity_provider(
            idp_id=data_utils.rand_name())['identity_provider']
        self.addCleanup(
            self.admin_client.domains_client.delete_domain, idp['domain_id'])
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            idp['domain_id'], enabled=False)
        self.addCleanup(
            self.admin_idp_client.delete_identity_provider, idp['id'])
        resp = self.do_request('list_identity_providers')
        self.assertIn(idp['id'], [i['id'] for i in resp['identity_providers']])

    def test_identity_update_identity_provider(self):
        idp = self.admin_idp_client.create_identity_provider(
            idp_id=data_utils.rand_name())['identity_provider']
        self.addCleanup(
            self.admin_client.domains_client.delete_domain, idp['domain_id'])
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            idp['domain_id'], enabled=False)
        self.addCleanup(
            self.admin_idp_client.delete_identity_provider, idp['id'])
        self.do_request('update_identity_provider',
                        idp_id=idp['id'],
                        description=data_utils.arbitrary_string())
        # user gets a 404 for nonexistent idp
        self.do_request('update_identity_provider',
                        expected_status=exceptions.NotFound,
                        idp_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_identity_provider(self):
        idp = self.admin_idp_client.create_identity_provider(
            idp_id=data_utils.rand_name())['identity_provider']
        self.addCleanup(
            self.admin_client.domains_client.delete_domain, idp['domain_id'])
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            idp['domain_id'], enabled=False)
        self.do_request('delete_identity_provider', expected_status=204,
                        idp_id=idp['id'])
        # user gets a 404 for nonexistent idp
        self.do_request('delete_identity_provider',
                        expected_status=exceptions.NotFound,
                        idp_id=data_utils.rand_uuid_hex())


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_identity_provider(self):
        self.do_request('create_identity_provider',
                        expected_status=exceptions.Forbidden,
                        idp_id=data_utils.rand_name())

    def test_identity_update_identity_provider(self):
        idp = self.admin_idp_client.create_identity_provider(
            idp_id=data_utils.rand_name())['identity_provider']
        self.addCleanup(
            self.admin_client.domains_client.delete_domain, idp['domain_id'])
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            idp['domain_id'], enabled=False)
        self.addCleanup(
            self.admin_idp_client.delete_identity_provider, idp['id'])
        self.do_request('update_identity_provider',
                        expected_status=exceptions.Forbidden,
                        idp_id=idp['id'],
                        description=data_utils.arbitrary_string())
        # user gets a 403 for nonexistent idp
        self.do_request('update_identity_provider',
                        expected_status=exceptions.Forbidden,
                        idp_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_identity_provider(self):
        idp = self.admin_idp_client.create_identity_provider(
            idp_id=data_utils.rand_name())['identity_provider']
        self.addCleanup(
            self.admin_client.domains_client.delete_domain, idp['domain_id'])
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            idp['domain_id'], enabled=False)
        self.addCleanup(
            self.admin_idp_client.delete_identity_provider, idp['id'])
        self.do_request('delete_identity_provider',
                        expected_status=exceptions.Forbidden,
                        idp_id=idp['id'])
        # user gets a 403 for nonexistent idp
        self.do_request('delete_identity_provider',
                        expected_status=exceptions.Forbidden,
                        idp_id=data_utils.rand_uuid_hex())


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_identity_provider(self):
        idp = self.admin_idp_client.create_identity_provider(
            idp_id=data_utils.rand_name())['identity_provider']
        self.addCleanup(
            self.admin_client.domains_client.delete_domain, idp['domain_id'])
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            idp['domain_id'], enabled=False)
        self.addCleanup(
            self.admin_idp_client.delete_identity_provider, idp['id'])
        self.do_request('show_identity_provider',
                        expected_status=exceptions.Forbidden,
                        idp_id=idp['id'])
        # user gets a 403 for nonexistent idp
        self.do_request('show_identity_provider',
                        expected_status=exceptions.Forbidden,
                        idp_id=data_utils.rand_uuid_hex())

    def test_identity_list_identity_providers(self):
        idp = self.admin_idp_client.create_identity_provider(
            idp_id=data_utils.rand_name())['identity_provider']
        self.addCleanup(
            self.admin_client.domains_client.delete_domain, idp['domain_id'])
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            idp['domain_id'], enabled=False)
        self.addCleanup(
            self.admin_idp_client.delete_identity_provider, idp['id'])
        self.do_request('list_identity_providers',
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
