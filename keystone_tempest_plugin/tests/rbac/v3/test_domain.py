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


class IdentityV3RbacDomainTests(rbac_base.IdentityV3RbacBaseTests,
                                metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacDomainTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.domains_client
        admin_client = cls.os_system_admin
        cls.admin_domains_client = admin_client.domains_client

    @abc.abstractmethod
    def test_identity_create_domain(self):
        """Test identity:create_domain policy.

        This test must check:
          * whether the persona can create a domain
        """
        pass

    @abc.abstractmethod
    def test_identity_get_domain(self):
        """Test identity:get_domain policy.

        This test must check:
          * whether the persona can get a domain
          * whether the persona can get a domain that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_domains(self):
        """Test identity:list_domains policy.

        This test must check:
          * whether the persona can list all domains
        """
        pass

    @abc.abstractmethod
    def test_identity_update_domain(self):
        """Test identity:update_domain policy.

        This test must check:
          * whether the persona can update a domain
          * whether the persona can update a domain that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_domain(self):
        """Test identity:delete_domain policy.

        This test must check
          * whether the persona can delete a domain
          * whether the persona can delete a domain that does not exist
        """
        pass


class SystemAdminTests(IdentityV3RbacDomainTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_domain(self):
        domain_id = self.do_request(
            'create_domain', expected_status=201, name=data_utils.rand_name()
        )['domain']['id']
        self.addCleanup(self.admin_domains_client.delete_domain, domain_id)
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=domain_id, enabled=False)

    def test_identity_get_domain(self):
        domain_id = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_domains_client.delete_domain, domain_id)
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=domain_id, enabled=False)
        self.do_request('show_domain', domain_id=domain_id)
        # user gets a 404 for nonexistent domain
        self.do_request('show_domain', expected_status=exceptions.NotFound,
                        domain_id=data_utils.rand_uuid_hex())

    def test_identity_list_domains(self):
        domain_id = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_domains_client.delete_domain, domain_id)
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=domain_id, enabled=False)
        resp = self.do_request('list_domains')
        self.assertIn(domain_id, [d['id'] for d in resp['domains']])

    def test_identity_update_domain(self):
        domain_id = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_domains_client.delete_domain, domain_id)
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=domain_id, enabled=False)
        self.do_request('update_domain',
                        domain_id=domain_id,
                        description=data_utils.arbitrary_string())
        # user gets a 404 for nonexistent domain
        self.do_request('update_domain', expected_status=exceptions.NotFound,
                        domain_id=data_utils.rand_uuid_hex())

    def test_identity_delete_domain(self):
        domain_id = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.do_request('update_domain',
                        domain_id=domain_id,
                        enabled=False)
        self.do_request('delete_domain', expected_status=204,
                        domain_id=domain_id)


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_domain(self):
        self.do_request('create_domain', expected_status=exceptions.Forbidden,
                        name=data_utils.rand_name())

    def test_identity_update_domain(self):
        domain_id = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_domains_client.delete_domain, domain_id)
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=domain_id, enabled=False)
        self.do_request('update_domain', expected_status=exceptions.Forbidden,
                        domain_id=domain_id,
                        description=data_utils.arbitrary_string())
        # user gets a 404 for nonexistent domain
        self.do_request('update_domain', expected_status=exceptions.NotFound,
                        domain_id=data_utils.rand_uuid_hex())

    def test_identity_delete_domain(self):
        domain_id = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_domains_client.delete_domain, domain_id)
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=domain_id, enabled=False)
        self.do_request('delete_domain', expected_status=exceptions.Forbidden,
                        domain_id=domain_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_domain(self):
        domain_id = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_domains_client.delete_domain, domain_id)
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=domain_id, enabled=False)
        self.do_request('show_domain', expected_status=exceptions.Forbidden,
                        domain_id=domain_id)
        # user gets a 403 for nonexistent domain
        self.do_request('show_domain', expected_status=exceptions.Forbidden,
                        domain_id=data_utils.rand_uuid_hex())

    def test_identity_list_domains(self):
        domain_id = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_domains_client.delete_domain, domain_id)
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=domain_id, enabled=False)
        self.do_request('list_domains',
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
