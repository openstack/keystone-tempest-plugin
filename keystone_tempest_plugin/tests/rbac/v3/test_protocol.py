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


class IdentityV3RbacProtocolTests(rbac_base.IdentityV3RbacBaseTests,
                                  metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacProtocolTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.keystone_manager = clients.Manager(cls.persona.credentials)
        persona_mgr = clients.Manager(cls.persona.credentials)
        cls.client = persona_mgr.identity_providers_client
        admin_client = cls.os_system_admin
        admin_mgr = clients.Manager(admin_client.credentials)
        cls.admin_idp_client = admin_mgr.identity_providers_client
        cls.admin_mapping_client = admin_mgr.mapping_rules_client

    @classmethod
    def setUpClass(cls):
        super(IdentityV3RbacProtocolTests, cls).setUpClass()
        cls.idp_id = cls.admin_idp_client.create_identity_provider(
            idp_id=data_utils.rand_name())['identity_provider']['id']
        cls.addClassResourceCleanup(
            cls.admin_idp_client.delete_identity_provider, cls.idp_id)
        rules = {
            "rules":
                [{
                    "local": [],
                    "remote": [{"type": data_utils.rand_name()}]
                }]
        }
        cls.mapping_id = cls.admin_mapping_client.create_mapping_rule(
            mapping_id=data_utils.rand_name(), rules=rules)['mapping']['id']
        cls.addClassResourceCleanup(
            cls.admin_mapping_client.delete_mapping_rule,
            mapping_id=cls.mapping_id)

    @abc.abstractmethod
    def test_identity_create_protocol(self):
        """Test identity:create_protocol policy.

        This test must check:
          * whether the persona can create a protocol
        """
        pass

    @abc.abstractmethod
    def test_identity_get_protocol(self):
        """Test identity:get_protocol policy.

        This test must check:
          * whether the persona can get a protocol
          * whether the persona can get a protocol that does not
            exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_protocols(self):
        """Test identity:list_protocols policy.

        This test must check:
          * whether the persona can list all identity providers
        """
        pass

    @abc.abstractmethod
    def test_identity_update_protocol(self):
        """Test identity:update_protocol policy.

        This test must check:
          * whether the persona can update a protocol
          * whether the persona can update a protocol that does not
            exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_protocol(self):
        """Test identity:delete_protocol policy.

        This test must check
          * whether the persona can delete a protocol
          * whether the persona can delete a protocol that does not
            exist
        """
        pass


class SystemAdminTests(IdentityV3RbacProtocolTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_protocol(self):
        protocol_id = self.do_request(
            'add_protocol_and_mapping', expected_status=201,
            idp_id=self.idp_id,
            protocol_id=data_utils.rand_name(),
            mapping_id=self.mapping_id
        )['protocol']['id']
        self.addCleanup(self.admin_idp_client.delete_protocol_and_mapping,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)

    def test_identity_get_protocol(self):
        protocol_id = self.admin_idp_client.add_protocol_and_mapping(
            idp_id=self.idp_id,
            protocol_id=data_utils.rand_name(),
            mapping_id=self.mapping_id)['protocol']['id']
        self.addCleanup(self.admin_idp_client.delete_protocol_and_mapping,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        self.do_request('get_protocol_and_mapping',
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        # user gets a 404 for nonexistent idp
        self.do_request('get_protocol_and_mapping',
                        expected_status=exceptions.NotFound,
                        idp_id=self.idp_id,
                        protocol_id=data_utils.rand_uuid_hex())

    def test_identity_list_protocols(self):
        protocol_id = self.admin_idp_client.add_protocol_and_mapping(
            idp_id=self.idp_id,
            protocol_id=data_utils.rand_name(),
            mapping_id=self.mapping_id)['protocol']['id']
        self.addCleanup(self.admin_idp_client.delete_protocol_and_mapping,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        resp = self.do_request('list_protocols_and_mappings',
                               idp_id=self.idp_id)
        self.assertIn(protocol_id, [p['id'] for p in resp['protocols']])

    def test_identity_update_protocol(self):
        protocol_id = self.admin_idp_client.add_protocol_and_mapping(
            idp_id=self.idp_id,
            protocol_id=data_utils.rand_name(),
            mapping_id=self.mapping_id)['protocol']['id']
        self.addCleanup(self.admin_idp_client.delete_protocol_and_mapping,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        self.do_request('update_protocol_mapping',
                        idp_id=self.idp_id,
                        protocol_id=protocol_id,
                        mapping_id=self.mapping_id)
        # user gets a 404 for nonexistent protocol
        self.do_request('update_protocol_mapping',
                        expected_status=exceptions.NotFound,
                        idp_id=self.idp_id,
                        protocol_id=data_utils.rand_uuid_hex(),
                        mapping_id=self.mapping_id)

    def test_identity_delete_protocol(self):
        protocol_id = self.admin_idp_client.add_protocol_and_mapping(
            idp_id=self.idp_id,
            protocol_id=data_utils.rand_name(),
            mapping_id=self.mapping_id)['protocol']['id']
        self.do_request('delete_protocol_and_mapping', expected_status=204,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        # user gets a 404 for nonexistent idp
        self.do_request('delete_protocol_and_mapping',
                        expected_status=exceptions.NotFound,
                        idp_id=self.idp_id,
                        protocol_id=data_utils.rand_uuid_hex())


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_protocol(self):
        self.do_request('add_protocol_and_mapping',
                        expected_status=exceptions.Forbidden,
                        idp_id=self.idp_id,
                        protocol_id=data_utils.rand_name(),
                        mapping_id=self.mapping_id)

    def test_identity_update_protocol(self):
        protocol_id = self.admin_idp_client.add_protocol_and_mapping(
            idp_id=self.idp_id,
            protocol_id=data_utils.rand_name(),
            mapping_id=self.mapping_id)['protocol']['id']
        self.addCleanup(self.admin_idp_client.delete_protocol_and_mapping,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        self.do_request('update_protocol_mapping',
                        expected_status=exceptions.Forbidden,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id,
                        mapping_id=self.mapping_id)
        # user gets a 403 for nonexistent protocol
        self.do_request('update_protocol_mapping',
                        expected_status=exceptions.Forbidden,
                        idp_id=self.idp_id,
                        protocol_id=data_utils.rand_uuid_hex(),
                        mapping_id=self.mapping_id)

    def test_identity_delete_protocol(self):
        protocol_id = self.admin_idp_client.add_protocol_and_mapping(
            idp_id=self.idp_id,
            protocol_id=data_utils.rand_name(),
            mapping_id=self.mapping_id)['protocol']['id']
        self.addCleanup(self.admin_idp_client.delete_protocol_and_mapping,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        self.do_request('delete_protocol_and_mapping',
                        expected_status=exceptions.Forbidden,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        # user gets a 403 for nonexistent protocol
        self.do_request('delete_protocol_and_mapping',
                        expected_status=exceptions.Forbidden,
                        idp_id=self.idp_id,
                        protocol_id=data_utils.rand_uuid_hex())


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_protocol(self):
        protocol_id = self.admin_idp_client.add_protocol_and_mapping(
            idp_id=self.idp_id,
            protocol_id=data_utils.rand_name(),
            mapping_id=self.mapping_id)['protocol']['id']
        self.addCleanup(self.admin_idp_client.delete_protocol_and_mapping,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        self.do_request('get_protocol_and_mapping',
                        expected_status=exceptions.Forbidden,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        # user gets a 403 for nonexistent idp
        self.do_request('get_protocol_and_mapping',
                        expected_status=exceptions.Forbidden,
                        idp_id=self.idp_id,
                        protocol_id=data_utils.rand_uuid_hex())

    def test_identity_list_protocols(self):
        protocol_id = self.admin_idp_client.add_protocol_and_mapping(
            idp_id=self.idp_id,
            protocol_id=data_utils.rand_name(),
            mapping_id=self.mapping_id)['protocol']['id']
        self.addCleanup(self.admin_idp_client.delete_protocol_and_mapping,
                        idp_id=self.idp_id,
                        protocol_id=protocol_id)
        self.do_request('list_protocols_and_mappings',
                        expected_status=exceptions.Forbidden,
                        idp_id=self.idp_id)


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
