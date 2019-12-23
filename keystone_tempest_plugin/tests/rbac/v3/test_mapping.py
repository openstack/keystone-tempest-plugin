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


class IdentityV3RbacMappingTests(rbac_base.IdentityV3RbacBaseTests,
                                 metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacMappingTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.keystone_manager = clients.Manager(cls.persona.credentials)
        persona_mgr = clients.Manager(cls.persona.credentials)
        cls.client = persona_mgr.mapping_rules_client
        admin_client = cls.os_system_admin
        admin_mgr = clients.Manager(admin_client.credentials)
        cls.admin_mapping_client = admin_mgr.mapping_rules_client

    @abc.abstractmethod
    def test_identity_create_mapping(self):
        """Test identity:create_mapping policy.

        This test must check:
          * whether the persona can create a mapping
        """
        pass

    @abc.abstractmethod
    def test_identity_get_mapping(self):
        """Test identity:get_mapping policy.

        This test must check:
          * whether the persona can get a mapping
          * whether the persona can get a mapping that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_mappings(self):
        """Test identity:list_mappings policy.

        This test must check:
          * whether the persona can list all mappings
        """
        pass

    @abc.abstractmethod
    def test_identity_update_mapping(self):
        """Test identity:update_mapping policy.

        This test must check:
          * whether the persona can update a mapping
          * whether the persona can update a mapping that does not
            exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_mapping(self):
        """Test identity:delete_mapping policy.

        This test must check
          * whether the persona can delete a mapping
          * whether the persona can delete a mapping that does not
            exist
        """
        pass


_RULES = {
    "rules":
        [{
            "local": [],
            "remote": [{"type": data_utils.rand_name()}]
        }]
}


class SystemAdminTests(IdentityV3RbacMappingTests, base.BaseIdentityTest):
    credentials = ['system_admin']

    def test_identity_create_mapping(self):
        mapping_id = self.do_request(
            'create_mapping_rule', expected_status=201,
            mapping_id=data_utils.rand_name(),
            rules=_RULES
        )['mapping']['id']
        self.addCleanup(self.admin_mapping_client.delete_mapping_rule,
                        mapping_id)

    def test_identity_get_mapping(self):
        mapping_id = self.admin_mapping_client.create_mapping_rule(
            mapping_id=data_utils.rand_name(),
            rules=_RULES)['mapping']['id']
        self.addCleanup(self.admin_mapping_client.delete_mapping_rule,
                        mapping_id)
        self.do_request('show_mapping_rule', mapping_id=mapping_id)
        # user gets a 404 for nonexistent mapping
        self.do_request('show_mapping_rule',
                        expected_status=exceptions.NotFound,
                        mapping_id=data_utils.rand_uuid_hex())

    def test_identity_list_mappings(self):
        mapping_id = self.admin_mapping_client.create_mapping_rule(
            mapping_id=data_utils.rand_name(),
            rules=_RULES)['mapping']['id']
        self.addCleanup(self.admin_mapping_client.delete_mapping_rule,
                        mapping_id)
        resp = self.do_request('list_mapping_rules')
        self.assertIn(mapping_id, [i['id'] for i in resp['mappings']])

    def test_identity_update_mapping(self):
        mapping_id = self.admin_mapping_client.create_mapping_rule(
            mapping_id=data_utils.rand_name(),
            rules=_RULES)['mapping']['id']
        self.addCleanup(self.admin_mapping_client.delete_mapping_rule,
                        mapping_id)
        self.do_request('update_mapping_rule',
                        mapping_id=mapping_id,
                        rules=_RULES)
        # user gets a 404 for nonexistent mapping
        self.do_request('update_mapping_rule',
                        expected_status=exceptions.NotFound,
                        mapping_id=data_utils.rand_uuid_hex(),
                        rules=_RULES)

    def test_identity_delete_mapping(self):
        mapping_id = self.admin_mapping_client.create_mapping_rule(
            mapping_id=data_utils.rand_name(),
            rules=_RULES)['mapping']['id']
        self.do_request('delete_mapping_rule', expected_status=204,
                        mapping_id=mapping_id)
        # user gets a 404 for nonexistent mapping
        self.do_request('delete_mapping_rule',
                        expected_status=exceptions.NotFound,
                        mapping_id=mapping_id)


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_mapping(self):
        self.do_request('create_mapping_rule',
                        expected_status=exceptions.Forbidden,
                        mapping_id=data_utils.rand_name(),
                        rules=_RULES)

    def test_identity_update_mapping(self):
        mapping_id = self.admin_mapping_client.create_mapping_rule(
            mapping_id=data_utils.rand_name(),
            rules=_RULES)['mapping']['id']
        self.addCleanup(self.admin_mapping_client.delete_mapping_rule,
                        mapping_id)
        self.do_request('update_mapping_rule',
                        expected_status=exceptions.Forbidden,
                        mapping_id=mapping_id,
                        rules=_RULES)
        # user gets a 403 for nonexistent mapping
        self.do_request('update_mapping_rule',
                        expected_status=exceptions.Forbidden,
                        mapping_id=data_utils.rand_uuid_hex(),
                        rules=_RULES)

    def test_identity_delete_mapping(self):
        mapping_id = self.admin_mapping_client.create_mapping_rule(
            mapping_id=data_utils.rand_name(),
            rules=_RULES)['mapping']['id']
        self.addCleanup(self.admin_mapping_client.delete_mapping_rule,
                        mapping_id)
        self.do_request('delete_mapping_rule',
                        expected_status=exceptions.Forbidden,
                        mapping_id=mapping_id)
        # user gets a 403 for nonexistent mapping
        self.do_request('delete_mapping_rule',
                        expected_status=exceptions.Forbidden,
                        mapping_id=mapping_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_mapping(self):
        mapping_id = self.admin_mapping_client.create_mapping_rule(
            mapping_id=data_utils.rand_name(),
            rules=_RULES)['mapping']['id']
        self.addCleanup(self.admin_mapping_client.delete_mapping_rule,
                        mapping_id)
        self.do_request('show_mapping_rule',
                        expected_status=exceptions.Forbidden,
                        mapping_id=mapping_id)
        # user gets a 403 for nonexistent mapping
        self.do_request('show_mapping_rule',
                        expected_status=exceptions.Forbidden,
                        mapping_id=data_utils.rand_uuid_hex())

    def test_identity_list_mappings(self):
        mapping_id = self.admin_mapping_client.create_mapping_rule(
            mapping_id=data_utils.rand_name(),
            rules=_RULES)['mapping']['id']
        self.addCleanup(self.admin_mapping_client.delete_mapping_rule,
                        mapping_id)
        self.do_request('list_mapping_rules',
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
