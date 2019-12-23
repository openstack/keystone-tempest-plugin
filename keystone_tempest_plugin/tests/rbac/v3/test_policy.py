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


class IdentityV3RbacPolicyTests(rbac_base.IdentityV3RbacBaseTests,
                                metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacPolicyTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.policies_client
        admin_client = cls.os_system_admin
        cls.admin_policies_client = admin_client.policies_client

    def policy(self):
        return {
            'blob': data_utils.rand_uuid_hex(),
            'type': data_utils.rand_uuid_hex()
        }

    @abc.abstractmethod
    def test_identity_create_policy(self):
        """Test identity:create_policy policy.

        This test must check:
          * whether the persona can create a policy
        """
        pass

    @abc.abstractmethod
    def test_identity_get_policy(self):
        """Test identity:get_policy policy.

        This test must check:
          * whether the persona can get a policy
          * whether the persona can get a policy that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_policies(self):
        """Test identity:list_policies policy.

        This test must check:
          * whether the persona can list all policies
        """
        pass

    @abc.abstractmethod
    def test_identity_update_policy(self):
        """Test identity:update_policy policy.

        This test must check:
          * whether the persona can update a policy
          * whether the persona can update a policy that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_policy(self):
        """Test identity:delete_policy policy.

        This test must check
          * whether the persona can delete a policy
          * whether the persona can delete a policy that does not exist
        """
        pass


class SystemAdminTests(IdentityV3RbacPolicyTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_policy(self):
        policy_id = self.do_request(
            'create_policy', expected_status=201,
            **self.policy())['policy']['id']
        self.addCleanup(
            self.admin_policies_client.delete_policy,
            policy_id=policy_id)

    def test_identity_get_policy(self):
        policy_id = self.admin_policies_client.create_policy(
            **self.policy())['policy']['id']
        self.addCleanup(
            self.admin_policies_client.delete_policy,
            policy_id=policy_id)
        self.do_request('show_policy', policy_id=policy_id)
        # user gets a 404 for nonexistent policy
        self.do_request('show_policy', expected_status=exceptions.NotFound,
                        policy_id=data_utils.rand_uuid_hex())

    def test_identity_list_policies(self):
        policy_id = self.admin_policies_client.create_policy(
            **self.policy())['policy']['id']
        self.addCleanup(
            self.admin_policies_client.delete_policy,
            policy_id=policy_id)
        resp = self.do_request('list_policies')
        self.assertIn(policy_id, [e['id'] for e in resp['policies']])

    def test_identity_update_policy(self):
        policy_id = self.admin_policies_client.create_policy(
            **self.policy())['policy']['id']
        self.addCleanup(
            self.admin_policies_client.delete_policy,
            policy_id=policy_id)
        self.do_request('update_policy',
                        policy_id=policy_id,
                        blob=data_utils.rand_uuid_hex())
        # user gets a 404 for nonexistent policy
        self.do_request('update_policy', expected_status=exceptions.NotFound,
                        policy_id=data_utils.rand_uuid_hex(),
                        blob=data_utils.rand_uuid_hex())

    def test_identity_delete_policy(self):
        policy_id = self.admin_policies_client.create_policy(
            **self.policy())['policy']['id']
        self.do_request('delete_policy', expected_status=204,
                        policy_id=policy_id)
        # user gets a 404 for nonexistent policy
        self.do_request('delete_policy', expected_status=exceptions.NotFound,
                        policy_id=data_utils.rand_uuid_hex())


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_policy(self):
        self.do_request(
            'create_policy', expected_status=exceptions.Forbidden,
            **self.policy())

    def test_identity_update_policy(self):
        policy_id = self.admin_policies_client.create_policy(
            **self.policy())['policy']['id']
        self.addCleanup(
            self.admin_policies_client.delete_policy,
            policy_id=policy_id)
        self.do_request('update_policy', expected_status=exceptions.Forbidden,
                        policy_id=policy_id,
                        blob=data_utils.rand_uuid_hex())
        # user gets a 403 for nonexistent policy
        self.do_request('update_policy', expected_status=exceptions.Forbidden,
                        policy_id=data_utils.rand_uuid_hex(),
                        blob=data_utils.rand_uuid_hex())

    def test_identity_delete_policy(self):
        policy_id = self.admin_policies_client.create_policy(
            **self.policy())['policy']['id']
        self.do_request('delete_policy',
                        expected_status=exceptions.Forbidden,
                        policy_id=policy_id)
        # user gets a 403 for nonexistent policy
        self.do_request('delete_policy', expected_status=exceptions.Forbidden,
                        policy_id=data_utils.rand_uuid_hex())


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_policy(self):
        policy_id = self.admin_policies_client.create_policy(
            **self.policy())['policy']['id']
        self.addCleanup(
            self.admin_policies_client.delete_policy,
            policy_id=policy_id)
        self.do_request('show_policy', expected_status=exceptions.Forbidden,
                        policy_id=policy_id)
        # user gets a 403 for nonexistent policy
        self.do_request('show_policy', expected_status=exceptions.Forbidden,
                        policy_id=data_utils.rand_uuid_hex())

    def test_identity_list_policies(self):
        policy_id = self.admin_policies_client.create_policy(
            **self.policy())['policy']['id']
        self.addCleanup(
            self.admin_policies_client.delete_policy,
            policy_id=policy_id)
        self.do_request('list_policies', expected_status=exceptions.Forbidden)


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
