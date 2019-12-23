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


class IdentityV3RbacImpliedRoleTest(rbac_base.IdentityV3RbacBaseTests,
                                    metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacImpliedRoleTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.roles_v3_client
        cls.admin_client = cls.os_system_admin
        cls.admin_roles_client = cls.admin_client.roles_v3_client

    @classmethod
    def resource_setup(cls):
        super(IdentityV3RbacImpliedRoleTest, cls).resource_setup()
        cls.prior_role = cls.admin_roles_client.create_role(
            name=data_utils.rand_name('prior_role'))['role']['id']
        cls.addClassResourceCleanup(
            cls.admin_roles_client.delete_role, cls.prior_role)
        cls.implied_role = cls.admin_roles_client.create_role(
            name=data_utils.rand_name('implied_role'))['role']['id']
        cls.addClassResourceCleanup(
            cls.admin_roles_client.delete_role, cls.implied_role)

    @abc.abstractmethod
    def test_identity_create_implied_role(self):
        """Test identity:create_implied_role policy.

        This test must check:
          * whether the persona can create an implied role
        """
        pass

    @abc.abstractmethod
    def test_identity_get_implied_role(self):
        """Test identity:get_implied_role policy.

        This test must check:
          * whether the persona can get an implied role
        """
        pass

    @abc.abstractmethod
    def test_identity_list_implied_roles(self):
        """Test identity:list_implied_roles policy.

        This test must check:
          * whether the persona can list implied roles
        """
        pass

    @abc.abstractmethod
    def test_identity_list_role_inference_rules(self):
        """Test identity:list_role_inference_rules policy.

        This test must check:
          * whether the persona can list role inference rules
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_implied_role(self):
        """Test identity:delete_implied_role policy.

        This test must check
          * whether the persona can delete an implied role
        """
        pass

    @abc.abstractmethod
    def test_identity_check_implied_role(self):
        """Test identity:check_implied_role policy.

        This test must check:
          * whether the persona can check an association between two roles
        """
        pass


class SystemAdminTests(IdentityV3RbacImpliedRoleTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_implied_role(self):
        self.do_request('create_role_inference_rule',
                        expected_status=201,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)
        self.addCleanup(self.admin_roles_client.delete_role_inference_rule,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)

    def test_identity_get_implied_role(self):
        self.admin_roles_client.create_role_inference_rule(
            prior_role=self.prior_role, implies_role=self.implied_role)
        self.addCleanup(self.admin_roles_client.delete_role_inference_rule,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)
        self.do_request('show_role_inference_rule',
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)

    def test_identity_list_implied_roles(self):
        self.admin_roles_client.create_role_inference_rule(
            prior_role=self.prior_role, implies_role=self.implied_role)
        self.addCleanup(self.admin_roles_client.delete_role_inference_rule,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)
        self.do_request('list_role_inferences_rules',
                        prior_role=self.prior_role)

    def test_identity_list_role_inference_rules(self):
        self.admin_roles_client.create_role_inference_rule(
            prior_role=self.prior_role, implies_role=self.implied_role)
        self.addCleanup(self.admin_roles_client.delete_role_inference_rule,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)
        self.do_request('list_all_role_inference_rules')

    def test_identity_delete_implied_role(self):
        self.admin_roles_client.create_role_inference_rule(
            prior_role=self.prior_role, implies_role=self.implied_role)
        self.do_request('delete_role_inference_rule',
                        expected_status=204,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)

    def test_identity_check_implied_role(self):
        self.admin_roles_client.create_role_inference_rule(
            prior_role=self.prior_role, implies_role=self.implied_role)
        self.addCleanup(self.admin_roles_client.delete_role_inference_rule,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)
        self.do_request('check_role_inference_rule',
                        expected_status=204,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_implied_role(self):
        self.do_request('create_role_inference_rule',
                        expected_status=exceptions.Forbidden,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)

    def test_identity_delete_implied_role(self):
        self.admin_roles_client.create_role_inference_rule(
            prior_role=self.prior_role, implies_role=self.implied_role)
        self.addCleanup(self.admin_roles_client.delete_role_inference_rule,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)
        self.do_request('delete_role_inference_rule',
                        expected_status=exceptions.Forbidden,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_implied_role(self):
        self.admin_roles_client.create_role_inference_rule(
            prior_role=self.prior_role, implies_role=self.implied_role)
        self.addCleanup(self.admin_roles_client.delete_role_inference_rule,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)
        self.do_request('show_role_inference_rule',
                        expected_status=exceptions.Forbidden,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)

    def test_identity_list_implied_roles(self):
        self.admin_roles_client.create_role_inference_rule(
            prior_role=self.prior_role, implies_role=self.implied_role)
        self.addCleanup(self.admin_roles_client.delete_role_inference_rule,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)
        self.do_request('list_role_inferences_rules',
                        expected_status=exceptions.Forbidden,
                        prior_role=self.prior_role)

    def test_identity_list_role_inference_rules(self):
        self.admin_roles_client.create_role_inference_rule(
            prior_role=self.prior_role, implies_role=self.implied_role)
        self.addCleanup(self.admin_roles_client.delete_role_inference_rule,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)
        self.do_request('list_all_role_inference_rules',
                        expected_status=exceptions.Forbidden)

    def test_identity_check_implied_role(self):
        self.admin_roles_client.create_role_inference_rule(
            prior_role=self.prior_role, implies_role=self.implied_role)
        self.addCleanup(self.admin_roles_client.delete_role_inference_rule,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)
        self.do_request('check_role_inference_rule',
                        expected_status=exceptions.Forbidden,
                        prior_role=self.prior_role,
                        implies_role=self.implied_role)


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainMemberTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(DomainReaderTests):

    credentials = ['project_admin', 'system_admin']


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
