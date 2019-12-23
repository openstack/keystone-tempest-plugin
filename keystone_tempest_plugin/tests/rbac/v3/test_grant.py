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


class IdentityV3RbacGrantTest(rbac_base.IdentityV3RbacBaseTests,
                              metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacGrantTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.roles_v3_client
        cls.admin_client = cls.os_system_admin
        cls.admin_roles_client = cls.admin_client.roles_v3_client

    @classmethod
    def resource_setup(cls):
        super(IdentityV3RbacGrantTest, cls).resource_setup()
        cls._setup_assignments()

    @classmethod
    def _setup_assignments(cls):
        # global role
        cls.role_id = cls.admin_client.roles_v3_client.create_role(
            name=data_utils.rand_name('role'))['role']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.roles_v3_client.delete_role, cls.role_id)

        # own domain - if system or project user, this will be the user's
        # namespace and isn't applicable for RBAC testing
        # if domain user, this will be the domain on which the user has a role
        # assignment
        cls.own_domain = cls.persona.credentials.domain_id

        # domain-specific role in own domain
        cls.role_own_domain = cls.admin_client.roles_v3_client.create_role(
            name=data_utils.rand_name('role'),
            domain_id=cls.own_domain)['role']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.roles_v3_client.delete_role, cls.role_own_domain)

        # arbitrary domain
        cls.other_domain = cls.admin_client.domains_client.create_domain(
            name=data_utils.rand_name('domain'))['domain']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.delete_domain,
            cls.other_domain)
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.update_domain,
            cls.other_domain,
            enabled=False)

        # domain-specific role in another domain
        cls.role_other_domain = cls.admin_client.roles_v3_client.create_role(
            name=data_utils.rand_name('role'),
            domain_id=cls.other_domain)['role']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.roles_v3_client.delete_role,
            cls.role_other_domain)

        # user in own domain
        cls.user_in_domain = cls.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=cls.own_domain)['user']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.users_v3_client.delete_user,
            cls.user_in_domain)

        # group in own domain
        cls.group_in_domain = cls.admin_client.groups_client.create_group(
            name=data_utils.rand_name('group'),
            domain_id=cls.own_domain)['group']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.groups_client.delete_group,
            cls.group_in_domain)

        # project in own domain
        cls.project_in_domain = (
            cls.admin_client.projects_client.create_project(
                name=data_utils.rand_name('project'),
                domain_id=cls.own_domain)['project']['id'])
        cls.addClassResourceCleanup(
            cls.admin_client.projects_client.delete_project,
            cls.project_in_domain)

        # stuff in arbitrary domain, useful for testing system users' access to
        # arbitrary domain and domain users non-access to domains they don't
        # belong to
        # user in other domain
        cls.user_other_domain = cls.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=cls.other_domain)['user']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.users_v3_client.delete_user,
            cls.user_other_domain)

        # group in other domain
        cls.group_other_domain = cls.admin_client.groups_client.create_group(
            name=data_utils.rand_name('group'),
            domain_id=cls.other_domain)['group']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.groups_client.delete_group,
            cls.group_other_domain)

        # project in other domain
        cls.project_other_domain = (
            cls.admin_client.projects_client.create_project(
                name=data_utils.rand_name('project'),
                domain_id=cls.other_domain)['project']['id'])
        cls.addClassResourceCleanup(
            cls.admin_client.projects_client.delete_project,
            cls.project_other_domain)

        # assignments
        roles_client = cls.admin_client.roles_v3_client
        roles_client.create_user_role_on_project(
            cls.project_in_domain,
            cls.user_in_domain,
            cls.role_id)
        roles_client.create_user_role_on_project(
            cls.project_in_domain,
            cls.user_other_domain,
            cls.role_id)
        roles_client.create_user_role_on_project(
            cls.project_other_domain,
            cls.user_in_domain,
            cls.role_id)
        roles_client.create_user_role_on_project(
            cls.project_other_domain,
            cls.user_other_domain,
            cls.role_id)
        roles_client.create_user_role_on_domain(
            cls.own_domain,
            cls.user_in_domain,
            cls.role_id)
        roles_client.create_user_role_on_domain(
            cls.own_domain,
            cls.user_other_domain,
            cls.role_id)
        roles_client.create_user_role_on_domain(
            cls.other_domain,
            cls.user_in_domain,
            cls.role_id)
        roles_client.create_user_role_on_domain(
            cls.other_domain,
            cls.user_other_domain,
            cls.role_id)
        roles_client.create_user_role_on_system(
            cls.user_in_domain,
            cls.role_id)
        roles_client.create_user_role_on_system(
            cls.user_other_domain,
            cls.role_id)
        roles_client.create_user_role_on_project(
            cls.project_in_domain,
            cls.user_in_domain,
            cls.role_own_domain)
        roles_client.create_user_role_on_project(
            cls.project_in_domain,
            cls.user_other_domain,
            cls.role_own_domain)
        roles_client.create_user_role_on_project(
            cls.project_other_domain,
            cls.user_in_domain,
            cls.role_other_domain)
        roles_client.create_user_role_on_project(
            cls.project_other_domain,
            cls.user_other_domain,
            cls.role_other_domain)
        roles_client.create_user_role_on_domain(
            cls.own_domain,
            cls.user_in_domain,
            cls.role_own_domain)
        roles_client.create_user_role_on_domain(
            cls.own_domain,
            cls.user_other_domain,
            cls.role_own_domain)
        roles_client.create_user_role_on_domain(
            cls.other_domain,
            cls.user_in_domain,
            cls.role_other_domain)
        roles_client.create_user_role_on_domain(
            cls.other_domain,
            cls.user_other_domain,
            cls.role_other_domain)
        roles_client.create_group_role_on_project(
            cls.project_in_domain,
            cls.group_in_domain,
            cls.role_id)
        roles_client.create_group_role_on_project(
            cls.project_in_domain,
            cls.group_other_domain,
            cls.role_id)
        roles_client.create_group_role_on_project(
            cls.project_other_domain,
            cls.group_in_domain,
            cls.role_id)
        roles_client.create_group_role_on_project(
            cls.project_other_domain,
            cls.group_other_domain,
            cls.role_id)
        roles_client.create_group_role_on_domain(
            cls.own_domain,
            cls.group_in_domain,
            cls.role_id)
        roles_client.create_group_role_on_domain(
            cls.own_domain,
            cls.group_other_domain,
            cls.role_id)
        roles_client.create_group_role_on_domain(
            cls.other_domain,
            cls.group_in_domain,
            cls.role_id)
        roles_client.create_group_role_on_domain(
            cls.other_domain,
            cls.group_other_domain,
            cls.role_id)
        roles_client.create_group_role_on_system(
            cls.group_in_domain,
            cls.role_id)
        roles_client.create_group_role_on_system(
            cls.group_other_domain,
            cls.role_id)
        roles_client.create_group_role_on_project(
            cls.project_in_domain,
            cls.group_in_domain,
            cls.role_own_domain)
        roles_client.create_group_role_on_project(
            cls.project_in_domain,
            cls.group_other_domain,
            cls.role_own_domain)
        roles_client.create_group_role_on_project(
            cls.project_other_domain,
            cls.group_in_domain,
            cls.role_other_domain)
        roles_client.create_group_role_on_project(
            cls.project_other_domain,
            cls.group_other_domain,
            cls.role_other_domain)
        roles_client.create_group_role_on_domain(
            cls.own_domain,
            cls.group_in_domain,
            cls.role_own_domain)
        roles_client.create_group_role_on_domain(
            cls.own_domain,
            cls.group_other_domain,
            cls.role_own_domain)
        roles_client.create_group_role_on_domain(
            cls.other_domain,
            cls.group_in_domain,
            cls.role_other_domain)
        roles_client.create_group_role_on_domain(
            cls.other_domain,
            cls.group_other_domain,
            cls.role_other_domain)

    @abc.abstractmethod
    def test_identity_check_grant(self):
        """Test identity:check_grant policy.

        This test must check:
          * whether the persona can check a grant for

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |  X   |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |  X   |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass

    @abc.abstractmethod
    def test_identity_list_grants(self):
        """Test identity:list_grants policy.

        This test must check:
          * whether the persona can list grants for
                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |      |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |      |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass

    @abc.abstractmethod
    def test_identity_create_grant(self):
        """Test identity:create_grant policy.

        This test must check:
          * whether the persona can create a grant of

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |  X   |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |  X   |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+

        """
        pass

    @abc.abstractmethod
    def test_identity_revoke_grant(self):
        """Test identity:revoke_grant policy.

        This test must check:
          * whether the persona can revoke a grant for

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |  X   |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |  X   |  X   |  X    |   X     |   X    |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass

    @abc.abstractmethod
    def test_identity_list_system_grants_for_user(self):
        """Test identity:list_system_grants_for_user policy.

        This test must check:
          * whether the persona can list grants for

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |  X   |       |         |        |  X     |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |      |  X   |       |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |      |  X   |       |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass

    @abc.abstractmethod
    def test_identity_check_system_grant_for_user(self):
        """Test identity:check_system_grant_for_user policy.

        This test must check:
          * whether the persona can check a grant for

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |  X   |       |         |        |  X     |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |  X   |  X   |       |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |  X   |  X   |       |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass

    @abc.abstractmethod
    def test_identity_create_system_grant_for_user(self):
        """Test identity:create_system_grant_for_user policy.

        This test must check:
          * whether the persona can create a grant for

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |  X   |       |         |        |  X     |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |  X   |  X   |       |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |  X   |  X   |       |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass

    @abc.abstractmethod
    def test_identity_revoke_system_grant_for_user(self):
        """Test identity:revoke_system_grant_for_user policy.

        This test must check:
          * whether the persona can revoke a grant for

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |  X   |       |         |        |  X     |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |  X   |  X   |       |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |  X   |  X   |       |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass

    @abc.abstractmethod
    def test_identity_list_system_grants_for_group(self):
        """Test identity:list_system_grants_for_group policy.

        This test must check:
          * whether the persona can list grants for

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |      |  X    |         |        |  X     |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |      |      |  X    |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |      |      |  X    |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass

    @abc.abstractmethod
    def test_identity_check_system_grant_for_group(self):
        """Test identity:check_system_grant_for_group policy.

        This test must check:
          * whether the persona can check a grant for

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |      |  X    |         |        |  X     |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |  X   |      |  X    |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |  X   |      |  X    |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass

    @abc.abstractmethod
    def test_identity_create_system_grant_for_group(self):
        """Test identity:create_system_grant_for_group policy.

        This test must check:
          * whether the persona can create a grant for

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |      |  X    |         |        |  X     |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |  X   |      |  X    |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |  X   |      |  X    |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass

    @abc.abstractmethod
    def test_identity_revoke_system_grant_for_group(self):
        """Test identity:revoke_system_grant_for_group policy.

        This test must check:
          * whether the persona can revoke a grant for

                         +------+------+-------+---------+--------+--------+
                         | Role | User | Group | Project | Domain | System |
          +--------------+------+------+-------+---------+--------+--------+
          | global       |  X   |      |  X    |         |        |  X     |
          +--------------+------+------+-------+---------+--------+--------+
          | own domain   |  X   |      |  X    |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
          | other domain |  X   |      |  X    |         |        |        |
          +--------------+------+------+-------+---------+--------+--------+
        """
        pass


class SystemAdminTests(IdentityV3RbacGrantTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_check_grant(self):
        # global role, arbitrary project, arbitrary user
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=204,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary project, arbitrary group
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=204,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary user
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=204,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary group
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=204,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)

        # domain-specific role not matching arbitrary project, arbitrary group
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.NotFound,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # domain-specific role not matching arbitrary project, arbitrary group
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.NotFound,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # domain-specific role not matching arbitrary domain, arbitrary user
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.NotFound,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # domain-specific role not matching arbitrary domain, arbitrary group
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.NotFound,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)

        # domain-specific role, arbitrary project, arbitrary user
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=204,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary project, arbitrary group
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=204,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary domain, arbitrary user
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=204,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary domain, arbitrary group
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=204,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)

    def test_identity_list_grants(self):
        # arbitrary project, arbitrary user
        self.do_request(
            'list_user_roles_on_project',
            project_id=self.project_other_domain,
            user_id=self.user_other_domain)
        # arbitrary project, arbitrary group
        self.do_request(
            'list_group_roles_on_project',
            project_id=self.project_other_domain,
            group_id=self.group_other_domain)
        # arbitrary domain, arbitrary user
        self.do_request(
            'list_user_roles_on_domain',
            domain_id=self.other_domain,
            user_id=self.user_other_domain)
        # arbitrary domain, arbitrary group
        self.do_request(
            'list_group_roles_on_domain',
            domain_id=self.other_domain,
            group_id=self.group_other_domain)
        # other domain-specific tests not applicable to system user

    def test_identity_create_grant(self):
        # global role, arbitrary project, arbitrary user
        self.do_request(
            'create_user_role_on_project',
            expected_status=204,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_project,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary project, arbitrary group
        self.do_request(
            'create_group_role_on_project',
            expected_status=204,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_project,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary user
        self.do_request(
            'create_user_role_on_domain',
            expected_status=204,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_domain,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary group
        self.do_request(
            'create_group_role_on_domain',
            expected_status=204,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_domain,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # domain-specific, arbitrary project, arbitrary user
        self.do_request(
            'create_user_role_on_project',
            expected_status=204,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_project,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific, arbitrary project, arbitrary group
        self.do_request(
            'create_group_role_on_project',
            expected_status=204,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_project,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # domain-specific, arbitrary domain, arbitrary user
        self.do_request(
            'create_user_role_on_domain',
            expected_status=204,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_domain,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific, arbitrary domain, arbitrary group
        self.do_request(
            'create_group_role_on_domain',
            expected_status=204,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_domain,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # other domain-specific tests not applicable to system user

    def test_identity_revoke_grant(self):
        # global role, arbitrary project, arbitrary user
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=204,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary project, arbitrary group
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=204,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary user
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=204,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary group
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=204,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # domain-specific role, arbitrary project, arbitrary user
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=204,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary project, arbitrary group
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=204,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary domain, arbitrary user
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=204,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary domain, arbitrary group
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=204,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # other domain-specific tests not applicable to system user

    def test_identity_list_system_grants_for_user(self):
        self.do_request('list_user_roles_on_system',
                        user_id=self.user_other_domain)

    def test_identity_check_system_grant_for_user(self):
        self.do_request('check_user_role_existence_on_system',
                        expected_status=204,
                        user_id=self.user_other_domain,
                        role_id=self.role_id)

    def test_identity_create_system_grant_for_user(self):
        self.do_request(
            'create_user_role_on_system',
            expected_status=204,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_system,
            user_id=self.user_other_domain,
            role_id=self.role_id)

    def test_identity_revoke_system_grant_for_user(self):
        self.admin_roles_client.create_user_role_on_system(
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_system',
            expected_status=204,
            user_id=self.user_other_domain,
            role_id=self.role_id)

    def test_identity_list_system_grants_for_group(self):
        self.do_request('list_group_roles_on_system',
                        group_id=self.group_other_domain)

    def test_identity_check_system_grant_for_group(self):
        self.do_request('check_role_from_group_on_system_existence',
                        expected_status=204,
                        group_id=self.group_other_domain,
                        role_id=self.role_id)

    def test_identity_create_system_grant_for_group(self):
        self.do_request(
            'create_group_role_on_system',
            expected_status=204,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_system,
            group_id=self.group_other_domain,
            role_id=self.role_id)

    def test_identity_revoke_system_grant_for_group(self):
        self.admin_roles_client.create_group_role_on_system(
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_system',
            expected_status=204,
            group_id=self.group_other_domain,
            role_id=self.role_id)


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_grant(self):
        # global role, arbitrary project, arbitrary user
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_project,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary project, arbitrary group
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_project,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary user
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_domain,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary group
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_domain,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # domain-specific, arbitrary project, arbitrary user
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_project,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific, arbitrary project, arbitrary group
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_project,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # domain-specific, arbitrary domain, arbitrary user
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_domain,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific, arbitrary domain, arbitrary group
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_domain,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # other domain-specific tests not applicable to system user

    def test_identity_revoke_grant(self):
        # global role, arbitrary project, arbitrary user
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary project, arbitrary group
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary user
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary group
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # domain-specific role, arbitrary project, arbitrary user
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary project, arbitrary group
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary domain, arbitrary user
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary domain, arbitrary group
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # other domain-specific tests not applicable to system user

    def test_identity_create_system_grant_for_user(self):
        self.do_request(
            'create_user_role_on_system',
            expected_status=exceptions.Forbidden,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_system,
            user_id=self.user_other_domain,
            role_id=self.role_id)

    def test_identity_revoke_system_grant_for_user(self):
        self.admin_roles_client.create_user_role_on_system(
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_system,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_system',
            expected_status=exceptions.Forbidden,
            user_id=self.user_other_domain,
            role_id=self.role_id)

    def test_identity_create_system_grant_for_group(self):
        self.do_request(
            'create_group_role_on_system',
            expected_status=exceptions.Forbidden,
            group_id=self.group_other_domain,
            role_id=self.role_id)

    def test_identity_revoke_system_grant_for_group(self):
        self.admin_roles_client.create_group_role_on_system(
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_system,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_system',
            expected_status=exceptions.Forbidden,
            group_id=self.group_other_domain,
            role_id=self.role_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(IdentityV3RbacGrantTest, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_check_grant(self):
        ###################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OWN DOMAIN #
        ###################################################
        # global role, project in own domain, user in own domain
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=204,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, project in own domain, group in own domain
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=204,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # global role, own domain, user in own domain
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=204,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, own domain, group in own domain
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=204,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # role in own domain, project in own domain, user in own domain
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=204,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in own domain, group in own domain
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=204,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, domain in own domain, user in own domain
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=204,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, domain in own domain, group in own domain
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=204,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in own domain, user in own domain
        # (none created, should 403)
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in own domain, group in own domain
        # (none created, should 403)
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, domain in own domain, user in own domain
        # (none created, should 403)
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, domain in own domain, group in own domain
        # (none created, should 403)
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        #####################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OTHER DOMAIN #
        #####################################################
        # global role, project in own domain, user in other domain
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, project in own domain, group in other domain
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, own domain, user in other domain
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, own domain, group in other domain
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # role in own domain, project in own domain, user in other domain
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in own domain, group in other domain
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, domain in own domain, user in other domain
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, domain in own domain, group in other domain
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in own domain, user in other domain
        # (none created, should 403)
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in own domain, group in other domain
        # (none created, should 403)
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, domain in own domain, user in other domain
        # (none created, should 403)
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, domain in own domain, group in other domain
        # (none created, should 403)
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)

        #####################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OWN DOMAIN #
        #####################################################
        # global role, project in other domain, user in own domain
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, project in other domain, group in own domain
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # global role, other domain, user in own domain
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, other domain, group in own domain
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # role in own domain, project in other domain, user in own domain
        # (none created, should 403)
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in other domain, group in own domain
        # (none created, should 403)
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, user in own domain
        # (none created, should 403)
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, group in own domain
        # (none created, should 403)
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in other domain, user in own domain
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in other domain, group in own domain
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, user in own domain
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, group in own domain
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        #######################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OTHER DOMAIN #
        #######################################################
        # global role, project in other domain, user in other domain
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, project in other domain, group in other domain
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, other domain, user in other domain
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, other domain, group in other domain
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # role in own domain, project in other domain, user in other domain
        # (none created, should 403)
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in other domain, group in other domain
        # (none created, should 403)
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, user in other domain
        # (none created, should 403)
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, group in other domain
        # (none created, should 403)
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in other domain, user in other domain
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in other domain, group in other domain
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, user in other domain
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, group in other domain
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)

    def test_identity_list_grants(self):
        ###################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OWN DOMAIN #
        ###################################################
        # project in other domain, user in other domain
        self.do_request(
            'list_user_roles_on_project',
            project_id=self.project_in_domain,
            user_id=self.user_in_domain)
        # project in other domain, group in other domain
        self.do_request(
            'list_group_roles_on_project',
            project_id=self.project_in_domain,
            group_id=self.group_in_domain)
        # other domain, user in other domain
        self.do_request(
            'list_user_roles_on_domain',
            domain_id=self.own_domain,
            user_id=self.user_in_domain)
        # other domain, group in other domain
        self.do_request(
            'list_group_roles_on_domain',
            domain_id=self.own_domain,
            group_id=self.group_in_domain)
        #####################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OTHER DOMAIN #
        #####################################################
        # project in other domain, user in other domain
        self.do_request(
            'list_user_roles_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain)
        # project in other domain, group in other domain
        self.do_request(
            'list_group_roles_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain)
        # other domain, user in other domain
        self.do_request(
            'list_user_roles_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain)
        # other domain, group in other domain
        self.do_request(
            'list_group_roles_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain)
        #####################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OWN DOMAIN #
        #####################################################
        # project in other domain, user in other domain
        self.do_request(
            'list_user_roles_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain)
        # project in other domain, group in other domain
        self.do_request(
            'list_group_roles_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain)
        # other domain, user in other domain
        self.do_request(
            'list_user_roles_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain)
        # other domain, group in other domain
        self.do_request(
            'list_group_roles_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain)
        #######################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OTHER DOMAIN #
        #######################################################
        # project in other domain, user in other domain
        self.do_request(
            'list_user_roles_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain)
        # project in other domain, group in other domain
        self.do_request(
            'list_group_roles_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain)
        # other domain, user in other domain
        self.do_request(
            'list_user_roles_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain)
        # other domain, group in other domain
        self.do_request(
            'list_group_roles_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain)

    def test_identity_create_grant(self):
        ###################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OWN DOMAIN #
        ###################################################
        # global role, project in own domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=204,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, project in own domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=204,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # global role, own domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=204,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, own domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=204,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # role in own domain, project in own domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=204,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in own domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=204,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=204,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=204,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in own domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in own domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        #####################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OTHER DOMAIN #
        #####################################################
        # global role, project in own domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, project in own domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, own domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, own domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # role in own domain, project in own domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in own domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in own domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in own domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        #####################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OWN DOMAIN #
        #####################################################
        # global role, project in other domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, project in other domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # global role, other domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, other domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # role in own domain, project in other domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in other domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in other domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in other domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        #######################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OTHER DOMAIN #
        #######################################################
        # global role, project in other domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, project in other domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, other domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, other domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # role in own domain, project in other domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in other domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in other domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in other domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)

    def test_identity_revoke_grant(self):
        ###################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OWN DOMAIN #
        ###################################################
        # global role, project in own domain, user in own domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=204,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, project in own domain, group in own domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=204,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # global role, own domain, user in own domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=204,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, own domain, group in own domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=204,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # role in own domain, project in own domain, user in own domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=204,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in own domain, group in own domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=204,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, user in own domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=204,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, group in own domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=204,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in own domain, user in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in own domain, group in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, user in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, group in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        #####################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OTHER DOMAIN #
        #####################################################
        # global role, project in own domain, user in other domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, project in own domain, group in other domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, own domain, user in other domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, own domain, group in other domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # role in own domain, project in own domain, user in other domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in own domain, group in other domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, user in other domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, group in other domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in own domain, user in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in own domain, group in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, user in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, group in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        #####################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OWN DOMAIN #
        #####################################################
        # global role, project in other domain, user in own domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, project in other domain, group in own domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # global role, other domain, user in own domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, other domain, group in own domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # role in own domain, project in other domain, user in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in other domain, group in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, user in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, group in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in other domain, user in own domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in other domain, group in own domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, user in own domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, group in own domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        #######################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OTHER DOMAIN #
        #######################################################
        # global role, project in other domain, user in other domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, project in other domain, group in other domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, other domain, user in other domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, other domain, group in other domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # role in own domain, project in other domain, user in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in other domain, group in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, user in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, group in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in other domain, user in other domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in other domain, group in other domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, user in other domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, group in other domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)

    def test_identity_list_system_grants_for_user(self):
        self.do_request('list_user_roles_on_system',
                        expected_status=exceptions.Forbidden,
                        user_id=self.user_other_domain)
        self.do_request('list_user_roles_on_system',
                        expected_status=exceptions.Forbidden,
                        user_id=self.user_other_domain)

    def test_identity_check_system_grant_for_user(self):
        self.do_request('check_user_role_existence_on_system',
                        exceptions.Forbidden,
                        user_id=self.user_other_domain,
                        role_id=self.role_id)
        self.do_request('check_user_role_existence_on_system',
                        exceptions.Forbidden,
                        user_id=self.user_other_domain,
                        role_id=self.role_id)

    def test_identity_create_system_grant_for_user(self):
        self.do_request(
            'create_user_role_on_system',
            expected_status=exceptions.Forbidden,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'create_user_role_on_system',
            expected_status=exceptions.Forbidden,
            user_id=self.user_other_domain,
            role_id=self.role_id)

    def test_identity_revoke_system_grant_for_user(self):
        # user in own domain
        self.admin_roles_client.create_user_role_on_system(
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_system,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_system',
            expected_status=exceptions.Forbidden,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # user in other domain
        self.admin_roles_client.create_user_role_on_system(
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_system,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_system',
            expected_status=exceptions.Forbidden,
            user_id=self.user_other_domain,
            role_id=self.role_id)

    def test_identity_list_system_grants_for_group(self):
        self.do_request('list_group_roles_on_system',
                        expected_status=exceptions.Forbidden,
                        group_id=self.group_in_domain)
        self.do_request('list_group_roles_on_system',
                        expected_status=exceptions.Forbidden,
                        group_id=self.group_other_domain)

    def test_identity_check_system_grant_for_group(self):
        self.do_request('check_role_from_group_on_system_existence',
                        exceptions.Forbidden,
                        group_id=self.group_other_domain,
                        role_id=self.role_id)
        self.do_request('check_role_from_group_on_system_existence',
                        exceptions.Forbidden,
                        group_id=self.group_other_domain,
                        role_id=self.role_id)

    def test_identity_create_system_grant_for_group(self):
        self.do_request(
            'create_group_role_on_system',
            expected_status=exceptions.Forbidden,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'create_group_role_on_system',
            expected_status=exceptions.Forbidden,
            group_id=self.group_other_domain,
            role_id=self.role_id)

    def test_identity_revoke_system_grant_for_group(self):
        # group in own domain
        self.admin_roles_client.create_group_role_on_system(
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_system,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_system',
            expected_status=exceptions.Forbidden,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # group in other domain
        self.admin_roles_client.create_group_role_on_system(
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_system,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_system',
            expected_status=exceptions.Forbidden,
            group_id=self.group_other_domain,
            role_id=self.role_id)


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']

    def test_identity_create_grant(self):
        ###################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OWN DOMAIN #
        ###################################################
        # global role, project in own domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, project in own domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # global role, own domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, own domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # role in own domain, project in own domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in own domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in own domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in own domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        #####################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OTHER DOMAIN #
        #####################################################
        # global role, project in own domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, project in own domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, own domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, own domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # role in own domain, project in own domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in own domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in own domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in own domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        #####################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OWN DOMAIN #
        #####################################################
        # global role, project in other domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, project in other domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # global role, other domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, other domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # role in own domain, project in other domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in other domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in other domain, user in own domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in other domain, group in own domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, user in own domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, group in own domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        #######################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OTHER DOMAIN #
        #######################################################
        # global role, project in other domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, project in other domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, other domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, other domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # role in own domain, project in other domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in other domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in other domain, user in other domain
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in other domain, group in other domain
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, user in other domain
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, group in other domain
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)

    def test_identity_revoke_grant(self):
        ###################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OWN DOMAIN #
        ###################################################
        # global role, project in own domain, user in own domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, project in own domain, group in own domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # global role, own domain, user in own domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, own domain, group in own domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # role in own domain, project in own domain, user in own domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in own domain, group in own domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, user in own domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, group in own domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in own domain, user in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in own domain, group in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, user in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, group in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        #####################################################
        # RESOURCE IN OWN DOMAIN - IDENTITY IN OTHER DOMAIN #
        #####################################################
        # global role, project in own domain, user in other domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, project in own domain, group in other domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, own domain, user in other domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, own domain, group in other domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # role in own domain, project in own domain, user in other domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in own domain, group in other domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, user in other domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, own domain, group in other domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in own domain, user in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in own domain, group in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_in_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, user in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, own domain, group in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.own_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        #####################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OWN DOMAIN #
        #####################################################
        # global role, project in other domain, user in own domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, project in other domain, group in own domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # global role, other domain, user in own domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        # global role, other domain, group in own domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # role in own domain, project in other domain, user in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in other domain, group in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, user in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, group in own domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in other domain, user in own domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in other domain, group in own domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, user in own domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_in_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, group in own domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_in_domain,
            role_id=self.role_other_domain)
        #######################################################
        # RESOURCE IN OTHER DOMAIN - IDENTITY IN OTHER DOMAIN #
        #######################################################
        # global role, project in other domain, user in other domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, project in other domain, group in other domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, other domain, user in other domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, other domain, group in other domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # role in own domain, project in other domain, user in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, project in other domain, group in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, user in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # role in own domain, other domain, group in other domain
        # role assignment does not exist, should 403
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # role in other domain, project in other domain, user in other domain
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, project in other domain, group in other domain
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, user in other domain
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # role in other domain, other domain, group in other domain
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)

    def test_identity_create_system_grant_for_user(self):
        self.do_request(
            'create_user_role_on_system',
            expected_status=exceptions.Forbidden,
            user_id=self.user_in_domain,
            role_id=self.role_id)
        self.do_request(
            'create_user_role_on_system',
            expected_status=exceptions.Forbidden,
            user_id=self.user_other_domain,
            role_id=self.role_id)

    def test_identity_revoke_system_grant_for_user(self):
        # group in own domain
        self.admin_roles_client.create_group_role_on_system(
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_system,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_system',
            expected_status=exceptions.Forbidden,
            group_id=self.group_in_domain,
            role_id=self.role_id)
        # group in other domain
        self.admin_roles_client.create_group_role_on_system(
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_system,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_system',
            expected_status=exceptions.Forbidden,
            group_id=self.group_other_domain,
            role_id=self.role_id)


class DomainReaderTests(DomainMemberTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(IdentityV3RbacGrantTest, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']

    def test_identity_check_grant(self):
        # global role, arbitrary project, arbitrary user
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary project, arbitrary group
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary user
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary group
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)

        # domain-specific role not matching arbitrary project, arbitrary group
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # domain-specific role not matching arbitrary project, arbitrary group
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)
        # domain-specific role not matching arbitrary domain, arbitrary user
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_own_domain)
        # domain-specific role not matching arbitrary domain, arbitrary group
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_own_domain)

        # domain-specific role, arbitrary project, arbitrary user
        self.do_request(
            'check_user_role_existence_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary project, arbitrary group
        self.do_request(
            'check_role_from_group_on_project_existence',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary domain, arbitrary user
        self.do_request(
            'check_user_role_existence_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary domain, arbitrary group
        self.do_request(
            'check_role_from_group_on_domain_existence',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)

    def test_identity_list_grants(self):
        # arbitrary project, arbitrary user
        self.do_request(
            'list_user_roles_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain)
        # arbitrary project, arbitrary group
        self.do_request(
            'list_group_roles_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain)
        # arbitrary domain, arbitrary user
        self.do_request(
            'list_user_roles_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain)
        # arbitrary domain, arbitrary group
        self.do_request(
            'list_group_roles_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain)
        # other domain-specific tests not applicable to system user

    def test_identity_create_grant(self):
        # global role, arbitrary project, arbitrary user
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary project, arbitrary group
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary user
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary group
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # domain-specific, arbitrary project, arbitrary user
        self.do_request(
            'create_user_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_project,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific, arbitrary project, arbitrary group
        self.do_request(
            'create_group_role_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_group_on_project,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # domain-specific, arbitrary domain, arbitrary user
        self.do_request(
            'create_user_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.addCleanup(
            self.admin_roles_client.delete_role_from_user_on_domain,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific, arbitrary domain, arbitrary group
        self.do_request(
            'create_group_role_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # other domain-specific tests not applicable to system user

    def test_identity_revoke_grant(self):
        # global role, arbitrary project, arbitrary user
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary project, arbitrary group
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary user
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_id)
        # global role, arbitrary domain, arbitrary group
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_id)
        # domain-specific role, arbitrary project, arbitrary user
        self.admin_roles_client.create_user_role_on_project(
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary project, arbitrary group
        self.admin_roles_client.create_group_role_on_project(
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_project',
            expected_status=exceptions.Forbidden,
            project_id=self.project_other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary domain, arbitrary user
        self.admin_roles_client.create_user_role_on_domain(
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_user_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            user_id=self.user_other_domain,
            role_id=self.role_other_domain)
        # domain-specific role, arbitrary domain, arbitrary group
        self.admin_roles_client.create_group_role_on_domain(
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        self.do_request(
            'delete_role_from_group_on_domain',
            expected_status=exceptions.Forbidden,
            domain_id=self.other_domain,
            group_id=self.group_other_domain,
            role_id=self.role_other_domain)
        # other domain-specific tests not applicable to system user

    def test_identity_list_system_grants_for_user(self):
        self.do_request('list_user_roles_on_system',
                        expected_status=exceptions.Forbidden,
                        user_id=self.user_other_domain)

    def test_identity_check_system_grant_for_user(self):
        self.do_request('check_user_role_existence_on_system',
                        exceptions.Forbidden,
                        user_id=self.user_other_domain,
                        role_id=self.role_id)

    def test_identity_create_system_grant_for_user(self):
        self.do_request(
            'create_user_role_on_system',
            expected_status=exceptions.Forbidden,
            user_id=self.user_other_domain,
            role_id=self.role_id)

    def test_identity_revoke_system_grant_for_user(self):
        self.admin_roles_client.create_user_role_on_system(
            user_id=self.user_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_user_on_system',
            exceptions.Forbidden,
            user_id=self.user_other_domain,
            role_id=self.role_id)

    def test_identity_list_system_grants_for_group(self):
        self.do_request('list_group_roles_on_system',
                        exceptions.Forbidden,
                        group_id=self.group_other_domain)

    def test_identity_check_system_grant_for_group(self):
        self.do_request('check_role_from_group_on_system_existence',
                        exceptions.Forbidden,
                        group_id=self.group_other_domain,
                        role_id=self.role_id)

    def test_identity_create_system_grant_for_group(self):
        self.do_request(
            'create_group_role_on_system',
            expected_status=exceptions.Forbidden,
            group_id=self.group_other_domain,
            role_id=self.role_id)

    def test_identity_revoke_system_grant_for_group(self):
        self.admin_roles_client.create_group_role_on_system(
            group_id=self.group_other_domain,
            role_id=self.role_id)
        self.do_request(
            'delete_role_from_group_on_system',
            expected_status=exceptions.Forbidden,
            group_id=self.group_other_domain,
            role_id=self.role_id)


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectMemberTests):

    credentials = ['project_reader', 'system_admin']
