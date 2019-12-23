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


class IdentityV3RbacAssignmentTest(rbac_base.IdentityV3RbacBaseTests,
                                   metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacAssignmentTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.role_assignments_client
        cls.admin_client = cls.os_system_admin

    @classmethod
    def resource_setup(cls):
        super(IdentityV3RbacAssignmentTest, cls).resource_setup()
        cls._setup_assignments()

    @classmethod
    def _setup_assignments(cls):
        cls.own_domain = cls.persona.credentials.domain_id
        cls.role_id = cls.admin_client.roles_v3_client.create_role(
            name=data_utils.rand_name('role'))['role']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.roles_v3_client.delete_role, cls.role_id)
        cls.user_in_domain = cls.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=cls.own_domain)['user']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.users_v3_client.delete_user,
            cls.user_in_domain)
        cls.group_in_domain = cls.admin_client.groups_client.create_group(
            name=data_utils.rand_name('group'),
            domain_id=cls.own_domain)['group']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.groups_client.delete_group,
            cls.group_in_domain)
        cls.project_in_domain = (
            cls.admin_client.projects_client.create_project(
                name=data_utils.rand_name('project'),
                domain_id=cls.own_domain)['project']['id'])
        cls.addClassResourceCleanup(
            cls.admin_client.projects_client.delete_project,
            cls.project_in_domain)
        cls.other_domain = cls.admin_client.domains_client.create_domain(
            name=data_utils.rand_name('domain'))['domain']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.delete_domain,
            cls.other_domain)
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.update_domain,
            cls.other_domain,
            enabled=False)
        cls.user_other_domain = cls.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=cls.other_domain)['user']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.users_v3_client.delete_user,
            cls.user_other_domain)
        cls.group_other_domain = cls.admin_client.groups_client.create_group(
            name=data_utils.rand_name('group'),
            domain_id=cls.other_domain)['group']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.groups_client.delete_group,
            cls.group_other_domain)
        cls.project_other_domain = (
            cls.admin_client.projects_client.create_project(
                name=data_utils.rand_name('project'),
                domain_id=cls.other_domain)['project']['id'])
        cls.addClassResourceCleanup(
            cls.admin_client.projects_client.delete_project,
            cls.project_other_domain)

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

        cls.assignments = [
            {
                'user_id': cls.user_in_domain,
                'project_id': cls.project_in_domain,
                'role_id': cls.role_id
            },
            {
                'user_id': cls.user_other_domain,
                'project_id': cls.project_in_domain,
                'role_id': cls.role_id
            },
            {
                'user_id': cls.user_in_domain,
                'project_id': cls.project_other_domain,
                'role_id': cls.role_id
            },
            {
                'user_id': cls.user_other_domain,
                'project_id': cls.project_other_domain,
                'role_id': cls.role_id
            },
            {
                'user_id': cls.user_in_domain,
                'domain_id': cls.own_domain,
                'role_id': cls.role_id
            },
            {
                'user_id': cls.user_other_domain,
                'domain_id': cls.own_domain,
                'role_id': cls.role_id
            },
            {
                'user_id': cls.user_in_domain,
                'domain_id': cls.other_domain,
                'role_id': cls.role_id
            },
            {
                'user_id': cls.user_other_domain,
                'domain_id': cls.other_domain,
                'role_id': cls.role_id
            },
            {
                'user_id': cls.user_in_domain,
                'system': 'all',
                'role_id': cls.role_id
            },
            {
                'user_id': cls.user_other_domain,
                'system': 'all',
                'role_id': cls.role_id
            },
            {
                'group_id': cls.group_in_domain,
                'project_id': cls.project_in_domain,
                'role_id': cls.role_id
            },
            {
                'group_id': cls.group_other_domain,
                'project_id': cls.project_in_domain,
                'role_id': cls.role_id
            },
            {
                'group_id': cls.group_in_domain,
                'project_id': cls.project_other_domain,
                'role_id': cls.role_id
            },
            {
                'group_id': cls.group_other_domain,
                'project_id': cls.project_other_domain,
                'role_id': cls.role_id
            },
            {
                'group_id': cls.group_in_domain,
                'domain_id': cls.own_domain,
                'role_id': cls.role_id
            },
            {
                'group_id': cls.group_other_domain,
                'domain_id': cls.own_domain,
                'role_id': cls.role_id
            },
            {
                'group_id': cls.group_in_domain,
                'domain_id': cls.other_domain,
                'role_id': cls.role_id
            },
            {
                'group_id': cls.group_other_domain,
                'domain_id': cls.other_domain,
                'role_id': cls.role_id
            },
            {
                'group_id': cls.group_in_domain,
                'system': 'all',
                'role_id': cls.role_id
            },
            {
                'group_id': cls.group_other_domain,
                'system': 'all',
                'role_id': cls.role_id
            },
        ]

    def _extract_role_assignments_from_response_body(self, r):
        # Condense the role assignment details into a set of key things we can
        # use in assertions.
        assignments = []
        for assignment in r['role_assignments']:
            a = {}
            if 'project' in assignment['scope']:
                a['project_id'] = assignment['scope']['project']['id']
            elif 'domain' in assignment['scope']:
                a['domain_id'] = assignment['scope']['domain']['id']
            elif 'system' in assignment['scope']:
                a['system'] = 'all'

            if 'user' in assignment:
                a['user_id'] = assignment['user']['id']
            elif 'group' in assignment:
                a['group_id'] = assignment['group']['id']

            a['role_id'] = assignment['role']['id']

            assignments.append(a)
        return assignments

    @abc.abstractmethod
    def test_identity_list_role_assignments(self):
        """Test identity:list_role_assignments policy.

        This test must check:
          * whether the persona can list all user and group assignments across
            the deployment
          * whether the persona can list all user and group assignments in
            a domain
          * whether the persona can list user and group assignments with names
          * whether the persona can filter user and group assignments by domain
          * whether the persona can filter user and group assignments by
            project in their own domain
          * whether the persona can filter user and group assignments by
            project in another domain
          * whether the persona can filter user and group assignments by system
          * whether the persona can filter user assignments by user in their
            own domain
          * whether the persona can filter user assignments by user in another
            domain
          * whether the persona can filter group assignments by group in their
            own domain
          * whether the persona can filter group assignments by group in
            another domain
          * whether the persona can filter role assignments by global role
          * whether the persona can filter assignments by project and role
          * whether the persona can filter assignments by domain and role
          * whether the persona can filter assignments by system and role
          * whether the persona can filter assignments by user and role
          * whether the persona can filter assignments by group and role
          * whether the persona can filter assignments by project and user
          * whether the persona can filter assignments by project and group
          * whether the persona can filter assignments by domain and user
          * whether the persona can filter assignments by domain and group

        """
        pass

    @abc.abstractmethod
    def test_identity_list_role_assignments_for_tree(self):
        """Test identity:list_role_assignments_for_tree policy.

        This test must check:
          * whether the persona can list role assignments for a subtree of a
            project in their own domain
          * whether the persona can list role assignments for a subtree of a
            project in another domain
          * whether the persona can list role assignments for a subtree of a
            project on which they have a role assignment (if applicable)
        """
        pass


class SystemAdminTests(IdentityV3RbacAssignmentTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_list_role_assignments(self):
        # Listing all assignments with no filters should return all assignments
        resp = self.do_request('list_role_assignments')
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in self.assignments:
            self.assertIn(assignment, actual)

        # Listing all assignments with names
        query = {'include_names': True}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in self.assignments:
            self.assertIn(assignment, actual)

        # Filter assignments by own domain should succeed
        expected = [a for a in self.assignments
                    if a.get('domain_id') == self.own_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.domain.id': self.own_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by other domain should succeed
        expected = [a for a in self.assignments
                    if a.get('domain_id') == self.other_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.domain.id': self.other_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by project in own domain should succeed
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.project.id': self.project_in_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by project in other domain should succeed
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_other_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.project.id': self.project_other_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by system should succeed
        expected = [a for a in self.assignments if a.get('system') == 'all']
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.system': 'all'}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by user in own domain should succeed
        expected = [a for a in self.assignments
                    if a.get('user_id') == self.user_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'user.id': self.user_in_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by user in other domain should succeed
        expected = [a for a in self.assignments
                    if a.get('user_id') == self.user_other_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'user.id': self.user_other_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by group in own domain should succeed
        expected = [a for a in self.assignments
                    if a.get('group_id') == self.group_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'group.id': self.group_in_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by group in other domain should succeed
        expected = [a for a in self.assignments
                    if a.get('group_id') == self.group_other_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'group.id': self.group_other_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by global role should succeed
        expected = self.assignments
        query = {'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        # Reverse the check: only ephemeral tempest roles should be in the list
        for assignment in actual:
            self.assertIn(assignment, expected)

        # Filter assignments by project and role should succeed
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.project.id': self.project_in_domain,
                 'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)
        # Reverse the check: only ephemeral tempest roles should be in the list
        for assignment in actual:
            self.assertIn(assignment, expected)

        # Filter assignments by domain and role should succeed
        expected = [a for a in self.assignments
                    if a.get('domain_id') == self.other_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.domain.id': self.other_domain, 'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)
        # Reverse the check: only ephemeral tempest roles should be in the list
        for assignment in actual:
            self.assertIn(assignment, expected)

        # Filter assignments by system and role should succeed
        expected = [a for a in self.assignments if a.get('system') == 'all']
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.system': 'all', 'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)
        # Reverse the check: only ephemeral tempest roles should be in the list
        for assignment in actual:
            self.assertIn(assignment, expected)

        # Filter assignments by user and role should succeed
        expected = [a for a in self.assignments
                    if a.get('user_id') == self.user_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'user.id': self.user_in_domain, 'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)
        # Reverse the check: only ephemeral tempest roles should be in the list
        for assignment in actual:
            self.assertIn(assignment, expected)

        # Filter assignments by group and role should succeed
        expected = [a for a in self.assignments
                    if a.get('group_id') == self.group_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'group.id': self.group_in_domain, 'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)
        # Reverse the check: only ephemeral tempest roles should be in the list
        for assignment in actual:
            self.assertIn(assignment, expected)

        # Filter assignments by project and user should succeed
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_in_domain
                    and a.get('user_id') == self.user_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'user.id': self.user_in_domain,
                 'scope.project.id': self.project_in_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by project and group should succeed
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_in_domain
                    and a.get('group_id') == self.group_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'group.id': self.group_in_domain,
                 'scope.project.id': self.project_in_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by domain and user should succeed
        expected = [a for a in self.assignments
                    if a.get('domain_id') == self.own_domain
                    and a.get('user_id') == self.user_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'user.id': self.user_in_domain,
                 'scope.domain.id': self.own_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by domain and group should succeed
        expected = [a for a in self.assignments
                    if a.get('domain_id') == self.own_domain
                    and a.get('group_id') == self.group_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'group.id': self.group_in_domain,
                 'scope.domain.id': self.own_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

    def test_identity_list_role_assignments_for_tree(self):
        # Should see subtree assignments for project in own domain
        subproject_id = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'),
            domain_id=self.own_domain,
            parent_id=self.project_in_domain)['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        subproject_id)
        self.admin_client.roles_v3_client.create_user_role_on_project(
            subproject_id, self.user_in_domain, self.role_id)
        query = {'scope.project.id': self.project_in_domain,
                 'include_subtree': True}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        expected_assignment = {'user_id': self.user_in_domain,
                               'project_id': subproject_id,
                               'role_id': self.role_id}
        self.assertIn(expected_assignment, actual)

        # Should see subtree assignments for project in other domain
        subproject_id = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'),
            domain_id=self.other_domain,
            parent_id=self.project_other_domain)['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        subproject_id)
        self.admin_client.roles_v3_client.create_user_role_on_project(
            subproject_id, self.user_in_domain, self.role_id)
        query = {'scope.project.id': self.project_other_domain,
                 'include_subtree': True}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        expected_assignment = {'user_id': self.user_in_domain,
                               'project_id': subproject_id,
                               'role_id': self.role_id}
        self.assertIn(expected_assignment, actual)


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(IdentityV3RbacAssignmentTest, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_list_role_assignments(self):
        # Listing all assignments with no filters should only return
        # assignments in own domain
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_in_domain
                    or a.get('domain_id') == self.own_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        resp = self.do_request('list_role_assignments')
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Listing all assignments with names and no filters should only return
        # assignments in own domain
        query = {'include_names': True}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by own domain should succeed
        expected = [a for a in self.assignments
                    if a.get('domain_id') == self.own_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.domain.id': self.own_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by other domain should be empty
        query = {'scope.domain.id': self.other_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        self.assertEmpty(actual)

        # Filter assignments by project in own domain should succeed
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.project.id': self.project_in_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by project in other domain should be empty
        query = {'scope.project.id': self.project_other_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        self.assertEmpty(actual)

        # Filter assignments by system should be empty
        query = {'scope.system': 'all'}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        self.assertEmpty(actual)

        # Filter assignments by user in own domain should get assignments for
        # that user only for projects in own domain or for own domain itself
        expected = [a for a in self.assignments
                    if a.get('user_id') == self.user_in_domain
                    and (a.get('project_id') == self.project_in_domain
                         or a.get('domain_id') == self.own_domain)]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'user.id': self.user_in_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by user in other domain should still work but only
        # return assignments for projects in own domain or for own domain
        # itself
        expected = [a for a in self.assignments
                    if a.get('user_id') == self.user_other_domain
                    and (a.get('project_id') == self.project_in_domain
                         or a.get('domain_id') == self.own_domain)]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'user.id': self.user_other_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by group in own domain should succeed
        expected = [a for a in self.assignments
                    if a.get('group_id') == self.group_in_domain
                    and (a.get('project_id') == self.project_in_domain
                         or a.get('domain_id') == self.own_domain)]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'group.id': self.group_in_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by group in other domain should still work but
        # only return assignments for projects in own domain or for own domain
        # itself
        expected = [a for a in self.assignments
                    if a.get('group_id') == self.group_other_domain
                    and (a.get('project_id') == self.project_in_domain
                         or a.get('domain_id') == self.own_domain)]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'group.id': self.group_other_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by global role should only return role
        # assignments for own domain
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_in_domain
                    or a.get('domain_id') == self.own_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by project and role should succeed
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.project.id': self.project_in_domain,
                 'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)
        # Reverse the check: only ephemeral tempest roles should be in the list
        for assignment in actual:
            self.assertIn(assignment, expected)

        # Filter assignments by domain and role should succeed
        expected = [a for a in self.assignments
                    if a.get('domain_id') == self.other_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'scope.domain.id': self.other_domain, 'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)
        # Reverse the check: only ephemeral tempest roles should be in the list
        for assignment in actual:
            self.assertIn(assignment, expected)

        # Filter assignments by system and role should be empty
        query = {'scope.system': 'all', 'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        self.assertEmpty(actual)

        # Filter assignments by user and role should should get assignments for
        # that user only for projects in own domain or for own domain itself
        expected = [a for a in self.assignments
                    if a.get('user_id') == self.user_in_domain
                    and (a.get('project_id') == self.project_in_domain
                         or a.get('domain_id') == self.own_domain)]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'user.id': self.user_in_domain, 'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)
        # Reverse the check: only ephemeral tempest roles should be in the list
        for assignment in actual:
            self.assertIn(assignment, expected)

        # Filter assignments by group and role should get assignments for
        # that group only for projects in own domain or for own domain itself
        expected = [a for a in self.assignments
                    if a.get('group_id') == self.group_in_domain
                    and (a.get('project_id') == self.project_in_domain
                         or a.get('domain_id') == self.own_domain)]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'group.id': self.group_in_domain, 'role.id': self.role_id}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)
        # Reverse the check: only ephemeral tempest roles should be in the list
        for assignment in actual:
            self.assertIn(assignment, expected)

        # Filter assignments by project and user should succeed
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_in_domain
                    and a.get('user_id') == self.user_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'user.id': self.user_in_domain,
                 'scope.project.id': self.project_in_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by project and group should succeed
        expected = [a for a in self.assignments
                    if a.get('project_id') == self.project_in_domain
                    and a.get('group_id') == self.group_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'group.id': self.group_in_domain,
                 'scope.project.id': self.project_in_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by domain and user should succeed
        expected = [a for a in self.assignments
                    if a.get('domain_id') == self.own_domain
                    and a.get('user_id') == self.user_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'user.id': self.user_in_domain,
                 'scope.domain.id': self.own_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

        # Filter assignments by domain and group should succeed
        expected = [a for a in self.assignments
                    if a.get('domain_id') == self.own_domain
                    and a.get('group_id') == self.group_in_domain]
        not_expected = [a for a in self.assignments if a not in expected]
        query = {'group.id': self.group_in_domain,
                 'scope.domain.id': self.own_domain}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        for assignment in expected:
            self.assertIn(assignment, actual)
        for assignment in not_expected:
            self.assertNotIn(assignment, actual)

    def test_identity_list_role_assignments_for_tree(self):
        # Should see subtree assignments for project in own domain
        subproject_id = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'),
            domain_id=self.own_domain,
            parent_id=self.project_in_domain)['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        subproject_id)
        self.admin_client.roles_v3_client.create_user_role_on_project(
            subproject_id, self.user_in_domain, self.role_id)
        query = {'scope.project.id': self.project_in_domain,
                 'include_subtree': True}
        resp = self.do_request('list_role_assignments', **query)
        actual = self._extract_role_assignments_from_response_body(resp)
        expected_assignment = {'user_id': self.user_in_domain,
                               'project_id': subproject_id,
                               'role_id': self.role_id}
        self.assertIn(expected_assignment, actual)

        # Should not see subtree assignments for project in other domain
        query = {'scope.project.id': self.project_other_domain,
                 'include_subtree': True}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainMemberTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(IdentityV3RbacAssignmentTest, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']

    def test_identity_list_role_assignments(self):
        # Listing all assignments with no filters should fail
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden)

        # Listing all assignments with names and no filters should fail
        query = {'include_names': True}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by own domain should fail
        query = {'scope.domain.id': self.own_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by other domain should fail
        query = {'scope.domain.id': self.other_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by project in own domain should fail
        query = {'scope.project.id': self.project_in_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by project in other domain should fail
        query = {'scope.project.id': self.project_other_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by system should fail
        query = {'scope.system': 'all'}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by user in own domain should fail
        query = {'user.id': self.user_in_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by user in other domain should fail
        query = {'user.id': self.user_other_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by group in own domain should fail
        query = {'group.id': self.group_in_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by group in other domain should fail
        query = {'group.id': self.group_other_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by global role should fail
        query = {'role.id': self.role_id}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by project and role should fail
        query = {'scope.project.id': self.project_in_domain,
                 'role.id': self.role_id}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by domain and role should fail
        query = {'scope.domain.id': self.other_domain, 'role.id': self.role_id}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by system and role should fail
        query = {'scope.system': 'all', 'role.id': self.role_id}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by user and role should should fail
        query = {'user.id': self.user_in_domain, 'role.id': self.role_id}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by group and role should fail
        query = {'group.id': self.group_in_domain, 'role.id': self.role_id}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by project and user should fail
        query = {'user.id': self.user_in_domain,
                 'scope.project.id': self.project_in_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by project and group should fail
        query = {'group.id': self.group_in_domain,
                 'scope.project.id': self.project_in_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by domain and user should fail
        query = {'user.id': self.user_in_domain,
                 'scope.domain.id': self.own_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Filter assignments by domain and group should fail
        query = {'group.id': self.group_in_domain,
                 'scope.domain.id': self.own_domain}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

    def test_identity_list_role_assignments_for_tree(self):
        # Should not see subtree assignments for project in own domain
        query = {'scope.project.id': self.project_in_domain,
                 'include_subtree': True}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Should not see subtree assignments for project in other domain
        query = {'scope.project.id': self.project_other_domain,
                 'include_subtree': True}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Should see subtree for own project
        own_project = self.persona.credentials.project_id
        subproject_id = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'),
            domain_id=self.own_domain,
            parent_id=own_project)['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        subproject_id)
        self.admin_client.roles_v3_client.create_user_role_on_project(
            subproject_id, self.user_other_domain, self.role_id)
        query = {'scope.project.id': own_project,
                 'include_subtree': True}
        resp = self.do_request('list_role_assignments', **query)
        expected_assignment = {'user_id': self.user_other_domain,
                               'project_id': subproject_id,
                               'role_id': self.role_id}
        actual = self._extract_role_assignments_from_response_body(resp)
        self.assertIn(expected_assignment, actual)


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']

    def test_identity_list_role_assignments_for_tree(self):
        # Should not see subtree assignments for project in own domain
        query = {'scope.project.id': self.project_in_domain,
                 'include_subtree': True}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Should not see subtree assignments for project in other domain
        query = {'scope.project.id': self.project_other_domain,
                 'include_subtree': True}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)

        # Should not see subtree for own project
        own_project = self.persona.credentials.project_id
        query = {'scope.project.id': own_project,
                 'include_subtree': True}
        self.do_request('list_role_assignments',
                        expected_status=exceptions.Forbidden, **query)


class ProjectReaderTests(ProjectMemberTests):

    credentials = ['project_reader', 'system_admin']
