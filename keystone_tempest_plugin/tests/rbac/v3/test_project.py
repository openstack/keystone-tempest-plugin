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


class IdentityV3RbacProjectsTests(rbac_base.IdentityV3RbacBaseTests,
                                  metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacProjectsTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.projects_client
        cls.users_client = cls.persona.users_v3_client
        cls.admin_client = cls.os_system_admin
        cls.admin_projects_client = cls.admin_client.projects_client

    @abc.abstractmethod
    def test_identity_create_project(self):
        """Test identity:create_project policy.

        This test must check:
          * whether the persona can create a project
          * whether the persona can create a project in their own domain
          * whether the persona can create a project in another domain
        """
        pass

    @abc.abstractmethod
    def test_identity_get_project(self):
        """Test identity:get_project policy.

        This test must check:
          * whether the persona can get a project
          * whether the persona can get a project in their own domain
          * whether the persona can get a project in another domain
          * whether the persona can get a project that does not exist
          * whether the persona can get their own project
        """
        pass

    @abc.abstractmethod
    def test_identity_list_projects(self):
        """Test identity:list_projects policy.

        This test must check:
          * whether the persona can list all projects
          * whether the persona can list all projects in their own domain
          * whether the persona can list all projects in another domain
        """
        pass

    @abc.abstractmethod
    def test_identity_list_user_projects(self):
        """Test identity:list_user_projects policy.

        This test must check:
          * whether the persona can list projects of a user
          * whether the persona can list projects of a user in their own domain
          * whether the persona can list projects of a user in another domain
          * whether the persona can list projects for themself
        """
        pass

    @abc.abstractmethod
    def test_identity_update_project(self):
        """Test identity:update_project policy.

        This test must check:
          * whether the persona can update a project
          * whether the persona can update a project in their own domain
          * whether the persona can update a project in another domain
          * whether the persona can update a project that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_project(self):
        """Test identity:delete_project policy.

        This test must check
          * whether the persona can delete a project
          * whether the persona can delete a project in their own domain
          * whether the persona can delete a project in another domain
          * whether the persona can delete a project that does not exist
        """
        pass


class SystemAdminTests(IdentityV3RbacProjectsTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_project(self):
        project_id = self.do_request(
            'create_project', expected_status=201, name=data_utils.rand_name()
        )['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)

    def test_identity_get_project(self):
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('show_project', project_id=project_id)
        # user gets a 404 for nonexistent project
        self.do_request('show_project', expected_status=exceptions.NotFound,
                        project_id=data_utils.rand_uuid_hex())

    def test_identity_list_projects(self):
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        resp = self.do_request('list_projects')
        self.assertIn(project_id, [p['id'] for p in resp['projects']])

    def test_identity_list_user_projects(self):
        user_id = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name())['user']['id']
        self.addCleanup(self.admin_client.users_v3_client.delete_user, user_id)
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        role_id = self.admin_client.roles_v3_client.create_role(
            name=data_utils.rand_name())['role']['id']
        self.addCleanup(self.admin_client.roles_v3_client.delete_role,
                        role_id)
        self.admin_client.roles_v3_client.create_user_role_on_project(
            project_id, user_id, role_id)
        # user can list projects for arbitrary user
        resp = self.do_request('list_user_projects', client=self.users_client,
                               user_id=user_id)
        self.assertIn(project_id, [p['id'] for p in resp['projects']])
        # user can list projects for self
        resp = self.do_request('list_user_projects', client=self.users_client,
                               user_id=self.persona.credentials.user_id)
        self.assertEqual(0, len([p['id'] for p in resp['projects']]))

    def test_identity_update_project(self):
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('update_project',
                        project_id=project_id,
                        description=data_utils.arbitrary_string())
        # user gets a 404 for nonexistent domain
        self.do_request('update_project', expected_status=exceptions.NotFound,
                        project_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_project(self):
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.do_request('delete_project', expected_status=204,
                        project_id=project_id)


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_project(self):
        self.do_request('create_project', expected_status=exceptions.Forbidden,
                        name=data_utils.rand_name())

    def test_identity_update_project(self):
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('update_project', expected_status=exceptions.Forbidden,
                        project_id=project_id,
                        description=data_utils.arbitrary_string())
        # user gets a 403 for nonexistent domain
        self.do_request('update_project', expected_status=exceptions.Forbidden,
                        project_id=data_utils.rand_uuid_hex())

    def test_identity_delete_project(self):
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('delete_project', expected_status=exceptions.Forbidden,
                        project_id=project_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(IdentityV3RbacProjectsTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def setUp(self):
        super(DomainAdminTests, self).setUp()
        self.own_domain = self.persona.credentials.domain_id
        self.other_domain = self.admin_client.domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_client.domains_client.delete_domain,
                        self.other_domain)
        self.addCleanup(self.admin_client.domains_client.update_domain,
                        domain_id=self.other_domain, enabled=False)

    def test_identity_create_project(self):
        # user can create project in own domain
        project_id = self.do_request(
            'create_project', expected_status=201, name=data_utils.rand_name(),
            domain_id=self.own_domain
        )['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        # user cannot create project in other domain
        self.do_request(
            'create_project', expected_status=exceptions.Forbidden,
            name=data_utils.rand_name(), domain_id=self.other_domain
        )

    def test_identity_get_project(self):
        # user can get project in own domain
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.own_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('show_project', project_id=project_id)
        # user cannot get project in other domain
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.other_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('show_project', expected_status=exceptions.Forbidden,
                        project_id=project_id)
        # user gets a 403 for nonexistent project
        self.do_request('show_project', expected_status=exceptions.Forbidden,
                        project_id=data_utils.rand_uuid_hex())

    def test_identity_list_projects(self):
        # user can list projects but cannot see project in other domain
        own_project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.own_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project,
                        own_project_id)
        other_project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.other_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project,
                        other_project_id)
        resp = self.do_request('list_projects')
        self.assertIn(own_project_id, [d['id'] for d in resp['projects']])
        self.assertNotIn(other_project_id, [d['id'] for d in resp['projects']])

    def test_identity_list_user_projects(self):
        # user can list projects for user in own domain
        user_id = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name(),
            domain_id=self.own_domain)['user']['id']
        self.addCleanup(self.admin_client.users_v3_client.delete_user, user_id)
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        role_id = self.admin_client.roles_v3_client.create_role(
            name=data_utils.rand_name())['role']['id']
        self.addCleanup(self.admin_client.roles_v3_client.delete_role,
                        role_id)
        self.admin_client.roles_v3_client.create_user_role_on_project(
            project_id, user_id, role_id)
        resp = self.do_request('list_user_projects', client=self.users_client,
                               user_id=user_id)
        self.assertIn(project_id, [p['id'] for p in resp['projects']])
        # user cannot list projects for user in other domain
        user_id = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name(),
            domain_id=self.other_domain)['user']['id']
        self.addCleanup(self.admin_client.users_v3_client.delete_user, user_id)
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        role_id = self.admin_client.roles_v3_client.create_role(
            name=data_utils.rand_name())['role']['id']
        self.addCleanup(self.admin_client.roles_v3_client.delete_role,
                        role_id)
        self.admin_client.roles_v3_client.create_user_role_on_project(
            project_id, user_id, role_id)
        self.do_request('list_user_projects', client=self.users_client,
                        expected_status=exceptions.Forbidden,
                        user_id=user_id)
        # user can list projects for self
        resp = self.do_request('list_user_projects', client=self.users_client,
                               user_id=self.persona.credentials.user_id)
        self.assertEqual(0, len([p['id'] for p in resp['projects']]))

    def test_identity_update_project(self):
        # user can update project in own domain
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.own_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('update_project',
                        project_id=project_id,
                        description=data_utils.arbitrary_string())
        # user cannot update project in other domain
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.other_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('update_project',
                        expected_status=exceptions.Forbidden,
                        project_id=project_id,
                        description=data_utils.arbitrary_string())
        # user gets a 403 for nonexistent domain
        self.do_request('update_project', expected_status=exceptions.Forbidden,
                        project_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_project(self):
        # user can delete project in own domain
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.own_domain)['project']['id']
        self.do_request('delete_project', expected_status=204,
                        project_id=project_id)
        # user cannot delete project in other domain
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.other_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('delete_project', expected_status=exceptions.Forbidden,
                        project_id=project_id)


class DomainMemberTests(DomainAdminTests, base.BaseIdentityTest):

    credentials = ['domain_member', 'system_admin']

    def test_identity_create_project(self):
        # user cannot create project in own domain
        self.do_request(
            'create_project', expected_status=exceptions.Forbidden,
            name=data_utils.rand_name(),
            domain_id=self.own_domain
        )
        # user cannot create project in other domain
        self.do_request(
            'create_project', expected_status=exceptions.Forbidden,
            name=data_utils.rand_name(), domain_id=self.other_domain
        )

    def test_identity_update_project(self):
        # user cannot update project in own domain
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.own_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('update_project',
                        expected_status=exceptions.Forbidden,
                        project_id=project_id,
                        description=data_utils.arbitrary_string())
        # user cannot update project in other domain
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.other_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('update_project',
                        expected_status=exceptions.Forbidden,
                        project_id=project_id,
                        description=data_utils.arbitrary_string())
        # user gets a 403 for nonexistent domain
        self.do_request('update_project', expected_status=exceptions.Forbidden,
                        project_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_project(self):
        # user cannot delete project in own domain
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.own_domain)['project']['id']
        self.do_request('delete_project', expected_status=exceptions.Forbidden,
                        project_id=project_id)
        # user cannot delete project in other domain
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.other_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('delete_project', expected_status=exceptions.Forbidden,
                        project_id=project_id)


class DomainReaderTests(DomainMemberTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(DomainReaderTests, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']

    def test_identity_get_project(self):
        # user cannot get arbitrary project
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=self.own_domain)['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        self.do_request('show_project', expected_status=exceptions.Forbidden,
                        project_id=project_id)
        # user gets a 403 for nonexistent project
        self.do_request('show_project', expected_status=exceptions.Forbidden,
                        project_id=data_utils.rand_uuid_hex())
        # user can get own project
        self.do_request('show_project',
                        project_id=self.persona.credentials.project_id)

    def test_identity_list_projects(self):
        # user cannot list projects
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project,
                        project_id)
        self.do_request('list_projects', expected_status=exceptions.Forbidden)

    def test_identity_list_user_projects(self):
        # user can list projects for other user
        user_id = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name())['user']['id']
        self.addCleanup(self.admin_client.users_v3_client.delete_user, user_id)
        project_id = self.admin_projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        self.addCleanup(self.admin_projects_client.delete_project, project_id)
        role_id = self.admin_client.roles_v3_client.create_role(
            name=data_utils.rand_name())['role']['id']
        self.addCleanup(self.admin_client.roles_v3_client.delete_role,
                        role_id)
        self.admin_client.roles_v3_client.create_user_role_on_project(
            project_id, user_id, role_id)
        self.do_request('list_user_projects', client=self.users_client,
                        expected_status=exceptions.Forbidden,
                        user_id=user_id)
        # user can list projects for self
        resp = self.do_request('list_user_projects', client=self.users_client,
                               user_id=self.persona.credentials.user_id)
        self.assertIn(self.persona.credentials.project_id,
                      [p['id'] for p in resp['projects']])


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
