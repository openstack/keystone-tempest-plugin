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


class IdentityV3RbacLimitTests(rbac_base.IdentityV3RbacBaseTests,
                               metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacLimitTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        persona_mgr = clients.Manager(cls.persona.credentials)
        cls.client = persona_mgr.limits_client
        cls.admin_client = cls.os_system_admin
        admin_mgr = clients.Manager(cls.admin_client.credentials)
        cls.admin_reglim_client = admin_mgr.registered_limits_client
        cls.admin_limits_client = admin_mgr.limits_client

    @classmethod
    def resource_setup(cls):
        cls.region_id = cls.admin_client.regions_client.create_region(
            region_id=data_utils.rand_name())['region']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.regions_client.delete_region,
            cls.region_id)
        svc_client = cls.admin_client.identity_services_v3_client
        cls.service_id = svc_client.create_service(
            type=data_utils.rand_name())['service']['id']
        cls.addClassResourceCleanup(svc_client.delete_service, cls.service_id)
        cls.own_domain = cls.persona.credentials.domain_id
        cls.other_domain = cls.admin_client.domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.delete_domain, cls.other_domain)
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.update_domain,
            domain_id=cls.other_domain,
            enabled=False)
        cls.own_project = cls.persona.credentials.project_id
        # if project-scoped, use existing project
        # else create project in domain
        if not cls.own_project:
            cls.own_project = cls.admin_client.projects_client.create_project(
                name=data_utils.rand_name(),
                domain_id=cls.own_domain)['project']['id']
            cls.addClassResourceCleanup(
                cls.admin_client.projects_client.delete_project,
                cls.own_project)
        cls.other_project = cls.admin_client.projects_client.create_project(
            name=data_utils.rand_name(),
            domain_id=cls.other_domain)['project']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.projects_client.delete_project, cls.other_project)
        cls.reg_limit = cls.admin_reglim_client.create_registered_limits(
            payload=[{
                "service_id": cls.service_id,
                "region_id": cls.region_id,
                "resource_name": data_utils.rand_name(),
                "default_limit": 5
            }])['registered_limits'][0]
        cls.addClassResourceCleanup(
            cls.admin_reglim_client.delete_registered_limit,
            registered_limit_id=cls.reg_limit['id'])

    def limits(self, project_id=None):
        return [
            {
                "service_id": self.service_id,
                "region_id": self.region_id,
                "project_id": project_id or self.other_project,
                "resource_name": self.reg_limit['resource_name'],
                "resource_limit": 10
            }
        ]

    @abc.abstractmethod
    def test_identity_get_limit_model(self):
        """Test identity:get_limit_model policy.

        This test must check:
          * whether the persona can get the limit model
        """
        pass

    @abc.abstractmethod
    def test_identity_create_limits(self):
        """Test identity:create_limits policy.

        This test must check:
          * whether the persona can create a project limit for a project in any
            domain
          * whether the persona can create a project limit for a project in own
            domain
          * whether the persona can create a project limit for own project
        """
        pass

    @abc.abstractmethod
    def test_identity_list_limits(self):
        """Test identity:list_limits policy.

        This test must check:
          * whether the persona can list limits for any project
          * whether the persona can list limits for projects in own domain
          * whether the persona can list limits for own project
        """
        pass

    @abc.abstractmethod
    def test_identity_get_limit(self):
        """Test identity:get_limit policy.

        This test must check:
          * whether the persona can get a project limit for a project in any
            domain
          * whether the persona can get a project limit for a project in own
            domain
          * whether the persona can get a project limit for own project
        """
        pass

    @abc.abstractmethod
    def test_identity_update_limit(self):
        """Test identity:update_limit policy.

        This test must check:
          * whether the persona can update a project limit for a project in any
            domain
          * whether the persona can update a project limit for a project in own
            domain
          * whether the persona can update a project limit for own project
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_limit(self):
        """Test identity:delete_limit policy.

        This test must check:
          * whether the persona can delete a project limit for a project limit
            in any domain
          * whether the persona can delete a project limit for a project limit
            in own domain
          * whether the persona can delete a project limit for a project limit
            own project
        """
        pass


class SystemAdminTests(IdentityV3RbacLimitTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_get_limit_model(self):
        self.do_request('limits_model')

    def test_identity_create_limits(self):
        resp = self.do_request('create_limits',
                               expected_status=201,
                               payload=self.limits())
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=resp['limits'][0]['id'])

    def test_identity_list_limits(self):
        reg_limit_id = self.admin_limits_client.create_limits(
            payload=self.limits())['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_id)
        resp = self.do_request('list_limits')
        self.assertIn(
            reg_limit_id, [rl['id'] for rl in resp['limits']])

    def test_identity_get_limit(self):
        reg_limit_id = self.admin_limits_client.create_limits(
            payload=self.limits())['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_id)
        self.do_request('show_limit',
                        limit_id=reg_limit_id)

    def test_identity_update_limit(self):
        reg_limit_id = self.admin_limits_client.create_limits(
            payload=self.limits())['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_id)
        updated = {'description': data_utils.arbitrary_string()}
        self.do_request('update_limit',
                        limit_id=reg_limit_id,
                        limit=updated)

    def test_identity_delete_limit(self):
        reg_limit_id = self.admin_limits_client.create_limits(
            payload=self.limits())['limits'][0]['id']
        self.do_request('delete_limit',
                        expected_status=204,
                        limit_id=reg_limit_id)


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_limits(self):
        self.do_request('create_limits',
                        expected_status=exceptions.Forbidden,
                        payload=self.limits())

    def test_identity_update_limit(self):
        reg_limit_id = self.admin_limits_client.create_limits(
            payload=self.limits())['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_id)
        updated = {'description': data_utils.arbitrary_string()}
        self.do_request('update_limit',
                        expected_status=exceptions.Forbidden,
                        limit_id=reg_limit_id,
                        limit=updated)

    def test_identity_delete_limit(self):
        reg_limit_id = self.admin_limits_client.create_limits(
            payload=self.limits())['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_id)
        self.do_request('delete_limit',
                        expected_status=exceptions.Forbidden,
                        limit_id=reg_limit_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(IdentityV3RbacLimitTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_limit_model(self):
        self.do_request('limits_model')

    def test_identity_create_limits(self):
        # cannot create limit in arbitrary project
        self.do_request('create_limits',
                        expected_status=exceptions.Forbidden,
                        payload=self.limits())
        # cannot create limit in project in own domain
        self.do_request('create_limits',
                        expected_status=exceptions.Forbidden,
                        payload=self.limits(project_id=self.own_project))

    def test_identity_list_limits(self):
        # random project
        reg_limit_1 = self.admin_limits_client.create_limits(
            payload=self.limits())['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_1)
        # project in own domain
        reg_limit_2 = self.admin_limits_client.create_limits(
            payload=self.limits(project_id=self.own_project)
        )['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_2)
        resp = self.do_request('list_limits')
        # should not see limit for other project
        self.assertNotIn(
            reg_limit_1, [rl['id'] for rl in resp['limits']])
        # should see limit for project in own domain
        self.assertIn(
            reg_limit_2, [rl['id'] for rl in resp['limits']])

    def test_identity_get_limit(self):
        # random project
        reg_limit_1 = self.admin_limits_client.create_limits(
            payload=self.limits())['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_1)
        # project in own domain
        reg_limit_2 = self.admin_limits_client.create_limits(
            payload=self.limits(project_id=self.own_project)
        )['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_2)
        # cannot get limit for other project
        self.do_request('show_limit',
                        expected_status=exceptions.Forbidden,
                        limit_id=reg_limit_1)
        # can get limit for project in own domain
        self.do_request('show_limit',
                        limit_id=reg_limit_2)

    def test_identity_update_limit(self):
        # cannot update limit for arbitrary project
        reg_limit_id = self.admin_limits_client.create_limits(
            payload=self.limits())['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_id)
        updated = {'description': data_utils.arbitrary_string()}
        self.do_request('update_limit',
                        expected_status=exceptions.Forbidden,
                        limit_id=reg_limit_id,
                        limit=updated)
        # cannot update limit for project in own domain
        reg_limit_id = self.admin_limits_client.create_limits(
            payload=self.limits(project_id=self.own_project)
        )['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_id)
        updated = {'description': data_utils.arbitrary_string()}
        self.do_request('update_limit',
                        expected_status=exceptions.Forbidden,
                        limit_id=reg_limit_id,
                        limit=updated)

    def test_identity_delete_limit(self):
        # cannot delete limit for arbitrary project
        reg_limit_id = self.admin_limits_client.create_limits(
            payload=self.limits())['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_id)
        self.do_request('delete_limit',
                        expected_status=exceptions.Forbidden,
                        limit_id=reg_limit_id)

        # cannot delete limit for project in own domain
        reg_limit_id = self.admin_limits_client.create_limits(
            payload=self.limits(project_id=self.own_project)
        )['limits'][0]['id']
        self.addCleanup(
            self.admin_limits_client.delete_limit,
            limit_id=reg_limit_id)
        self.do_request('delete_limit',
                        expected_status=exceptions.Forbidden,
                        limit_id=reg_limit_id)


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainMemberTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(DomainReaderTests):

    credentials = ['project_admin', 'system_admin']


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectMemberTests):

    credentials = ['project_reader', 'system_admin']
