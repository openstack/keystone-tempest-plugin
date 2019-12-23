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


class IdentityV3RbacProjectEndpointsTests(rbac_base.IdentityV3RbacBaseTests,
                                          metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacProjectEndpointsTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.endpoint_filter_client
        cls.admin_client = cls.os_system_admin
        cls.admin_ef_client = cls.admin_client.endpoint_filter_client

    @classmethod
    def resource_setup(cls):
        super(IdentityV3RbacProjectEndpointsTests, cls).resource_setup()
        cls.project_id = cls.admin_client.projects_client.create_project(
            name=data_utils.rand_name())['project']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.projects_client.delete_project,
            project_id=cls.project_id)
        service = cls.admin_client.identity_services_v3_client.create_service(
            type=data_utils.rand_name())['service']
        cls.addClassResourceCleanup(
            cls.admin_client.identity_services_v3_client.delete_service,
            service['id'])
        cls.endpoint_id = cls.admin_client.endpoints_v3_client.create_endpoint(
            interface='public',
            url='http://localhost/foo',
            service_id=service['id'])['endpoint']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.endpoints_v3_client.delete_endpoint,
            endpoint_id=cls.endpoint_id)

    @abc.abstractmethod
    def test_identity_add_endpoint_to_project(self):
        """Test identity:add_endpoint_to_project policy.

        This test must check:
          * whether the persona can allow a project to access an endpoint
        """
        pass

    @abc.abstractmethod
    def test_identity_check_endpoint_in_project(self):
        """Test identity:check_endpoint_in_project policy.

        This test must check:
          * whether the persona can check if a project has access to an
            endpoint
        """
        pass

    @abc.abstractmethod
    def test_identity_list_projects_for_endpoint(self):
        """Test identity:list_projects_for_endpoint policy.

        This test must check:
          * whether the persona can list all projects that have access to an
            endpoint
        """
        pass

    @abc.abstractmethod
    def test_identity_list_endpoints_for_project(self):
        """Test identity:list_endpoints_for_project policy.

        This test must check:
          * whether the persona can list all endpoints to which a project has
            access
        """
        pass

    @abc.abstractmethod
    def test_identity_remove_endpoint_from_project(self):
        """Test identity:remove_endpoint_from_project policy.

        This test must check
          * whether the persona can remove a project's access to an endpoint
        """
        pass


class SystemAdminTests(IdentityV3RbacProjectEndpointsTests):

    credentials = ['system_admin']

    def test_identity_add_endpoint_to_project(self):
        self.do_request('add_endpoint_to_project',
                        expected_status=204,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)
        self.addCleanup(self.admin_ef_client.delete_endpoint_from_project,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)

    def test_identity_check_endpoint_in_project(self):
        self.admin_ef_client.add_endpoint_to_project(
            project_id=self.project_id,
            endpoint_id=self.endpoint_id)
        self.addCleanup(self.admin_ef_client.delete_endpoint_from_project,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)
        self.do_request('check_endpoint_in_project',
                        expected_status=204,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)

    def test_identity_list_projects_for_endpoint(self):
        self.admin_ef_client.add_endpoint_to_project(
            project_id=self.project_id,
            endpoint_id=self.endpoint_id)
        self.addCleanup(self.admin_ef_client.delete_endpoint_from_project,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)
        resp = self.do_request('list_projects_for_endpoint',
                               endpoint_id=self.endpoint_id)
        self.assertIn(self.project_id, [p['id'] for p in resp['projects']])

    def test_identity_list_endpoints_for_project(self):
        self.admin_ef_client.add_endpoint_to_project(
            project_id=self.project_id,
            endpoint_id=self.endpoint_id)
        self.addCleanup(self.admin_ef_client.delete_endpoint_from_project,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)
        resp = self.do_request('list_endpoints_in_project',
                               project_id=self.project_id)
        self.assertIn(self.endpoint_id, [e['id'] for e in resp['endpoints']])

    def test_identity_remove_endpoint_from_project(self):
        self.admin_ef_client.add_endpoint_to_project(
            project_id=self.project_id,
            endpoint_id=self.endpoint_id)
        self.do_request('delete_endpoint_from_project',
                        expected_status=204,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_add_endpoint_to_project(self):
        self.do_request('add_endpoint_to_project',
                        expected_status=exceptions.Forbidden,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)

    def test_identity_remove_endpoint_from_project(self):
        self.admin_ef_client.add_endpoint_to_project(
            project_id=self.project_id,
            endpoint_id=self.endpoint_id)
        self.addCleanup(self.admin_ef_client.delete_endpoint_from_project,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)
        self.do_request('delete_endpoint_from_project',
                        expected_status=exceptions.Forbidden,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_check_endpoint_in_project(self):
        self.admin_ef_client.add_endpoint_to_project(
            project_id=self.project_id,
            endpoint_id=self.endpoint_id)
        self.addCleanup(self.admin_ef_client.delete_endpoint_from_project,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)
        self.do_request('check_endpoint_in_project',
                        expected_status=exceptions.Forbidden,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)

    def test_identity_list_projects_for_endpoint(self):
        self.admin_ef_client.add_endpoint_to_project(
            project_id=self.project_id,
            endpoint_id=self.endpoint_id)
        self.addCleanup(self.admin_ef_client.delete_endpoint_from_project,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)
        self.do_request('list_projects_for_endpoint',
                        expected_status=exceptions.Forbidden,
                        endpoint_id=self.endpoint_id)

    def test_identity_list_endpoints_for_project(self):
        self.admin_ef_client.add_endpoint_to_project(
            project_id=self.project_id,
            endpoint_id=self.endpoint_id)
        self.addCleanup(self.admin_ef_client.delete_endpoint_from_project,
                        project_id=self.project_id,
                        endpoint_id=self.endpoint_id)
        self.do_request('list_endpoints_in_project',
                        expected_status=exceptions.Forbidden,
                        project_id=self.project_id)


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
