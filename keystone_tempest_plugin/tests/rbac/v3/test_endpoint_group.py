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


class IdentityV3RbacEndpointGroupTests(rbac_base.IdentityV3RbacBaseTests,
                                       metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacEndpointGroupTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.eg_client = cls.persona.endpoint_groups_client
        cls.ef_client = cls.persona.endpoint_filter_client
        cls.admin_client = cls.os_system_admin
        cls.admin_eg_client = cls.admin_client.endpoint_groups_client
        cls.admin_ef_client = cls.admin_client.endpoint_filter_client

    def endpoint_group(self):
        return {
            'name': data_utils.rand_name('endpoint_group'),
            'filters': {'interface': 'public'},
        }

    @abc.abstractmethod
    def test_identity_create_endpoint_group(self):
        """Test identity:create_endpoint_group policy.

        This test must check:
          * whether the persona can create an endpoint group
        """
        pass

    @abc.abstractmethod
    def test_identity_get_endpoint_group(self):
        """Test identity:get_endpoint_group policy.

        This test must check:
          * whether the persona can get an endpoint group
          * whether the persona can get an endpoint group that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_endpoint_groups(self):
        """Test identity:list_endpoint_groups policy.

        This test must check:
          * whether the persona can list all endpoint groups
        """
        pass

    @abc.abstractmethod
    def test_identity_update_endpoint_group(self):
        """Test identity:update_endpoint_group policy.

        This test must check:
          * whether the persona can update an endpoint group
          * whether the persona can update an endpoint group that does not
            exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_endpoint_group(self):
        """Test identity:delete_endpoint_group policy.

        This test must check
          * whether the persona can delete an endpoint group
          * whether the persona can delete an endpoint group that does not
            exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_projects_associated_with_endpoint_group(self):
        """Test identity:list_projects_associated_with_endpoint_group policy.

        This test must check
          * whether the persona can list projects associated with an endpoint
            group
        """
        pass

    @abc.abstractmethod
    def test_identity_list_endpoints_associated_with_endpoint_group(self):
        """Test identity:list_endpoints_associated_with_endpoint_group

        This test must check
          * whether the persona can list endpoints associated with an endpoint
            group
        """
        pass

    @abc.abstractmethod
    def test_identity_get_endpoint_group_in_project(self):
        """Test identity:get_endpoint_group_in_project

        This test must check
          * whether the persona can check if an endpoint group is associated
            with a project
        """
        pass

    @abc.abstractmethod
    def test_identity_list_endpoint_groups_for_project(self):
        """Test identity:list_endpoint_groups_for_project

        This test must check
          * whether the persona can list endpoint groups associated with a
            project
        """
        pass

    @abc.abstractmethod
    def test_identity_add_endpoint_group_to_project(self):
        """Test identity:add_endpoint_group_to_project

        This test must check
          * whether the persona can allow a project to access an endpoint group
        """
        pass

    @abc.abstractmethod
    def test_identity_remove_endpoint_group_from_project(self):
        """Test identity:remove_endpoint_group_from_project

        This test must check
          * whether the persona can remove an endpoint group from a project
        """
        pass


class SystemAdminTests(
    IdentityV3RbacEndpointGroupTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_endpoint_group(self):
        eg = self.do_request('create_endpoint_group', expected_status=201,
                             client=self.eg_client,
                             **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)

    def test_identity_get_endpoint_group(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        # user can get an endpoint group
        self.do_request('show_endpoint_group', client=self.eg_client,
                        endpoint_group_id=eg)
        # nonexistent endpoint group gives a 404
        self.do_request('show_endpoint_group',
                        expected_status=exceptions.NotFound,
                        client=self.eg_client,
                        endpoint_group_id=data_utils.rand_uuid_hex())

    def test_identity_list_endpoint_groups(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        resp = self.do_request('list_endpoint_groups',
                               client=self.eg_client)['endpoint_groups']
        self.assertIn(eg, [e['id'] for e in resp])

    def test_identity_update_endpoint_group(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        # user can update an endpoint group
        self.do_request('update_endpoint_group', client=self.eg_client,
                        endpoint_group_id=eg,
                        description=data_utils.arbitrary_string())
        # nonexistent endpoint group gives a 404
        self.do_request('update_endpoint_group', client=self.eg_client,
                        expected_status=exceptions.NotFound,
                        endpoint_group_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_endpoint_group(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        # user can delete an endpoint group
        self.do_request('delete_endpoint_group',
                        expected_status=204,
                        client=self.eg_client,
                        endpoint_group_id=eg)
        # nonexistent endpoint group gives a 404
        self.do_request('delete_endpoint_group',
                        expected_status=exceptions.NotFound,
                        client=self.eg_client,
                        endpoint_group_id=data_utils.rand_uuid_hex())

    def test_identity_list_projects_associated_with_endpoint_group(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        project = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'))['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        project)
        self.admin_ef_client.add_endpoint_group_to_project(
            endpoint_group_id=eg, project_id=project)
        self.addCleanup(
            self.admin_ef_client.delete_endpoint_group_from_project,
            endpoint_group_id=eg, project_id=project)
        resp = self.do_request('list_projects_for_endpoint_group',
                               client=self.ef_client,
                               endpoint_group_id=eg)['projects']
        self.assertIn(project, [p['id'] for p in resp])

    def test_identity_list_endpoints_associated_with_endpoint_group(self):
        service = self.admin_client.identity_services_v3_client.create_service(
            type=data_utils.rand_name('service'))['service']['id']
        self.addCleanup(
            self.admin_client.identity_services_v3_client.delete_service,
            service)
        endpoint = self.admin_client.endpoints_v3_client.create_endpoint(
            interface='public',
            url='http://localhost/foo',
            service_id=service)['endpoint']['id']
        self.addCleanup(self.admin_client.endpoints_v3_client.delete_endpoint,
                        endpoint)
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        resp = self.do_request('list_endpoints_for_endpoint_group',
                               client=self.ef_client,
                               endpoint_group_id=eg)['endpoints']
        self.assertIn(endpoint, [e['id'] for e in resp])

    def test_identity_get_endpoint_group_in_project(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        project = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'))['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        project)
        self.admin_ef_client.add_endpoint_group_to_project(
            endpoint_group_id=eg, project_id=project)
        self.addCleanup(
            self.admin_ef_client.delete_endpoint_group_from_project,
            endpoint_group_id=eg, project_id=project)
        self.do_request('show_endpoint_group_for_project',
                        client=self.ef_client,
                        endpoint_group_id=eg,
                        project_id=project)

    def test_identity_list_endpoint_groups_for_project(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        project = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'))['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        project)
        self.admin_ef_client.add_endpoint_group_to_project(
            endpoint_group_id=eg, project_id=project)
        self.addCleanup(
            self.admin_ef_client.delete_endpoint_group_from_project,
            endpoint_group_id=eg, project_id=project)
        resp = self.do_request('list_endpoint_groups_for_project',
                               client=self.ef_client,
                               project_id=project)
        self.assertIn(eg, [e['id'] for e in resp['endpoint_groups']])

    def test_identity_add_endpoint_group_to_project(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        project = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'))['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        project)
        self.do_request('add_endpoint_group_to_project',
                        client=self.ef_client,
                        expected_status=204,
                        endpoint_group_id=eg,
                        project_id=project)
        self.addCleanup(
            self.admin_ef_client.delete_endpoint_group_from_project,
            endpoint_group_id=eg, project_id=project)

    def test_identity_remove_endpoint_group_from_project(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        project = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'))['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        project)
        self.admin_ef_client.add_endpoint_group_to_project(
            endpoint_group_id=eg, project_id=project)
        self.do_request('delete_endpoint_group_from_project',
                        client=self.ef_client,
                        expected_status=204,
                        endpoint_group_id=eg, project_id=project)


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_endpoint_group(self):
        self.do_request('create_endpoint_group',
                        expected_status=exceptions.Forbidden,
                        client=self.eg_client,
                        **self.endpoint_group())

    def test_identity_update_endpoint_group(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        # user can update an endpoint group
        self.do_request('update_endpoint_group', client=self.eg_client,
                        expected_status=exceptions.Forbidden,
                        endpoint_group_id=eg,
                        description=data_utils.arbitrary_string())
        # nonexistent endpoint group gives a 403
        self.do_request('update_endpoint_group', client=self.eg_client,
                        expected_status=exceptions.Forbidden,
                        endpoint_group_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_endpoint_group(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        # user cannot delete an endpoint group
        self.do_request('delete_endpoint_group',
                        expected_status=exceptions.Forbidden,
                        client=self.eg_client,
                        endpoint_group_id=eg)
        # nonexistent endpoint group gives a 403
        self.do_request('delete_endpoint_group',
                        expected_status=exceptions.Forbidden,
                        client=self.eg_client,
                        endpoint_group_id=data_utils.rand_uuid_hex())

    def test_identity_add_endpoint_group_to_project(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        project = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'))['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        project)
        self.do_request('add_endpoint_group_to_project',
                        client=self.ef_client,
                        expected_status=exceptions.Forbidden,
                        endpoint_group_id=eg,
                        project_id=project)

    def test_identity_remove_endpoint_group_from_project(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        project = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'))['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        project)
        self.admin_ef_client.add_endpoint_group_to_project(
            endpoint_group_id=eg, project_id=project)
        self.addCleanup(
            self.admin_ef_client.delete_endpoint_group_from_project,
            endpoint_group_id=eg, project_id=project)
        self.do_request('delete_endpoint_group_from_project',
                        client=self.ef_client,
                        expected_status=exceptions.Forbidden,
                        endpoint_group_id=eg, project_id=project)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_endpoint_group(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        # user cannot get an endpoint group
        self.do_request('show_endpoint_group', client=self.eg_client,
                        expected_status=exceptions.Forbidden,
                        endpoint_group_id=eg)
        # nonexistent endpoint group gives a 403
        self.do_request('show_endpoint_group',
                        expected_status=exceptions.Forbidden,
                        client=self.eg_client,
                        endpoint_group_id=data_utils.rand_uuid_hex())

    def test_identity_list_endpoint_groups(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        self.do_request('list_endpoint_groups',
                        expected_status=exceptions.Forbidden,
                        client=self.eg_client)

    def test_identity_list_projects_associated_with_endpoint_group(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        project = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'))['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        project)
        self.admin_ef_client.add_endpoint_group_to_project(
            endpoint_group_id=eg, project_id=project)
        self.addCleanup(
            self.admin_ef_client.delete_endpoint_group_from_project,
            endpoint_group_id=eg, project_id=project)
        self.do_request('list_projects_for_endpoint_group',
                        client=self.ef_client,
                        expected_status=exceptions.Forbidden,
                        endpoint_group_id=eg)

    def test_identity_list_endpoints_associated_with_endpoint_group(self):
        service = self.admin_client.identity_services_v3_client.create_service(
            type=data_utils.rand_name('service'))['service']['id']
        self.addCleanup(
            self.admin_client.identity_services_v3_client.delete_service,
            service)
        endpoint = self.admin_client.endpoints_v3_client.create_endpoint(
            interface='public',
            url='http://localhost/foo',
            service_id=service)['endpoint']['id']
        self.addCleanup(self.admin_client.endpoints_v3_client.delete_endpoint,
                        endpoint)
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        self.do_request('list_endpoints_for_endpoint_group',
                        client=self.ef_client,
                        expected_status=exceptions.Forbidden,
                        endpoint_group_id=eg)

    def test_identity_get_endpoint_group_in_project(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        project = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'))['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        project)
        self.admin_ef_client.add_endpoint_group_to_project(
            endpoint_group_id=eg, project_id=project)
        self.addCleanup(
            self.admin_ef_client.delete_endpoint_group_from_project,
            endpoint_group_id=eg, project_id=project)
        self.do_request('show_endpoint_group_for_project',
                        client=self.ef_client,
                        expected_status=exceptions.Forbidden,
                        endpoint_group_id=eg,
                        project_id=project)

    def test_identity_list_endpoint_groups_for_project(self):
        eg = self.admin_eg_client.create_endpoint_group(
            **self.endpoint_group())['endpoint_group']['id']
        self.addCleanup(self.admin_eg_client.delete_endpoint_group, eg)
        project = self.admin_client.projects_client.create_project(
            name=data_utils.rand_name('project'))['project']['id']
        self.addCleanup(self.admin_client.projects_client.delete_project,
                        project)
        self.admin_ef_client.add_endpoint_group_to_project(
            endpoint_group_id=eg, project_id=project)
        self.addCleanup(
            self.admin_ef_client.delete_endpoint_group_from_project,
            endpoint_group_id=eg, project_id=project)
        self.do_request('list_endpoint_groups_for_project',
                        client=self.ef_client,
                        expected_status=exceptions.Forbidden,
                        project_id=project)


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
