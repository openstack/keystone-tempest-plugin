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


class IdentityV3RbacServiceTests(rbac_base.IdentityV3RbacBaseTests,
                                 metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacServiceTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.identity_services_v3_client
        admin_client = cls.os_system_admin
        cls.admin_services_client = admin_client.identity_services_v3_client

    def service(self):
        return {
            'name': data_utils.rand_name('service_name'),
            'type': data_utils.rand_name('service_type'),
        }

    @abc.abstractmethod
    def test_identity_create_service(self):
        """Test identity:create_service policy.

        This test must check:
          * whether the persona can create a service
        """
        pass

    @abc.abstractmethod
    def test_identity_get_service(self):
        """Test identity:get_service policy.

        This test must check:
          * whether the persona can get a service
          * whether the persona can get a service that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_services(self):
        """Test identity:list_services policy.

        This test must check:
          * whether the persona can list all services
        """
        pass

    @abc.abstractmethod
    def test_identity_update_service(self):
        """Test identity:update_service policy.

        This test must check:
          * whether the persona can update a service
          * whether the persona can update a service that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_service(self):
        """Test identity:delete_service policy.

        This test must check
          * whether the persona can delete a service
          * whether the persona can delete a service that does not exist
        """
        pass


class SystemAdminTests(IdentityV3RbacServiceTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_service(self):
        service_id = self.do_request(
            'create_service', expected_status=201,
            **self.service())['service']['id']
        self.addCleanup(
            self.admin_services_client.delete_service,
            service_id=service_id)

    def test_identity_get_service(self):
        service_id = self.admin_services_client.create_service(
            **self.service())['service']['id']
        self.addCleanup(
            self.admin_services_client.delete_service,
            service_id=service_id)
        self.do_request('show_service', service_id=service_id)
        # user gets a 404 for nonexistent service
        self.do_request('show_service', expected_status=exceptions.NotFound,
                        service_id=data_utils.rand_uuid_hex())

    def test_identity_list_services(self):
        service_id = self.admin_services_client.create_service(
            **self.service())['service']['id']
        self.addCleanup(
            self.admin_services_client.delete_service,
            service_id=service_id)
        resp = self.do_request('list_services')
        self.assertIn(service_id, [e['id'] for e in resp['services']])

    def test_identity_update_service(self):
        service_id = self.admin_services_client.create_service(
            **self.service())['service']['id']
        self.addCleanup(
            self.admin_services_client.delete_service,
            service_id=service_id)
        self.do_request('update_service',
                        service_id=service_id,
                        type=data_utils.rand_name('service_type'))
        # user gets a 404 for nonexistent service
        self.do_request('update_service', expected_status=exceptions.NotFound,
                        service_id=data_utils.rand_uuid_hex(),
                        type=data_utils.rand_name('service_type'))

    def test_identity_delete_service(self):
        service_id = self.admin_services_client.create_service(
            **self.service())['service']['id']
        self.do_request('delete_service', expected_status=204,
                        service_id=service_id)
        # user gets a 404 for nonexistent service
        self.do_request('delete_service', expected_status=exceptions.NotFound,
                        service_id=data_utils.rand_uuid_hex())


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_service(self):
        self.do_request(
            'create_service', expected_status=exceptions.Forbidden,
            **self.service())

    def test_identity_update_service(self):
        service_id = self.admin_services_client.create_service(
            **self.service())['service']['id']
        self.addCleanup(
            self.admin_services_client.delete_service,
            service_id=service_id)
        self.do_request('update_service',
                        expected_status=exceptions.Forbidden,
                        service_id=service_id,
                        type=data_utils.rand_name('service_type'))
        # user gets a 403 for nonexistent service
        self.do_request('update_service', expected_status=exceptions.Forbidden,
                        service_id=data_utils.rand_uuid_hex(),
                        type=data_utils.rand_name('service_type'))

    def test_identity_delete_service(self):
        service_id = self.admin_services_client.create_service(
            **self.service())['service']['id']
        self.do_request('delete_service',
                        expected_status=exceptions.Forbidden,
                        service_id=service_id)
        # user gets a 403 for nonexistent service
        self.do_request('delete_service', expected_status=exceptions.Forbidden,
                        service_id=data_utils.rand_uuid_hex())


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_service(self):
        service_id = self.admin_services_client.create_service(
            **self.service())['service']['id']
        self.addCleanup(
            self.admin_services_client.delete_service,
            service_id=service_id)
        self.do_request('show_service', expected_status=exceptions.Forbidden,
                        service_id=service_id)
        # user gets a 403 for nonexistent service
        self.do_request('show_service', expected_status=exceptions.Forbidden,
                        service_id=data_utils.rand_uuid_hex())

    def test_identity_list_services(self):
        service_id = self.admin_services_client.create_service(
            **self.service())['service']['id']
        self.addCleanup(
            self.admin_services_client.delete_service,
            service_id=service_id)
        self.do_request('list_services', expected_status=exceptions.Forbidden)


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
