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


class IdentityV3RbacRegisteredLimitTests(
    rbac_base.IdentityV3RbacBaseTests, metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacRegisteredLimitTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        persona_mgr = clients.Manager(cls.persona.credentials)
        cls.client = persona_mgr.registered_limits_client
        cls.admin_client = cls.os_system_admin
        admin_mgr = clients.Manager(cls.admin_client.credentials)
        cls.admin_reglim_client = admin_mgr.registered_limits_client

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

    def registered_limits(self):
        return [
            {
                "service_id": self.service_id,
                "region_id": self.region_id,
                "resource_name": data_utils.rand_name(),
                "default_limit": 5,
                "description": data_utils.arbitrary_string()
            }
        ]

    @abc.abstractmethod
    def test_identity_create_registered_limits(self):
        """Test identity:create_registered_limits policy.

        This test must check:
          * whether the persona can create a registered limit
        """
        pass

    @abc.abstractmethod
    def test_identity_list_registered_limits(self):
        """Test identity:list_registered_limits policy.

        This test must check:
          * whether the persona can list registered limits
        """
        pass

    @abc.abstractmethod
    def test_identity_get_registered_limit(self):
        """Test identity:get_registered_limit policy.

        This test must check:
          * whether the persona can get a registered limit
        """
        pass

    @abc.abstractmethod
    def test_identity_update_registered_limit(self):
        """Test identity:update_registered_limit policy.

        This test must check:
          * whether the persona can update a registered limit
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_registered_limit(self):
        """Test identity:delete_registered_limit policy.

        This test must check:
          * whether the persona can delete a registered limit
        """
        pass


class SystemAdminTests(IdentityV3RbacRegisteredLimitTests,
                       base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_registered_limits(self):
        resp = self.do_request('create_registered_limits',
                               expected_status=201,
                               payload=self.registered_limits())
        self.addCleanup(
            self.admin_reglim_client.delete_registered_limit,
            registered_limit_id=resp['registered_limits'][0]['id'])

    def test_identity_list_registered_limits(self):
        reg_limit_id = self.admin_reglim_client.create_registered_limits(
            payload=self.registered_limits())['registered_limits'][0]['id']
        self.addCleanup(
            self.admin_reglim_client.delete_registered_limit,
            registered_limit_id=reg_limit_id)
        resp = self.do_request('list_registered_limits')
        self.assertIn(
            reg_limit_id, [rl['id'] for rl in resp['registered_limits']])

    def test_identity_get_registered_limit(self):
        reg_limit_id = self.admin_reglim_client.create_registered_limits(
            payload=self.registered_limits())['registered_limits'][0]['id']
        self.addCleanup(
            self.admin_reglim_client.delete_registered_limit,
            registered_limit_id=reg_limit_id)
        self.do_request('show_registered_limit',
                        registered_limit_id=reg_limit_id)

    def test_identity_update_registered_limit(self):
        reg_limit_id = self.admin_reglim_client.create_registered_limits(
            payload=self.registered_limits())['registered_limits'][0]['id']
        self.addCleanup(
            self.admin_reglim_client.delete_registered_limit,
            registered_limit_id=reg_limit_id)
        updated = {'description': data_utils.arbitrary_string()}
        self.do_request('update_registered_limit',
                        registered_limit_id=reg_limit_id,
                        registered_limit=updated)

    def test_identity_delete_registered_limit(self):
        reg_limit_id = self.admin_reglim_client.create_registered_limits(
            payload=self.registered_limits())['registered_limits'][0]['id']
        self.do_request('delete_registered_limit',
                        expected_status=204,
                        registered_limit_id=reg_limit_id)


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_registered_limits(self):
        self.do_request('create_registered_limits',
                        expected_status=exceptions.Forbidden,
                        payload=self.registered_limits())

    def test_identity_update_registered_limit(self):
        reg_limit_id = self.admin_reglim_client.create_registered_limits(
            payload=self.registered_limits())['registered_limits'][0]['id']
        self.addCleanup(
            self.admin_reglim_client.delete_registered_limit,
            registered_limit_id=reg_limit_id)
        updated = {'description': data_utils.arbitrary_string()}
        self.do_request('update_registered_limit',
                        expected_status=exceptions.Forbidden,
                        registered_limit_id=reg_limit_id,
                        registered_limit=updated)

    def test_identity_delete_registered_limit(self):
        reg_limit_id = self.admin_reglim_client.create_registered_limits(
            payload=self.registered_limits())['registered_limits'][0]['id']
        self.addCleanup(
            self.admin_reglim_client.delete_registered_limit,
            registered_limit_id=reg_limit_id)
        self.do_request('delete_registered_limit',
                        expected_status=exceptions.Forbidden,
                        registered_limit_id=reg_limit_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests):

    credentials = ['domain_admin', 'system_admin']


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
