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


class IdentityV3RbacRegionTests(rbac_base.IdentityV3RbacBaseTests,
                                metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacRegionTests, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.regions_client
        admin_client = cls.os_system_admin
        cls.admin_regions_client = admin_client.regions_client

    def region(self):
        return {'region_id': data_utils.rand_uuid_hex()}

    @abc.abstractmethod
    def test_identity_create_region(self):
        """Test identity:create_region policy.

        This test must check:
          * whether the persona can create a region
        """
        pass

    @abc.abstractmethod
    def test_identity_get_region(self):
        """Test identity:get_region policy.

        This test must check:
          * whether the persona can get a region
          * whether the persona can get a region that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_regions(self):
        """Test identity:list_regions policy.

        This test must check:
          * whether the persona can list all regions
        """
        pass

    @abc.abstractmethod
    def test_identity_update_region(self):
        """Test identity:update_region policy.

        This test must check:
          * whether the persona can update a region
          * whether the persona can update a region that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_region(self):
        """Test identity:delete_region policy.

        This test must check
          * whether the persona can delete a region
          * whether the persona can delete a region that does not exist
        """
        pass


class SystemAdminTests(IdentityV3RbacRegionTests, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_region(self):
        region_id = self.do_request(
            'create_region', expected_status=201,
            **self.region())['region']['id']
        self.addCleanup(
            self.admin_regions_client.delete_region,
            region_id=region_id)

    def test_identity_get_region(self):
        region_id = self.admin_regions_client.create_region(
            **self.region())['region']['id']
        self.addCleanup(
            self.admin_regions_client.delete_region,
            region_id=region_id)
        self.do_request('show_region', region_id=region_id)
        # user gets a 404 for nonexistent region
        self.do_request('show_region', expected_status=exceptions.NotFound,
                        region_id=data_utils.rand_uuid_hex())

    def test_identity_list_regions(self):
        region_id = self.admin_regions_client.create_region(
            **self.region())['region']['id']
        self.addCleanup(
            self.admin_regions_client.delete_region,
            region_id=region_id)
        resp = self.do_request('list_regions')
        self.assertIn(region_id, [e['id'] for e in resp['regions']])

    def test_identity_update_region(self):
        region_id = self.admin_regions_client.create_region(
            **self.region())['region']['id']
        self.addCleanup(
            self.admin_regions_client.delete_region,
            region_id=region_id)
        self.do_request('update_region',
                        region_id=region_id,
                        description=data_utils.rand_uuid_hex())
        # user gets a 404 for nonexistent region
        self.do_request('update_region', expected_status=exceptions.NotFound,
                        region_id=data_utils.rand_uuid_hex(),
                        description=data_utils.rand_uuid_hex())

    def test_identity_delete_region(self):
        region_id = self.admin_regions_client.create_region(
            **self.region())['region']['id']
        self.do_request('delete_region', expected_status=204,
                        region_id=region_id)
        # user gets a 404 for nonexistent region
        self.do_request('delete_region', expected_status=exceptions.NotFound,
                        region_id=data_utils.rand_uuid_hex())


class SystemMemberTests(SystemAdminTests, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_region(self):
        self.do_request(
            'create_region', expected_status=exceptions.Forbidden,
            **self.region())

    def test_identity_update_region(self):
        region_id = self.admin_regions_client.create_region(
            **self.region())['region']['id']
        self.addCleanup(
            self.admin_regions_client.delete_region,
            region_id=region_id)
        self.do_request('update_region', expected_status=exceptions.Forbidden,
                        region_id=region_id,
                        description=data_utils.rand_uuid_hex())
        # user gets a 403 for nonexistent region
        self.do_request('update_region', expected_status=exceptions.Forbidden,
                        region_id=data_utils.rand_uuid_hex(),
                        description=data_utils.rand_uuid_hex())

    def test_identity_delete_region(self):
        region_id = self.admin_regions_client.create_region(
            **self.region())['region']['id']
        self.do_request('delete_region',
                        expected_status=exceptions.Forbidden,
                        region_id=region_id)
        # user gets a 403 for nonexistent region
        self.do_request('delete_region', expected_status=exceptions.Forbidden,
                        region_id=data_utils.rand_uuid_hex())


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']


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
