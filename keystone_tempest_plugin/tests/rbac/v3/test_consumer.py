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


class IdentityV3RbacOauth1ConsumerTest(rbac_base.IdentityV3RbacBaseTests,
                                       metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacOauth1ConsumerTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.oauth_consumers_client
        cls.admin_client = cls.os_system_admin.oauth_consumers_client

    def consumer(self):
        return {"description": data_utils.arbitrary_string()}

    @abc.abstractmethod
    def test_identity_create_consumer(self):
        """Test identity:create_consumer policy.

        This test must check:
          * whether the persona can create a consumer
        """
        pass

    @abc.abstractmethod
    def test_identity_get_consumer(self):
        """Test identity:get_consumer policy.

        This test must check:
          * whether the persona can get a consumer
        """
        pass

    @abc.abstractmethod
    def test_identity_list_consumers(self):
        """Test identity:list_consumers policy.

        This test must check:
          * whether the persona can list all consumers
        """
        pass

    @abc.abstractmethod
    def test_identity_update_consumer(self):
        """Test identity:update_consumer policy.

        This test must check:
          * whether the persona can update a
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_consumer(self):
        """Test identity:delete_consumer policy.

        This test must check
          * whether the persona can delete a consumer
        """
        pass


class SystemAdminTests(
    IdentityV3RbacOauth1ConsumerTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_consumer(self):
        resp = self.do_request('create_consumer',
                               expected_status=201,
                               **self.consumer())
        self.addCleanup(self.client.delete_consumer,
                        resp['consumer']['id'])

    def test_identity_get_consumer(self):
        consumer = self.admin_client.create_consumer(
            **self.consumer())['consumer']
        self.addCleanup(self.admin_client.delete_consumer, consumer['id'])
        resp = self.do_request('show_consumer', consumer_id=consumer['id'])
        self.assertEqual(resp['consumer']['id'], consumer['id'])

    def test_identity_list_consumers(self):
        consumer = self.admin_client.create_consumer(
            **self.consumer())['consumer']
        self.addCleanup(self.admin_client.delete_consumer, consumer['id'])
        resp = self.do_request('list_consumers')
        self.assertIn(consumer['id'], set(c['id'] for c in resp['consumers']))

    def test_identity_update_consumer(self):
        consumer = self.client.create_consumer(**self.consumer())['consumer']
        self.addCleanup(self.client.delete_consumer, consumer['id'])
        self.do_request('update_consumer',
                        consumer_id=consumer['id'],
                        description=data_utils.arbitrary_string())

    def test_identity_delete_consumer(self):
        consumer = self.client.create_consumer(**self.consumer())['consumer']
        self.do_request('delete_consumer',
                        expected_status=204,
                        consumer_id=consumer['id'])


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_consumer(self):
        self.do_request('create_consumer',
                        expected_status=exceptions.Forbidden,
                        **self.consumer())

    def test_identity_update_consumer(self):
        consumer = self.admin_client.create_consumer(
            **self.consumer())['consumer']
        self.addCleanup(self.admin_client.delete_consumer, consumer['id'])
        self.do_request('update_consumer',
                        expected_status=exceptions.Forbidden,
                        consumer_id=consumer['id'],
                        description=data_utils.arbitrary_string())

    def test_identity_delete_consumer(self):
        consumer = self.admin_client.create_consumer(
            **self.consumer())['consumer']
        self.do_request('delete_consumer',
                        expected_status=exceptions.Forbidden,
                        consumer_id=consumer['id'])


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemMemberTests):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_consumer(self):
        consumer = self.admin_client.create_consumer(
            **self.consumer())['consumer']
        self.addCleanup(self.admin_client.delete_consumer, consumer['id'])
        self.do_request('show_consumer',
                        expected_status=exceptions.Forbidden,
                        consumer_id=consumer['id'])

    def test_identity_list_consumers(self):
        consumer = self.admin_client.create_consumer(
            **self.consumer())['consumer']
        self.addCleanup(self.admin_client.delete_consumer, consumer['id'])
        self.do_request('list_consumers',
                        expected_status=exceptions.Forbidden)


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
