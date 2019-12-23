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


class IdentityV3RbacUserTest(rbac_base.IdentityV3RbacBaseTests,
                             metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacUserTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.users_v3_client
        admin_client = cls.os_system_admin
        cls.admin_users_client = admin_client.users_v3_client
        cls.admin_domains_client = admin_client.domains_client

    def user(self):
        user = {}
        name = data_utils.rand_name('user')
        user['name'] = name
        user['description'] = name + 'description'
        user['email'] = name + '@testmail.tm'
        user['password'] = data_utils.rand_password()
        user['enabled'] = False
        return user

    @abc.abstractmethod
    def test_identity_create_user(self):
        """Test identity:create_user policy.

        This test must check:
          * whether the persona can create an arbitrary user
          * whether the persona can create a user in another domain
            (if applicable)
          * whether the persona can create a user in their own domain
            (if applicable)
        """
        pass

    @abc.abstractmethod
    def test_identity_get_user(self):
        """Test identity:get_user policy.

        This test must check:
          * whether the persona can get an arbitary user
          * whether the persona can get their own user
          * whether the persona can get a user in another domain
            (if applicable)
          * whether the persona can get a user in their own domain
            (if applicable)
          * whether the persona can get a user that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_users(self):
        """Test identity:list_users policy.

        This test must check:
          * whether the persona can list all users
          * whether the result list is appropriately filtered to domain
            (if applicable)
        """
        pass

    @abc.abstractmethod
    def test_identity_update_user(self):
        """Test identity:update_users policy.

        This test must check:
          * whether the persona can update an arbitrary user
          * whether the persona can update a user in another domain
            (if applicable)
          * whether the persona can update a user in their own domain
            (if applicable)
          * whether the persona can update a user that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_user(self):
        """Test identity:delete_user policy.

        This test must check
          * whether the persona can delete an arbitrary user
          * whether the persona can delete a user in another domain
            (if applicable)
          * whether the persona can delete a user in their own domain
            (if applicable)
          * whether the persona can delete a user that does not exist
        """
        pass


class SystemAdminTests(IdentityV3RbacUserTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_user(self):
        resp = self.do_request('create_user',
                               expected_status=201,
                               **self.user())
        self.addCleanup(self.admin_users_client.delete_user,
                        resp['user']['id'])

    def test_identity_get_user(self):
        user = self.admin_users_client.create_user(**self.user())['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        # user can get arbitrary user
        resp = self.do_request('show_user', user_id=user['id'])
        self.assertEqual(resp['user']['id'], user['id'])
        # user can get own user
        user_id = self.persona.credentials.user_id
        resp = self.do_request('show_user', user_id=user_id)
        self.assertEqual(resp['user']['id'], user_id)
        # user gets a 404 for nonexistent user
        self.do_request('show_user', expected_status=exceptions.NotFound,
                        user_id='fakeuser')

    def test_identity_list_users(self):
        domain = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']
        user_create = self.user()
        # create user in default domain
        user1 = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user1['id'])
        # create user in arbitrary domain
        user_create['domain_id'] = domain['id']
        user2 = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user2['id'])
        resp = self.do_request('list_users')
        user_ids = set(u['id'] for u in resp['users'])
        # both users should be in the list
        self.assertIn(user1['id'], user_ids)
        self.assertIn(user2['id'], user_ids)

    def test_identity_update_user(self):
        user = self.admin_users_client.create_user(**self.user())['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        user_update = {
            'user_id': user['id'],
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', **user_update)
        # user gets a 404 for nonexistent user
        user_update = {
            'user_id': 'fakeuser',
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', expected_status=exceptions.NotFound,
                        **user_update)

    def test_identity_delete_user(self):
        user = self.admin_users_client.create_user(**self.user())['user']
        self.do_request('delete_user', expected_status=204, user_id=user['id'])
        # user gets a 404 for nonexistent user
        self.do_request('delete_user', expected_status=exceptions.NotFound,
                        user_id='fakeuser')


class SystemMemberTests(IdentityV3RbacUserTest, base.BaseIdentityTest):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_user(self):
        self.do_request('create_user', expected_status=exceptions.Forbidden,
                        **self.user())

    def test_identity_get_user(self):
        user = self.admin_users_client.create_user(**self.user())['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        # user can get arbitrary user
        resp = self.do_request('show_user', user_id=user['id'])
        self.assertEqual(resp['user']['id'], user['id'])
        # user can get own user
        user_id = self.persona.credentials.user_id
        resp = self.do_request('show_user', user_id=user_id)
        self.assertEqual(resp['user']['id'], user_id)
        # user gets a 404 for nonexistent user
        self.do_request('show_user', expected_status=exceptions.NotFound,
                        user_id='fakeuser')

    def test_identity_list_users(self):
        domain = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']
        user_create = self.user()
        # create user in default domain
        user1 = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user1['id'])
        # create user in arbitrary domain
        user_create['domain_id'] = domain['id']
        user2 = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user2['id'])
        resp = self.do_request('list_users')
        user_ids = set(u['id'] for u in resp['users'])
        # both users should be in the list
        self.assertIn(user1['id'], user_ids)
        self.assertIn(user2['id'], user_ids)

    def test_identity_update_user(self):
        user = self.admin_users_client.create_user(**self.user())['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        user_update = {
            'user_id': user['id'],
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', expected_status=exceptions.Forbidden,
                        **user_update)
        # user gets a 403 for nonexistent user
        user_update = {
            'user_id': 'fakeuser',
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', expected_status=exceptions.Forbidden,
                        **user_update)

    def test_identity_delete_user(self):
        user = self.admin_users_client.create_user(**self.user())['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        self.do_request('delete_user', expected_status=exceptions.Forbidden,
                        user_id=user['id'])
        # user gets a 403 for nonexistent user
        self.do_request('delete_user', expected_status=exceptions.Forbidden,
                        user_id='fakeuser')


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(IdentityV3RbacUserTest, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def setUp(self):
        super(DomainAdminTests, self).setUp()
        self.other_domain = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']
        self.addCleanup(self.admin_domains_client.delete_domain,
                        self.other_domain['id'])
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=self.other_domain['id'], enabled=False)

    def test_identity_create_user(self):
        user_create = self.user()
        # create user in other domain
        user_create['domain_id'] = self.other_domain['id']
        self.do_request('create_user', expected_status=exceptions.Forbidden,
                        **user_create)
        # create user in own domain
        user_create['domain_id'] = self.persona.credentials.domain_id
        resp = self.do_request('create_user',
                               expected_status=201,
                               **user_create)
        self.addCleanup(self.admin_users_client.delete_user,
                        resp['user']['id'])

    def test_identity_get_user(self):
        user_create = self.user()
        user_create['domain_id'] = self.other_domain['id']
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        # user cannot get user in other domain
        self.do_request('show_user', expected_status=exceptions.Forbidden,
                        user_id=user['id'])
        user_create['domain_id'] = self.persona.credentials.domain_id
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        # user can get user in own domain
        resp = self.do_request('show_user', user_id=user['id'])
        self.assertEqual(resp['user']['id'], user['id'])
        # user can get own user
        user_id = self.persona.credentials.user_id
        resp = self.do_request('show_user', user_id=user_id)
        self.assertEqual(resp['user']['id'], user_id)
        # user gets a 403 for nonexistent user
        self.do_request('show_user', expected_status=exceptions.Forbidden,
                        user_id='fakeuser')

    def test_identity_list_users(self):
        user_create = self.user()
        # create user in other domain
        user_create['domain_id'] = self.other_domain['id']
        user1 = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user1['id'])
        # create user in own domain
        user_create['domain_id'] = self.persona.credentials.domain_id
        user2 = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user2['id'])
        resp = self.do_request('list_users')
        user_ids = set(u['id'] for u in resp['users'])
        self.assertNotIn(user1['id'], user_ids)
        self.assertIn(user2['id'], user_ids)

    def test_identity_update_user(self):
        user_create = self.user()
        # create user in other domain
        user_create['domain_id'] = self.other_domain['id']
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        user_update = {
            'user_id': user['id'],
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', expected_status=exceptions.Forbidden,
                        **user_update)
        # create user in own domain
        user_create['domain_id'] = self.persona.credentials.domain_id
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        user_update = {
            'user_id': user['id'],
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', **user_update)
        # user gets a 403 for nonexistent user
        user_update = {
            'user_id': 'fakeuser',
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', expected_status=exceptions.Forbidden,
                        **user_update)

    def test_identity_delete_user(self):
        user_create = self.user()
        # create user in other domain
        user_create['domain_id'] = self.other_domain['id']
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        self.do_request('delete_user', expected_status=exceptions.Forbidden,
                        user_id=user['id'])
        # create user in own domain
        user_create['domain_id'] = self.persona.credentials.domain_id
        user = self.admin_users_client.create_user(**user_create)['user']
        self.do_request('delete_user', expected_status=204, user_id=user['id'])
        # user gets a 403 for nonexistent user
        self.do_request('delete_user', expected_status=exceptions.Forbidden,
                        user_id='fakeuser')


class DomainMemberTests(IdentityV3RbacUserTest, base.BaseIdentityTest):

    credentials = ['domain_member', 'system_admin']

    def setUp(self):
        super(DomainMemberTests, self).setUp()
        self.other_domain = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']
        self.addCleanup(self.admin_domains_client.delete_domain,
                        self.other_domain['id'])
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=self.other_domain['id'], enabled=False)

    def test_identity_create_user(self):
        user_create = self.user()
        # create user without domain specified
        self.do_request('create_user', expected_status=exceptions.Forbidden,
                        **user_create)
        # create user in other domain
        user_create['domain_id'] = self.other_domain['id']
        self.do_request('create_user', expected_status=exceptions.Forbidden,
                        **user_create)
        # create user in own domain
        user_create['domain_id'] = self.persona.credentials.domain_id
        self.do_request('create_user', expected_status=exceptions.Forbidden,
                        **user_create)

    def test_identity_get_user(self):
        user_create = self.user()
        user_create['domain_id'] = self.other_domain['id']
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        # user cannot get user in other domain
        self.do_request('show_user', expected_status=exceptions.Forbidden,
                        user_id=user['id'])
        user_create['domain_id'] = self.persona.credentials.domain_id
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        # user can get user in own domain
        resp = self.do_request('show_user', user_id=user['id'])
        self.assertEqual(resp['user']['id'], user['id'])
        # user can get own user
        user_id = self.persona.credentials.user_id
        resp = self.do_request('show_user', user_id=user_id)
        self.assertEqual(resp['user']['id'], user_id)
        # user gets a 403 for nonexistent user
        self.do_request('show_user', expected_status=exceptions.Forbidden,
                        user_id='fakeuser')

    def test_identity_list_users(self):
        user_create = self.user()
        # create user in other domain
        user_create['domain_id'] = self.other_domain['id']
        user1 = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user1['id'])
        # create user in own domain
        user_create['domain_id'] = self.persona.credentials.domain_id
        user2 = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user2['id'])
        resp = self.do_request('list_users')
        user_ids = set(u['id'] for u in resp['users'])
        self.assertNotIn(user1['id'], user_ids)
        self.assertIn(user2['id'], user_ids)

    def test_identity_update_user(self):
        user_create = self.user()
        # create user in other domain
        user_create['domain_id'] = self.other_domain['id']
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        user_update = {
            'user_id': user['id'],
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', expected_status=exceptions.Forbidden,
                        **user_update)
        # create user in own domain
        user_create['domain_id'] = self.persona.credentials.domain_id
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        user_update = {
            'user_id': user['id'],
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', expected_status=exceptions.Forbidden,
                        **user_update)
        # user gets a 403 for nonexistent user
        user_update = {
            'user_id': 'fakeuser',
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', expected_status=exceptions.Forbidden,
                        **user_update)

    def test_identity_delete_user(self):
        user_create = self.user()
        # create user in other domain
        user_create['domain_id'] = self.other_domain['id']
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        self.do_request('delete_user', expected_status=exceptions.Forbidden,
                        user_id=user['id'])
        # create user in own domain
        user_create['domain_id'] = self.persona.credentials.domain_id
        user = self.admin_users_client.create_user(**user_create)['user']
        self.do_request('delete_user', expected_status=exceptions.Forbidden,
                        user_id=user['id'])
        # user gets a 403 for nonexistent user
        self.do_request('delete_user', expected_status=exceptions.Forbidden,
                        user_id='fakeuser')


class DomainReaderTests(DomainMemberTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(IdentityV3RbacUserTest, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']

    def test_identity_create_user(self):
        self.do_request('create_user', expected_status=exceptions.Forbidden,
                        **self.user())

    def test_identity_get_user(self):
        user = self.admin_users_client.create_user(**self.user())['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        # user cannot get arbitrary user
        self.do_request('show_user', expected_status=exceptions.Forbidden,
                        user_id=user['id'])
        # user can get own user
        user_id = self.persona.credentials.user_id
        resp = self.do_request('show_user', user_id=user_id)
        self.assertEqual(resp['user']['id'], user_id)
        # user gets a 403 for nonexistent user
        self.do_request('show_user', expected_status=exceptions.Forbidden,
                        user_id='fakeuser')

    def test_identity_list_users(self):
        user = self.admin_users_client.create_user(**self.user())['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        self.do_request('list_users', expected_status=exceptions.Forbidden)

    def test_identity_update_user(self):
        user_create = self.user()
        user = self.admin_users_client.create_user(**user_create)['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        user_update = {
            'user_id': user['id'],
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', expected_status=exceptions.Forbidden,
                        **user_update)
        # user gets a 403 for nonexistent user
        user_update = {
            'user_id': 'fakeuser',
            'description': data_utils.arbitrary_string()
        }
        self.do_request('update_user', expected_status=exceptions.Forbidden,
                        **user_update)

    def test_identity_delete_user(self):
        user = self.admin_users_client.create_user(**self.user())['user']
        self.addCleanup(self.admin_users_client.delete_user, user['id'])
        self.do_request('delete_user', expected_status=exceptions.Forbidden,
                        user_id=user['id'])
        # user gets a 403 for nonexistent user
        self.do_request('delete_user', expected_status=exceptions.Forbidden,
                        user_id='fakeuser')


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
