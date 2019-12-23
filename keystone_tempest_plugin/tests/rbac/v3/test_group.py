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


class IdentityV3RbacGroupTest(rbac_base.IdentityV3RbacBaseTests,
                              metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacGroupTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.groups_client
        cls.users_client = cls.persona.users_v3_client
        cls.admin_client = cls.os_system_admin
        cls.admin_groups_client = cls.admin_client.groups_client
        cls.admin_users_client = cls.admin_client.users_v3_client
        cls.admin_domains_client = cls.admin_client.domains_client

    def setUp(self):
        super(IdentityV3RbacGroupTest, self).setUp()
        self.own_domain = self.persona.credentials.domain_id
        self.other_domain = self.admin_domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_domains_client.delete_domain,
                        self.other_domain)
        self.addCleanup(self.admin_domains_client.update_domain,
                        domain_id=self.other_domain, enabled=False)

    def group(self, domain_id=None):
        group = {}
        name = data_utils.rand_name('group')
        group['name'] = name
        if domain_id:
            group['domain_id'] = domain_id
        return group

    @abc.abstractmethod
    def test_identity_create_group(self):
        """Test identity:create_group policy.

        This test must check:
          * whether the persona can create an arbitrary group
          * whether the persona can create a group in another domain
          * whether the persona can create a group in their own domain
        """
        pass

    @abc.abstractmethod
    def test_identity_get_group(self):
        """Test identity:get_group policy.

        This test must check:
          * whether the persona can get an arbitrary group
          * whether the persona can get a group in another domain
          * whether the persona can get a group in their own domain
          * whether the persona can get a group that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_groups(self):
        """Test identity:list_groups policy.

        This test must check:
          * whether the persona can list all groups
          * whether the result list is appropriately filtered to domain
        """
        pass

    @abc.abstractmethod
    def test_identity_list_groups_for_user(self):
        """Test identity:list_groups_for_user policy.

        This test must check:
          * whether the persona can list groups for an arbitrary user
          * whether the persona can see groups in their own domain for user in
            their own domain
          * whether the persona can see groups in another domain for user in
            their own domain
          * whether the persona can see groups in their own domain for user in
            another domain
          * whether the persona can see groups in another domain for user in
            another domain
          * whether the persona can list groups for a nonexistent user
        """
        pass

    @abc.abstractmethod
    def test_identity_update_group(self):
        """Test identity:update_groups policy.

        This test must check:
          * whether the persona can update an arbitrary group
          * whether the persona can update a group in another domain
          * whether the persona can update a group in their own domain
          * whether the persona can update a group that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_group(self):
        """Test identity:delete_group policy.

        This test must check
          * whether the persona can delete an arbitrary group
          * whether the persona can delete a group in another domain
          * whether the persona can delete a group in their own domain
          * whether the persona can delete a group that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_users_in_group(self):
        """Test identity:list_users_in_group policy.

        This test must check
          * whether the persona can list users in an arbitrary group
          * whether the persona can see users in their own domain for group in
            their own domain
          * whether the persona can see users in another domain for group in
            their own domain
          * whether the persona can see users in their own domain for group in
            another domain
          * whether the persona can see users in another domain for group in
            another domain
          * whether the persona can list users for a nonexistent group
        """
        pass

    @abc.abstractmethod
    def test_identity_add_user_to_group(self):
        """Test identity:add_user_to_group policy.

        This test must check
          * whether the persona can add an arbitrary user to an arbitrary group
          * whether the persona can add a user in their own domain to a group
            in their own domain
          * whether the persona can add a user in another domain to a group in
            their own domain
          * whether the persona can add a user in their own domain to a group
            in another domain
          * whether the persona can add a user in another domain to a group in
            their own domain
          * whether the persona can add a nonexistent user to a group
          * whether the persona can add a user to a nonexistent group
        """
        pass

    @abc.abstractmethod
    def test_identity_remove_user_from_group(self):
        """Test identity:remove_user_from_group policy.

        This test must check
          * whether the persona can remove an arbitrary user from an arbitrary
            group
          * whether the persona can remove a user in their own domain from a
            group in their own domain
          * whether the persona can remove a user in another domain from a
            group in their own domain
          * whether the persona can remove a user in their own domain from a
            group in another domain
          * whether the persona can remove a user in another domain from a
            group in their own domain
          * whether the persona can remove a nonexistent user from a group
          * whether the persona can remove a user from a nonexistent group
        """
        pass

    @abc.abstractmethod
    def test_identity_check_user_in_group(self):
        """Test identity:check_user_in_group policy.

        This test must check
          * whether the persona can check if an arbitrary user is in an
            arbitrary group
          * whether the persona can check if a user in their own domain is in a
            group in their own domain
          * whether the persona can check if a user in another domain is in a
            group in their own domain
          * whether the persona can check if a user in their own domain is in a
            group in another domain
          * whether the persona can check if a user in another domain is in a
            group in another domain
          * whether the persona can check if a nonexistent user is in a group
          * whether the persona can check if a user is in a nonexistent group
        """
        pass


class SystemAdminTests(IdentityV3RbacGroupTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_group(self):
        resp = self.do_request('create_group', expected_status=201,
                               **self.group())
        self.addCleanup(self.admin_groups_client.delete_group,
                        resp['group']['id'])

    def test_identity_get_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        # user can get an arbitrary group
        self.do_request('show_group', group_id=group['id'])
        # user gets a 404 for nonexistent group
        self.do_request('show_group', expected_status=exceptions.NotFound,
                        group_id='fakegroup')

    def test_identity_list_groups(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        resp = self.do_request('list_groups')
        self.assertIn(group['id'], set(g['id'] for g in resp['groups']))

    def test_identity_list_groups_for_user(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        user = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'))['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user['id'])
        self.admin_groups_client.add_group_user(group['id'], user['id'])
        resp = self.do_request('list_user_groups', client=self.users_client,
                               user_id=user['id'])
        self.assertIn(group['id'], set(g['id'] for g in resp['groups']))
        self.do_request('list_user_groups', client=self.users_client,
                        expected_status=exceptions.NotFound,
                        user_id='fakeuser')

    def test_identity_update_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        # user can update an arbitrary group
        group_update = {
            'group_id': group['id'],
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', **group_update)
        # user gets a 404 for nonexistent group
        group_update = {
            'group_id': 'fakegroup',
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.NotFound,
                        **group_update)

    def test_identity_delete_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        # user can delete an arbitrary group
        self.do_request('delete_group', expected_status=204,
                        group_id=group['id'])
        # user gets a 404 for nonexistent group
        self.do_request('delete_group', expected_status=exceptions.NotFound,
                        group_id='fakegroup')

    def test_identity_list_users_in_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        user = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'))['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user['id'])
        self.admin_groups_client.add_group_user(group['id'], user['id'])
        resp = self.do_request('list_group_users', group_id=group['id'])
        user_ids = set(u['id'] for u in resp['users'])
        self.assertEqual(1, len(user_ids))
        self.assertIn(user['id'], user_ids)

    def test_identity_add_user_to_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        user = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'))['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user['id'])
        # user can add a user to a group
        self.do_request('add_group_user', expected_status=204,
                        group_id=group['id'], user_id=user['id'])
        # user gets a 404 for nonexistent group
        self.do_request('add_group_user', expected_status=exceptions.NotFound,
                        group_id='fakegroup', user_id=user['id'])
        # user gets a 404 for nonexistent user
        self.do_request('add_group_user', expected_status=exceptions.NotFound,
                        group_id=group['id'], user_id='fakeuser')

    def test_identity_remove_user_from_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        user = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'))['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user['id'])
        self.admin_groups_client.add_group_user(group['id'], user['id'])
        # user can remove a user from a group
        self.do_request('delete_group_user', expected_status=204,
                        group_id=group['id'], user_id=user['id'])
        # user gets a 404 for nonexistent group
        self.do_request('delete_group_user',
                        expected_status=exceptions.NotFound,
                        group_id='fakegroup', user_id=user['id'])
        # user gets a 404 for nonexistent user
        self.do_request('delete_group_user',
                        expected_status=exceptions.NotFound,
                        group_id=group['id'], user_id='fakeuser')

    def test_identity_check_user_in_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        user = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'))['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user['id'])
        self.admin_groups_client.add_group_user(group['id'], user['id'])
        # user can check if a user is in a group
        self.do_request('check_group_user_existence', expected_status=204,
                        group_id=group['id'], user_id=user['id'])
        # user gets a 404 for nonexistent group
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.NotFound,
                        group_id='fakegroup', user_id=user['id'])
        # user gets a 404 for nonexistent user
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.NotFound,
                        group_id=group['id'], user_id='fakeuser')


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_group(self):
        self.do_request('create_group', expected_status=exceptions.Forbidden,
                        **self.group())

    def test_identity_update_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        # user cannot update an arbitrary group
        group_update = {
            'group_id': group['id'],
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.Forbidden,
                        **group_update)
        # user gets a 403 for nonexistent group
        group_update = {
            'group_id': 'fakegroup',
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.Forbidden,
                        **group_update)

    def test_identity_delete_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        # user cannot delete an arbitrary group
        self.do_request('delete_group', expected_status=exceptions.Forbidden,
                        group_id=group['id'])
        # user gets a 403 for nonexistent group
        self.do_request('delete_group', expected_status=exceptions.Forbidden,
                        group_id=group['id'])

    def test_identity_add_user_to_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        user = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'))['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user['id'])
        # user cannot add a user to a group
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group['id'], user_id=user['id'])
        # user gets a 403 for nonexistent group
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id='fakegroup', user_id=user['id'])
        # user gets a 403 for nonexistent user
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group['id'], user_id='fakeuser')

    def test_identity_remove_user_from_group(self):
        group = self.admin_groups_client.create_group(**self.group())['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        user = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'))['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user['id'])
        self.admin_groups_client.add_group_user(group['id'], user['id'])
        # user cannot remove a user from a group
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group['id'], user_id=user['id'])
        # user gets a 403 for nonexistent group
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id='fakegroup', user_id=user['id'])
        # user gets a 403 for nonexistent user
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group['id'], user_id='fakeuser')


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(IdentityV3RbacGroupTest, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_create_group(self):
        # user can create group in own domain
        resp = self.do_request('create_group', expected_status=201,
                               **self.group(domain_id=self.own_domain))
        self.addCleanup(self.admin_groups_client.delete_group,
                        resp['group']['id'])
        # user cannot create group in another domain
        resp = self.do_request('create_group',
                               expected_status=exceptions.Forbidden,
                               **self.group(domain_id=self.other_domain))

    def test_identity_get_group(self):
        group = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        # user can get group in own domain
        self.do_request('show_group', group_id=group['id'])
        # user cannot get group in other domain
        group = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        self.do_request('show_group', expected_status=exceptions.Forbidden,
                        group_id=group['id'])
        # user gets a 403 for nonexistent group
        self.do_request('show_group', expected_status=exceptions.Forbidden,
                        group_id='fakegroup')

    def test_identity_list_groups(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        resp = self.do_request('list_groups')
        # user can get groups in own domain
        self.assertIn(group1['id'], set(g['id'] for g in resp['groups']))
        # user cannot get groups in other domain
        self.assertNotIn(group2['id'], set(g['id'] for g in resp['groups']))

    def test_identity_list_groups_for_user(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.other_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        self.admin_groups_client.add_group_user(group1['id'], user1['id'])
        self.admin_groups_client.add_group_user(group1['id'], user2['id'])
        self.admin_groups_client.add_group_user(group2['id'], user1['id'])
        self.admin_groups_client.add_group_user(group2['id'], user2['id'])
        resp = self.do_request('list_user_groups', client=self.users_client,
                               user_id=user1['id'])
        # user can list groups in own domain for user in own domain
        self.assertIn(group1['id'], set(g['id'] for g in resp['groups']))
        # user cannot list groups in other domain for user in own domain
        self.assertNotIn(group2['id'], set(g['id'] for g in resp['groups']))
        # user cannot list groups for user in other domain
        resp = self.do_request('list_user_groups', client=self.users_client,
                               expected_status=exceptions.Forbidden,
                               user_id=user2['id'])
        # user gets a 403 for nonexistent user
        self.do_request('list_user_groups', client=self.users_client,
                        expected_status=exceptions.Forbidden,
                        user_id='fakeuser')

    def test_identity_update_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        # user can update a group in own domain
        group_update = {
            'group_id': group1['id'],
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', **group_update)
        # user cannot update a group in other domain
        group_update = {
            'group_id': group2['id'],
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.Forbidden,
                        **group_update)
        # user gets a 403 for nonexistent group
        group_update = {
            'group_id': 'fakegroup',
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.Forbidden,
                        **group_update)

    def test_identity_delete_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        # user can delete a group in own domain
        self.do_request('delete_group', expected_status=204,
                        group_id=group1['id'])
        # user cannot delete a group in other domain
        self.do_request('delete_group', expected_status=exceptions.Forbidden,
                        group_id=group2['id'])
        # user gets a 404 for nonexistent group
        self.do_request('delete_group', expected_status=exceptions.NotFound,
                        group_id='fakegroup')

    def test_identity_list_users_in_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.other_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        self.admin_groups_client.add_group_user(group1['id'], user1['id'])
        self.admin_groups_client.add_group_user(group1['id'], user2['id'])
        self.admin_groups_client.add_group_user(group2['id'], user1['id'])
        self.admin_groups_client.add_group_user(group2['id'], user2['id'])
        resp = self.do_request('list_group_users', group_id=group1['id'])
        # user can list users in own domain for group in own domain
        self.assertIn(user1['id'], set(u['id'] for u in resp['users']))
        # user cannot list users in another domain for group in own domain
        self.assertNotIn(user2['id'], set(u['id'] for u in resp['users']))
        # user cannot list users for group in another domain
        self.do_request('list_group_users',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'])

    def test_identity_add_user_to_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        # user can add a user in own domain to a group in own domain
        self.do_request('add_group_user', expected_status=204,
                        group_id=group1['id'], user_id=user1['id'])
        # user can add a user in another domain to a group in own domain
        self.do_request('add_group_user', expected_status=204,
                        group_id=group1['id'], user_id=user2['id'])
        # user cannot add a user in own domain to a group in another domain
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user1['id'])
        # user cannot add a user in another domain to a group in another domain
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user2['id'])
        # user gets a 403 for nonexistent group
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id='fakegroup', user_id=user1['id'])
        # user gets a 403 for nonexistent user
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id='fakeuser')

    def test_identity_remove_user_from_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        self.admin_groups_client.add_group_user(group1['id'], user1['id'])
        self.admin_groups_client.add_group_user(group1['id'], user2['id'])
        self.admin_groups_client.add_group_user(group2['id'], user1['id'])
        self.admin_groups_client.add_group_user(group2['id'], user2['id'])
        # user can remove a user in own domain from a group in own domain
        self.do_request('delete_group_user', expected_status=204,
                        group_id=group1['id'], user_id=user1['id'])
        # user can remove a user in another domain from a group in own
        # domain
        self.do_request('delete_group_user', expected_status=204,
                        group_id=group1['id'], user_id=user2['id'])
        # user cannot remove a user in own domain from a group in another
        # domain
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user1['id'])
        # user cannot remove a user in another domain from a group in another
        # domain
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user2['id'])
        # user gets a 403 for nonexistent group
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id='fakegroup', user_id=user1['id'])
        # user gets a 403 for nonexistent user
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id='fakeuser')

    def test_identity_check_user_in_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        self.admin_groups_client.add_group_user(group1['id'], user1['id'])
        self.admin_groups_client.add_group_user(group1['id'], user2['id'])
        self.admin_groups_client.add_group_user(group2['id'], user1['id'])
        self.admin_groups_client.add_group_user(group2['id'], user2['id'])
        # user can check if a user in own domain is in a group in own domain
        self.do_request('check_group_user_existence', expected_status=204,
                        group_id=group1['id'], user_id=user1['id'])
        # user can check if a user in another domain is in a group in own
        # domain
        self.do_request('check_group_user_existence',
                        expected_status=204,
                        group_id=group1['id'], user_id=user2['id'])
        # user cannot check if a user in own domain is in a group in another
        # domain
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user1['id'])
        # user cannot check if a user in another domain is in a group in
        # another domain
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user2['id'])
        # user gets a 403 for nonexistent group
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.Forbidden,
                        group_id='fakegroup', user_id=user1['id'])
        # user gets a 403 for nonexistent user
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id='fakeuser')


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']

    def test_identity_create_group(self):
        # user cannot create group in own domain
        self.do_request('create_group',
                        expected_status=exceptions.Forbidden,
                        **self.group(domain_id=self.own_domain))
        # user cannot create group in another domain
        self.do_request('create_group',
                        expected_status=exceptions.Forbidden,
                        **self.group(domain_id=self.other_domain))

    def test_identity_update_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        # user cannot update a group in own domain
        group_update = {
            'group_id': group1['id'],
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.Forbidden,
                        **group_update)
        # user cannot update a group in other domain
        group_update = {
            'group_id': group2['id'],
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.Forbidden,
                        **group_update)
        # user gets a 403 for nonexistent group
        group_update = {
            'group_id': 'fakegroup',
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.Forbidden,
                        **group_update)

    def test_identity_delete_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        # user cannot delete a group in own domain
        self.do_request('delete_group', expected_status=exceptions.Forbidden,
                        group_id=group1['id'])
        # user cannot delete a group in other domain
        self.do_request('delete_group', expected_status=exceptions.Forbidden,
                        group_id=group2['id'])
        # user gets a 404 for nonexistent group
        self.do_request('delete_group', expected_status=exceptions.NotFound,
                        group_id='fakegroup')

    def test_identity_add_user_to_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        # user cannot add a user in own domain to a group in own domain
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id=user1['id'])
        # user cannot add a user in another domain to a group in own domain
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id=user2['id'])
        # user cannot add a user in own domain to a group in another domain
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user1['id'])
        # user cannot add a user in another domain to a group in another domain
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user2['id'])
        # user gets a 403 for nonexistent group
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id='fakegroup', user_id=user1['id'])
        # user gets a 403 for nonexistent user
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id='fakeuser')

    def test_identity_remove_user_from_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        self.admin_groups_client.add_group_user(group1['id'], user1['id'])
        self.admin_groups_client.add_group_user(group1['id'], user2['id'])
        self.admin_groups_client.add_group_user(group2['id'], user1['id'])
        self.admin_groups_client.add_group_user(group2['id'], user2['id'])
        # user cannot remove a user in own domain from a group in own domain
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id=user1['id'])
        # user cannot remove a user in another domain from a group in own
        # domain
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id=user2['id'])
        # user cannot remove a user in own domain from a group in another
        # domain
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user1['id'])
        # user cannot remove a user in another domain from a group in another
        # domain
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user2['id'])
        # user gets a 403 for nonexistent group
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id='fakegroup', user_id=user1['id'])
        # user gets a 403 for nonexistent user
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id='fakeuser')


class DomainReaderTests(DomainMemberTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(IdentityV3RbacGroupTest, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']

    def test_identity_create_group(self):
        # user cannot create group in own domain
        self.do_request('create_group', expected_status=exceptions.Forbidden,
                        **self.group(domain_id=self.own_domain))
        # user cannot create group in another domain
        self.do_request('create_group',
                        expected_status=exceptions.Forbidden,
                        **self.group(domain_id=self.other_domain))

    def test_identity_get_group(self):
        group = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        # user cannot get group in own domain
        self.do_request('show_group', expected_status=exceptions.Forbidden,
                        group_id=group['id'])
        # user cannot get group in other domain
        group = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group['id'])
        self.do_request('show_group', expected_status=exceptions.Forbidden,
                        group_id=group['id'])
        # user gets a 403 for nonexistent group
        self.do_request('show_group', expected_status=exceptions.Forbidden,
                        group_id='fakegroup')

    def test_identity_list_groups(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        self.do_request('list_groups', expected_status=exceptions.Forbidden)

    def test_identity_list_groups_for_user(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.other_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        self.admin_groups_client.add_group_user(group1['id'], user1['id'])
        self.admin_groups_client.add_group_user(group1['id'], user2['id'])
        self.admin_groups_client.add_group_user(group2['id'], user1['id'])
        self.admin_groups_client.add_group_user(group2['id'], user2['id'])
        # user cannot list groups for user in own domain
        self.do_request('list_user_groups', client=self.users_client,
                        expected_status=exceptions.Forbidden,
                        user_id=user1['id'])
        # user cannot list groups for user in other domain
        self.do_request('list_user_groups', client=self.users_client,
                        expected_status=exceptions.Forbidden,
                        user_id=user2['id'])
        # user gets a 403 for nonexistent user
        self.do_request('list_user_groups', client=self.users_client,
                        expected_status=exceptions.Forbidden,
                        user_id='fakeuser')

    def test_identity_update_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        # user cannot update a group in own domain
        group_update = {
            'group_id': group1['id'],
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.Forbidden,
                        **group_update)
        # user cannot update a group in other domain
        group_update = {
            'group_id': group2['id'],
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.Forbidden,
                        **group_update)
        # user gets a 403 for nonexistent group
        group_update = {
            'group_id': 'fakegroup',
            'description': data_utils.arbitrary_string
        }
        self.do_request('update_group', expected_status=exceptions.Forbidden,
                        **group_update)

    def test_identity_delete_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        # user cannot delete a group in own domain
        self.do_request('delete_group', expected_status=exceptions.Forbidden,
                        group_id=group1['id'])
        # user cannot delete a group in other domain
        self.do_request('delete_group', expected_status=exceptions.Forbidden,
                        group_id=group2['id'])
        # user gets a 403 for nonexistent group
        self.do_request('delete_group', expected_status=exceptions.NotFound,
                        group_id='fakegroup')

    def test_identity_list_users_in_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(domain_id=self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.other_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        self.admin_groups_client.add_group_user(group1['id'], user1['id'])
        self.admin_groups_client.add_group_user(group1['id'], user2['id'])
        self.admin_groups_client.add_group_user(group2['id'], user1['id'])
        self.admin_groups_client.add_group_user(group2['id'], user2['id'])
        # user cannot list users for group in own domain
        self.do_request('list_group_users',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'])
        # user cannot list users for group in another domain
        self.do_request('list_group_users',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'])

    def test_identity_add_user_to_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        # user cannot add a user in own domain to a group in own domain
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id=user1['id'])
        # user cannot add a user in another domain to a group in own domain
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id=user2['id'])
        # user cannot add a user in own domain to a group in another domain
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user1['id'])
        # user cannot add a user in another domain to a group in another domain
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user2['id'])
        # user gets a 403 for nonexistent group
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id='fakegroup', user_id=user1['id'])
        # user gets a 403 for nonexistent user
        self.do_request('add_group_user', expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id='fakeuser')

    def test_identity_remove_user_from_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        self.admin_groups_client.add_group_user(group1['id'], user1['id'])
        self.admin_groups_client.add_group_user(group1['id'], user2['id'])
        self.admin_groups_client.add_group_user(group2['id'], user1['id'])
        self.admin_groups_client.add_group_user(group2['id'], user2['id'])
        # user cannot remove a user in own domain from a group in own domain
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id=user1['id'])
        # user cannot remove a user in another domain from a group in own
        # domain
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id=user2['id'])
        # user cannot remove a user in own domain from a group in another
        # domain
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user1['id'])
        # user cannot remove a user in another domain from a group in another
        # domain
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user2['id'])
        # user gets a 403 for nonexistent group
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id='fakegroup', user_id=user1['id'])
        # user gets a 403 for nonexistent user
        self.do_request('delete_group_user',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id='fakeuser')

    def test_identity_check_user_in_group(self):
        group1 = self.admin_groups_client.create_group(
            **self.group(self.own_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group1['id'])
        group2 = self.admin_groups_client.create_group(
            **self.group(self.other_domain))['group']
        self.addCleanup(self.admin_groups_client.delete_group, group2['id'])
        user1 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user1['id'])
        user2 = self.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            domain_id=self.own_domain)['user']
        self.addCleanup(self.admin_client.users_v3_client.delete_user,
                        user2['id'])
        self.admin_groups_client.add_group_user(group1['id'], user1['id'])
        self.admin_groups_client.add_group_user(group1['id'], user2['id'])
        self.admin_groups_client.add_group_user(group2['id'], user1['id'])
        self.admin_groups_client.add_group_user(group2['id'], user2['id'])
        # user cannot check if a user in own domain is in a group in own domain
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id=user1['id'])
        # user cannot check if a user in another domain is in a group in own
        # domain
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id=user2['id'])
        # user cannot check if a user in own domain is in a group in another
        # domain
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user1['id'])
        # user cannot check if a user in another domain is in a group in
        # another domain
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.Forbidden,
                        group_id=group2['id'], user_id=user2['id'])
        # user gets a 403 for nonexistent group
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.Forbidden,
                        group_id='fakegroup', user_id=user1['id'])
        # user gets a 403 for nonexistent user
        self.do_request('check_group_user_existence',
                        expected_status=exceptions.Forbidden,
                        group_id=group1['id'], user_id='fakeuser')


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
