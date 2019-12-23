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
from tempest import clients
from tempest.lib import auth
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions

from keystone_tempest_plugin.tests.rbac.v3 import base as rbac_base


class IdentityV3RbacTrustTest(rbac_base.IdentityV3RbacBaseTests,
                              metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacTrustTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.trusts_client
        cls.admin_client = cls.os_system_admin
        cls.admin_trusts_client = cls.admin_client.trusts_client

    @classmethod
    def resource_setup(cls):
        trustor_user = {
            'name': data_utils.rand_name('user'),
            'password': data_utils.rand_password(),
        }
        cls.trustor = cls.admin_client.users_v3_client.create_user(
            **trustor_user)['user']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.users_v3_client.delete_user,
            user_id=cls.trustor)
        cls.trustee = cls.admin_client.users_v3_client.create_user(
            name=data_utils.rand_name())['user']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.users_v3_client.delete_user,
            user_id=cls.trustee)
        cls.project = cls.admin_client.projects_client.create_project(
            name=data_utils.rand_name()
        )['project']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.projects_client.delete_project,
            project_id=cls.project)
        cls.roles = [
            {'id': cls.admin_client.roles_v3_client.create_role(
                name=data_utils.rand_name())['role']['id']}
        ]
        cls.addClassResourceCleanup(
            cls.admin_client.roles_v3_client.delete_role,
            role_id=cls.roles[0]['id'])
        cls.admin_client.roles_v3_client.create_user_role_on_project(
            project_id=cls.project,
            user_id=cls.trustor,
            role_id=cls.roles[0]['id']
        )
        creds = auth.KeystoneV3Credentials(
            user_id=cls.trustor,
            password=trustor_user['password'],
            project_id=cls.project)
        auth_provider = clients.get_auth_provider(creds)
        creds = auth_provider.fill_credentials()
        user_client = clients.Manager(credentials=creds)
        cls.user_trust_client = user_client.trusts_client

        cls.admin_role_id = cls.admin_client.roles_v3_client.list_roles(
            name='admin')['roles'][0]['id']
        cls.member_role_id = cls.admin_client.roles_v3_client.list_roles(
            name='member')['roles'][0]['id']
        cls.reader_role_id = cls.admin_client.roles_v3_client.list_roles(
            name='reader')['roles'][0]['id']

    def trust(self, trustor=None, trustee=None, project_id=None, roles=None):
        trust = {}
        trust['trustor_user_id'] = trustor or self.trustor
        trust['trustee_user_id'] = trustee or self.trustee
        trust['project_id'] = project_id or self.project
        trust['roles'] = roles or self.roles
        trust['impersonation'] = False
        return trust

    @abc.abstractmethod
    def test_identity_create_trust(self):
        """Test identity:create_trust policy.

        This test must check:
          * whether the persona can create a trust for themself
          * whether the persona can create a trust for another user
        """
        pass

    @abc.abstractmethod
    def test_identity_get_trust(self):
        """Test identity:get_trust policy.

        This test must check:
          * whether the persona can get a trust for which they are the trustor
          * whether the persona can get a trust for which they are the trustee
          * whether the persona can get a trust with which they are
            unaffiliated
        """
        pass

    @abc.abstractmethod
    def test_identity_list_trusts(self):
        """Test identity:list_trusts policy.

        This test must check:
          * whether the persona can list all trusts
        """
        pass

    @abc.abstractmethod
    def test_identity_list_trusts_for_trustor(self):
        """Test identity:list_trusts_for_trustor policy.

        This test must check:
          * whether the persona can list trusts by trustor for which they are
            the trustor
          * whether the persona can list trusts by trustor for which another
            user is trustor
        """
        pass

    @abc.abstractmethod
    def test_identity_list_trusts_for_trustee(self):
        """Test identity:list_trusts_for_trustee policy.

        This test must check:
          * whether the persona can list trusts by trustee for which they are
            the trustee
          * whether the persona can list trusts by trustee for which another
            user is trustee
        """
        pass

    @abc.abstractmethod
    def test_identity_list_roles_for_trust(self):
        """Test identity:list_roles_for_trust policy.

        This test must check:
          * whether the persona can list the roles of a trust for which they
            are the trustee
          * whether the persona can list the roles of a trust for which they
            are the trustor
          * whether the persona can list the roles of a trust with which they
            are unaffiliated
        """
        pass

    @abc.abstractmethod
    def test_identity_get_role_for_trust(self):
        """Test identity:get_role_for_trust policy.

        This test must check:
          * whether the persona can get a role of a trust for which they are
            the trustee
          * whether the persona can get a role of a trust for which they are
            the trustor
          * whether the persona can get a role of a trust with which they are
            unaffiliated
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_trust(self):
        """Test identity:delete_trust policy.

        This test must check
          * whether the persona can delete a trust for which they are the
            trustor
          * whether the persona can delete a trust for which they are the
            trustee
          * whether the persona can delete a trust which which they are
            unaffiliated
        """
        pass


class SystemAdminTests(IdentityV3RbacTrustTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_trust(self):
        # user cannot create trust for themself
        self.do_request('create_trust',
                        expected_status=exceptions.Forbidden,
                        **self.trust(trustor=self.persona.credentials.user_id))
        # user cannot create trust for another user
        self.do_request('create_trust',
                        expected_status=exceptions.Forbidden,
                        **self.trust())

    def test_identity_get_trust(self):
        # user cannot have their own trust
        # user can get trust for other user
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('show_trust', trust_id=trust_id)

    def test_identity_list_trusts(self):
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        resp = self.do_request('list_trusts')
        self.assertIn(trust_id, [t['id'] for t in resp['trusts']])

    def test_identity_list_trusts_for_trustor(self):
        # user cannot have their own trust
        # user can list trusts for other user
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('list_trusts', trustor_user_id=self.trustor)

    def test_identity_list_trusts_for_trustee(self):
        # user cannot have their own trust
        # user can list trusts for other user
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('list_trusts', trustee_user_id=self.trustee)

    def test_identity_list_roles_for_trust(self):
        # user cannot have their own trust
        # user can list roles of trust for other user
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        resp = self.do_request('list_trust_roles', trust_id=trust_id)
        self.assertIn(self.roles[0]['id'], [r['id'] for r in resp['roles']])

    def test_identity_get_role_for_trust(self):
        # user cannot have their own trust
        # user can get role of trust for other user
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('show_trust_role',
                        trust_id=trust_id, role_id=self.roles[0]['id'])

    def test_identity_delete_trust(self):
        # user cannot have their own trust
        # user can delete a user's trust
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.do_request('delete_trust', expected_status=204, trust_id=trust_id)


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_delete_trust(self):
        # system user cannot have their own trust
        # user cannot delete another user's trust
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('delete_trust', expected_status=exceptions.Forbidden,
                        trust_id=trust_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    # Domain admins cannot create their own trusts (trusts can only be
    # scoped to projects) and domain admins have no special privileges over the
    # trusts own by users in their domains.

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_trust(self):
        # user cannot have their own trust
        # user can get trust for other user
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('show_trust', expected_status=exceptions.Forbidden,
                        trust_id=trust_id)

    def test_identity_list_trusts(self):
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('list_trusts',
                        expected_status=exceptions.Forbidden)

    def test_identity_list_trusts_for_trustor(self):
        # user cannot have their own trust
        # user can list trusts for other user
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('list_trusts', expected_status=exceptions.Forbidden,
                        trustor_user_id=self.trustor)

    def test_identity_list_trusts_for_trustee(self):
        # user cannot have their own trust
        # user can list trusts for other user
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('list_trusts', expected_status=exceptions.Forbidden,
                        trustee_user_id=self.trustee)

    def test_identity_list_roles_for_trust(self):
        # user cannot have their own trust
        # user can list roles of trust for other user
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('list_trust_roles',
                        expected_status=exceptions.Forbidden,
                        trust_id=trust_id)

    def test_identity_get_role_for_trust(self):
        # user cannot have their own trust
        # user can get role of trust for other user
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('show_trust_role',
                        expected_status=exceptions.Forbidden,
                        trust_id=trust_id, role_id=self.roles[0]['id'])


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainAdminTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(IdentityV3RbacTrustTest, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']

    def setUp(self):
        super(ProjectAdminTests, self).setUp()
        self.role_id = self.admin_role_id

    def test_identity_create_trust(self):
        # user can create a trust for their own project
        trustor_user_id = self.persona.credentials.user_id
        project_id = self.persona.credentials.project_id
        resp = self.do_request(
            'create_trust',
            expected_status=201,
            **self.trust(
                trustor=trustor_user_id,
                project_id=project_id,
                roles=[{'id': self.role_id}])
        )['trust']
        self.addCleanup(self.client.delete_trust, resp['id'])

        # user cannot create trust with another user as trustor
        self.do_request(
            'create_trust',
            expected_status=exceptions.Forbidden,
            **self.trust())

    def test_identity_get_trust(self):
        # user can get a trust for which they are trustor
        trustor_user_id = self.persona.credentials.user_id
        project_id = self.persona.credentials.project_id
        trust_id = self.client.create_trust(
            **self.trust(trustor=trustor_user_id,
                         project_id=project_id,
                         roles=[{'id': self.role_id}]))['trust']['id']
        self.addCleanup(self.client.delete_trust, trust_id=trust_id)
        self.do_request('show_trust', trust_id=trust_id)

        # user can get a trust for which they are trustee
        trustee_user_id = self.persona.credentials.user_id
        trust_id = self.user_trust_client.create_trust(
            **self.trust(trustee=trustee_user_id))['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('show_trust', trust_id=trust_id)

        # user cannot get a trust with which they are unaffiliated
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('show_trust', expected_status=exceptions.Forbidden,
                        trust_id=trust_id)

    def test_identity_list_trusts(self):
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.admin_trusts_client.delete_trust,
                        trust_id=trust_id)
        self.do_request('list_trusts',
                        expected_status=exceptions.Forbidden)

    def test_identity_list_trusts_for_trustor(self):
        # user can list their own trusts
        trustor_user_id = self.persona.credentials.user_id
        project_id = self.persona.credentials.project_id
        trust_id = self.client.create_trust(
            **self.trust(trustor=trustor_user_id,
                         project_id=project_id,
                         roles=[{'id': self.role_id}]))['trust']['id']
        self.addCleanup(self.client.delete_trust, trust_id=trust_id)
        self.do_request('list_trusts', trustor_user_id=trustor_user_id)

        # user cannot list another user's trusts
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('list_trusts', expected_status=exceptions.Forbidden,
                        trustor_user_id=self.trustor)

    def test_identity_list_trusts_for_trustee(self):
        # user can list their own trusts
        trustee_user_id = self.persona.credentials.user_id
        trust_id = self.user_trust_client.create_trust(
            **self.trust(trustee=trustee_user_id))['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('list_trusts', trustee_user_id=trustee_user_id)

        # user cannot list another user's trusts
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('list_trusts', expected_status=exceptions.Forbidden,
                        trustee_user_id=self.trustee)

    def test_identity_list_roles_for_trust(self):
        # user can list roles for trust for which they are trustor
        trustor_user_id = self.persona.credentials.user_id
        project_id = self.persona.credentials.project_id
        trust_id = self.client.create_trust(
            **self.trust(trustor=trustor_user_id,
                         project_id=project_id,
                         roles=[{'id': self.role_id}]))['trust']['id']
        self.addCleanup(self.client.delete_trust, trust_id=trust_id)
        self.do_request('list_trust_roles', trust_id=trust_id)

        # user can list roles for trust for which they are trustee
        trustee_user_id = self.persona.credentials.user_id
        trust_id = self.user_trust_client.create_trust(
            **self.trust(trustee=trustee_user_id))['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('list_trust_roles', trust_id=trust_id)

        # user cannot list roles for trust with which they are unaffiliated
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('list_trust_roles',
                        expected_status=exceptions.Forbidden,
                        trust_id=trust_id)

    def test_identity_get_role_for_trust(self):
        # user can get roles for trust for which they are trustor
        trustor_user_id = self.persona.credentials.user_id
        project_id = self.persona.credentials.project_id
        trust_id = self.client.create_trust(
            **self.trust(trustor=trustor_user_id,
                         project_id=project_id,
                         roles=[{'id': self.role_id}]))['trust']['id']
        self.addCleanup(self.client.delete_trust, trust_id=trust_id)
        self.do_request('show_trust_role',
                        trust_id=trust_id, role_id=self.role_id)

        # user can list roles for trust for which they are trustee
        trustee_user_id = self.persona.credentials.user_id
        trust_id = self.user_trust_client.create_trust(
            **self.trust(trustee=trustee_user_id))['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('show_trust_role',
                        trust_id=trust_id, role_id=self.roles[0]['id'])

        # user cannot list roles for trust with which they are unaffiliated
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('show_trust_role',
                        expected_status=exceptions.Forbidden,
                        trust_id=trust_id, role_id=self.role_id)

    def test_identity_delete_trust(self):
        # user can delete trust for which they are the trustor
        trustor_user_id = self.persona.credentials.user_id
        project_id = self.persona.credentials.project_id
        trust_id = self.client.create_trust(
            **self.trust(trustor=trustor_user_id,
                         project_id=project_id,
                         roles=[{'id': self.role_id}]))['trust']['id']
        self.do_request('delete_trust', expected_status=204, trust_id=trust_id)

        # user cannot delete trust for which they are the trustee
        trustee_user_id = self.persona.credentials.user_id
        trust_id = self.user_trust_client.create_trust(
            **self.trust(trustee=trustee_user_id))['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('delete_trust', expected_status=exceptions.Forbidden,
                        trust_id=trust_id)

        # user cannot delete trust with which they are unaffiliated
        trust_id = self.user_trust_client.create_trust(
            **self.trust())['trust']['id']
        self.addCleanup(self.user_trust_client.delete_trust, trust_id=trust_id)
        self.do_request('delete_trust', expected_status=exceptions.Forbidden,
                        trust_id=trust_id)


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']

    def setUp(self):
        super(ProjectMemberTests, self).setUp()
        self.role_id = self.member_role_id


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']

    def setUp(self):
        super(ProjectReaderTests, self).setUp()
        self.role_id = self.reader_role_id
