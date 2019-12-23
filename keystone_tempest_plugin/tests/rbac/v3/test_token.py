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


class IdentityV3RbacTokenTest(rbac_base.IdentityV3RbacBaseTests,
                              metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacTokenTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.identity_v3_client

    @classmethod
    def resource_setup(cls):
        admin_client = cls.os_system_admin
        cls.user = {
            'name': data_utils.rand_name('user'),
            'password': data_utils.rand_password(),
        }
        cls.user_id = admin_client.users_v3_client.create_user(
            **cls.user)['user']['id']
        cls.addClassResourceCleanup(
            admin_client.users_v3_client.delete_user, user_id=cls.user_id)
        cls.project_id = admin_client.projects_client.create_project(
            name=data_utils.rand_name()
        )['project']['id']
        cls.addClassResourceCleanup(
            admin_client.projects_client.delete_project,
            project_id=cls.project_id)
        cls.domain_id = admin_client.domains_client.create_domain(
            name=data_utils.rand_name()
        )['domain']['id']
        cls.addClassResourceCleanup(
            admin_client.domains_client.delete_domain,
            domain_id=cls.domain_id)
        cls.addClassResourceCleanup(
            admin_client.domains_client.update_domain,
            domain_id=cls.domain_id, enabled=False)
        role_id = admin_client.roles_v3_client.create_role(
            name=data_utils.rand_name())['role']['id']
        cls.addClassResourceCleanup(
            admin_client.roles_v3_client.delete_role,
            role_id=role_id)
        admin_client.roles_v3_client.create_user_role_on_project(
            project_id=cls.project_id,
            user_id=cls.user_id,
            role_id=role_id
        )
        admin_client.roles_v3_client.create_user_role_on_domain(
            domain_id=cls.domain_id,
            user_id=cls.user_id,
            role_id=role_id
        )
        admin_client.roles_v3_client.create_user_role_on_system(
            user_id=cls.user_id,
            role_id=role_id
        )

    def setUp(self):
        super(IdentityV3RbacTokenTest, self).setUp()
        own_creds = auth.KeystoneV3Credentials(**self.own_keystone_creds)
        own_creds = clients.get_auth_provider(own_creds).fill_credentials()
        self.own_token = clients.Manager(
            credentials=own_creds).identity_v3_client.token
        project_creds = auth.KeystoneV3Credentials(
            user_id=self.user_id,
            password=self.user['password'],
            project_id=self.project_id)
        project_creds = clients.get_auth_provider(
            project_creds).fill_credentials()
        self.project_token = clients.Manager(
            credentials=project_creds).identity_v3_client.token
        domain_creds = auth.KeystoneV3Credentials(
            user_id=self.user_id,
            password=self.user['password'],
            domain_id=self.domain_id)
        domain_creds = clients.get_auth_provider(
            domain_creds).fill_credentials()
        self.domain_token = clients.Manager(
            credentials=domain_creds).identity_v3_client.token
        system_creds = auth.KeystoneV3Credentials(
            user_id=self.user_id,
            password=self.user['password'],
            system='all')
        system_creds = clients.get_auth_provider(
            system_creds).fill_credentials()
        self.system_token = clients.Manager(
            credentials=system_creds).identity_v3_client.token

    @abc.abstractmethod
    def test_identity_check_token(self):
        """Test identity:check_token policy.

        This test must check:
          * whether the persona can check their own token in their current
            scope
          * whether the persona can check a system-scoped token for a different
            user
          * whether the persona can check a domain-scoped token for a different
            user
          * whether the persona can check a project-scoped token for a
            different user
        """
        pass

    @abc.abstractmethod
    def test_identity_validate_token(self):
        """Test identity:validate_token policy.

        This test must validate:
          * whether the persona can validate their own token in their current
            scope
          * whether the persona can validate a system-scoped token for a
            different user
          * whether the persona can validate a domain-scoped token for a
            different user
          * whether the persona can validate a project-scoped token for a
            different user
        """
        pass

    @abc.abstractmethod
    def test_identity_revoke_token(self):
        """Test identity:revoke_token policy.

        This test must revoke:
          * whether the persona can revoke their own token in their current
            scope
          * whether the persona can revoke a system-scoped token for a
            different user
          * whether the persona can revoke a domain-scoped token for a
            different user
          * whether the persona can revoke a project-scoped token for a
            different user
        """
        pass


class SystemAdminTests(IdentityV3RbacTokenTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def setUp(self):
        self.own_keystone_creds = {
            'user_id': self.persona.credentials.user_id,
            'password': self.persona.credentials.password,
            'system': 'all'
        }
        super(SystemAdminTests, self).setUp()

    def test_identity_check_token(self):
        # user can check own token
        self.do_request('check_token_existence', resp_token=self.own_token)
        # user can check other system user's token
        self.do_request('check_token_existence', resp_token=self.system_token)
        # user can check domain user's token
        self.do_request('check_token_existence', resp_token=self.domain_token)
        # user can check project user's token
        self.do_request('check_token_existence', resp_token=self.project_token)

    def test_identity_validate_token(self):
        # user can validate own token
        self.do_request('show_token', resp_token=self.own_token)
        # user can validate other system user's token
        self.do_request('show_token', resp_token=self.system_token)
        # user can validate domain user's token
        self.do_request('show_token', resp_token=self.domain_token)
        # user can validate project user's token
        self.do_request('show_token', resp_token=self.project_token)

    def test_identity_revoke_token(self):
        # user can revoke own token
        self.do_request('delete_token', expected_status=204,
                        resp_token=self.own_token)
        # user can revoke other system user's token
        self.do_request('delete_token', expected_status=204,
                        resp_token=self.system_token)
        # user can revoke domain user's token
        self.do_request('delete_token', expected_status=204,
                        resp_token=self.domain_token)
        # user can revoke project user's token
        self.do_request('delete_token', expected_status=204,
                        resp_token=self.project_token)


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_revoke_token(self):
        # user can revoke own token
        self.do_request('delete_token', expected_status=204,
                        resp_token=self.own_token)
        # user cannot revoke other system user's token
        self.do_request('delete_token', expected_status=exceptions.Forbidden,
                        resp_token=self.system_token)
        # user cannot revoke domain user's token
        self.do_request('delete_token', expected_status=exceptions.Forbidden,
                        resp_token=self.domain_token)
        # user cannot revoke project user's token
        self.do_request('delete_token', expected_status=exceptions.Forbidden,
                        resp_token=self.project_token)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def setUp(self):
        self.own_keystone_creds = {
            'user_id': self.persona.credentials.user_id,
            'password': self.persona.credentials.password,
            'domain_id': self.persona.credentials.domain_id
        }
        # call base setUp directly to ensure we don't use system creds
        super(SystemAdminTests, self).setUp()

    def test_identity_check_token(self):
        # user can check own token
        self.do_request('check_token_existence', resp_token=self.own_token)
        # user cannot check other system user's token
        self.do_request('check_token_existence',
                        expected_status=exceptions.Forbidden,
                        resp_token=self.system_token)
        # user cannot check domain user's token
        self.do_request('check_token_existence',
                        expected_status=exceptions.Forbidden,
                        resp_token=self.domain_token)
        # user cannot check project user's token
        self.do_request('check_token_existence',
                        expected_status=exceptions.Forbidden,
                        resp_token=self.project_token)

    def test_identity_validate_token(self):
        # user can validate own token
        self.do_request('show_token', resp_token=self.own_token)
        # user cannot validate other system user's token
        self.do_request('show_token',
                        expected_status=exceptions.Forbidden,
                        resp_token=self.system_token)
        # user cannot validate domain user's token
        self.do_request('show_token',
                        expected_status=exceptions.Forbidden,
                        resp_token=self.domain_token)
        # user cannot validate project user's token
        self.do_request('show_token',
                        expected_status=exceptions.Forbidden,
                        resp_token=self.project_token)


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainAdminTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(DomainAdminTests, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']

    def setUp(self):
        self.own_keystone_creds = {
            'user_id': self.persona.credentials.user_id,
            'password': self.persona.credentials.password,
            'project_id': self.persona.credentials.project_id
        }
        # call base setUp directly to ensure we don't use system creds
        super(SystemAdminTests, self).setUp()


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
