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


class IdentityV3RbacCredentialTest(rbac_base.IdentityV3RbacBaseTests,
                                   metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacCredentialTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.credentials_client
        cls.admin_client = cls.os_system_admin
        cls.admin_credentials_client = cls.admin_client.credentials_client

        # personas in own or other domains
        own_domain_id = cls.persona.credentials.domain_id
        cls.test_client_1, cls.test_user_1 = cls.setup_user_client(
            domain_id=own_domain_id)
        cls.other_domain_id = cls.admin_client.domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.delete_domain, cls.other_domain_id)
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.update_domain,
            domain_id=cls.other_domain_id, enabled=False)
        cls.test_client_2, cls.test_user_2 = cls.setup_user_client(
            domain_id=cls.other_domain_id)

    @classmethod
    def setup_user_client(cls, domain_id=None):
        """Set up project user with its own client.

        This is to enable the project user to create its own credential.

        Returns a client object and the user's ID.
        """
        user_dict = {
            'name': data_utils.rand_name('user'),
            'password': data_utils.rand_password(),
        }
        if domain_id:
            user_dict['domain_id'] = domain_id
        user_id = cls.admin_client.users_v3_client.create_user(
            **user_dict)['user']['id']

        def try_cleanup_user():
            # if domain is cleaned up first, user will already be deleted
            try:
                cls.admin_client.users_v3_client.delete_user(user_id)
            except exceptions.NotFound:
                pass

        cls.addClassResourceCleanup(try_cleanup_user)
        project_id = cls.admin_client.projects_client.create_project(
            data_utils.rand_name())['project']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.projects_client.delete_project, project_id)
        member_role_id = cls.admin_client.roles_v3_client.list_roles(
            name='member')['roles'][0]['id']
        cls.admin_client.roles_v3_client.create_user_role_on_project(
            project_id, user_id, member_role_id)
        creds = auth.KeystoneV3Credentials(
            user_id=user_id,
            password=user_dict['password'],
            project_id=project_id)
        auth_provider = clients.get_auth_provider(creds)
        creds = auth_provider.fill_credentials()
        client = clients.Manager(credentials=creds)
        return client, user_id

    def credential(self, user_id):
        cred = {
            'blob': data_utils.rand_uuid_hex(),
            'type': data_utils.rand_uuid_hex(),
            'user_id': user_id,
        }
        return cred

    @abc.abstractmethod
    def test_identity_create_credential(self):
        """Test identity:create_credential policy.

        This test must check:
          * whether the persona can create a credential for themself
          * whether the persona can create acredential for another user in
            their own domain
          * whether the persona can create acredential for another user in
            another domain
        """
        pass

    @abc.abstractmethod
    def test_identity_get_credential(self):
        """Test identity:get_credential policy.

        This test must check:
          * whether the persona can get their own credential
          * whether the persona can get a credential for a user in another
            domain
          * whether the persona can get a credential for a user in their own
            domain
          * whether the persona can get a credential that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_credentials(self):
        """Test identity:list_credentials policy.

        This test must check:
          * whether the persona can list all credentials for themself
          * whether the persona can list credentials for a user in their own
            domain
          * whether the persona can list credentials for a user in another
            domain
        """
        pass

    @abc.abstractmethod
    def test_identity_update_credential(self):
        """Test identity:update_credential policy.

        This test must check:
          * whether the persona can update their own credential
          * whether the persona can update a credential for a user in another
            domain
          * whether the persona can update a credential for a user in their own
            domain
          * whether the persona can update a credential that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_credential(self):
        """Test identity:delete_credential policy.

        This test must check
          * whether the persona can delete their own credential
          * whether the persona can delete a credential for a user in another
            domain
          * whether the persona can delete a credential for a user in their own
            domain
          * whether the persona can delete a credential that does not exist
        """
        pass


class SystemAdminTests(IdentityV3RbacCredentialTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_credential(self):
        # user can create their own credential
        user_id = self.persona.credentials.user_id
        resp = self.do_request(
            'create_credential',
            expected_status=201,
            **self.credential(user_id=user_id))['credential']
        self.addCleanup(self.client.delete_credential, resp['id'])
        # user can create credential for other user in own domain
        resp = self.do_request(
            'create_credential',
            expected_status=201,
            **self.credential(user_id=self.test_user_1))['credential']
        self.addCleanup(self.client.delete_credential, resp['id'])
        # user can create credential for other user in other domain
        resp = self.do_request(
            'create_credential',
            expected_status=201,
            **self.credential(user_id=self.test_user_2))['credential']
        self.addCleanup(self.client.delete_credential, resp['id'])

    def test_identity_get_credential(self):
        # user can get their own credential, credential for user in own domain,
        # or credential for user in other domain
        user_id = self.persona.credentials.user_id
        for u in [user_id, self.test_user_1, self.test_user_2]:
            cred = self.admin_credentials_client.create_credential(
                **self.credential(user_id=u))['credential']
            self.addCleanup(
                self.admin_credentials_client.delete_credential, cred['id'])
            self.do_request('show_credential', credential_id=cred['id'])
        # non-existent credential is Not Found
        self.do_request(
            'show_credential',
            expected_status=exceptions.NotFound,
            credential_id=data_utils.rand_uuid_hex())

    def test_identity_list_credentials(self):
        # user can list their own credentials, credentials for user in own
        # domain, or credentials for user in other domain
        user_id = self.persona.credentials.user_id
        for u in [user_id, self.test_user_1, self.test_user_2]:
            cred = self.admin_credentials_client.create_credential(
                **self.credential(user_id=u))['credential']
            self.addCleanup(
                self.admin_credentials_client.delete_credential, cred['id'])
            resp = self.do_request('list_credentials')['credentials']
            self.assertIn(cred['id'], [c['id'] for c in resp])

    def test_identity_update_credential(self):
        # user can update their own credential, credential for user in own
        # domain, or credential for user in other domain
        user_id = self.persona.credentials.user_id
        for u in [user_id, self.test_user_1, self.test_user_2]:
            cred = self.credential(user_id=u)
            resp = self.client.create_credential(**cred)['credential']
            self.addCleanup(self.client.delete_credential, resp['id'])
            cred['blob'] = data_utils.rand_uuid_hex()
            self.do_request(
                'update_credential', credential_id=resp['id'], **cred)
        # non-existent credential is Not Found
        self.do_request(
            'update_credential',
            expected_status=exceptions.NotFound,
            credential_id=data_utils.rand_uuid_hex(),
            **self.credential(user_id=self.test_user_2))

    def test_identity_delete_credential(self):
        # user can delete their own credential, credential for user in own
        # domain, or credential for user in other domain
        user_id = self.persona.credentials.user_id
        for u in [user_id, self.test_user_1, self.test_user_2]:
            cred = self.credential(user_id=u)
            resp = self.client.create_credential(**cred)['credential']
            self.do_request(
                'delete_credential',
                expected_status=204,
                credential_id=resp['id'])
        # non-existent credential is Not Found
        self.do_request(
            'delete_credential',
            expected_status=exceptions.NotFound,
            credential_id=data_utils.rand_uuid_hex())


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_credential(self):
        # user can create their own credential
        user_id = self.persona.credentials.user_id
        resp = self.do_request(
            'create_credential',
            expected_status=201,
            **self.credential(user_id=user_id))['credential']
        self.addCleanup(self.client.delete_credential, resp['id'])
        # user cannot create credential for other user
        for u in [self.test_user_1, self.test_user_2]:
            self.do_request(
                'create_credential',
                expected_status=exceptions.Forbidden,
                **self.credential(user_id=u))

    def test_identity_update_credential(self):
        # user can update their own credential
        user_id = self.persona.credentials.user_id
        cred = self.credential(user_id=user_id)
        resp = self.admin_credentials_client.create_credential(
            **cred)['credential']
        self.addCleanup(
            self.admin_credentials_client.delete_credential, resp['id'])
        cred['blob'] = data_utils.rand_uuid_hex()
        self.do_request(
            'update_credential',
            credential_id=resp['id'], **cred)
        # user cannot update credential for other user
        for u in [self.test_user_1, self.test_user_2]:
            cred = self.credential(user_id=u)
            resp = self.admin_credentials_client.create_credential(
                **cred)['credential']
            self.addCleanup(
                self.admin_credentials_client.delete_credential, resp['id'])
            cred['blob'] = data_utils.rand_uuid_hex()
            self.do_request(
                'update_credential',
                expected_status=exceptions.Forbidden,
                credential_id=resp['id'], **cred)
        # non-existent credential is Forbidden
        self.do_request(
            'update_credential',
            expected_status=exceptions.Forbidden,
            credential_id=data_utils.rand_uuid_hex(),
            **self.credential(user_id=self.test_user_2))

    def test_identity_delete_credential(self):
        # user can delete their own credential
        user_id = self.persona.credentials.user_id
        cred = self.credential(user_id=user_id)
        resp = self.admin_credentials_client.create_credential(
            **cred)['credential']
        self.do_request(
            'delete_credential',
            expected_status=204,
            credential_id=resp['id'])
        # user cannot delete credential for other user
        for u in [self.test_user_1, self.test_user_2]:
            cred = self.credential(user_id=u)
            resp = self.admin_credentials_client.create_credential(
                **cred)['credential']
            self.addCleanup(
                self.admin_credentials_client.delete_credential, resp['id'])
            self.do_request(
                'delete_credential',
                expected_status=exceptions.Forbidden,
                credential_id=resp['id'])
        # non-existent credential is Forbidden
        self.do_request(
            'delete_credential',
            expected_status=exceptions.Forbidden,
            credential_id=data_utils.rand_uuid_hex())


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(IdentityV3RbacCredentialTest, base.BaseIdentityTest):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_create_credential(self):
        # domain admins cannot create credentials
        user_id = self.persona.credentials.user_id
        for u in [user_id, self.test_user_1, self.test_user_2]:
            self.do_request(
                'create_credential',
                expected_status=exceptions.Forbidden,
                **self.credential(user_id=u))

    def test_identity_get_credential(self):
        # domain admins cannot get credentials
        user_id = self.persona.credentials.user_id
        for u in [user_id, self.test_user_1, self.test_user_2]:
            cred = self.admin_credentials_client.create_credential(
                **self.credential(user_id=u))['credential']
            self.addCleanup(
                self.admin_credentials_client.delete_credential, cred['id'])
            self.do_request(
                'show_credential',
                expected_status=exceptions.Forbidden,
                credential_id=cred['id'])
        # non-existent credential is Forbidden
        self.do_request(
            'show_credential',
            expected_status=exceptions.Forbidden,
            credential_id=data_utils.rand_uuid_hex())

    def test_identity_list_credentials(self):
        # domain admins cannot list credentials
        user_id = self.persona.credentials.user_id
        for u in [user_id, self.test_user_1, self.test_user_2]:
            cred = self.admin_credentials_client.create_credential(
                **self.credential(user_id=u))['credential']
            self.addCleanup(
                self.admin_credentials_client.delete_credential, cred['id'])
            self.do_request(
                'list_credentials',
                expected_status=exceptions.Forbidden)

    def test_identity_update_credential(self):
        # domain admins cannot update credentials
        user_id = self.persona.credentials.user_id
        for u in [user_id, self.test_user_1, self.test_user_2]:
            cred = self.credential(user_id=u)
            resp = self.admin_credentials_client.create_credential(
                **cred)['credential']
            self.addCleanup(
                self.admin_credentials_client.delete_credential, resp['id'])
            cred['blob'] = data_utils.rand_uuid_hex()
            self.do_request(
                'update_credential',
                expected_status=exceptions.Forbidden,
                credential_id=resp['id'], **cred)
        # non-existent credential is Forbidden
        self.do_request(
            'update_credential',
            expected_status=exceptions.Forbidden,
            credential_id=data_utils.rand_uuid_hex(),
            **self.credential(user_id=user_id))

    def test_identity_delete_credential(self):
        # domain admins cannot delete credentials
        user_id = self.persona.credentials.user_id
        for u in [user_id, self.test_user_1, self.test_user_2]:
            cred = self.credential(user_id=u)
            resp = self.admin_credentials_client.create_credential(
                **cred)['credential']
            self.addCleanup(
                self.admin_credentials_client.delete_credential, resp['id'])
            self.do_request(
                'delete_credential',
                expected_status=exceptions.Forbidden,
                credential_id=resp['id'])
        # non-existent credential is Forbidden
        self.do_request(
            'delete_credential',
            expected_status=exceptions.Forbidden,
            credential_id=data_utils.rand_uuid_hex())


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainAdminTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(SystemReaderTests):

    credentials = ['project_admin', 'system_admin']

    def test_identity_get_credential(self):
        # user can get their own credential
        user_id = self.persona.credentials.user_id
        cred = self.admin_credentials_client.create_credential(
            **self.credential(user_id=user_id))['credential']
        self.addCleanup(
            self.admin_credentials_client.delete_credential, cred['id'])
        self.do_request('show_credential', credential_id=cred['id'])
        # user cannot get credential for another user
        for u in [self.test_user_1, self.test_user_2]:
            cred = self.admin_credentials_client.create_credential(
                **self.credential(user_id=u))['credential']
            self.addCleanup(
                self.admin_credentials_client.delete_credential, cred['id'])
            self.do_request(
                'show_credential',
                expected_status=exceptions.Forbidden,
                credential_id=cred['id'])
        # non-existent credential is Forbidden
        self.do_request(
            'show_credential',
            expected_status=exceptions.Forbidden,
            credential_id=data_utils.rand_uuid_hex())

    def test_identity_list_credentials(self):
        # user can list their own credentials
        user_id = self.persona.credentials.user_id
        cred = self.admin_credentials_client.create_credential(
            **self.credential(user_id=user_id))['credential']
        self.addCleanup(
            self.admin_credentials_client.delete_credential, cred['id'])
        resp = self.do_request('list_credentials')['credentials']
        self.assertIn(cred['id'], [c['id'] for c in resp])
        # user cannot list credentials for other users
        for u in [self.test_user_1, self.test_user_2]:
            cred = self.admin_credentials_client.create_credential(
                **self.credential(user_id=u))['credential']
            self.addCleanup(
                self.admin_credentials_client.delete_credential, cred['id'])
            resp = self.do_request('list_credentials')['credentials']
            self.assertNotIn(cred['id'], [c['id'] for c in resp])


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
