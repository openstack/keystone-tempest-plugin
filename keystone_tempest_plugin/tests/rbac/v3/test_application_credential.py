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


class IdentityV3RbacApplicationCredentialTest(
    rbac_base.IdentityV3RbacBaseTests, metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacApplicationCredentialTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.application_credentials_client
        cls.admin_client = cls.os_system_admin

    @classmethod
    def setup_user_client(cls, domain_id=None):
        """Set up project user with its own client.

        This is to enable the project user to create its own app cred.

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

    def app_cred(self):
        app_cred = {}
        app_cred['name'] = data_utils.rand_name('app_cred')
        return app_cred

    @abc.abstractmethod
    def test_identity_create_application_credential(self):
        """Test identity:create_application_credential policy.

        This test must check:
          * whether the persona can create an application credential for
            themself
          * whether the persona can create an application credential for
            another user
        """
        pass

    @abc.abstractmethod
    def test_identity_get_application_credential(self):
        """Test identity:get_application_credential policy.

        This test must check:
          * whether the persona can get their own application credential
          * whether the persona can get an application credential for another
            user
          * whether the persona can get an application credential for a user in
            another domain (if applicable)
          * whether the persona can get an application credential for a user in
            their own domain (if applicable)
          * whether the persona can get an application credential that does not
            exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_application_credentials(self):
        """Test identity:list_application_credentials policy.

        This test must check:
          * whether the persona can list all application credentials for
            themself
          * whether the persona can list all application credentials for
            another user
          * whether the persona can list application credentials for a user in
            their own domain
          * whether the persona can list application credentials for a user in
            another domain
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_application_credential(self):
        """Test identity:delete_application_credential policy.

        This test must check
          * whether the persona can delete their own application credential
          * whether the persona can delete an application credential for
            another user
          * whether the persona can delete an application credential for a user
            in another domain (if applicable)
          * whether the persona can delete an application credential for a user
            in their own domain (if applicable)
          * whether the persona can delete an application credential that does
            not exist
        """
        pass


class SystemAdminTests(
    IdentityV3RbacApplicationCredentialTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    @classmethod
    def setup_clients(cls):
        super(SystemAdminTests, cls).setup_clients()
        cls.test_user_client, cls.test_user_id = cls.setup_user_client()

    def test_identity_create_application_credential(self):
        # Creating an application credential requires a project ID in the
        # token, therefore system-scoped users cannot create app creds.
        raise self.skipException(
            "Skipping identity:create_application_credential test for "
            "system user")

    def test_identity_get_application_credential(self):
        # Creating an application credential requires a project ID in the
        # token, therefore system-scoped users cannot create app creds, so skip
        # check for showing user's own app creds

        # retrieve other user's app cred
        user_app_cred_client = \
            self.test_user_client.application_credentials_client
        app_cred = user_app_cred_client.create_application_credential(
            user_id=self.test_user_id, **self.app_cred()
        )['application_credential']
        self.addCleanup(
            user_app_cred_client.delete_application_credential,
            self.test_user_id,
            app_cred['id'])
        self.do_request(
            'show_application_credential',
            user_id=self.test_user_id,
            application_credential_id=app_cred['id'])

        # retrieve app cred that does not exist
        self.do_request(
            'show_application_credential',
            expected_status=exceptions.NotFound,
            user_id=self.test_user_id,
            application_credential_id=data_utils.rand_uuid_hex())

    def test_identity_list_application_credentials(self):
        # Creating an application credential requires a project ID in the
        # token, therefore system-scoped users cannot create app creds, so skip
        # check for listing user's own app creds

        # list other user's app creds
        user_app_cred_client = \
            self.test_user_client.application_credentials_client
        app_cred = user_app_cred_client.create_application_credential(
            user_id=self.test_user_id, **self.app_cred()
        )['application_credential']
        self.addCleanup(
            user_app_cred_client.delete_application_credential,
            self.test_user_id,
            app_cred['id'])
        resp = self.do_request(
            'list_application_credentials',
            user_id=self.test_user_id)
        self.assertEqual(
            resp['application_credentials'][0]['id'],
            app_cred['id'])

    def test_identity_delete_application_credential(self):
        # Creating an application credential requires a project ID in the
        # token, therefore system-scoped users cannot create app creds, so skip
        # check for deleting user's own app creds

        # delete other user's app cred
        user_app_cred_client = \
            self.test_user_client.application_credentials_client
        app_cred = user_app_cred_client.create_application_credential(
            user_id=self.test_user_id, **self.app_cred()
        )['application_credential']
        self.do_request(
            'delete_application_credential',
            expected_status=204,
            user_id=self.test_user_id,
            application_credential_id=app_cred['id'])

        # delete app cred that does not exist
        self.do_request(
            'delete_application_credential',
            expected_status=exceptions.NotFound,
            user_id=self.test_user_id,
            application_credential_id=data_utils.rand_uuid_hex())


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_delete_application_credential(self):
        # Creating an application credential requires a project ID in the
        # token, therefore system-scoped users cannot create app creds, so skip
        # check for deleting user's own app creds

        # delete other user's app cred
        user_app_cred_client = \
            self.test_user_client.application_credentials_client
        app_cred = user_app_cred_client.create_application_credential(
            user_id=self.test_user_id, **self.app_cred()
        )['application_credential']
        self.addCleanup(
            user_app_cred_client.delete_application_credential,
            self.test_user_id,
            app_cred['id'])
        self.do_request(
            'delete_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=self.test_user_id,
            application_credential_id=app_cred['id'])

        # delete app cred that does not exist
        self.do_request(
            'delete_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=self.test_user_id,
            application_credential_id=data_utils.rand_uuid_hex())


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(
    IdentityV3RbacApplicationCredentialTest, base.BaseIdentityTest):

    # Domain admins cannot create their own app creds (app creds can only be
    # scoped to projects) and domain admins have no special privileges over the
    # app creds own by users in their domains.

    credentials = ['domain_admin', 'system_admin']

    @classmethod
    def setup_clients(cls):
        super(DomainAdminTests, cls).setup_clients()
        own_domain_id = cls.persona.credentials.domain_id
        cls.test_client_1, cls.test_user_1 = cls.setup_user_client(
            domain_id=own_domain_id)

    def setUp(self):
        super(DomainAdminTests, self).setUp()
        self.other_domain_id = self.admin_client.domains_client.create_domain(
            name=data_utils.rand_name())['domain']['id']
        self.addCleanup(self.admin_client.domains_client.delete_domain,
                        self.other_domain_id)
        self.addCleanup(self.admin_client.domains_client.update_domain,
                        domain_id=self.other_domain_id, enabled=False)
        self.test_client_2, self.test_user_2 = self.setup_user_client(
            domain_id=self.other_domain_id)
        client = self.test_client_1.application_credentials_client
        self.app_cred_1 = client.create_application_credential(
            user_id=self.test_user_1, **self.app_cred()
        )['application_credential']
        self.addCleanup(
            client.delete_application_credential,
            self.test_user_1,
            self.app_cred_1['id'])
        client = self.test_client_2.application_credentials_client
        self.app_cred_2 = client.create_application_credential(
            user_id=self.test_user_2, **self.app_cred()
        )['application_credential']
        self.addCleanup(
            client.delete_application_credential,
            self.test_user_2,
            self.app_cred_2['id'])

    def test_identity_create_application_credential(self):
        # Creating an application credential requires a project ID in the
        # token, therefore system-scoped users cannot create app creds.
        raise self.skipException(
            "Skipping identity:create_application_credential test for "
            "domain user")

    def test_identity_get_application_credential(self):
        # Creating an application credential requires a project ID in the
        # token, therefore domain-scoped users cannot create app creds, so skip
        # check for showing user's own app creds

        # accessing application credentials should be forbidden no matter
        # whether the owner is in the domain or outside of it

        # retrieve app cred from user in own domain
        self.do_request(
            'show_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=self.test_user_1,
            application_credential_id=self.app_cred_1['id'])

        # retrieve app cred from user in other domain
        self.do_request(
            'show_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=self.test_user_2,
            application_credential_id=self.app_cred_2['id'])

        # retrieve app cred that does not exist
        self.do_request(
            'show_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=self.test_user_1,
            application_credential_id=data_utils.rand_uuid_hex())

    def test_identity_list_application_credentials(self):
        # Creating an application credential requires a project ID in the
        # token, therefore domain-scoped users cannot create app creds, so skip
        # check for listing user's own app creds

        # listing application credentials should be forbidden no matter
        # whether the owner is in the domain or outside of it

        # list app creds from user in own domain
        self.do_request(
            'list_application_credentials',
            expected_status=exceptions.Forbidden,
            user_id=self.test_user_1)

        # list app creds from user in other domain
        self.do_request(
            'list_application_credentials',
            expected_status=exceptions.Forbidden,
            user_id=self.test_user_2)

    def test_identity_delete_application_credential(self):
        # Creating an application credential requires a project ID in the
        # token, therefore domain-scoped users cannot create app creds, so skip
        # check for deleting user's own app creds

        # deleting application credentials should be forbidden no matter
        # whether the owner is in the domain or outside of it

        # delete app cred from user in own domain
        self.do_request(
            'delete_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=self.test_user_1,
            application_credential_id=self.app_cred_1['id'])

        # delete app cred from user in other domain
        self.do_request(
            'delete_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=self.test_user_2,
            application_credential_id=self.app_cred_2['id'])

        # delete app cred that does not exist
        self.do_request(
            'delete_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=self.test_user_1,
            application_credential_id=data_utils.rand_uuid_hex())


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainAdminTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(IdentityV3RbacApplicationCredentialTest,
                        base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']

    @classmethod
    def setup_clients(cls):
        super(ProjectAdminTests, cls).setup_clients()
        cls.test_user_client, cls.test_user_id = cls.setup_user_client()

    def test_identity_create_application_credential(self):
        # user can create their own app cred
        user_id = self.persona.credentials.user_id
        resp = self.do_request(
            'create_application_credential',
            expected_status=201,
            user_id=user_id,
            **self.app_cred())['application_credential']
        self.addCleanup(
            self.client.delete_application_credential,
            user_id, resp['id'])

        # user cannot create app cred for another user
        user_id = self.test_user_id
        self.do_request(
            'create_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=user_id,
            **self.app_cred())

    def test_identity_get_application_credential(self):
        # user can retrieve their own app cred
        user_id = self.persona.credentials.user_id
        app_cred = self.client.create_application_credential(
            user_id=user_id, **self.app_cred())['application_credential']
        self.addCleanup(
            self.client.delete_application_credential,
            user_id=user_id, application_credential_id=app_cred['id'])
        self.do_request(
            'show_application_credential',
            user_id=user_id, application_credential_id=app_cred['id'])

        # retrieving non-existent app cred for self should return 404
        self.do_request(
            'show_application_credential',
            expected_status=exceptions.NotFound,
            user_id=user_id,
            application_credential_id=data_utils.rand_uuid_hex())

        # user cannot retrieve another user's app cred by using the victim's
        # user ID in the request or by trying to bypass the user ownership
        # check by crafting a path the the attacker's user ID
        user_id = self.test_user_id
        client = self.test_user_client.application_credentials_client
        app_cred = client.create_application_credential(
            user_id=user_id, **self.app_cred())['application_credential']
        self.addCleanup(
            client.delete_application_credential,
            user_id=user_id, application_credential_id=app_cred['id'])
        self.do_request(
            'show_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=self.persona.credentials.user_id,
            application_credential_id=app_cred['id'])
        self.do_request(
            'show_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=user_id, application_credential_id=app_cred['id'])

        # retrieving non-existent app cred for another user should return 403
        self.do_request(
            'show_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=user_id,
            application_credential_id=data_utils.rand_uuid_hex())

    def test_identity_list_application_credentials(self):
        # user can list their own app creds
        user_id = self.persona.credentials.user_id
        app_cred = self.client.create_application_credential(
            user_id=user_id, **self.app_cred())['application_credential']
        self.addCleanup(
            self.client.delete_application_credential,
            user_id=user_id, application_credential_id=app_cred['id'])
        self.do_request(
            'list_application_credentials', user_id=user_id)

        # user cannot list another user's app creds
        user_id = self.test_user_id
        client = self.test_user_client.application_credentials_client
        app_cred = client.create_application_credential(
            user_id=user_id, **self.app_cred())['application_credential']
        self.addCleanup(
            client.delete_application_credential,
            user_id=user_id, application_credential_id=app_cred['id'])
        self.do_request(
            'list_application_credentials',
            expected_status=exceptions.Forbidden, user_id=user_id)

    def test_identity_delete_application_credential(self):
        # user can delete their own app cred
        user_id = self.persona.credentials.user_id
        app_cred = self.client.create_application_credential(
            user_id=user_id, **self.app_cred())['application_credential']
        self.do_request(
            'delete_application_credential',
            expected_status=204,
            user_id=user_id, application_credential_id=app_cred['id'])

        # deleting non-existent app cred for self should return 404
        self.do_request(
            'delete_application_credential',
            expected_status=exceptions.NotFound,
            user_id=user_id,
            application_credential_id=data_utils.rand_uuid_hex())

        # user cannot delete another user's app cred by using the victim's
        # user ID in the request or by trying to bypass the user ownership
        # check by crafting a path the the attacker's user ID
        user_id = self.test_user_id
        client = self.test_user_client.application_credentials_client
        app_cred = client.create_application_credential(
            user_id=user_id, **self.app_cred())['application_credential']
        self.addCleanup(
            client.delete_application_credential,
            user_id=user_id, application_credential_id=app_cred['id'])
        self.do_request(
            'delete_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=self.persona.credentials.user_id,
            application_credential_id=app_cred['id'])
        self.do_request(
            'delete_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=user_id, application_credential_id=app_cred['id'])

        # deleting non-existent app cred for another user should return 403
        self.do_request(
            'delete_application_credential',
            expected_status=exceptions.Forbidden,
            user_id=user_id,
            application_credential_id=data_utils.rand_uuid_hex())


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
