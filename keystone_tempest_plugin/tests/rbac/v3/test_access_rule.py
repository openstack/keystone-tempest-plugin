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


class IdentityV3RbacAccessRuleTest(rbac_base.IdentityV3RbacBaseTests,
                                   metaclass=abc.ABCMeta):

    identity_version = 'v3'

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacAccessRuleTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.access_rules_client
        cls.admin_client = cls.os_system_admin

    def user(self):
        user = {}
        name = data_utils.rand_name('user')
        user['name'] = name
        user['password'] = data_utils.rand_password()
        return user

    def app_cred(self):
        app_cred = {}
        app_cred['name'] = data_utils.rand_name('app_cred')
        app_cred['access_rules'] = [
            {
                'path': '/servers',
                'method': 'GET',
                'service': 'compute',
            }
        ]
        return app_cred

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

        def try_delete_user():
            # delete user if not deleted by domain deletion
            try:
                cls.admin_client.users_v3_client.delete_user(user_id)
            except exceptions.NotFound:
                pass

        cls.addClassResourceCleanup(try_delete_user)
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

    @abc.abstractmethod
    def test_identity_get_access_rule(self):
        """Test identity:get_access_rule policy

        This test must check:
          * whether the persona can retrieve an access rule they own
          * whether the persona can retrieve an access rule they do not own
          * whether the persona can retrieve an access rule that does not exist
          * whether the persona can retrieve an access rule for a user in their
            own domain (if applicable)
          * whether the persona can retrieve an access rule for a user in
            another domain (if applicable)
        """
        pass

    @abc.abstractmethod
    def test_identity_list_access_rules(self):
        """Test identity:list_access_rules policy

        This test must check:
          * whether the persona can list their own access rules
          * whether the persona can list the access rules for another user
          * whether the persona can list the access rules for a user in their
            own domain
          * whether the persona can list the access rules for a user in another
            domain
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_access_rule(self):
        """Test identity:delete_access_rule policy.

        This test must check
          * whether the persona can delete an access rule they own
          * whether the persona can delete an access rule for an arbitrary user
          * whether the persona can delete an access rule that does not exist
          * whether the persona can delete an access rule for a user in another
            domain (if applicable)
          * whether the persona can delete an access rule for a user in their
            own domain (if applicable)
          * whether the persona can delete an access rule that does not exist
        """
        pass


class SystemAdminTests(IdentityV3RbacAccessRuleTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    @classmethod
    def setup_clients(cls):
        super(SystemAdminTests, cls).setup_clients()
        cls.test_user_client, cls.test_user_id = cls.setup_user_client()

    def setUp(self):
        # create app cred for other user
        super(SystemAdminTests, self).setUp()
        app_cred_client = self.test_user_client.application_credentials_client
        app_cred = app_cred_client.create_application_credential(
            user_id=self.test_user_id, **self.app_cred()
        )['application_credential']
        self.app_cred_id = app_cred['id']
        self.access_rule_id = app_cred['access_rules'][0]['id']

        def try_delete_app_cred(id):
            app_cred_client = self.admin_client.application_credentials_client
            try:
                app_cred_client.delete_application_credential(
                    user_id=self.test_user_id,
                    application_credential_id=id)
            except exceptions.NotFound:
                pass

        def try_delete_access_rule(id):
            try:
                self.admin_client.access_rules_client.delete_access_rule(
                    user_id=self.test_user_id,
                    access_rule_id=id)
            except exceptions.NotFound:
                pass
        self.addCleanup(try_delete_access_rule, self.access_rule_id)
        self.addCleanup(try_delete_app_cred, self.app_cred_id)

    def test_identity_get_access_rule(self):
        # system admin cannot create app creds and therefore cannot create
        # access rules, so skip retrieval of own access rule

        # retrieve other user's access rules
        self.do_request(
            'show_access_rule',
            user_id=self.test_user_id, access_rule_id=self.access_rule_id)

        # retrieving a non-existent access rule should return a 404
        self.do_request(
            'show_access_rule', expected_status=exceptions.NotFound,
            user_id=self.test_user_id,
            access_rule_id=data_utils.rand_uuid_hex())

    def test_identity_list_access_rules(self):
        # system admin cannot create app creds and therefore cannot create
        # access rules, so skip listing of own access rule

        # list other user's access rules
        self.do_request('list_access_rules', user_id=self.test_user_id)

    def test_identity_delete_access_rule(self):
        # system admin cannot create app creds and therefore cannot create
        # access rules, so skip deletion of own access rule

        # delete other user's access rules
        app_cred_client = self.admin_client.application_credentials_client
        app_cred_client.delete_application_credential(
            user_id=self.test_user_id,
            application_credential_id=self.app_cred_id)
        self.do_request(
            'delete_access_rule', expected_status=204,
            user_id=self.test_user_id, access_rule_id=self.access_rule_id)

        # deleting a non-existent access rule should return a 404
        self.do_request(
            'delete_access_rule', expected_status=exceptions.NotFound,
            user_id=self.test_user_id,
            access_rule_id=data_utils.rand_uuid_hex())


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_delete_access_rule(self):
        app_cred_client = self.admin_client.application_credentials_client
        app_cred_client.delete_application_credential(
            user_id=self.test_user_id,
            application_credential_id=self.app_cred_id)
        self.do_request(
            'delete_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_id, access_rule_id=self.access_rule_id)

        # retrieving a non-existent access rule should return a 404
        self.do_request(
            'show_access_rule', expected_status=exceptions.NotFound,
            user_id=self.test_user_id,
            access_rule_id=data_utils.rand_uuid_hex())


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(IdentityV3RbacAccessRuleTest, base.BaseIdentityTest):

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
        app_cred_1 = client.create_application_credential(
            user_id=self.test_user_1, **self.app_cred()
        )['application_credential']
        self.access_rule_1 = app_cred_1['access_rules'][0]['id']
        self.addCleanup(
            self.test_client_1.access_rules_client.delete_access_rule,
            self.test_user_1,
            self.access_rule_1)
        self.addCleanup(
            client.delete_application_credential,
            self.test_user_1,
            app_cred_1['id'])
        client = self.test_client_2.application_credentials_client
        app_cred_2 = client.create_application_credential(
            user_id=self.test_user_2, **self.app_cred()
        )['application_credential']
        self.access_rule_2 = app_cred_2['access_rules'][0]['id']
        self.addCleanup(
            self.test_client_2.access_rules_client.delete_access_rule,
            self.test_user_2,
            self.access_rule_2)
        self.addCleanup(
            client.delete_application_credential,
            self.test_user_2,
            app_cred_2['id'])

    def test_identity_get_access_rule(self):
        # accessing access rules should be forbidden no matter whether the
        # owner is in the domain or outside of it

        # retrieve access rule from user in own domain
        self.do_request(
            'show_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_1, access_rule_id=self.access_rule_1)

        # retrieve access rule from user in other domain
        self.do_request(
            'show_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_2, access_rule_id=self.access_rule_2)

        # retrieving a non-existent access rule should return a 403
        self.do_request(
            'show_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_1,
            access_rule_id=data_utils.rand_uuid_hex())
        self.do_request(
            'show_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_2,
            access_rule_id=data_utils.rand_uuid_hex())

    def test_identity_list_access_rules(self):
        # listing access rules should be forbidden no matter whether the
        # owner is in the domain or outside of it
        self.do_request(
            'list_access_rules', expected_status=exceptions.Forbidden,
            user_id=self.test_user_1)
        self.do_request(
            'list_access_rules', expected_status=exceptions.Forbidden,
            user_id=self.test_user_2)

    def test_identity_delete_access_rule(self):
        # deleting access rules should be forbidden no matter whether the
        # owner is in the domain or outside of it

        # delete access rule from user in own domain
        self.do_request(
            'delete_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_1, access_rule_id=self.access_rule_1)

        # delete access rule from user in other domain
        self.do_request(
            'delete_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_2, access_rule_id=self.access_rule_2)

        # deleting a non-existent access rule should return a 403
        self.do_request(
            'delete_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_1,
            access_rule_id=data_utils.rand_uuid_hex())
        self.do_request(
            'delete_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_2,
            access_rule_id=data_utils.rand_uuid_hex())


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainAdminTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(IdentityV3RbacAccessRuleTest, base.BaseIdentityTest):

    credentials = ['project_admin', 'system_admin']

    @classmethod
    def setup_clients(cls):
        super(ProjectAdminTests, cls).setup_clients()
        cls.test_user_client, cls.test_user_id = cls.setup_user_client()

    def setUp(self):
        super(ProjectAdminTests, self).setUp()
        app_cred_client = self.persona.application_credentials_client
        user_id = self.persona.credentials.user_id
        self.app_cred_1 = app_cred_client.create_application_credential(
            user_id, **self.app_cred())['application_credential']
        self.access_rule_1 = self.app_cred_1['access_rules'][0]['id']

        def try_delete_own_app_cred(id):
            app_cred_client = self.persona.application_credentials_client
            try:
                app_cred_client.delete_application_credential(
                    self.persona.credentials.user_id, id)
            except exceptions.NotFound:
                pass

        def try_delete_own_access_rule(id):
            try:
                self.persona.access_rules_client.delete_access_rule(
                    self.persona.credentials.user_id, id)
            except exceptions.NotFound:
                pass

        self.addCleanup(try_delete_own_access_rule, self.access_rule_1)
        self.addCleanup(try_delete_own_app_cred, self.app_cred_1['id'])

        app_cred_client = self.test_user_client.application_credentials_client
        self.app_cred_2 = app_cred_client.create_application_credential(
            self.test_user_id, **self.app_cred())['application_credential']
        self.access_rule_2 = self.app_cred_2['access_rules'][0]['id']
        self.addCleanup(
            self.test_user_client.access_rules_client.delete_access_rule,
            self.test_user_id, self.access_rule_2)
        self.addCleanup(
            app_cred_client.delete_application_credential,
            self.test_user_id, self.app_cred_2['id'])

    def test_identity_get_access_rule(self):
        # should be able to access own credential
        self.do_request(
            'show_access_rule',
            user_id=self.persona.credentials.user_id,
            access_rule_id=self.access_rule_1)

        # retrieving non-existent access rule for self should return 404
        self.do_request(
            'show_access_rule', expected_status=exceptions.NotFound,
            user_id=self.persona.credentials.user_id,
            access_rule_id=data_utils.rand_uuid_hex())

        # should not be able to access another user's credential
        self.do_request(
            'show_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_id, access_rule_id=self.access_rule_2)

        # retrieving non-existent access rule for other user should return 403
        self.do_request(
            'show_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_id,
            access_rule_id=data_utils.rand_uuid_hex())

    def test_identity_list_access_rules(self):
        # should be able to list own credentials
        self.do_request(
            'list_access_rules', user_id=self.persona.credentials.user_id)

        # should not be able to list another user's credentials
        self.do_request(
            'list_access_rules', expected_status=exceptions.Forbidden,
            user_id=self.test_user_id)

    def test_identity_delete_access_rule(self):
        # should be able to delete own credential
        app_cred_client = self.persona.application_credentials_client
        app_cred_client.delete_application_credential(
            user_id=self.persona.credentials.user_id,
            application_credential_id=self.app_cred_1['id'])
        self.do_request(
            'delete_access_rule', expected_status=204,
            user_id=self.persona.credentials.user_id,
            access_rule_id=self.access_rule_1)

        # deleting non-existent access rule for self should return 404
        self.do_request(
            'delete_access_rule', expected_status=exceptions.NotFound,
            user_id=self.persona.credentials.user_id,
            access_rule_id=data_utils.rand_uuid_hex())

        # should not be able to delete another user's credential
        self.do_request(
            'delete_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_id, access_rule_id=self.access_rule_2)

        # deleting non-existent access rule for other user should return 403
        self.do_request(
            'delete_access_rule', expected_status=exceptions.Forbidden,
            user_id=self.test_user_id,
            access_rule_id=data_utils.rand_uuid_hex())


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
