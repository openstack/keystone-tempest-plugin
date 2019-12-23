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


class IdentityV3RbacRoleTest(rbac_base.IdentityV3RbacBaseTests,
                             metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacRoleTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.roles_v3_client
        cls.admin_client = cls.os_system_admin
        cls.admin_roles_client = cls.admin_client.roles_v3_client

    @classmethod
    def resource_setup(cls):
        super(IdentityV3RbacRoleTest, cls).resource_setup()
        cls.own_domain = cls.persona.credentials.domain_id
        cls.domain_id = cls.admin_client.domains_client.create_domain(
            name=data_utils.rand_name('domain'))['domain']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.delete_domain,
            cls.domain_id)
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.update_domain,
            cls.domain_id,
            enabled=False)

    def role(self, domain_id=None):
        role = {}
        name = data_utils.rand_name('role')
        role['name'] = name
        if domain_id:
            role['domain_id'] = domain_id
        return role

    @abc.abstractmethod
    def test_identity_create_role(self):
        """Test identity:create_role policy.

        This test must check:
          * whether the persona can create a role
        """
        pass

    @abc.abstractmethod
    def test_identity_get_role(self):
        """Test identity:get_role policy.

        This test must check:
          * whether the persona can get a role
          * whether the persona can get a role that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_roles(self):
        """Test identity:list_roles policy.

        This test must check:
          * whether the persona can list roles
        """
        pass

    @abc.abstractmethod
    def test_identity_update_role(self):
        """Test identity:update_role policy.

        This test must check:
          * whether the persona can update a role
          * whether the persona can update a role that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_role(self):
        """Test identity:delete_role policy.

        This test must check
          * whether the persona can delete a role
          * whether the persona can delete a role that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_create_domain_role(self):
        """Test identity:create_domain_role policy.

        This test must check:
          * whether the persona can create a domain role in their own domain
          * whether the persona can create a domain role in another domain
        """
        pass

    @abc.abstractmethod
    def test_identity_get_domain_role(self):
        """Test identity:get_domain_role policy.

        This test must check:
          * whether the persona can get a domain role in their own domain
          * whether the persona can get a domain role in another domain
          * whether the persona can get a domain role that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_list_domain_roles(self):
        """Test identity:list_domain_roles policy.

        This test must check:
          * whether the persona can list domain roles for their own domain
          * whether the persona can list domain roles for another domain
        """
        pass

    @abc.abstractmethod
    def test_identity_update_domain_role(self):
        """Test identity:update_domain_role policy.

        This test must check:
          * whether the persona can update a domain role for their own domain
          * whether the persona can update a domain role for another domain
          * whether the persona can update a domain role that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_domain_role(self):
        """Test identity:delete_domain_role policy.

        This test must check
          * whether the persona can delete a domain role for their own domain
          * whether the persona can delete a domain role for another domain
          * whether the persona can delete a domain role that does not exist
        """
        pass


class SystemAdminTests(IdentityV3RbacRoleTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_role(self):
        # user can create role
        resp = self.do_request('create_role',
                               expected_status=201,
                               **self.role())
        self.addCleanup(self.admin_roles_client.delete_role,
                        resp['role']['id'])

    def test_identity_get_role(self):
        # user can get role
        role = self.admin_roles_client.create_role(**self.role())['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('show_role', role_id=role['id'])
        # user gets a 404 for nonexistent role
        self.do_request('show_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex())

    def test_identity_list_roles(self):
        # user can list roles
        role = self.admin_roles_client.create_role(**self.role())['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('list_roles')

    def test_identity_update_role(self):
        # user can update role
        role = self.admin_roles_client.create_role(**self.role())['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('update_role',
                        role_id=role['id'],
                        description=data_utils.arbitrary_string())
        # user gets a 404 for nonexistent role
        self.do_request('update_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_role(self):
        # user can delete role
        role = self.admin_roles_client.create_role(**self.role())['role']
        self.do_request('delete_role', expected_status=204, role_id=role['id'])
        # user gets a 404 for nonexistent role
        self.do_request('delete_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex())

    def test_identity_create_domain_role(self):
        # user can create domain role
        resp = self.do_request('create_role',
                               expected_status=201,
                               **self.role(domain_id=self.domain_id))
        self.addCleanup(self.admin_roles_client.delete_role,
                        resp['role']['id'])

    def test_identity_get_domain_role(self):
        # user can get domain role
        role = self.admin_roles_client.create_role(
            **self.role(domain_id=self.domain_id))['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('show_role', role_id=role['id'])
        # user gets a 404 for nonexistent domain role
        self.do_request('show_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex())

    def test_identity_list_domain_roles(self):
        # user can list domain roles
        role = self.admin_roles_client.create_role(
            **self.role(domain_id=self.domain_id))['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('list_roles', domain_id=self.domain_id)

    def test_identity_update_domain_role(self):
        # user can update domain role
        role = self.admin_roles_client.create_role(
            **self.role(domain_id=self.domain_id))['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('update_role',
                        role_id=role['id'],
                        description=data_utils.arbitrary_string())
        # user gets a 404 for nonexistent domain role
        self.do_request('update_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_domain_role(self):
        # user can delete role in other domain
        role = self.admin_roles_client.create_role(
            **self.role(domain_id=self.domain_id))['role']
        self.do_request('delete_role', expected_status=204, role_id=role['id'])
        # user gets a 404 for nonexistent role
        self.do_request('delete_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex())


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_role(self):
        # user cannot create role
        self.do_request('create_role',
                        expected_status=exceptions.Forbidden,
                        **self.role())

    def test_identity_update_role(self):
        # user cannot update role
        role = self.admin_roles_client.create_role(
            **self.role())['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('update_role', expected_status=exceptions.Forbidden,
                        role_id=role['id'],
                        description=data_utils.arbitrary_string())
        # user gets a 404 for nonexistent role
        self.do_request('update_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_role(self):
        # user can delete role
        role = self.admin_roles_client.create_role(
            **self.role())['role']
        self.do_request('delete_role', expected_status=exceptions.Forbidden,
                        role_id=role['id'])
        # user gets a 404 for nonexistent domain role
        self.do_request('delete_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex())

    def test_identity_create_domain_role(self):
        # user cannot create domain role
        self.do_request('create_role',
                        expected_status=exceptions.Forbidden,
                        **self.role(domain_id=self.domain_id))

    def test_identity_update_domain_role(self):
        # user cannot update domain role
        role = self.admin_roles_client.create_role(
            **self.role(domain_id=self.domain_id))['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('update_role', expected_status=exceptions.Forbidden,
                        role_id=role['id'],
                        description=data_utils.arbitrary_string())
        # user gets a 404 for nonexistent domain role
        self.do_request('update_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex(),
                        description=data_utils.arbitrary_string())

    def test_identity_delete_domain_role(self):
        # user can delete domain role
        role = self.admin_roles_client.create_role(
            **self.role(domain_id=self.domain_id))['role']
        self.do_request('delete_role', expected_status=exceptions.Forbidden,
                        role_id=role['id'])
        # user gets a 404 for nonexistent domain role
        self.do_request('delete_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex())


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_role(self):
        # user cannot get role
        role = self.admin_roles_client.create_role(
            **self.role())['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('show_role', expected_status=exceptions.Forbidden,
                        role_id=role['id'])
        # user gets a 404 for nonexistent role
        self.do_request('show_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex())

    def test_identity_list_roles(self):
        # user cannot list roles
        role = self.admin_roles_client.create_role(**self.role())['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('list_roles', expected_status=exceptions.Forbidden)

    def test_identity_get_domain_role(self):
        # user cannot get domain role in own domain
        role = self.admin_roles_client.create_role(**self.role())['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('show_role', expected_status=exceptions.Forbidden,
                        role_id=role['id'])
        # user gets a 404 for nonexistent domain role
        self.do_request('show_role', expected_status=exceptions.NotFound,
                        role_id=data_utils.rand_uuid_hex())

    def test_identity_list_domain_roles(self):
        # user cannot list domain roles in own domain
        role = self.admin_roles_client.create_role(
            **self.role(domain_id=self.own_domain))['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('list_roles', expected_status=exceptions.Forbidden,
                        domain_id=self.persona.credentials.domain_id)
        # user cannot get domain role in other domain
        role = self.admin_roles_client.create_role(
            **self.role(domain_id=self.domain_id))['role']
        self.addCleanup(self.admin_roles_client.delete_role, role['id'])
        self.do_request('list_roles', expected_status=exceptions.Forbidden,
                        domain_id=self.domain_id)


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
