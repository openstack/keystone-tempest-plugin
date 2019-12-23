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


class IdentityV3RbacDomainConfigTest(rbac_base.IdentityV3RbacBaseTests,
                                     metaclass=abc.ABCMeta):

    @classmethod
    def setup_clients(cls):
        super(IdentityV3RbacDomainConfigTest, cls).setup_clients()
        cls.persona = getattr(cls, 'os_%s' % cls.credentials[0])
        cls.client = cls.persona.domain_config_client
        cls.admin_client = cls.os_system_admin
        cls.admin_domain_config_client = cls.admin_client.domain_config_client

    @classmethod
    def resource_setup(cls):
        super(IdentityV3RbacDomainConfigTest, cls).resource_setup()
        cls.domain_id = cls.admin_client.domains_client.create_domain(
            name=data_utils.rand_name('domain'))['domain']['id']
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.delete_domain,
            cls.domain_id)
        cls.addClassResourceCleanup(
            cls.admin_client.domains_client.update_domain,
            cls.domain_id,
            enabled=False)

    def domain_config(self, **kwargs):
        ref = {
            "identity": {
                "driver": "ldap"
            },
            "ldap": {
                "url": "ldap://myldap.com:389/",
                "user_tree_dn": "ou=Users,dc=my_new_root,dc=org"
            }
        }
        ref.update(kwargs)
        return ref

    @abc.abstractmethod
    def test_identity_create_domain_config(self):
        """Test identity:create_domain_config policy.

        This test must check:
          * whether the persona can create a domain config for a valid domain
        """
        pass

    @abc.abstractmethod
    def test_identity_get_domain_config(self):
        """Test identity:get_domain_config policy.

        This test must check:
          * whether the persona can get a domain config
          * whether the persona can get an option group for a domain config
          * whether the persona can get an option from a group in a domain
            config
          * whether the persona can get a config for an invalid domain
          * whether the persona can get a config that does not exist
        """
        pass

    @abc.abstractmethod
    def test_identity_get_domain_config_default(self):
        """Test identity:get_domain_config_default policy.

          * whether the persona can get the default config
          * whether the persona can get the default config for an option group
          * whether the persona can get the default value for an option
        """
        pass

    @abc.abstractmethod
    def test_identity_get_security_compliance_domain_config(self):
        """Test identity:get_security_compliance_domain_config policy.

        This test must check:
          * whether the persona can get the security compliance configuration
            for the default domain
          * whether the persona can get an option from the security compliance
            configuration for the default domain
        """
        pass

    @abc.abstractmethod
    def test_identity_update_domain_config(self):
        """Test identity:update_domain_config policy.

        This test must check:
          * whether the persona can update the config for a domain
          * whether the persona can update an option group config for a domain
          * whether the persona can update an option in a domain config
        """
        pass

    @abc.abstractmethod
    def test_identity_delete_domain_config(self):
        """Test identity:delete_domain_config policy.

        This test must check
          * whether the persona can delete a domain config
          * whether the persona can delete an option group within a domain
            config
          * whether the persona can delete an option within a domain config
        """
        pass


class SystemAdminTests(IdentityV3RbacDomainConfigTest, base.BaseIdentityTest):

    credentials = ['system_admin']

    def test_identity_create_domain_config(self):
        self.do_request(
            'create_domain_config',
            expected_status=201,
            domain_id=self.domain_id,
            **self.domain_config())
        self.addCleanup(
            self.admin_domain_config_client.delete_domain_config,
            self.domain_id)

    def test_identity_get_domain_config(self):
        # should be able to get domain config, group and individual options
        self.admin_domain_config_client.create_domain_config(
            self.domain_id, **self.domain_config())
        self.addCleanup(
            self.admin_domain_config_client.delete_domain_config,
            self.domain_id)
        self.do_request(
            'show_domain_config',
            domain_id=self.domain_id)
        self.do_request(
            'show_domain_group_config',
            domain_id=self.domain_id,
            group='ldap')
        self.do_request(
            'show_domain_group_option_config',
            domain_id=self.domain_id,
            group='ldap',
            option='url')
        # should get Not Found for invalid domain
        self.do_request(
            'show_domain_config',
            expected_status=exceptions.NotFound,
            domain_id=data_utils.rand_uuid_hex())
        # should get Not Found for nonexistent config for valid domain
        domain = self.admin_client.domains_client.create_domain(
            name=data_utils.rand_name('domain'))['domain']['id']
        self.addCleanup(self.admin_client.domains_client.delete_domain, domain)
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            domain, enabled=False)
        self.do_request(
            'show_domain_config',
            expected_status=exceptions.NotFound,
            domain_id=domain)

    def test_identity_get_domain_config_default(self):
        self.do_request('show_default_config_settings')
        self.do_request('show_default_group_config', group='ldap')
        self.do_request(
            'show_default_group_option', group='ldap', option='url')

    def test_identity_get_security_compliance_domain_config(self):
        self.do_request(
            'show_domain_group_config',
            domain_id='default',
            group='security_compliance')
        self.do_request(
            'show_domain_group_option_config',
            domain_id='default',
            group='security_compliance',
            option='password_regex_description')

    def test_identity_update_domain_config(self):
        self.admin_domain_config_client.create_domain_config(
            self.domain_id, **self.domain_config())
        self.addCleanup(
            self.admin_domain_config_client.delete_domain_config,
            self.domain_id)
        self.do_request(
            'update_domain_group_config',
            domain_id=self.domain_id,
            group='ldap',
            ldap={'url': 'ldaps://myldap.com:636/',
                  'user_tree_dn': 'ou=People,dc=my_new_root,dc=org'})
        self.do_request(
            'update_domain_group_option_config',
            domain_id=self.domain_id,
            group='ldap',
            option='user_tree_dn',
            user_tree_dn='ou=Aliens,dc=my_new_root,dc=org')
        # test changing the entire config last
        self.do_request(
            'update_domain_config',
            domain_id=self.domain_id,
            identity={"driver": "sql"})

    def test_identity_delete_domain_config(self):
        self.admin_domain_config_client.create_domain_config(
            self.domain_id, **self.domain_config())
        self.do_request(
            'delete_domain_group_option_config',
            expected_status=204,
            domain_id=self.domain_id,
            group='ldap',
            option='user_tree_dn')
        self.do_request(
            'delete_domain_group_config',
            expected_status=204,
            domain_id=self.domain_id,
            group='ldap')
        self.do_request(
            'delete_domain_config',
            expected_status=204,
            domain_id=self.domain_id)


class SystemMemberTests(SystemAdminTests):

    credentials = ['system_member', 'system_admin']

    def test_identity_create_domain_config(self):
        self.do_request(
            'create_domain_config',
            expected_status=exceptions.Forbidden,
            domain_id=self.domain_id,
            **self.domain_config())

    def test_identity_update_domain_config(self):
        self.admin_domain_config_client.create_domain_config(
            self.domain_id, **self.domain_config())
        self.addCleanup(
            self.admin_domain_config_client.delete_domain_config,
            self.domain_id)
        self.do_request(
            'update_domain_group_config',
            expected_status=exceptions.Forbidden,
            domain_id=self.domain_id,
            group='ldap',
            ldap={'url': 'ldaps://myldap.com:636/',
                  'user_tree_dn': 'ou=People,dc=my_new_root,dc=org'})
        self.do_request(
            'update_domain_group_option_config',
            expected_status=exceptions.Forbidden,
            domain_id=self.domain_id,
            group='ldap',
            option='user_tree_dn',
            user_tree_dn='ou=Aliens,dc=my_new_root,dc=org')
        # test changing the entire config last
        self.do_request(
            'update_domain_config',
            expected_status=exceptions.Forbidden,
            domain_id=self.domain_id,
            identity={"driver": "sql"})

    def test_identity_delete_domain_config(self):
        self.admin_domain_config_client.create_domain_config(
            self.domain_id, **self.domain_config())
        self.do_request(
            'delete_domain_group_option_config',
            expected_status=exceptions.Forbidden,
            domain_id=self.domain_id,
            group='ldap',
            option='user_tree_dn')
        self.do_request(
            'delete_domain_group_config',
            expected_status=exceptions.Forbidden,
            domain_id=self.domain_id,
            group='ldap')
        self.do_request(
            'delete_domain_config',
            expected_status=exceptions.Forbidden,
            domain_id=self.domain_id)


class SystemReaderTests(SystemMemberTests):

    credentials = ['system_reader', 'system_admin']


class DomainAdminTests(SystemReaderTests):

    credentials = ['domain_admin', 'system_admin']

    def test_identity_get_domain_config(self):
        # should not be able to get domain config, group and individual options
        self.admin_domain_config_client.create_domain_config(
            self.domain_id, **self.domain_config())
        self.addCleanup(
            self.admin_domain_config_client.delete_domain_config,
            self.domain_id)
        self.do_request(
            'show_domain_config',
            expected_status=exceptions.Forbidden,
            domain_id=self.domain_id)
        self.do_request(
            'show_domain_group_config',
            expected_status=exceptions.Forbidden,
            domain_id=self.domain_id,
            group='ldap')
        self.do_request(
            'show_domain_group_option_config',
            expected_status=exceptions.Forbidden,
            domain_id=self.domain_id,
            group='ldap',
            option='url')
        # should get Forbidden for invalid domain
        self.do_request(
            'show_domain_config',
            expected_status=exceptions.Forbidden,
            domain_id=data_utils.rand_uuid_hex())
        # should get Forbidden for nonexistent config for valid domain
        domain = self.admin_client.domains_client.create_domain(
            name=data_utils.rand_name('domain'))['domain']['id']
        self.addCleanup(self.admin_client.domains_client.delete_domain, domain)
        self.addCleanup(
            self.admin_client.domains_client.update_domain,
            domain, enabled=False)
        self.do_request(
            'show_domain_config',
            expected_status=exceptions.Forbidden,
            domain_id=domain)

    def test_identity_get_domain_config_default(self):
        self.do_request(
            'show_default_config_settings',
            expected_status=exceptions.Forbidden)
        self.do_request(
            'show_default_group_config',
            expected_status=exceptions.Forbidden, group='ldap')
        self.do_request(
            'show_default_group_option',
            expected_status=exceptions.Forbidden, group='ldap', option='url')


class DomainMemberTests(DomainAdminTests):

    credentials = ['domain_member', 'system_admin']


class DomainReaderTests(DomainAdminTests):

    credentials = ['domain_reader', 'system_admin']


class ProjectAdminTests(DomainReaderTests):

    credentials = ['project_admin', 'system_admin']


class ProjectMemberTests(ProjectAdminTests):

    credentials = ['project_member', 'system_admin']


class ProjectReaderTests(ProjectAdminTests):

    credentials = ['project_reader', 'system_admin']
