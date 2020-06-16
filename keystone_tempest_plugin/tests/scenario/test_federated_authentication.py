# Copyright 2016 Red Hat, Inc.
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

import http.client
import json
from lxml import etree
from tempest import config
from tempest.lib.common.utils import data_utils
import testtools
import urllib

from keystone_tempest_plugin.tests import base


CONF = config.CONF


class TestSaml2EcpFederatedAuthentication(base.BaseIdentityTest):

    ECP_SAML2_NAMESPACES = {
        'ecp': 'urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp',
        'S': 'http://schemas.xmlsoap.org/soap/envelope/',
        'paos': 'urn:liberty:paos:2003-08'
    }

    ECP_SERVICE_PROVIDER_CONSUMER_URL = ('/S:Envelope/S:Header/paos:Request/'
                                         '@responseConsumerURL')

    ECP_IDP_CONSUMER_URL = ('/S:Envelope/S:Header/ecp:Response/'
                            '@AssertionConsumerServiceURL')

    ECP_RELAY_STATE = '//ecp:RelayState'

    def _setup_settings(self):
        self.idp_id = CONF.fed_scenario.idp_id
        self.idp_remote_ids = CONF.fed_scenario.idp_remote_ids
        self.idp_url = CONF.fed_scenario.idp_ecp_url
        self.keystone_v3_endpoint = CONF.identity.uri_v3
        self.password = CONF.fed_scenario.idp_password
        self.protocol_id = CONF.fed_scenario.protocol_id
        self.username = CONF.fed_scenario.idp_username

        self.mapping_remote_type = CONF.fed_scenario.mapping_remote_type
        self.mapping_user_name = CONF.fed_scenario.mapping_user_name
        self.mapping_group_name = CONF.fed_scenario.mapping_group_name
        self.mapping_group_domain_name = \
            CONF.fed_scenario.mapping_group_domain_name

        # NOTE(knikolla): Authentication endpoint for keystone. If not set,
        # will be autodetected.
        self.auth_url = None

    def _setup_idp(self):
        idp = self.idps_client.create_identity_provider(
            self.idp_id, remote_ids=self.idp_remote_ids, enabled=True)
        self.addCleanup(
            self.keystone_manager.domains_client.delete_domain,
            idp['identity_provider']['domain_id'])
        self.addCleanup(
            self.keystone_manager.domains_client.update_domain,
            idp['identity_provider']['domain_id'], enabled=False)
        self.addCleanup(
            self.idps_client.delete_identity_provider, self.idp_id)

    def _setup_mapping(self):
        self.mapping_id = data_utils.rand_uuid_hex()
        rules = [{
            'local': [
                {
                    'user': {'name': self.mapping_user_name}
                },
                {
                    'group': {
                        'domain': {'name': self.mapping_group_domain_name},
                        'name': self.mapping_group_name
                    }
                }
            ],
            'remote': [
                {
                    'type': self.mapping_remote_type
                }
            ]
        }]
        mapping_ref = {'rules': rules}
        self.mappings_client.create_mapping_rule(self.mapping_id, mapping_ref)
        self.addCleanup(
            self.mappings_client.delete_mapping_rule, self.mapping_id)

    def _setup_protocol(self):
        self.idps_client.add_protocol_and_mapping(
            self.idp_id, self.protocol_id, self.mapping_id)
        self.addCleanup(
            self.idps_client.delete_protocol_and_mapping,
            self.idp_id,
            self.protocol_id)

    def setUp(self):
        super(TestSaml2EcpFederatedAuthentication, self).setUp()
        self._setup_settings()

        # Reset client's session to avoid getting garbage from another runs
        self.saml2_client.reset_session()

        # Setup identity provider, mapping and protocol
        self._setup_idp()
        self._setup_mapping()
        self._setup_protocol()

    def _str_from_xml(self, xml, path):
        item = xml.xpath(path, namespaces=self.ECP_SAML2_NAMESPACES)
        self.assertEqual(1, len(item))
        return item[0]

    def _get_sp_authn_request(self):
        resp = self.saml2_client.send_service_provider_request(
            self.keystone_v3_endpoint, self.idp_id, self.protocol_id)
        self.assertEqual(http.client.OK, resp.status_code)
        saml2_authn_request = etree.XML(resp.content)

        relay_state = self._str_from_xml(
            saml2_authn_request, self.ECP_RELAY_STATE)
        sp_consumer_url = self._str_from_xml(
            saml2_authn_request, self.ECP_SERVICE_PROVIDER_CONSUMER_URL)

        # Perform the authn request to the identity provider
        resp = self.saml2_client.send_identity_provider_authn_request(
            saml2_authn_request, self.idp_url, self.username, self.password)
        self.assertEqual(http.client.OK, resp.status_code)
        saml2_idp_authn_response = etree.XML(resp.content)

        idp_consumer_url = self._str_from_xml(
            saml2_idp_authn_response, self.ECP_IDP_CONSUMER_URL)

        # Assert that both saml2_authn_request and saml2_idp_authn_response
        # have the same consumer URL.
        self.assertEqual(sp_consumer_url, idp_consumer_url)

        self.saml2_client.prepare_sp_saml2_authn_response(
            saml2_idp_authn_response, relay_state)

        return saml2_idp_authn_response, sp_consumer_url

    def _request_unscoped_token(self):
        assertion, sp_url = self._get_sp_authn_request()

        # Present the identity provider authn response to the service provider
        resp = self.saml2_client.send_service_provider_saml2_authn_response(
            assertion, sp_url)
        # Must receive a redirect from service provider to the URL where the
        # unscoped token can be retrieved.
        self.assertIn(resp.status_code,
                      [http.client.FOUND, http.client.SEE_OTHER])

        # If this is K2K, don't follow HTTP specs - after the HTTP 302/303
        # response don't repeat the call directed to the Location URL. In this
        # case, this is an indication that SAML2 session is now active and
        # protected resource can be accessed.
        # https://opendev.org/openstack/keystoneauth/src/tag/3.17.1/keystoneauth1/identity/v3/k2k.py#L152
        sp_url = self.auth_url or resp.headers['location']

        # We can receive multiple types of errors here, the response depends on
        # the mapping and the username used to authenticate in the Identity
        # Provider and also in the Identity Provider remote ID validation.
        # If everything works well, we receive an unscoped token.
        resp = (
            self.saml2_client.send_service_provider_unscoped_token_request(
                sp_url))
        self.assertEqual(http.client.CREATED, resp.status_code)
        self.assertIn('X-Subject-Token', resp.headers)
        self.assertNotEmpty(resp.json())

        return resp

    def _test_request_unscoped_token(self):
        self._request_unscoped_token()

    def _test_request_scoped_token(self):
        resp = self._request_unscoped_token()
        token_id = resp.headers['X-Subject-Token']

        projects = self.auth_client.get_available_projects_scopes(
            self.keystone_v3_endpoint, token_id)['projects']
        self.assertNotEmpty(projects)

        # Get a scoped token to one of the listed projects
        self.tokens_client.auth(
            project_id=projects[0]['id'], token=token_id)


class TestSaml2FederatedExternalAuthentication(
    TestSaml2EcpFederatedAuthentication):

    @testtools.skipUnless(CONF.identity_feature_enabled.federation,
                          "Federated Identity feature not enabled")
    @testtools.skipUnless(CONF.identity_feature_enabled.external_idp,
                          "External identity provider is not available")
    def test_request_unscoped_token(self):
        self._test_request_unscoped_token()

    @testtools.skipUnless(CONF.identity_feature_enabled.federation,
                          "Federated Identity feature not enabled")
    @testtools.skipUnless(CONF.identity_feature_enabled.external_idp,
                          "External identity provider is not available")
    def test_request_scoped_token(self):
        self._test_request_scoped_token()


class TestK2KFederatedAuthentication(TestSaml2EcpFederatedAuthentication):

    def setUp(self):
        super(TestK2KFederatedAuthentication, self).setUp()
        self._setup_sp()
        self.auth = {'password': data_utils.rand_password()}
        user_id = self.keystone_manager.users_v3_client.create_user(
            name=data_utils.rand_name('user'),
            password=self.auth['password'])['user']['id']
        self.addCleanup(
            self.keystone_manager.users_v3_client.delete_user, user_id)
        self.auth['user_id'] = user_id
        idp_info = self.idps_client.show_identity_provider(self.idp_id)
        domain_id = idp_info['identity_provider']['domain_id']
        project_id = self.keystone_manager.identity_providers_client.tenant_id
        self.auth['project_id'] = project_id
        group = self.keystone_manager.groups_client.create_group(
            name=data_utils.rand_uuid_hex(), domain_id=domain_id)
        self.addCleanup(
            self.keystone_manager.groups_client.delete_group,
            group['group']['id'])
        role = self.keystone_manager.roles_v3_client.create_role(
            name=data_utils.rand_uuid_hex(), project_id=project_id)
        self.addCleanup(
            self.keystone_manager.roles_v3_client.delete_role,
            role['role']['id'])
        self.keystone_manager.roles_v3_client.create_group_role_on_project(
            group_id=group['group']['id'], project_id=project_id,
            role_id=role['role']['id'])
        self.keystone_manager.groups_client.add_group_user(
            group_id=group['group']['id'], user_id=user_id)

    def _setup_settings(self):
        super(TestK2KFederatedAuthentication, self)._setup_settings()
        self.idp_id = 'keystone'
        self.idp_remote_ids = [
            '%s/OS-FEDERATION/saml2/idp' % self.keystone_v3_endpoint]

        self.mapping_remote_type = 'openstack_user'

        self.sp_id = 'keystone'
        self.auth_url = (
            '%s/OS-FEDERATION/identity_providers/%s/protocols/%s/auth'
            ) % (self.keystone_v3_endpoint, self.sp_id, self.protocol_id)
        url = urllib.parse.urlparse(self.keystone_v3_endpoint)
        self.sp_url = '%s://%s/Shibboleth.sso/SAML2/ECP' % (url.scheme,
                                                            url.netloc)

    def _setup_mapping(self):
        if not CONF.fed_scenario.enable_k2k_groups_mapping:
            super(TestK2KFederatedAuthentication, self)._setup_mapping()
            return
        self.mapping_id = data_utils.rand_uuid_hex()
        rules = [{
            'local': [
                {
                    'user': {'name': self.mapping_user_name}
                },
                {
                    'groups': '{1}'
                }
            ],
            'remote': [
                {
                    'type': self.mapping_remote_type
                },
                {
                    "type": 'openstack_groups'
                }
            ]
        }]
        mapping_ref = {'rules': rules}
        self.mappings_client.create_mapping_rule(self.mapping_id, mapping_ref)
        self.addCleanup(
            self.mappings_client.delete_mapping_rule, self.mapping_id)

    def _setup_sp(self):
        self.sps_client.create_service_provider(self.sp_id,
                                                sp_url=self.sp_url,
                                                auth_url=self.auth_url,
                                                enabled=True)
        self.addCleanup(self.sps_client.delete_service_provider, self.sp_id)

    def _get_sp_authn_request(self):
        token = self.tokens_client.get_token(
            user_id=self.auth['user_id'],
            password=self.auth['password'],
            project_id=self.auth['project_id'])
        body = {
            'auth': {
                'identity': {
                    'methods': ['token'],
                    'token': {
                        'id': token
                    }
                },
                'scope': {
                    'service_provider': {
                        'id': self.sp_id
                    }
                }
            }
        }
        resp, saml = self.auth_client.post('auth/OS-FEDERATION/saml2/ecp',
                                           json.dumps(body))
        self.auth_client.expected_success(200, resp.status)

        return etree.XML(saml), self.sp_url

    @testtools.skipUnless(CONF.identity_feature_enabled.federation,
                          "Federated Identity feature not enabled")
    def test_request_unscoped_token(self):
        self._test_request_unscoped_token()

    @testtools.skipUnless(CONF.identity_feature_enabled.federation,
                          "Federated Identity feature not enabled")
    def test_request_scoped_token(self):
        self._test_request_scoped_token()
